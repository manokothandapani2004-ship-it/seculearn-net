import os
import sys
import ssl
import json
import socket
import struct
import time
from flask import Flask, request, jsonify

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.crypto_engine import get_current_ist_str

app = Flask(__name__)

VAULT_ID = int(sys.argv[1]) if len(sys.argv) > 1 else 1
VAULT_NAME = sys.argv[2] if len(sys.argv) > 2 else f"Custodian_Vault_{VAULT_ID}"
PORT = 9000 + VAULT_ID

VAULT_DATA_DIR = os.path.join("vault_cluster", "storage", f"Vault_{VAULT_ID}")
os.makedirs(VAULT_DATA_DIR, exist_ok=True)
SHARE_FILE = os.path.join(VAULT_DATA_DIR, "custody_share.json")
HEAD_FILE = os.path.join(VAULT_DATA_DIR, "replicated_heads.json")

NTP_SERVERS = ["pool.ntp.org", "time.google.com", "time.cloudflare.com"]


def get_trusted_ntp_time() -> tuple[float, str]:
    """
    Queries independent NTP servers so a compromised coordinator system clock
    cannot trick a custodian into releasing shares before T_0 (Section 3.2).
    """
    for srv in NTP_SERVERS:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(1.5)
            packet = b"\x1b" + 47 * b"\0"
            client.sendto(packet, (srv, 123))
            msg, _ = client.recvfrom(1024)
            ntp_seconds = struct.unpack("!12I", msg)[10] - 2208988800
            return float(ntp_seconds), f"NTP:{srv}"
        except Exception:
            continue
    return time.time(), "LOCAL_TRUSTED_CLOCK"


@app.route("/api/vault/health", methods=["GET"])
def health():
    return jsonify({"vault_id": VAULT_ID, "vault_name": VAULT_NAME, "port": PORT, "status": "ONLINE"})


@app.route("/api/vault/store_share", methods=["POST"])
def store_share():
    data = request.get_json() or {}
    record = {
        "vault_id": VAULT_ID,
        "vault_name": VAULT_NAME,
        "exam_id": data["exam_id"],
        "share_x": int(data["share_x"]),
        "share_y": str(data["share_y"]),
        "t0": float(data["t0"]),
        "scheme": data.get("scheme", ""),
        "stored_at_ist": get_current_ist_str()
    }
    with open(SHARE_FILE, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=4)
    return jsonify({"status": "STORED", "vault_id": VAULT_ID, "vault_name": VAULT_NAME}), 200


@app.route("/api/vault/release_share", methods=["POST"])
def release_share():
    data = request.get_json() or {}
    exam_id = data.get("exam_id")

    if not os.path.exists(SHARE_FILE):
        return jsonify({"error": "NO_SHARE_HELD", "vault_id": VAULT_ID}), 404

    with open(SHARE_FILE, "r", encoding="utf-8") as f:
        record = json.load(f)

    if record.get("exam_id") != exam_id:
        return jsonify({"error": "EXAM_ID_MISMATCH", "vault_id": VAULT_ID}), 404

    # Independent Trusted Time Check (Section 3.2 & Section 6.4)
    trusted_now, time_source = get_trusted_ntp_time()
    if trusted_now < record["t0"]:
        return jsonify({
            "error": "TIME_LOCK_ACTIVE",
            "vault_id": VAULT_ID,
            "vault_name": VAULT_NAME,
            "trusted_time": trusted_now,
            "t0": record["t0"],
            "time_source": time_source
        }), 403

    share_payload = {
        "vault_id": VAULT_ID,
        "vault_name": VAULT_NAME,
        "share_x": record["share_x"],
        "share_y": record["share_y"],
        "time_source": time_source
    }

    # Flush share after release so secret material does not linger
    os.remove(SHARE_FILE)
    return jsonify(share_payload), 200


@app.route("/api/vault/replicate_head", methods=["POST"])
def replicate_head():
    data = request.get_json() or {}
    access_code = data.get("access_code")
    heads = {}
    if os.path.exists(HEAD_FILE):
        with open(HEAD_FILE, "r", encoding="utf-8") as f:
            heads = json.load(f)
    heads[access_code] = {
        "head_hash": data.get("head_hash"),
        "block_index": data.get("block_index"),
        "replicated_at_ist": get_current_ist_str()
    }
    with open(HEAD_FILE, "w", encoding="utf-8") as f:
        json.dump(heads, f, indent=4)
    return jsonify({"status": "REPLICATED", "vault_id": VAULT_ID}), 200


@app.route("/api/vault/get_head/<access_code>", methods=["GET"])
def get_head(access_code):
    if not os.path.exists(HEAD_FILE):
        return jsonify({"head_hash": None}), 404
    with open(HEAD_FILE, "r", encoding="utf-8") as f:
        heads = json.load(f)
    entry = heads.get(access_code)
    if not entry:
        return jsonify({"head_hash": None}), 404
    return jsonify(entry), 200


if __name__ == "__main__":
    cert_path = os.path.join("certs", "cert.pem")
    key_path = os.path.join("certs", "key.pem")
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    app.run(host="0.0.0.0", port=PORT, ssl_context=ssl_ctx, debug=False)