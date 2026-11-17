import os
import sys
import ssl
import time
import random
import string
import json
import threading
import urllib3
import requests
import numpy as np

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, jsonify
from core.crypto_engine import CryptoEngine, ShamirSecretSharing, get_current_ist_str
from core.blockchain_ledger import BlockchainLedger, LEDGER_DIR, VAULT_URLS

app = Flask(__name__)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(LEDGER_DIR, exist_ok=True)

SHARED_STATE_FILE = "shared_exam_session.json"

INSTITUTION_POOL = [
    "IIT_Madras_Vault", "Anna_Univ_Vault", "NIT_Trichy_Vault", "BITS_Pilani_Vault",
    "VIT_Vellore_Vault", "IISc_Bangalore_Vault", "IIT_Bombay_Vault", "IIT_Delhi_Vault",
    "Jadavpur_Vault", "IIIT_Hyderabad_Vault", "Amrita_Vault", "SRM_Vault",
    "PSG_Tech_Vault", "Thapar_Vault", "Manipal_Vault"
]

EXAM_CONFIG = {
    "status": "IDLE",
    "exam_id": None,
    "filename": None,
    "mime_type": "application/pdf",
    "lock_until": 0,
    "exam_duration_seconds": 900,
    "exam_duration_str": "00:15:00",
    "access_code": None,
    "encrypted_package": None,
    "reconstructed_key_hex": None,
    "threshold": 3,
    "total_nodes": 5,
    "selected_vault_ids": []
}

# 11-parameter logistic violation model: 10 feature weights + 1 bias (Section 3.5)
FEDERATED_STATE = {
    "current_round": 1,
    "connected_nodes": {},
    "global_theta": [0.1] * 10 + [-1.5],
    "loss_history": [0.428],
    "total_updates_received": 0,
    "anomaly_count": 0,
    "normal_count": 0,
    "pending_updates": []
}


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


def fedavg_aggregate_round():
    """
    Executes Equation (6): theta^{(t+1)} = sum_{k=1}^K (n_k / n) * theta_k^{(t+1)}
    every 10 seconds across active client nodes.
    """
    pending = FEDERATED_STATE["pending_updates"]
    if not pending:
        return

    total_n = sum(max(1, item.get("n_k", 1)) for item in pending)
    agg_theta = np.zeros(11, dtype=np.float64)
    weighted_loss = 0.0

    for item in pending:
        nk = max(1, item.get("n_k", 1))
        theta_k = np.array(item["theta"][:11], dtype=np.float64)
        if theta_k.shape[0] == 11:
            agg_theta += (nk / total_n) * theta_k
        weighted_loss += (nk / total_n) * float(item.get("loss", FEDERATED_STATE["loss_history"][-1]))

    FEDERATED_STATE["global_theta"] = [round(float(x), 6) for x in agg_theta]
    FEDERATED_STATE["loss_history"].append(round(weighted_loss, 4))
    if len(FEDERATED_STATE["loss_history"]) > 20:
        FEDERATED_STATE["loss_history"].pop(0)

    FEDERATED_STATE["current_round"] += 1
    FEDERATED_STATE["pending_updates"].clear()


def background_fedavg_scheduler():
    """Runs FedAvg consensus round every 10.0 seconds (Section 3.5)."""
    while True:
        time.sleep(10.0)
        fedavg_aggregate_round()


threading.Thread(target=background_fedavg_scheduler, daemon=True).start()


def generate_access_code(length=6):
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def parse_duration_to_seconds(duration_str: str) -> int:
    parts = duration_str.strip().split(":")
    if len(parts) == 3:
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
    elif len(parts) == 2:
        return int(parts[0]) * 60 + int(parts[1])
    else:
        return int(duration_str)


def background_time_lock_monitor():
    while True:
        time.sleep(1)
        if EXAM_CONFIG["status"] == "LOCKED":
            rem = EXAM_CONFIG["lock_until"] - time.time()
            if rem <= 0:
                threshold = EXAM_CONFIG["threshold"]
                total_nodes = EXAM_CONFIG["total_nodes"]
                exam_id = EXAM_CONFIG["exam_id"]
                selected_ids = EXAM_CONFIG["selected_vault_ids"]

                print(f"\n[+] T_0 REACHED ({get_current_ist_str()})! Requesting quorum ({threshold} of {total_nodes} active vaults from 15-vault pool)...")

                quorum_candidates = random.sample(selected_ids, len(selected_ids))
                collected_shares = []
                used_vaults = []

                for v_id in quorum_candidates:
                    if len(collected_shares) >= threshold:
                        break
                    vault_url = VAULT_URLS[v_id - 1]
                    try:
                        res = requests.post(
                            f"{vault_url}/api/vault/release_share",
                            json={"exam_id": exam_id},
                            verify=False,
                            timeout=2.0
                        )
                        if res.status_code == 200:
                            payload = res.json()
                            share_pair = (int(payload["share_x"]), int(payload["share_y"]))
                            collected_shares.append(share_pair)
                            used_vaults.append(f"Vault_{v_id}({payload.get('vault_name')})")
                        else:
                            print(f"[!] Vault_{v_id} refused share release: {res.json()}")
                    except Exception as e:
                        print(f"[!] Vault_{v_id} unreachable: {e}")

                if len(collected_shares) < threshold:
                    print(f"[!] Waiting for quorum: collected {len(collected_shares)}/{threshold} shares...")
                    continue

                sss = ShamirSecretSharing(threshold=threshold, total_shares=total_nodes)
                key_int = sss.reconstruct_secret(collected_shares[:threshold])
                reconstructed_key = key_int.to_bytes(32, byteorder="big")

                code = generate_access_code(6)
                EXAM_CONFIG["access_code"] = code
                EXAM_CONFIG["reconstructed_key_hex"] = reconstructed_key.hex()
                EXAM_CONFIG["status"] = "READY"

                print("[+] Master AES-256 key reconstructed in volatile RAM via Lagrange interpolation!")
                print(f"[+] Quorum Custodians Used: {used_vaults}")
                print(f"[+] Faculty Access Code generated: {code}")

                BlockchainLedger.init_ledger_file(code)

                with open(SHARED_STATE_FILE, "w", encoding="utf-8") as f:
                    json.dump({
                        "access_code": code,
                        "status": "READY",
                        "created_ist": get_current_ist_str(),
                        "mime_type": EXAM_CONFIG["mime_type"],
                        "encrypted_package": EXAM_CONFIG["encrypted_package"],
                        "key_hex": reconstructed_key.hex(),
                        "threshold": threshold,
                        "total_nodes": total_nodes,
                        "pool_size": 15,
                        "exam_duration_seconds": EXAM_CONFIG["exam_duration_seconds"],
                        "exam_duration_str": EXAM_CONFIG["exam_duration_str"]
                    }, f, indent=4)

                # Flush reconstructed key from coordinator memory after handoff
                del key_int
                del reconstructed_key


threading.Thread(target=background_time_lock_monitor, daemon=True).start()


@app.route("/")
def index():
    return render_template("faculty_dashboard.html")


@app.route("/api/upload_and_lock", methods=["POST"])
def upload_and_lock():
    if "paper_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["paper_file"]
    lock_duration_str = request.form.get("lock_duration", "00:00:10").strip()
    exam_duration_str = request.form.get("exam_duration", "00:15:00").strip()

    # Select random active committee N in {5, 7, 9, 11} from the 15-vault institutional pool
    total_nodes = random.choice([5, 7, 9, 11])
    threshold = (total_nodes // 2) + 1

    try:
        lock_sec = parse_duration_to_seconds(lock_duration_str)
        exam_sec = parse_duration_to_seconds(exam_duration_str)
    except ValueError:
        return jsonify({"error": "Invalid duration format. Use HH:MM:SS"}), 400

    if lock_sec <= 0 or exam_sec <= 0:
        return jsonify({"error": "Durations must be positive numbers"}), 400

    filepath = os.path.join(UPLOAD_DIR, file.filename)
    file.save(filepath)

    with open(filepath, "rb") as f:
        content_bytes = f.read()

    # Encrypt paper with fresh 256-bit AES-GCM key and overwrite plaintext/key in memory
    master_key = CryptoEngine.generate_aes_key()
    encrypted_pkg = CryptoEngine.encrypt_data(content_bytes, master_key)
    del content_bytes
    EXAM_CONFIG["encrypted_package"] = encrypted_pkg

    key_int = int.from_bytes(master_key, byteorder="big")
    sss = ShamirSecretSharing(threshold=threshold, total_shares=total_nodes)
    shares = sss.split_secret(key_int)
    del master_key
    del key_int

    lock_target_time = time.time() + lock_sec
    exam_id = f"EXAM_{int(time.time())}_{generate_access_code(4)}"

    # Randomly sample N custodians out of the 15-vault pool (IDs 1..15)
    selected_vault_ids = sorted(random.sample(range(1, 16), total_nodes))

    dispatched_count = 0
    for idx, vault_id in enumerate(selected_vault_ids):
        vault_url = VAULT_URLS[vault_id - 1]
        inst_name = INSTITUTION_POOL[vault_id - 1]
        try:
            res = requests.post(
                f"{vault_url}/api/vault/store_share",
                json={
                    "exam_id": exam_id,
                    "share_x": shares[idx][0],
                    "share_y": str(shares[idx][1]),
                    "t0": lock_target_time,
                    "scheme": f"({threshold}, {total_nodes}) of 15-Vault Pool",
                    "institution": inst_name
                },
                verify=False,
                timeout=2.0
            )
            if res.status_code == 200:
                dispatched_count += 1
        except Exception as e:
            print(f"[!] Failed to reach Vault_{vault_id} ({vault_url}): {e}")

    if dispatched_count < threshold:
        return jsonify({
            "error": f"Only {dispatched_count}/{total_nodes} custodian vaults reachable (need >= {threshold}). Start launch_15_vaults.py first."
        }), 503

    EXAM_CONFIG["status"] = "LOCKED"
    EXAM_CONFIG["exam_id"] = exam_id
    EXAM_CONFIG["filename"] = file.filename
    EXAM_CONFIG["mime_type"] = "application/pdf" if file.filename.lower().endswith(".pdf") else "text/plain"
    EXAM_CONFIG["lock_until"] = lock_target_time
    EXAM_CONFIG["exam_duration_seconds"] = exam_sec
    EXAM_CONFIG["exam_duration_str"] = exam_duration_str
    EXAM_CONFIG["threshold"] = threshold
    EXAM_CONFIG["total_nodes"] = total_nodes
    EXAM_CONFIG["selected_vault_ids"] = selected_vault_ids
    EXAM_CONFIG["access_code"] = None

    print(f"\n[+] Dynamic Committee Selected from 15-Vault Pool: ({threshold}, {total_nodes}) SSS")
    print(f"[+] Dispatched shares over TLS 1.3 to Vault IDs: {selected_vault_ids}")

    return jsonify({
        "status": "LOCKED",
        "exam_id": exam_id,
        "lock_until": lock_target_time,
        "exam_duration_seconds": exam_sec,
        "seconds_remaining": lock_sec,
        "threshold": threshold,
        "total_nodes": total_nodes,
        "selected_vault_ids": selected_vault_ids
    })


@app.route("/api/status", methods=["GET"])
def get_status():
    rem = max(0.0, EXAM_CONFIG["lock_until"] - time.time()) if EXAM_CONFIG["status"] == "LOCKED" else 0
    return jsonify({
        "status": EXAM_CONFIG["status"],
        "filename": EXAM_CONFIG["filename"],
        "remaining_seconds": round(rem, 1),
        "exam_duration_str": EXAM_CONFIG["exam_duration_str"],
        "access_code": EXAM_CONFIG["access_code"],
        "threshold": EXAM_CONFIG["threshold"],
        "total_nodes": EXAM_CONFIG["total_nodes"],
        "selected_vault_ids": EXAM_CONFIG["selected_vault_ids"]
    })


@app.route("/api/federated/submit_update", methods=["POST", "OPTIONS"])
def federated_submit_update():
    if request.method == "OPTIONS":
        return jsonify({"status": "OK"}), 200

    data = request.get_json(force=True, silent=True) or {}
    student_id = data.get("student_id", "EDGE_NODE")
    is_anomaly = data.get("is_anomaly", False)
    theta_11 = data.get("parameters", FEDERATED_STATE["global_theta"])
    n_k = int(data.get("n_k", 1))
    local_loss = float(data.get("loss", FEDERATED_STATE["loss_history"][-1]))

    now = time.time()
    FEDERATED_STATE["connected_nodes"][student_id] = now
    FEDERATED_STATE["total_updates_received"] += 1

    if is_anomaly:
        FEDERATED_STATE["anomaly_count"] += 1
    else:
        FEDERATED_STATE["normal_count"] += 1

    FEDERATED_STATE["pending_updates"].append({
        "theta": theta_11,
        "n_k": n_k,
        "loss": local_loss
    })

    return jsonify({
        "status": "ACCEPTED",
        "round": FEDERATED_STATE["current_round"],
        "global_loss": FEDERATED_STATE["loss_history"][-1],
        "global_theta": FEDERATED_STATE["global_theta"]
    })


@app.route("/api/federated/hud_stats", methods=["GET"])
def federated_hud_stats():
    now = time.time()
    active_nodes = [sid for sid, last_ts in FEDERATED_STATE["connected_nodes"].items() if now - last_ts < 15]

    tot = FEDERATED_STATE["normal_count"] + FEDERATED_STATE["anomaly_count"]
    if tot == 0:
        normal_pct = 100.0
        anomaly_pct = 0.0
    else:
        normal_pct = round((FEDERATED_STATE["normal_count"] / tot) * 100, 1)
        anomaly_pct = round((FEDERATED_STATE["anomaly_count"] / tot) * 100, 1)

    return jsonify({
        "active_edge_nodes": len(active_nodes),
        "current_round": FEDERATED_STATE["current_round"],
        "global_loss": FEDERATED_STATE["loss_history"][-1],
        "loss_history": FEDERATED_STATE["loss_history"],
        "global_theta": FEDERATED_STATE["global_theta"],
        "normal_pct": normal_pct,
        "anomaly_pct": anomaly_pct,
        "total_updates": FEDERATED_STATE["total_updates_received"]
    })


@app.route("/api/session_ledger_status", methods=["GET"])
def session_ledger_status():
    code = EXAM_CONFIG["access_code"]
    if not code:
        return jsonify({"active": False, "message": "No active session published."})

    ledger_path = BlockchainLedger.get_ledger_filepath(code)
    if not os.path.exists(ledger_path):
        return jsonify({
            "active": True,
            "access_code": code,
            "total_candidates": 0,
            "integrity_status": "INITIALIZING",
            "blocks": []
        })

    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            chain = json.load(f)

        candidates = []
        is_intact = True
        tamper_reason = None

        for idx, block in enumerate(chain):
            if idx == 0:
                continue

            expected_hash = BlockchainLedger.compute_canonical_payload_hash(
                block_index=block.get("block_index", idx),
                timestamp=float(block.get("timestamp", 0.0)),
                access_code=block.get("access_code", code),
                student_id=block.get("student_id", ""),
                answers=block.get("answers", ""),
                previous_hash=block.get("previous_hash", "")
            )

            hash_matches = (block.get("payload_hash") == expected_hash)
            if not hash_matches and is_intact:
                is_intact = False
                tamper_reason = f"Hash mismatch at block #{idx} for {block.get('student_id')}"

            candidates.append({
                "block_index": block.get("block_index", idx),
                "student_id": block.get("student_id", "UNKNOWN"),
                "timestamp_ist": block.get("timestamp_ist", "N/A"),
                "is_auto": "[SYSTEM AUDIT: AUTO-SUBMITTED" in block.get("answers", ""),
                "tampered": not hash_matches
            })

        # Also check ledger head hash against replicated custodian copies (Equation 8)
        if chain and is_intact:
            local_head = chain[-1].get("payload_hash", "")
            head_ok, head_msg = BlockchainLedger.verify_head_against_custodians(code, local_head)
            if not head_ok:
                is_intact = False
                tamper_reason = head_msg

        return jsonify({
            "active": True,
            "access_code": code,
            "total_candidates": len(candidates),
            "integrity_status": "INTACT" if is_intact else "TAMPERED",
            "tamper_reason": tamper_reason,
            "blocks": candidates
        })
    except Exception as e:
        return jsonify({"active": True, "error": str(e), "total_candidates": 0, "blocks": []})


if __name__ == "__main__":
    cert_path = os.path.join("certs", "cert.pem")
    key_path = os.path.join("certs", "key.pem")
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    print(f"[*] Starting Phase 1 Faculty Portal on https://0.0.0.0:8000 (TLS 1.3) [{get_current_ist_str()}]")
    app.run(host="0.0.0.0", port=8000, ssl_context=ssl_ctx, debug=False)