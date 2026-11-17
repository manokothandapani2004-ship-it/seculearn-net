import os
import sys
import io
import ssl
import json
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, request, jsonify, send_file
from core.crypto_engine import CryptoEngine, ForensicWatermarker, get_current_ist_str
from core.blockchain_ledger import BlockchainLedger
from phase2_student.edge_ai import LogisticViolationScorer

app = Flask(__name__)
SHARED_STATE_FILE = "shared_exam_session.json"

local_scorer = LogisticViolationScorer(lr=0.01)


@app.route("/")
def index():
    return render_template("exam_portal.html")


@app.route("/api/verify_code", methods=["POST"])
def verify_code():
    data = request.get_json() or {}
    entered_code = data.get("access_code", "").strip().upper()
    student_id = data.get("student_id", "").strip()

    if not student_id or not entered_code:
        return jsonify({"valid": False, "message": "Both Registration ID and Access Code are required."}), 400

    if not os.path.exists(SHARED_STATE_FILE):
        return jsonify({"valid": False, "message": "No active examination published by the institution."}), 404

    with open(SHARED_STATE_FILE, "r", encoding="utf-8") as f:
        shared = json.load(f)

    if entered_code != shared.get("access_code"):
        return jsonify({"valid": False, "message": "Invalid Access Code! Please verify with faculty."}), 403

    ledger_path = BlockchainLedger.get_ledger_filepath(entered_code)
    if os.path.exists(ledger_path):
        try:
            with open(ledger_path, "r", encoding="utf-8") as lf:
                chain = json.load(lf)
                for block in chain:
                    if block.get("block_index") == 0:
                        continue
                    if block.get("student_id", "").strip().upper() == student_id.upper():
                        return jsonify({
                            "valid": False,
                            "already_submitted": True,
                            "message": f"Candidate [{student_id}] has already submitted this examination! Re-entry is strictly prohibited."
                        }), 403
        except Exception as e:
            print(f"[!] Ledger verification read error: {e}")

    return jsonify({
        "valid": True,
        "student_id": student_id,
        "access_code": entered_code,
        "exam_duration_seconds": shared.get("exam_duration_seconds", 900),
        "mime_type": shared.get("mime_type", "application/pdf")
    })


@app.route("/api/fetch_decrypted_paper", methods=["POST"])
def fetch_decrypted_paper():
    data = request.get_json() or {}
    access_code = data.get("access_code", "").strip().upper()
    student_id = data.get("student_id", "").strip()

    if not os.path.exists(SHARED_STATE_FILE):
        return jsonify({"error": "Session state unavailable"}), 404

    with open(SHARED_STATE_FILE, "r", encoding="utf-8") as f:
        shared = json.load(f)

    if access_code != shared.get("access_code"):
        return jsonify({"error": "Unauthorized access attempt"}), 403

    pkg = shared.get("encrypted_package")
    key_bytes = bytes.fromhex(shared.get("key_hex"))

    # Volatile in-memory AES-256-GCM decryption
    decrypted_bytes = CryptoEngine.decrypt_data(
        ciphertext_hex=pkg["ciphertext"],
        nonce_hex=pkg["nonce"],
        key=key_bytes
    )
    del key_bytes

    if shared.get("mime_type") == "application/pdf":
        final_stream_bytes = ForensicWatermarker.apply_watermark(
            raw_pdf_bytes=decrypted_bytes,
            student_id=student_id,
            access_code=access_code
        )
        print(f"[+] RAM forensic watermark stamped for candidate: '{student_id}' (Session: {access_code}) [{get_current_ist_str()}]")
    else:
        final_stream_bytes = decrypted_bytes

    return send_file(
        io.BytesIO(final_stream_bytes),
        mimetype=shared.get("mime_type", "application/pdf"),
        as_attachment=False,
        download_name="exam_paper.pdf"
    )


@app.route("/api/edge_proctor_heartbeat", methods=["POST"])
def edge_proctor_heartbeat():
    data = request.get_json() or {}
    student_id = data.get("student_id", "STUDENT_NODE")
    has_anomaly = bool(data.get("has_anomaly", False))
    features_10 = data.get("features", [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])

    # Local 11-parameter logistic regression gradient step in volatile RAM
    update = local_scorer.step(features_10, 1 if has_anomaly else 0)

    # Relay 11 parameters + status codes over TLS 1.3 to coordinator
    host_ip = request.host.split(":")[0]
    for target_url in [f"https://{host_ip}:8000/api/federated/submit_update", "https://127.0.0.1:8000/api/federated/submit_update"]:
        try:
            res = requests.post(
                target_url,
                json={
                    "student_id": student_id,
                    "is_anomaly": has_anomaly,
                    "parameters": update["parameters"],
                    "n_k": update["n_k"],
                    "loss": update["loss"]
                },
                verify=False,
                timeout=1.5
            )
            if res.status_code == 200:
                global_theta = res.json().get("global_theta")
                if global_theta:
                    local_scorer.set_global_parameters(global_theta)
                break
        except Exception:
            continue

    return jsonify({
        "status": "PROCTORING_ACTIVE",
        "fl_aggregation": "FedAvg_11Param_ACK",
        "violation_score": update["score"],
        "local_loss": update["loss"]
    })


@app.route("/api/submit_exam", methods=["POST"])
def submit_exam():
    data = request.get_json() or {}
    access_code = data.get("access_code", "").strip().upper()
    student_id = data.get("student_id", "").strip()
    answers = data.get("answers", "").strip()
    is_auto = data.get("auto_submitted", False)
    violation_reason = data.get("violation_reason", "")

    if not access_code or not student_id or not answers:
        return jsonify({"error": "Missing access code, registration ID, or answers."}), 400

    if is_auto:
        answers += f"\n\n[SYSTEM AUDIT: AUTO-SUBMITTED - {violation_reason}]"

    tx = BlockchainLedger.commit_transaction(access_code, student_id, answers)
    print(f"\n[+] Dual-Signed Transaction Committed for Candidate '{student_id}' at {get_current_ist_str()}")
    print(f"    Transaction ID:  {tx['tx_id']}")
    print(f"    Payload Hash:    {tx['payload_hash']}")
    print(f"    Ledger File:     ledger_storage/ledger_{access_code}.json")

    return jsonify({
        "status": "COMMITTED",
        "tx_id": tx["tx_id"],
        "payload_hash": tx["payload_hash"],
        "ledger_file": f"ledger_{access_code}.json",
        "student_signature": tx["student_signature"],
        "institution_signature": tx["institution_signature"]
    })


if __name__ == "__main__":
    cert_path = os.path.join("certs", "cert.pem")
    key_path = os.path.join("certs", "key.pem")
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    print(f"[*] Starting Phase 2 Student Exam Portal on https://0.0.0.0:5000 (TLS 1.3) [{get_current_ist_str()}]")
    app.run(host="0.0.0.0", port=5000, ssl_context=ssl_ctx, debug=False)