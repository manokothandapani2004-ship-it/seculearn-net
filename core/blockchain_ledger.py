import os
import json
import time
import hashlib
import smtplib
import urllib3
import requests
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from core.crypto_engine import DigitalSignatureEngine

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LEDGER_DIR = "ledger_storage"
os.makedirs(LEDGER_DIR, exist_ok=True)

IST = timezone(timedelta(hours=5, minutes=30))

def get_current_ist_str() -> str:
    return datetime.now(IST).strftime("%d-%m-%Y %H:%M:%S IST")

# Master Institutional Signing Keypair (SECP256k1)
INSTITUTION_KEYPAIR = DigitalSignatureEngine.generate_keypair()
INSTITUTION_PUB_PEM = DigitalSignatureEngine.export_public_key_pem(INSTITUTION_KEYPAIR)

# 15-Custodian Vault Endpoints (Ports 9001-9015 over TLS 1.3)
VAULT_URLS = [f"https://127.0.0.1:{9000 + i}" for i in range(1, 16)]

# Faculty notification credentials
FACULTY_EMAIL = "crazymano2004@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = os.environ.get("ALERT_SENDER_EMAIL", "manokothandapani2004@gmail.com")
SENDER_PASSWORD = os.environ.get("ALERT_SENDER_PASSWORD", "dksc uirc jfcr ximw")


class BlockchainLedger:
    @staticmethod
    def compute_canonical_payload_hash(block_index: int, timestamp: float, access_code: str,
                                       student_id: str, answers: str, previous_hash: str) -> str:
        """
        D_i = SHA-256(i || ts_i || code || sid || A_i || h_{i-1})
        """
        canonical_str = f"{block_index}|{timestamp:.6f}|{access_code}|{student_id}|{answers}|{previous_hash}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @staticmethod
    def get_ledger_filepath(access_code: str) -> str:
        clean_code = "".join(c for c in access_code if c.isalnum()).upper()
        return os.path.join(LEDGER_DIR, f"ledger_{clean_code}.json")

    @staticmethod
    def replicate_head_to_custodians(access_code: str, head_hash: str, block_index: int):
        """Replicates the latest ledger head hash h_n to all 15 custodian vaults (Section 3.6)."""
        for url in VAULT_URLS:
            try:
                requests.post(
                    f"{url}/api/vault/replicate_head",
                    json={
                        "access_code": access_code,
                        "head_hash": head_hash,
                        "block_index": block_index
                    },
                    verify=False,
                    timeout=0.5
                )
            except Exception:
                pass

    @staticmethod
    def verify_head_against_custodians(access_code: str, local_head_hash: str) -> tuple[bool, str]:
        """Checks h_n == head_cust across reachable custodians (Equation 8)."""
        custodian_heads = []
        for url in VAULT_URLS:
            try:
                res = requests.get(
                    f"{url}/api/vault/get_head/{access_code}",
                    verify=False,
                    timeout=0.5
                )
                if res.status_code == 200:
                    data = res.json()
                    if data.get("head_hash"):
                        custodian_heads.append(data["head_hash"])
            except Exception:
                pass

        if not custodian_heads:
            return True, "No external custodian reachable (skipped remote head check)"

        for ch in custodian_heads:
            if ch != local_head_hash:
                return False, f"Ledger head ({local_head_hash[:16]}...) differs from custodian copy ({ch[:16]}...)! Possible block deletion/relinking."
        return True, "Matched custodian head hashes"

    @staticmethod
    def init_ledger_file(access_code: str):
        filepath = BlockchainLedger.get_ledger_filepath(access_code)
        if not os.path.exists(filepath):
            ts = time.time()
            genesis_payload_hash = hashlib.sha256(b"GENESIS_PAYLOAD_ROOT").hexdigest()
            genesis_block = {
                "block_index": 0,
                "timestamp": ts,
                "timestamp_ist": get_current_ist_str(),
                "access_code": access_code,
                "student_id": "SYSTEM_GENESIS",
                "answers": "GENESIS_BLOCK_INITIALIZATION",
                "previous_hash": "0" * 64,
                "payload_hash": genesis_payload_hash,
                "dual_signatures": {
                    "student_signature": "GENESIS_AUTHORITY",
                    "student_public_key": "NONE",
                    "institution_signature": "GENESIS_AUTHORITY",
                    "institution_public_key": INSTITUTION_PUB_PEM
                }
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump([genesis_block], f, indent=4)
            BlockchainLedger.replicate_head_to_custodians(access_code, genesis_payload_hash, 0)
        return filepath

    @staticmethod
    def commit_transaction(access_code: str, student_id: str, answers: str,
                           student_sig: str = None, student_pub_pem: str = None,
                           client_digest: str = None, client_ts: float = None) -> dict:
        filepath = BlockchainLedger.init_ledger_file(access_code)

        with open(filepath, "r", encoding="utf-8") as f:
            chain = json.load(f)

        prev_block = chain[-1]
        prev_hash = prev_block.get("payload_hash", "0" * 64)
        new_block_index = len(chain)
        ts = client_ts if client_ts is not None else time.time()

        payload_hash = BlockchainLedger.compute_canonical_payload_hash(
            block_index=new_block_index,
            timestamp=ts,
            access_code=access_code,
            student_id=student_id,
            answers=answers,
            previous_hash=prev_hash
        )

        # 1. Student ECDSA Signature
        if not student_sig or not student_pub_pem:
            student_keypair = DigitalSignatureEngine.generate_keypair()
            student_pub_pem = DigitalSignatureEngine.export_public_key_pem(student_keypair)
            student_sig = DigitalSignatureEngine.sign_hash(payload_hash, student_keypair)

        # 2. Institutional Master ECDSA Counter-Signing
        inst_sig = DigitalSignatureEngine.sign_hash(payload_hash, INSTITUTION_KEYPAIR)

        new_block = {
            "block_index": new_block_index,
            "timestamp": ts,
            "timestamp_ist": get_current_ist_str(),
            "access_code": access_code,
            "student_id": student_id,
            "answers": answers,
            "previous_hash": prev_hash,
            "payload_hash": payload_hash,
            "dual_signatures": {
                "student_signature": student_sig,
                "student_public_key": student_pub_pem,
                "institution_signature": inst_sig,
                "institution_public_key": INSTITUTION_PUB_PEM
            }
        }

        chain.append(new_block)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(chain, f, indent=4)

        # Replicate new head hash h_n to all custodians
        BlockchainLedger.replicate_head_to_custodians(access_code, payload_hash, new_block_index)

        return {
            "tx_id": f"TX-{payload_hash[:16]}",
            "payload_hash": payload_hash,
            "student_signature": student_sig[:24] + "...",
            "institution_signature": inst_sig[:24] + "..."
        }

    @staticmethod
    def send_security_alert(filename: str, compromised_student_id: str, block_idx: int, reason: str):
        detection_ist = get_current_ist_str()
        print("\n" + "=" * 70)
        print("[!!! SECURITY BREACH DETECTED BY TAMPER DAEMON !!!]")
        print(f"[!] Ledger File:            {filename}")
        print(f"[!] Compromised Student ID: {compromised_student_id} (Block #{block_idx})")
        print(f"[!] Breach Details:         {reason}")
        print(f"[!] Timestamp (IST):        {detection_ist}")
        print(f"[+] Dispatching Alert Email to: {FACULTY_EMAIL}")
        print("=" * 70 + "\n")

        try:
            msg = MIMEMultipart()
            msg["From"] = SENDER_EMAIL
            msg["To"] = FACULTY_EMAIL
            msg["Subject"] = f"CRITICAL SECURITY ALERT: Ledger Tampering Detected [{compromised_student_id}]"

            body = (
                f"SecuLearn-Net Consortium Tamper Auditor Alert\n"
                f"Time of Detection: {detection_ist}\n\n"
                f"An unauthorized modification has been detected in the blockchain audit ledger:\n\n"
                f"• Ledger Storage File: {filename}\n"
                f"• Compromised Student Registration ID: {compromised_student_id}\n"
                f"• Corrupted Block Index: #{block_idx}\n"
                f"• Tamper Detection Root Cause: {reason}\n\n"
                f"Action Required: Check server ledger integrity immediately."
            )
            msg.attach(MIMEText(body, "plain"))

            if SENDER_PASSWORD:
                server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=5)
                server.starttls()
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.sendmail(SENDER_EMAIL, FACULTY_EMAIL, msg.as_string())
                server.quit()
                print(f"[+] Alert email delivered successfully via SMTP to {FACULTY_EMAIL}.")
            else:
                print("[*] (SMTP note: SENDER_PASSWORD env var not configured; simulated alert printed above)")
        except Exception as e:
            print(f"[!] SMTP dispatch failed: {e}")