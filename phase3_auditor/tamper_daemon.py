import os
import sys
import json
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.blockchain_ledger import LEDGER_DIR, BlockchainLedger
from core.crypto_engine import DigitalSignatureEngine, get_current_ist_str

alerted_breaches = set()


def verify_single_ledger_file(filepath: str):
    filename = os.path.basename(filepath)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            chain = json.load(f)
    except Exception as e:
        breach_key = f"{filename}:CORRUPTED_JSON"
        if breach_key not in alerted_breaches:
            alerted_breaches.add(breach_key)
            BlockchainLedger.send_security_alert(filename, "SYSTEM_UNKNOWN", 0, f"Unreadable JSON file or syntax corruption: {e}")
        return

    if not isinstance(chain, list) or len(chain) == 0:
        return

    access_code = chain[0].get("access_code", filename.replace("ledger_", "").replace(".json", ""))

    for idx, block in enumerate(chain):
        if idx == 0:
            continue

        prev_block = chain[idx - 1]
        student_id = block.get("student_id", "UNKNOWN_STUDENT")
        block_idx = block.get("block_index", idx)

        if block_idx != idx:
            breach_key = f"{filename}:{idx}:BLOCK_INDEX_TAMPER"
            if breach_key not in alerted_breaches:
                alerted_breaches.add(breach_key)
                reason = f"Block index modified or reordered! Expected #{idx}, found #{block_idx}."
                BlockchainLedger.send_security_alert(filename, student_id, idx, reason)
            return

        if block.get("previous_hash") != prev_block.get("payload_hash"):
            breach_key = f"{filename}:{idx}:MERKLE_LINK"
            if breach_key not in alerted_breaches:
                alerted_breaches.add(breach_key)
                reason = f"Hash Linkage Broken at Block #{idx}! previous_hash != previous block payload_hash."
                BlockchainLedger.send_security_alert(filename, student_id, idx, reason)
            return

        expected_hash = BlockchainLedger.compute_canonical_payload_hash(
            block_index=block_idx,
            timestamp=float(block.get("timestamp", 0.0)),
            access_code=block.get("access_code", ""),
            student_id=student_id,
            answers=block.get("answers", ""),
            previous_hash=block.get("previous_hash", "")
        )

        if block.get("payload_hash") != expected_hash:
            breach_key = f"{filename}:{idx}:DATA_TAMPERED"
            if breach_key not in alerted_breaches:
                alerted_breaches.add(breach_key)
                reason = (
                    f"Block contents tampered on disk! "
                    f"Recorded hash ({block.get('payload_hash')}) != Recomputed hash ({expected_hash})."
                )
                BlockchainLedger.send_security_alert(filename, student_id, idx, reason)
            return

        sigs = block.get("dual_signatures", {})
        student_sig = sigs.get("student_signature")
        student_pub = sigs.get("student_public_key")
        inst_sig = sigs.get("institution_signature")
        inst_pub = sigs.get("institution_public_key")

        if not student_sig or not student_pub or not inst_sig or not inst_pub:
            breach_key = f"{filename}:{idx}:MISSING_SIGNATURES"
            if breach_key not in alerted_breaches:
                alerted_breaches.add(breach_key)
                BlockchainLedger.send_security_alert(filename, student_id, idx, f"Missing dual signatures at Block #{idx}.")
            return

        if not DigitalSignatureEngine.verify_signature(block["payload_hash"], student_sig, student_pub):
            breach_key = f"{filename}:{idx}:STUDENT_SIG_FAIL"
            if breach_key not in alerted_breaches:
                alerted_breaches.add(breach_key)
                BlockchainLedger.send_security_alert(filename, student_id, idx, f"Invalid student ECDSA signature at Block #{idx}!")
            return

        if not DigitalSignatureEngine.verify_signature(block["payload_hash"], inst_sig, inst_pub):
            breach_key = f"{filename}:{idx}:INST_SIG_FAIL"
            if breach_key not in alerted_breaches:
                alerted_breaches.add(breach_key)
                BlockchainLedger.send_security_alert(filename, student_id, idx, f"Invalid institutional ECDSA signature at Block #{idx}!")
            return

    # Check final head hash h_n against replicated custodian copies (Equation 8)
    local_head = chain[-1].get("payload_hash", "")
    head_ok, head_msg = BlockchainLedger.verify_head_against_custodians(access_code, local_head)
    if not head_ok:
        breach_key = f"{filename}:HEAD_MISMATCH:{local_head}"
        if breach_key not in alerted_breaches:
            alerted_breaches.add(breach_key)
            BlockchainLedger.send_security_alert(filename, "LEDGER_CHAIN", len(chain) - 1, head_msg)


def scan_all_ledgers():
    if not os.path.exists(LEDGER_DIR):
        return
    for fname in os.listdir(LEDGER_DIR):
        if fname.startswith("ledger_") and fname.endswith(".json"):
            verify_single_ledger_file(os.path.join(LEDGER_DIR, fname))


if __name__ == "__main__":
    print(f"[*] Starting Phase 3 Tamper Auditor Daemon [{get_current_ist_str()}]...")
    print(f"[*] Watching ledger directory: {LEDGER_DIR} + verifying head hashes against 15 custodians")
    while True:
        try:
            scan_all_ledgers()
        except Exception as e:
            print(f"[!] Daemon error: {e}")
        time.sleep(2)