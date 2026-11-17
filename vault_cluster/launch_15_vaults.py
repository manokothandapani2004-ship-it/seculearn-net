import subprocess
import sys
import time

INSTITUTION_POOL = [
    "IIT_Madras_Vault", "Anna_Univ_Vault", "NIT_Trichy_Vault", "BITS_Pilani_Vault",
    "VIT_Vellore_Vault", "IISc_Bangalore_Vault", "IIT_Bombay_Vault", "IIT_Delhi_Vault",
    "Jadavpur_Vault", "IIIT_Hyderabad_Vault", "Amrita_Vault", "SRM_Vault",
    "PSG_Tech_Vault", "Thapar_Vault", "Manipal_Vault"
]

processes = []
print("[*] Launching 15 Independent TLS 1.3 Custodian Vault Services (Ports 9001 - 9015)...")

try:
    for idx, name in enumerate(INSTITUTION_POOL, start=1):
        p = subprocess.Popen([sys.executable, "vault_cluster/vault_node.py", str(idx), name])
        processes.append(p)
        print(f"    [+] Started Vault #{idx:02d} ({name}) on https://0.0.0.0:{9000 + idx}")
        time.sleep(0.15)

    print("\n[+] All 15 Custodian Vaults active. Press Ctrl+C to shut down all vaults.")
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Shutting down 15 Custodian Vaults...")
    for p in processes:
        p.terminate()