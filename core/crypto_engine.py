import os
import io
import time
import random
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import Color

# Indian Standard Time (UTC + 05:30)
IST = timezone(timedelta(hours=5, minutes=30))

def get_current_ist_str() -> str:
    return datetime.now(IST).strftime("%d-%m-%Y %H:%M:%S IST")

class CryptoEngine:
    @staticmethod
    def generate_aes_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt_data(data_bytes: bytes, key: bytes) -> dict:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit IV/nonce
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)  # Includes 128-bit GCM tag
        return {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

    @staticmethod
    def decrypt_data(ciphertext_hex: str, nonce_hex: str, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        return aesgcm.decrypt(nonce, ciphertext, None)


class ShamirSecretSharing:
    """
    Shamir's (T, N) Secret Sharing over the 256-bit prime field F_p,
    where p = 2^256 - 189 (largest prime below 2^256, Section 3.2).
    """
    P = (1 << 256) - 189

    def __init__(self, threshold: int, total_shares: int):
        self.threshold = threshold
        self.total_shares = total_shares

    def split_secret(self, secret: int):
        secret_mod = secret % self.P
        coefficients = [secret_mod]
        for _ in range(self.threshold - 1):
            coefficients.append(random.SystemRandom().randint(1, self.P - 1))

        shares = []
        for x in range(1, self.total_shares + 1):
            y = 0
            for exp, coeff in enumerate(coefficients):
                term = (coeff * pow(x, exp, self.P)) % self.P
                y = (y + term) % self.P
            shares.append((x, y))

        return shares

    def reconstruct_secret(self, shares: list) -> int:
        secret = 0
        k = len(shares)
        for i in range(k):
            xi, yi = shares[i]
            num = 1
            den = 1
            for j in range(k):
                if i != j:
                    xj, _ = shares[j]
                    num = (num * (-xj)) % self.P
                    den = (den * (xi - xj)) % self.P
            inv_den = pow(den, self.P - 2, self.P)
            li = (num * inv_den) % self.P
            term = (yi * li) % self.P
            secret = (secret + term) % self.P
        return secret


class DigitalSignatureEngine:
    """Provides ECDSA SECP256k1 dual digital signature generation and verification (Section 3.6)."""
    @staticmethod
    def generate_keypair():
        return ec.generate_private_key(ec.SECP256K1())

    @staticmethod
    def export_public_key_pem(private_key) -> str:
        pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode("utf-8")

    @staticmethod
    def sign_hash(digest_hex: str, private_key) -> str:
        digest_bytes = bytes.fromhex(digest_hex)
        sig = private_key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
        return sig.hex()

    @staticmethod
    def verify_signature(digest_hex: str, sig_hex: str, pub_pem: str) -> bool:
        try:
            pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
            pub_key.verify(bytes.fromhex(sig_hex), bytes.fromhex(digest_hex), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class ForensicWatermarker:
    """Dynamically applies candidate forensic tracing marks across all PDF pages in volatile RAM in IST."""
    @staticmethod
    def apply_watermark(raw_pdf_bytes: bytes, student_id: str, access_code: str) -> bytes:
        try:
            reader = PdfReader(io.BytesIO(raw_pdf_bytes))
            writer = PdfWriter()

            packet = io.BytesIO()
            can = canvas.Canvas(packet)
            can.setFont("Helvetica-Bold", 10)
            can.setFillColor(Color(0.85, 0.1, 0.1, alpha=0.32))

            timestamp_str = get_current_ist_str()
            watermark_text = f"RESTRICTED EXAM • CANDIDATE: {student_id.upper()} • SESSION: {access_code} • {timestamp_str}"

            can.saveState()
            can.translate(300, 420)
            can.rotate(45)
            can.drawCentredString(0, 0, watermark_text)
            can.restoreState()

            can.saveState()
            can.setFont("Helvetica", 8)
            can.setFillColor(Color(0.2, 0.2, 0.2, alpha=0.4))
            can.drawString(40, 810, f"SECULEARN-NET FORENSIC TRACE ID: [{student_id} | {access_code} | {timestamp_str}]")
            can.restoreState()

            can.save()
            packet.seek(0)

            watermark_pdf = PdfReader(packet)
            watermark_page = watermark_pdf.pages[0]

            for page in reader.pages:
                page.merge_page(watermark_page)
                writer.add_page(page)

            output_stream = io.BytesIO()
            writer.write(output_stream)
            return output_stream.getvalue()
        except Exception as e:
            print(f"[!] Forensic watermarking error: {e}")
            return raw_pdf_bytes