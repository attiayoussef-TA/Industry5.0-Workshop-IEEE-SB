# decrypt_verify.py
import json, os
from base64 import b64decode
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import qrcode
from io import BytesIO
import hashlib

def load_private_key(path):
    base_dir = Path(__file__).parent
    key_path = base_dir / path
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
def export_to_pdf(report_data):
    c = canvas.Canvas("sample_report.pdf", pagesize=A4)
    width, height = A4

    # 1.  Top-right: Company Name
    c.setFont("Helvetica-Bold", 14)
    title = "Industry 5.0 Automotive RF Manufacturing"
    title_width = c.stringWidth(title, "Helvetica-Bold", 14)
    c.drawString((width - title_width)/2, height - 50, title)

    # 2. Top-left subtitles
    c.setFont("Helvetica", 12)
    y = height - 80
    right_margin = 50

    texts = ["Production Service", "Antenna Report"]
    for text in texts:
        text_width = c.stringWidth(text, "Helvetica", 12)
        x = width - right_margin - text_width
        c.drawString(x, y, text)
        y -= 20

   # Set font and start text block
    c.setFont("Times-Italic", 11)
    text = c.beginText(50, y)
    # formal note
    text.textLines("""
    Dear Quality Assurance Team,
    This document contains CONFIDENTIAL and INTERNAL data pertaining to RF antenna performance. 
    All measurements detailed in this report have been conducted using fully calibrated and validated 
    equipment under standard operating conditions, in compliance with industrial protocols.
    The results have been reviewed, authenticated, and approved by the Production Department 
    at Industry 5.0 Automotive RF Manufacturing. Any unauthorized access, copying, or distribution 
    is strictly prohibited. This report is digitally signed and traceable, ensuring full integrity and tamper-evidence. 
                   
    """)
    # Draw paragraph
    c.drawText(text)

    # Move y position below the paragraph for the data
    y -= 100 

    # 3. Report data
    for key, value in report_data.items():
        c.drawString(50, y, f"{key}: {value}")
        y -= 20

    now = datetime.now()
    # Windows compatibility (since %-d may fail on Windows)
    if os.name == "nt":
        formatted_date = now.strftime("CryptaTrace workshop Lab, %#d %B %Y")  # Windows-style day format

    footer_width = c.stringWidth(formatted_date, "Helvetica", 10)
    c.setFont("Helvetica", 10)
    c.drawString(width - footer_width - 50, 40, formatted_date)

    # Create a hash of the report data as QR content
    digest = hashlib.sha256(json.dumps(report_data, sort_keys=True).encode()).hexdigest()
    qr = qrcode.make(f"Report Hash: {digest}")

    # Convert QR PIL image to a format reportlab can draw
    buffer = BytesIO()
    qr.save(buffer)
    buffer.seek(0)
    qr_image = ImageReader(buffer)

    # Draw QR code bottom-left (e.g., 50 pts from left, 40 pts from bottom)
    c.drawImage(qr_image, 50, 40, width=80, height=80)

    c.save()
    print("PDF generated: sample_report.pdf")

def load_public_key(path):
    base_dir = Path(__file__).parent
    key_path = base_dir / path
    with open(key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def log_status(status):
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)
    with open(log_dir / "verification.log", "a") as log:
        log.write(f"[{datetime.now()}] Status: {status}\n")

def hybrid_decrypt():
    with open("sample_report.enc", "r") as f:
        data = json.load(f)

    nonce = b64decode(data["nonce"])
    ciphertext = b64decode(data["ciphertext"])
    encrypted_key = b64decode(data["encrypted_key"])

    qa_private = load_private_key("keys/qa/private_key.pem")
    prod_public = load_public_key("keys/production/public_key.pem")

    try:
        aes_key = qa_private.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print("Failed to decrypt AES key.")
        log_status("TAMPERED: AES key decryption failed")
        return

    try:
        aesgcm = AESGCM(aes_key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        signed_report = json.loads(decrypted)
    except Exception:
        print("Failed to decrypt payload. Possible tampering.")
        log_status("TAMPERED: Payload decryption failed")
        return

    report = signed_report["report"]
    signature = b64decode(signed_report["signature"])
    message = json.dumps(report, sort_keys=True).encode()

    try:
        prod_public.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("VALID: Signature matches and report is intact.")
        log_status("VALID")
        export_to_pdf(report)
    except InvalidSignature:
        print("INVALID: Report has been tampered with!")
        log_status("TAMPERED: Invalid signature")
def decrypt_and_verify(enc_path):
    from base64 import b64decode
    import json

    try:
        with open(enc_path, "r") as f:
            data = json.load(f)

        nonce = b64decode(data["nonce"])
        ciphertext = b64decode(data["ciphertext"])
        encrypted_key = b64decode(data["encrypted_key"])

        qa_private = load_private_key("keys/qa/private_key.pem")
        prod_public = load_public_key("keys/production/public_key.pem")

        # Decrypt AES key
        aes_key = qa_private.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt payload
        aesgcm = AESGCM(aes_key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        signed_report = json.loads(decrypted)

        report = signed_report["report"]
        signature = b64decode(signed_report["signature"])
        message = json.dumps(report, sort_keys=True).encode()

        # Verify signature
        prod_public.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        status = "VALID"
        log_status(status)

        # Always export to "sample_report.pdf"
        export_to_pdf(report)

        return {
            "status": status,
            "report_data": report,
            "pdf_path": "sample_report.pdf"
        }

    except Exception as e:
        status = "TAMPERED"
        log_status(f"{status}: {str(e)}")
        return {
            "status": status,
            "error": str(e),
            "report_data": None,
            "pdf_path": "static/sample_report.pdf"
        }


if __name__ == "__main__":
    hybrid_decrypt()
