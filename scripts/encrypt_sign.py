# encrypt_sign.py
import json, os
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from base64 import b64encode, b64decode
import time

# Prepare key folders
Path("keys/production").mkdir(parents=True, exist_ok=True)
Path("keys/qa").mkdir(parents=True, exist_ok=True)

# Generate RSA key pair
def generate_keys(role):
    priv_path = f"keys/{role}/private_key.pem"
    pub_path = f"keys/{role}/public_key.pem"
    if not os.path.exists(priv_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(pub_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"New keys generated for: {role}")
    else:
        print(f"Keys for {role} already exist.")

# Load private/public keys
def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

# Simulated test report
def generate_report():
    return {

        
        # --- Identification & Traceability ---
        "report_id": "RF-ANT-2025-042",
        "batch_id": "BATCH-ANT-2401-A",
        "serial_number": "ANT-24-01-00078",
        "timestamp_utc": datetime.now().isoformat() + "Z",

        # --- Manufacturing Context ---
        "manufacturing_site": "Plant-A / RF Line 2",
        "test_stage": "End-of-Line (EOL)",
        "equipment_id": "VNA-KEYSIGHT-E5071C",
        "calibration_status": "VALID",

        # --- RF Performance Metrics ---
        "S11_dB": -12.3,
        "VSWR": 1.15,
        "Return_Loss_dB": 15.0,
        "Gain_dBi": 3.4,
        "Efficiency_pct": 85.0,
        "Bandwidth_MHz": 150.0,
        "Frequency_MHz": 2400.0,
        "Impedance_Ohm": 49.8,
        "Radiation_Pattern": "Omnidirectional",
        "Polarization": "Vertical",

        # --- Quality & Compliance ---
        "acceptance_criteria": "VSWR < 2.0, Efficiency > 80%",
        "qa_verdict": "PASS",
        "release_status": "APPROVED_FOR_MANUFACTURING",

        # --- Confidentiality & Control ---
        "data_classification": "INTERNAL_CONFIDENTIAL",
        "distribution_scope": ["Production", "Quality Assurance"],
        "tamper_protection": "DIGITAL_SIGNATURE_REQUIRED"
    }

# Sign report with production private key
def sign_report(report, private_key):
    message = json.dumps(report, sort_keys=True).encode()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return {
        "report": report,
        "signature": b64encode(signature).decode()
    }

# Encrypt report with AES, AES key encrypted with QA public key
def hybrid_encrypt(signed_report, qa_pubkey):
    aes_key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    data = json.dumps(signed_report).encode()
    ciphertext = aesgcm.encrypt(nonce, data, None)

    encrypted_aes_key = qa_pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    final_package = {
        "nonce": b64encode(nonce).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
        "encrypted_key": b64encode(encrypted_aes_key).decode()
    }

    with open("sample_report.enc", "w") as f:
        json.dump(final_package, f, indent=2)
    with open("sample_report.json", "w") as f:
        json.dump(signed_report, f, indent=2)
    print("Signed and encrypted report saved as sample_report.enc")

if __name__ == "__main__":
    generate_keys("production")
    generate_keys("qa")

    report = generate_report()
    prod_priv = load_private_key("keys/production/private_key.pem")
    qa_pub = load_public_key("keys/qa/public_key.pem")

    signed = sign_report(report, prod_priv)
    hybrid_encrypt(signed, qa_pub)


