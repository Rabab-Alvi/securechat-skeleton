#!/usr/bin/env python3
"""
Generate a self-signed Root Certificate Authority (CA)
This CA will be used to sign client and server certificates
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os

def generate_root_ca():
    """Generate root CA private key and self-signed certificate"""
    
    # Ensure certs directory exists
    os.makedirs("certs", exist_ok=True)
    
    print("[*] Generating Root CA private key (2048-bit RSA)...")
    
    # Generate private key for CA
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Define CA subject (issuer for certificates it will sign)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])
    
    print("[*] Creating self-signed CA certificate...")
    
    # Build the CA certificate
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    
    # Save CA private key
    ca_key_path = "certs/ca_key.pem"
    with open(ca_key_path, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[✓] CA private key saved to: {ca_key_path}")
    
    # Save CA certificate
    ca_cert_path = "certs/ca_cert.pem"
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"[✓] CA certificate saved to: {ca_cert_path}")
    
    print("\n[SUCCESS] Root CA generated successfully!")
    print(f"  Serial Number: {ca_cert.serial_number}")
    print(f"  Valid From: {ca_cert.not_valid_before}")
    print(f"  Valid Until: {ca_cert.not_valid_after}")
    
    return ca_private_key, ca_cert

if __name__ == "__main__":
    print("=" * 60)
    print("SecureChat Root CA Generator")
    print("=" * 60)
    generate_root_ca()