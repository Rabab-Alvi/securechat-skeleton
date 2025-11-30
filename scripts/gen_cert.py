#!/usr/bin/env python3
"""
Generate client and server certificates signed by the Root CA
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import sys

def load_ca():
    """Load CA private key and certificate"""
    try:
        with open("certs/ca_key.pem", "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        with open("certs/ca_cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        return ca_key, ca_cert
    except FileNotFoundError:
        print("[ERROR] CA files not found. Run gen_ca.py first!")
        sys.exit(1)

def generate_certificate(entity_type, common_name):
    """
    Generate a certificate for client or server
    
    Args:
        entity_type: "server" or "client"
        common_name: CN for the certificate (e.g., "localhost" or username)
    """
    
    print(f"[*] Loading Root CA...")
    ca_key, ca_cert = load_ca()
    
    print(f"[*] Generating {entity_type} private key...")
    
    # Generate private key for entity
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Define subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"SecureChat {entity_type.title()}"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    print(f"[*] Creating {entity_type} certificate signed by CA...")
    
    # Build certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    
    # Add key usage based on entity type
    if entity_type == "server":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        # Add Subject Alternative Name for server
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    else:  # client
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    
    # Sign the certificate with CA
    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_path = f"certs/{entity_type}_key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[✓] {entity_type.title()} private key saved to: {key_path}")
    
    # Save certificate
    cert_path = f"certs/{entity_type}_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[✓] {entity_type.title()} certificate saved to: {cert_path}")
    
    print(f"\n[SUCCESS] {entity_type.title()} certificate generated!")
    print(f"  Serial Number: {cert.serial_number}")
    print(f"  Valid From: {cert.not_valid_before}")
    print(f"  Valid Until: {cert.not_valid_after}")
    print(f"  Issuer: {cert.issuer.rfc4514_string()}")

if __name__ == "__main__":
    import ipaddress
    
    print("=" * 60)
    print("SecureChat Certificate Generator")
    print("=" * 60)
    
    # Generate server certificate
    print("\n--- Generating Server Certificate ---")
    generate_certificate("server", "localhost")
    
    print("\n--- Generating Client Certificate ---")
    generate_certificate("client", "securechat-client")
    
    print("\n" + "=" * 60)
    print("All certificates generated successfully!")
    print("=" * 60)