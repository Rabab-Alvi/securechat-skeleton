#!/usr/bin/env python3
"""
Cryptographic utility functions for SecureChat
Implements AES-128, RSA signatures, DH key exchange, and SHA-256
"""

import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509


# ==================== AES-128 Encryption ====================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Add PKCS#7 padding to data"""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data"""
    if not data:
        raise ValueError("Cannot unpad empty data")
    padding_len = data[-1]
    if padding_len > len(data) or padding_len == 0:
        raise ValueError("Invalid padding")
    # Verify all padding bytes are correct
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-CBC with PKCS#7 padding
    
    Args:
        plaintext: data to encrypt
        key: 16-byte AES key
        
    Returns:
        IV (16 bytes) + ciphertext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Pad plaintext
    padded = pkcs7_pad(plaintext)
    
    # Encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Return IV + ciphertext
    return iv + ciphertext

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-128-CBC ciphertext
    
    Args:
        data: IV (16 bytes) + ciphertext
        key: 16-byte AES key
        
    Returns:
        plaintext (unpadded)
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    if len(data) < 16:
        raise ValueError("Invalid ciphertext (too short)")
    
    # Extract IV and ciphertext
    iv = data[:16]
    ciphertext = data[16:]
    
    # Decrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    return pkcs7_unpad(padded_plaintext)


# ==================== SHA-256 Hashing ====================

def sha256_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash"""
    return hashlib.sha256(data).digest()

def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string"""
    return hashlib.sha256(data).hexdigest()


# ==================== Diffie-Hellman Key Exchange ====================

# Standard 2048-bit MODP group (RFC 3526)
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_GENERATOR = 2

def dh_generate_keypair():
    """
    Generate DH private/public keypair
    
    Returns:
        (private_key, public_key) as integers
    """
    private_key = int.from_bytes(os.urandom(256), byteorder='big') % (DH_PRIME - 2) + 1
    public_key = pow(DH_GENERATOR, private_key, DH_PRIME)
    return private_key, public_key

def dh_compute_shared_secret(private_key: int, peer_public_key: int) -> int:
    """
    Compute shared secret from peer's public key
    
    Args:
        private_key: our private key
        peer_public_key: peer's public key
        
    Returns:
        shared secret as integer
    """
    return pow(peer_public_key, private_key, DH_PRIME)

def derive_aes_key_from_dh(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret
    K = Trunc_16(SHA256(big_endian(Ks)))
    
    Args:
        shared_secret: DH shared secret (integer)
        
    Returns:
        16-byte AES key
    """
    # Convert to big-endian bytes
    secret_bytes = shared_secret.to_bytes(256, byteorder='big')
    # Hash and truncate to 16 bytes
    hash_digest = sha256_hash(secret_bytes)
    return hash_digest[:16]


# ==================== RSA Signatures ====================

def rsa_sign(private_key, data: bytes) -> bytes:
    """
    Sign data using RSA with SHA-256
    
    Args:
        private_key: RSA private key object
        data: data to sign
        
    Returns:
        signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    """
    Verify RSA signature
    
    Args:
        public_key: RSA public key object
        signature: signature to verify
        data: original data that was signed
        
    Returns:
        True if valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ==================== Certificate Utilities ====================

def load_certificate(cert_path: str):
    """Load X.509 certificate from PEM file"""
    with open(cert_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def load_private_key(key_path: str):
    """Load RSA private key from PEM file"""
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def get_cert_fingerprint(cert) -> str:
    """Get SHA-256 fingerprint of certificate"""
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()

def cert_to_pem_string(cert) -> str:
    """Convert certificate to PEM string"""
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def pem_string_to_cert(pem_str: str):
    """Convert PEM string to certificate object"""
    return x509.load_pem_x509_certificate(pem_str.encode('utf-8'), default_backend())

def verify_certificate(cert, ca_cert) -> tuple[bool, str]:
    """
    Verify certificate against CA
    
    Returns:
        (is_valid, error_message)
    """
    import datetime
    
    # Check if expired
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before:
        return False, "Certificate not yet valid"
    if now > cert.not_valid_after:
        return False, "Certificate expired"
    
    # Verify signature chain
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except Exception as e:
        return False, f"Certificate signature verification failed: {str(e)}"
    
    # Check issuer matches CA subject
    if cert.issuer != ca_cert.subject:
        return False, "Certificate issuer does not match CA"
    
    return True, ""


# ==================== Utility Functions ====================

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def b64encode(data: bytes) -> str:
    """Base64 encode bytes to string"""
    return base64.b64encode(data).decode('utf-8')

def b64decode(data: str) -> bytes:
    """Base64 decode string to bytes"""
    return base64.b64decode(data.encode('utf-8'))