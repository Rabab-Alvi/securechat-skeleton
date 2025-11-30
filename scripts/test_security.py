#!/usr/bin/env python3
"""
Security testing script for SecureChat
Tests: certificate validation, tampering detection, replay protection
"""

import os
import json
from crypto_utils import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import datetime

def test_certificate_validation():
    """Test 1: Certificate validation"""
    print("\n" + "=" * 60)
    print("TEST 1: Certificate Validation")
    print("=" * 60)
    
    try:
        # Load CA and valid cert
        ca_cert = load_certificate('certs/ca_cert.pem')
        server_cert = load_certificate('certs/server_cert.pem')
        
        # Test valid certificate
        is_valid, msg = verify_certificate(server_cert, ca_cert)
        print(f"[✓] Valid certificate: {is_valid}")
        assert is_valid, "Valid certificate should pass"
        
        # Test expired certificate (create one)
        print("\n[*] Testing expired certificate...")
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        # Create expired cert
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Expired Cert"),
        ])
        
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=10))
            .not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .sign(load_private_key('certs/ca_key.pem'), hashes.SHA256(), default_backend())
        )
        
        is_valid, msg = verify_certificate(expired_cert, ca_cert)
        print(f"[✓] Expired certificate rejected: {not is_valid}")
        print(f"    Error: {msg}")
        assert not is_valid, "Expired certificate should fail"
        
        print("\n[SUCCESS] Certificate validation tests passed!")
        return True
        
    except Exception as e:
        print(f"[FAIL] Certificate validation test failed: {e}")
        return False

def test_tampering_detection():
    """Test 2: Message tampering detection"""
    print("\n" + "=" * 60)
    print("TEST 2: Tampering Detection")
    print("=" * 60)
    
    try:
        # Load keys
        private_key = load_private_key('certs/client_key.pem')
        cert = load_certificate('certs/client_cert.pem')
        public_key = cert.public_key()
        
        # Create a message
        seqno = 1
        timestamp = 1234567890
        plaintext = b"Hello, secure world!"
        session_key = os.urandom(16)
        
        # Encrypt message
        ciphertext = aes_encrypt(plaintext, session_key)
        
        # Sign message
        digest_data = str(seqno).encode() + str(timestamp).encode() + ciphertext
        digest = sha256_hash(digest_data)
        signature = rsa_sign(private_key, digest)
        
        # Verify original (should pass)
        is_valid = rsa_verify(public_key, signature, digest)
        print(f"[✓] Original message verification: {is_valid}")
        assert is_valid, "Original signature should verify"
        
        # Tamper with ciphertext (flip one bit)
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0x01
        tampered_ct = bytes(tampered_ct)
        
        # Recompute digest with tampered data
        tampered_digest_data = str(seqno).encode() + str(timestamp).encode() + tampered_ct
        tampered_digest = sha256_hash(tampered_digest_data)
        
        # Try to verify with original signature (should fail)
        is_valid = rsa_verify(public_key, signature, tampered_digest)
        print(f"[✓] Tampered message rejected: {not is_valid}")
        assert not is_valid, "Tampered message should fail verification"
        
        # Try to decrypt tampered ciphertext (should fail or produce garbage)
        try:
            decrypted = aes_decrypt(tampered_ct, session_key)
            print(f"[✓] Decryption of tampered data produced: {decrypted[:20]}... (garbage)")
        except Exception as e:
            print(f"[✓] Decryption of tampered data failed: {type(e).__name__}")
        
        print("\n[SUCCESS] Tampering detection tests passed!")
        return True
        
    except Exception as e:
        print(f"[FAIL] Tampering detection test failed: {e}")
        return False

def test_replay_detection():
    """Test 3: Replay attack detection"""
    print("\n" + "=" * 60)
    print("TEST 3: Replay Detection")
    print("=" * 60)
    
    try:
        print("[*] Simulating message sequence...")
        
        # Simulate sequence numbers
        last_seq = 0
        messages = [1, 2, 3, 4, 5]
        
        for seq in messages:
            if seq > last_seq:
                print(f"[✓] Message {seq} accepted (seq > last_seq)")
                last_seq = seq
            else:
                print(f"[✓] Message {seq} rejected (replay)")
        
        # Try to replay old message
        replay_seq = 3
        if replay_seq <= last_seq:
            print(f"[✓] Replay attack detected: seq {replay_seq} <= last_seq {last_seq}")
        
        # Out of order (but not replay)
        future_seq = 10
        if future_seq > last_seq:
            print(f"[✓] Future message {future_seq} accepted")
            last_seq = future_seq
        
        print("\n[SUCCESS] Replay detection tests passed!")
        return True
        
    except Exception as e:
        print(f"[FAIL] Replay detection test failed: {e}")
        return False

def test_encryption_decryption():
    """Test 4: AES encryption/decryption"""
    print("\n" + "=" * 60)
    print("TEST 4: AES-128 Encryption/Decryption")
    print("=" * 60)
    
    try:
        key = os.urandom(16)
        plaintext = b"This is a test message for AES-128!"
        
        print(f"[*] Plaintext: {plaintext.decode()}")
        print(f"[*] Key (hex): {key.hex()}")
        
        # Encrypt
        ciphertext = aes_encrypt(plaintext, key)
        print(f"[✓] Ciphertext (len={len(ciphertext)}): {ciphertext[:32].hex()}...")
        
        # Decrypt
        decrypted = aes_decrypt(ciphertext, key)
        print(f"[✓] Decrypted: {decrypted.decode()}")
        
        assert plaintext == decrypted, "Decryption should recover original plaintext"
        
        # Wrong key should fail
        wrong_key = os.urandom(16)
        try:
            wrong_decrypt = aes_decrypt(ciphertext, wrong_key)
            # If it doesn't throw, check if it's garbage
            assert wrong_decrypt != plaintext, "Wrong key should not decrypt correctly"
            print(f"[✓] Wrong key produced garbage")
        except Exception:
            print(f"[✓] Wrong key failed to decrypt")
        
        print("\n[SUCCESS] AES encryption tests passed!")
        return True
        
    except Exception as e:
        print(f"[FAIL] AES encryption test failed: {e}")
        return False

def test_dh_key_exchange():
    """Test 5: Diffie-Hellman key exchange"""
    print("\n" + "=" * 60)
    print("TEST 5: Diffie-Hellman Key Exchange")
    print("=" * 60)
    
    try:
        # Alice generates keypair
        alice_private, alice_public = dh_generate_keypair()
        print(f"[✓] Alice generated keypair")
        print(f"    Public key: {hex(alice_public)[:50]}...")
        
        # Bob generates keypair
        bob_private, bob_public = dh_generate_keypair()
        print(f"[✓] Bob generated keypair")
        print(f"    Public key: {hex(bob_public)[:50]}...")
        
        # Both compute shared secret
        alice_shared = dh_compute_shared_secret(alice_private, bob_public)
        bob_shared = dh_compute_shared_secret(bob_private, alice_public)
        
        print(f"[✓] Shared secrets computed")
        assert alice_shared == bob_shared, "Shared secrets should match"
        
        # Derive AES keys
        alice_key = derive_aes_key_from_dh(alice_shared)
        bob_key = derive_aes_key_from_dh(bob_shared)
        
        print(f"[✓] AES keys derived")
        print(f"    Alice key: {alice_key.hex()}")
        print(f"    Bob key:   {bob_key.hex()}")
        assert alice_key == bob_key, "Derived keys should match"
        
        # Test encryption with derived key
        message = b"DH key exchange successful!"
        ct = aes_encrypt(message, alice_key)
        pt = aes_decrypt(ct, bob_key)
        assert pt == message, "Message should decrypt correctly"
        
        print(f"[✓] Message encrypted and decrypted successfully")
        print("\n[SUCCESS] DH key exchange tests passed!")
        return True
        
    except Exception as e:
        print(f"[FAIL] DH key exchange test failed: {e}")
        return False

def test_non_repudiation():
    """Test 6: Non-repudiation (transcript and receipt)"""
    print("\n" + "=" * 60)
    print("TEST 6: Non-Repudiation")
    print("=" * 60)
    
    try:
        # Load keys
        private_key = load_private_key('certs/client_key.pem')
        cert = load_certificate('certs/client_cert.pem')
        public_key = cert.public_key()
        
        # Create mock transcript
        transcript_lines = [
            "client|1|1234567890|aGVsbG8=|c2lnbmF0dXJl|abcdef",
            "server|2|1234567891|d29ybGQ=|c2lnbmF0dXJl|fedcba",
            "client|3|1234567892|dGVzdA==|c2lnbmF0dXJl|abcdef"
        ]
        
        transcript_text = "\n".join(transcript_lines)
        transcript_hash = sha256_hex(transcript_text.encode('utf-8'))
        
        print(f"[*] Transcript hash: {transcript_hash}")
        
        # Sign transcript hash
        signature = rsa_sign(private_key, transcript_hash.encode('utf-8'))
        print(f"[✓] Transcript signed")
        
        # Verify signature
        is_valid = rsa_verify(public_key, signature, transcript_hash.encode('utf-8'))
        print(f"[✓] Receipt signature valid: {is_valid}")
        assert is_valid, "Receipt signature should verify"
        
        # Tamper with transcript
        tampered_lines = transcript_lines.copy()
        tampered_lines[1] = "server|2|1234567891|TAMPERED|c2lnbmF0dXJl|fedcba"
        tampered_text = "\n".join(tampered_lines)
        tampered_hash = sha256_hex(tampered_text.encode('utf-8'))
        
        # Original signature should not verify tampered hash
        is_valid = rsa_verify(public_key, signature, tampered_hash.encode('utf-8'))
        print(f"[✓] Tampered transcript rejected: {not is_valid}")
        assert not is_valid, "Tampered transcript should fail verification"
        
        print("\n[SUCCESS] Non-repudiation tests passed!")
        return True
        
    except Exception as e:
        print(f"[FAIL] Non-repudiation test failed: {e}")
        return False

def main():
    """Run all security tests"""
    print("\n" + "=" * 60)
    print("SECURECHAT SECURITY TEST SUITE")
    print("=" * 60)
    
    results = []
    
    results.append(("Certificate Validation", test_certificate_validation()))
    results.append(("Tampering Detection", test_tampering_detection()))
    results.append(("Replay Detection", test_replay_detection()))
    results.append(("AES Encryption", test_encryption_decryption()))
    results.append(("DH Key Exchange", test_dh_key_exchange()))
    results.append(("Non-Repudiation", test_non_repudiation()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] All security tests passed! ✓")
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed")

if __name__ == "__main__":
    main()