#!/usr/bin/env python3
"""
Offline verification tool for SecureChat session receipts
Verifies non-repudiation evidence
"""

import json
import sys
from crypto_utils import *

def verify_receipt(receipt_path, transcript_path, cert_path):
    """
    Verify a session receipt against transcript and certificate
    
    Args:
        receipt_path: Path to receipt JSON file
        transcript_path: Path to transcript text file
        cert_path: Path to signer's certificate
    """
    print("\n" + "=" * 60)
    print("SECURECHAT RECEIPT VERIFICATION")
    print("=" * 60)
    
    try:
        # Load receipt
        print(f"\n[*] Loading receipt from: {receipt_path}")
        with open(receipt_path, 'r') as f:
            receipt = json.load(f)
        
        print(f"[✓] Receipt loaded")
        print(f"    Peer: {receipt.get('peer')}")
        print(f"    First seq: {receipt.get('first_seq')}")
        print(f"    Last seq: {receipt.get('last_seq')}")
        print(f"    Transcript SHA-256: {receipt.get('transcript_sha256')}")
        
        # Load transcript
        print(f"\n[*] Loading transcript from: {transcript_path}")
        with open(transcript_path, 'r') as f:
            transcript_text = f.read()
        
        line_count = len(transcript_text.strip().split('\n'))
        print(f"[✓] Transcript loaded ({line_count} lines)")
        
        # Recompute transcript hash
        print(f"\n[*] Recomputing transcript hash...")
        computed_hash = sha256_hex(transcript_text.encode('utf-8'))
        claimed_hash = receipt.get('transcript_sha256')
        
        print(f"    Claimed:  {claimed_hash}")
        print(f"    Computed: {computed_hash}")
        
        if computed_hash != claimed_hash:
            print(f"\n[FAIL] ❌ Transcript hash mismatch!")
            print(f"The transcript has been tampered with or does not match the receipt.")
            return False
        
        print(f"[✓] Transcript hash matches!")
        
        # Load certificate and verify signature
        print(f"\n[*] Loading certificate from: {cert_path}")
        cert = load_certificate(cert_path)
        public_key = cert.public_key()
        
        print(f"[✓] Certificate loaded")
        print(f"    Subject: {cert.subject.rfc4514_string()}")
        print(f"    Fingerprint: {get_cert_fingerprint(cert)}")
        
        # Verify RSA signature
        print(f"\n[*] Verifying RSA signature...")
        signature = b64decode(receipt.get('sig'))
        
        is_valid = rsa_verify(public_key, signature, claimed_hash.encode('utf-8'))
        
        if not is_valid:
            print(f"\n[FAIL] ❌ Signature verification failed!")
            print(f"The receipt signature is invalid or was signed by a different key.")
            return False
        
        print(f"[✓] Signature verified successfully!")
        
        # Verify individual messages in transcript
        print(f"\n[*] Verifying individual message signatures...")
        
        lines = transcript_text.strip().split('\n')
        verified_count = 0
        failed_count = 0
        
        for idx, line in enumerate(lines, 1):
            parts = line.split('|')
            if len(parts) != 6:
                print(f"[WARNING] Line {idx}: Invalid format, skipping")
                continue
            
            sender, seqno, timestamp, ct_b64, sig_b64, peer_fp = parts
            
            try:
                # Recompute digest
                ct = b64decode(ct_b64)
                digest_data = seqno.encode() + timestamp.encode() + ct
                digest = sha256_hash(digest_data)
                
                # Verify signature
                sig = b64decode(sig_b64)
                if rsa_verify(public_key, sig, digest):
                    verified_count += 1
                    if idx <= 3:  # Show first 3
                        print(f"    [✓] Message {seqno} verified")
                else:
                    failed_count += 1
                    print(f"    [✗] Message {seqno} FAILED")
            
            except Exception as e:
                failed_count += 1
                print(f"    [✗] Message {seqno} error: {e}")
        
        if failed_count == 0:
            print(f"\n[✓] All {verified_count} message signatures verified!")
        else:
            print(f"\n[WARNING] {failed_count} message(s) failed verification")
        
        # Final verdict
        print("\n" + "=" * 60)
        print("VERIFICATION RESULT")
        print("=" * 60)
        
        if computed_hash == claimed_hash and is_valid and failed_count == 0:
            print("\n✅ [SUCCESS] Receipt is VALID and AUTHENTIC")
            print("\nThis session receipt provides cryptographic proof that:")
            print(f"1. The transcript has NOT been tampered with")
            print(f"2. The {receipt.get('peer')} signed this receipt")
            print(f"3. All {verified_count} messages are authentic")
            print(f"4. Non-repudiation is ESTABLISHED")
            return True
        else:
            print("\n❌ [FAIL] Receipt verification FAILED")
            return False
    
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        return False
    except Exception as e:
        print(f"\n[ERROR] Verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    if len(sys.argv) != 4:
        print("Usage: python verify_receipt.py <receipt.json> <transcript.txt> <signer_cert.pem>")
        print("\nExample:")
        print("  python verify_receipt.py \\")
        print("    transcripts/client_receipt_20251130_143052.json \\")
        print("    transcripts/client_transcript_20251130_143052.txt \\")
        print("    certs/client_cert.pem")
        sys.exit(1)
    
    receipt_path = sys.argv[1]
    transcript_path = sys.argv[2]
    cert_path = sys.argv[3]
    
    success = verify_receipt(receipt_path, transcript_path, cert_path)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()