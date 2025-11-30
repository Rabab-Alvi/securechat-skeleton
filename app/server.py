#!/usr/bin/env python3
"""
SecureChat Server - Handles authentication, key exchange, and encrypted messaging
"""

import socket
import json
import os
import sys
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import datetime
import threading

from crypto_utils import *

load_dotenv()

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.socket = None
        
        # Load server certificate and key
        self.server_cert = load_certificate('certs/server_cert.pem')
        self.server_key = load_private_key('certs/server_key.pem')
        self.ca_cert = load_certificate('certs/ca_cert.pem')
        
        # Session state
        self.client_cert = None
        self.session_key = None
        self.username = None
        self.email = None
        self.seq_counter = 0
        self.last_client_seq = -1
        
        # Transcript for non-repudiation
        self.transcript = []
        
        print(f"[*] Server initialized on {host}:{port}")
        print(f"[*] Server cert fingerprint: {get_cert_fingerprint(self.server_cert)}")
    
    def get_db_connection(self):
        """Create database connection"""
        try:
            return mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'root'),
                password=os.getenv('DB_PASSWORD'),
                database=os.getenv('DB_NAME', 'securechat')
            )
        except Error as e:
            print(f"[ERROR] Database connection failed: {e}")
            return None
    
    def send_json(self, conn, data):
        """Send JSON message"""
        msg = json.dumps(data).encode('utf-8')
        conn.sendall(len(msg).to_bytes(4, 'big') + msg)
    
    def recv_json(self, conn):
        """Receive JSON message"""
        length_bytes = conn.recv(4)
        if not length_bytes:
            return None
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = conn.recv(min(length - len(data), 4096))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode('utf-8'))
    
    def handle_hello(self, conn, msg):
        """Handle initial hello and certificate exchange"""
        print("[*] Received client hello")
        
        # Extract client certificate
        try:
            client_cert_pem = msg.get('client_cert')
            if not client_cert_pem:
                self.send_json(conn, {'type': 'error', 'message': 'BAD_CERT: No certificate provided'})
                return False
            
            self.client_cert = pem_string_to_cert(client_cert_pem)
            
            # Verify client certificate
            is_valid, error_msg = verify_certificate(self.client_cert, self.ca_cert)
            if not is_valid:
                self.send_json(conn, {'type': 'error', 'message': f'BAD_CERT: {error_msg}'})
                return False
            
            print(f"[✓] Client certificate verified")
            print(f"    Subject: {self.client_cert.subject.rfc4514_string()}")
            print(f"    Fingerprint: {get_cert_fingerprint(self.client_cert)}")
            
            # Send server hello with certificate
            response = {
                'type': 'server_hello',
                'server_cert': cert_to_pem_string(self.server_cert),
                'nonce': b64encode(os.urandom(32))
            }
            self.send_json(conn, response)
            return True
            
        except Exception as e:
            print(f"[ERROR] Certificate verification failed: {e}")
            self.send_json(conn, {'type': 'error', 'message': f'BAD_CERT: {str(e)}'})
            return False
    
    def handle_dh_exchange(self, conn, msg):
        """Handle Diffie-Hellman key exchange for initial encryption"""
        print("[*] Starting DH key exchange for control plane")
        
        try:
            # Receive client's DH public key
            g = msg.get('g', DH_GENERATOR)
            p = msg.get('p', DH_PRIME)
            client_A = msg.get('A')
            
            if not client_A:
                self.send_json(conn, {'type': 'error', 'message': 'Missing DH parameters'})
                return None
            
            # Generate server's DH keypair
            server_b, server_B = dh_generate_keypair()
            
            # Compute shared secret
            shared_secret = dh_compute_shared_secret(server_b, client_A)
            temp_key = derive_aes_key_from_dh(shared_secret)
            
            # Send server's public key
            self.send_json(conn, {
                'type': 'dh_server',
                'B': server_B
            })
            
            print(f"[✓] DH exchange complete, derived temporary AES key")
            return temp_key
            
        except Exception as e:
            print(f"[ERROR] DH exchange failed: {e}")
            self.send_json(conn, {'type': 'error', 'message': 'DH exchange failed'})
            return None
    
    def handle_register(self, conn, msg, temp_key):
        """Handle user registration"""
        print("[*] Processing registration")
        
        try:
            # Decrypt registration data
            encrypted_data = b64decode(msg.get('data'))
            decrypted = aes_decrypt(encrypted_data, temp_key)
            reg_data = json.loads(decrypted.decode('utf-8'))
            
            email = reg_data.get('email')
            username = reg_data.get('username')
            salt = b64decode(reg_data.get('salt'))
            pwd_hash = reg_data.get('pwd_hash')
            
            # Validate inputs
            if not all([email, username, salt, pwd_hash]):
                self.send_json(conn, {'type': 'error', 'message': 'Missing registration fields'})
                return False
            
            # Store in database
            db = self.get_db_connection()
            if not db:
                self.send_json(conn, {'type': 'error', 'message': 'Database unavailable'})
                return False
            
            cursor = db.cursor()
            
            # Check if user exists
            cursor.execute("SELECT username FROM users WHERE email = %s OR username = %s", (email, username))
            if cursor.fetchone():
                self.send_json(conn, {'type': 'error', 'message': 'User already exists'})
                cursor.close()
                db.close()
                return False
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
            db.commit()
            cursor.close()
            db.close()
            
            print(f"[✓] User registered: {username} ({email})")
            
            self.username = username
            self.email = email
            
            encrypted_response = aes_encrypt(
                json.dumps({'success': True, 'message': 'Registration successful'}).encode('utf-8'),
                temp_key
            )
            
            self.send_json(conn, {
                'type': 'register_response',
                'data': b64encode(encrypted_response)
            })
            return True
            
        except Exception as e:
            print(f"[ERROR] Registration failed: {e}")
            self.send_json(conn, {'type': 'error', 'message': f'Registration failed: {str(e)}'})
            return False
    
    def handle_login(self, conn, msg, temp_key):
        """Handle user login"""
        print("[*] Processing login")
        
        try:
            # Decrypt login data
            encrypted_data = b64decode(msg.get('data'))
            decrypted = aes_decrypt(encrypted_data, temp_key)
            login_data = json.loads(decrypted.decode('utf-8'))
            
            email = login_data.get('email')
            pwd_hash_client = login_data.get('pwd_hash')
            
            # Retrieve from database
            db = self.get_db_connection()
            if not db:
                self.send_json(conn, {'type': 'error', 'message': 'Database unavailable'})
                return False
            
            cursor = db.cursor()
            cursor.execute("SELECT username, salt, pwd_hash FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            cursor.close()
            db.close()
            
            if not result:
                # Use constant time to prevent timing attacks
                dummy = sha256_hex(os.urandom(32).hex().encode())
                self.send_json(conn, {'type': 'error', 'message': 'Invalid credentials'})
                return False
            
            username, salt, pwd_hash_stored = result
            
            # Verify password hash (constant time)
            if not constant_time_compare(pwd_hash_client.encode(), pwd_hash_stored.encode()):
                self.send_json(conn, {'type': 'error', 'message': 'Invalid credentials'})
                return False
            
            print(f"[✓] User authenticated: {username} ({email})")
            
            self.username = username
            self.email = email
            
            encrypted_response = aes_encrypt(
                json.dumps({'success': True, 'message': 'Login successful'}).encode('utf-8'),
                temp_key
            )
            
            self.send_json(conn, {
                'type': 'login_response',
                'data': b64encode(encrypted_response)
            })
            return True
            
        except Exception as e:
            print(f"[ERROR] Login failed: {e}")
            self.send_json(conn, {'type': 'error', 'message': f'Login failed: {str(e)}'})
            return False
    
    def handle_session_dh(self, conn, msg):
        """Handle DH exchange for session key"""
        print("[*] Starting DH key exchange for chat session")
        
        try:
            client_A = msg.get('A')
            
            # Generate server's DH keypair
            server_b, server_B = dh_generate_keypair()
            
            # Compute shared secret
            shared_secret = dh_compute_shared_secret(server_b, client_A)
            self.session_key = derive_aes_key_from_dh(shared_secret)
            
            # Send server's public key
            self.send_json(conn, {
                'type': 'session_dh_response',
                'B': server_B
            })
            
            print(f"[✓] Session key established")
            return True
            
        except Exception as e:
            print(f"[ERROR] Session DH failed: {e}")
            return False
    
    def handle_chat_message(self, conn, msg):
        """Handle encrypted chat message"""
        try:
            seqno = msg.get('seqno')
            timestamp = msg.get('ts')
            ciphertext_b64 = msg.get('ct')
            signature_b64 = msg.get('sig')
            
            # Replay protection
            if seqno <= self.last_client_seq:
                print(f"[!] REPLAY detected: seqno {seqno}")
                self.send_json(conn, {'type': 'error', 'message': 'REPLAY'})
                return
            
            # Verify signature
            ciphertext = b64decode(ciphertext_b64)
            signature = b64decode(signature_b64)
            
            # Recompute digest: seqno || ts || ct
            digest_data = str(seqno).encode() + str(timestamp).encode() + ciphertext
            digest = sha256_hash(digest_data)
            
            client_public_key = self.client_cert.public_key()
            if not rsa_verify(client_public_key, signature, digest):
                print(f"[!] SIG_FAIL: Invalid signature on message {seqno}")
                self.send_json(conn, {'type': 'error', 'message': 'SIG_FAIL'})
                return
            
            # Decrypt message
            plaintext = aes_decrypt(ciphertext, self.session_key)
            message_text = plaintext.decode('utf-8')
            
            print(f"\n[Client {self.username}]: {message_text}")
            
            # Update sequence counter
            self.last_client_seq = seqno
            
            # Log to transcript
            self.transcript.append({
                'sender': 'client',
                'seqno': seqno,
                'ts': timestamp,
                'ct': ciphertext_b64,
                'sig': signature_b64,
                'peer_cert_fp': get_cert_fingerprint(self.client_cert)
            })
            
            # Check for exit command
            if message_text.strip().lower() == '/exit':
                print("[*] Client initiated session closure")
                self.generate_receipt(conn)
                return False
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Message handling failed: {e}")
            return True
    
    def send_chat_message(self, conn, plaintext: str):
        """Send encrypted chat message"""
        try:
            # Increment sequence number
            self.seq_counter += 1
            timestamp = int(datetime.datetime.now().timestamp() * 1000)
            
            # Encrypt message
            ciphertext = aes_encrypt(plaintext.encode('utf-8'), self.session_key)
            
            # Compute digest and sign
            digest_data = str(self.seq_counter).encode() + str(timestamp).encode() + ciphertext
            digest = sha256_hash(digest_data)
            signature = rsa_sign(self.server_key, digest)
            
            # Send message
            self.send_json(conn, {
                'type': 'msg',
                'seqno': self.seq_counter,
                'ts': timestamp,
                'ct': b64encode(ciphertext),
                'sig': b64encode(signature)
            })
            
            # Log to transcript
            self.transcript.append({
                'sender': 'server',
                'seqno': self.seq_counter,
                'ts': timestamp,
                'ct': b64encode(ciphertext),
                'sig': b64encode(signature),
                'peer_cert_fp': get_cert_fingerprint(self.server_cert)
            })
            
        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")
    
    def generate_receipt(self, conn):
        """Generate and exchange non-repudiation receipt"""
        print("\n[*] Generating session receipt...")
        
        try:
            # Compute transcript hash
            transcript_lines = []
            for entry in self.transcript:
                line = f"{entry['sender']}|{entry['seqno']}|{entry['ts']}|{entry['ct']}|{entry['sig']}|{entry['peer_cert_fp']}"
                transcript_lines.append(line)
            
            transcript_text = "\n".join(transcript_lines)
            transcript_hash = sha256_hex(transcript_text.encode('utf-8'))
            
            # Sign transcript hash
            signature = rsa_sign(self.server_key, transcript_hash.encode('utf-8'))
            
            # Create receipt
            receipt = {
                'type': 'receipt',
                'peer': 'server',
                'first_seq': self.transcript[0]['seqno'] if self.transcript else 0,
                'last_seq': self.transcript[-1]['seqno'] if self.transcript else 0,
                'transcript_sha256': transcript_hash,
                'sig': b64encode(signature)
            }
            
            # Save transcript and receipt
            os.makedirs('transcripts', exist_ok=True)
            session_id = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            
            with open(f'transcripts/server_transcript_{session_id}.txt', 'w') as f:
                f.write(transcript_text)
            
            with open(f'transcripts/server_receipt_{session_id}.json', 'w') as f:
                json.dump(receipt, f, indent=2)
            
            # Send receipt
            self.send_json(conn, receipt)
            
            print(f"[✓] Receipt generated and saved")
            print(f"    Transcript hash: {transcript_hash}")
            
        except Exception as e:
            print(f"[ERROR] Receipt generation failed: {e}")
    
    def handle_client(self, conn, addr):
        """Handle single client connection"""
        print(f"\n[*] New connection from {addr}")
        
        try:
            # Phase 1: Certificate exchange
            msg = self.recv_json(conn)
            if not msg or msg.get('type') != 'hello':
                return
            
            if not self.handle_hello(conn, msg):
                return
            
            # Phase 2: DH for control plane
            msg = self.recv_json(conn)
            if not msg or msg.get('type') != 'dh_client':
                return
            
            temp_key = self.handle_dh_exchange(conn, msg)
            if not temp_key:
                return
            
            # Phase 3: Register or Login
            msg = self.recv_json(conn)
            if not msg:
                return
            
            if msg.get('type') == 'register':
                if not self.handle_register(conn, msg, temp_key):
                    return
            elif msg.get('type') == 'login':
                if not self.handle_login(conn, msg, temp_key):
                    return
            else:
                return
            
            # Phase 4: Session DH
            msg = self.recv_json(conn)
            if not msg or msg.get('type') != 'session_dh':
                return
            
            if not self.handle_session_dh(conn, msg):
                return
            
            print(f"\n[✓] Secure session established with {self.username}")
            print("=" * 60)
            print("Chat started. Type messages to send. Use /exit to close.")
            print("=" * 60)
            
            # Phase 5: Chat loop
            def receive_messages():
                while True:
                    try:
                        msg = self.recv_json(conn)
                        if not msg:
                            break
                        if msg.get('type') == 'msg':
                            if not self.handle_chat_message(conn, msg):
                                break
                    except:
                        break
            
            # Start receive thread
            recv_thread = threading.Thread(target=receive_messages, daemon=True)
            recv_thread.start()
            
            # Send messages
            while True:
                try:
                    user_input = input()
                    if user_input.strip().lower() == '/exit':
                        self.send_chat_message(conn, '/exit')
                        break
                    if user_input.strip():
                        self.send_chat_message(conn, user_input)
                except KeyboardInterrupt:
                    break
            
            # Generate receipt
            self.generate_receipt(conn)
            
        except Exception as e:
            print(f"[ERROR] Client handler error: {e}")
        finally:
            conn.close()
            print(f"\n[*] Connection closed")
    
    def start(self):
        """Start server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        
        print(f"\n[✓] Server listening on {self.host}:{self.port}")
        print("Waiting for client connection...\n")
        
        try:
            while True:
                conn, addr = self.socket.accept()
                self.handle_client(conn, addr)
                
                # Reset for next client
                self.client_cert = None
                self.session_key = None
                self.username = None
                self.seq_counter = 0
                self.last_client_seq = -1
                self.transcript = []
                
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            if self.socket:
                self.socket.close()

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()