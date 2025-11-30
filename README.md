SecureChat - Cryptographic Chat System
FAST-NUCES Information Security Assignment #2
Student: i22-1338 - Rabab Alvi
GitHub Repository: https://github.com/Rabab-Alvi/securechat-skeleton

🎯 Project Overview
SecureChat is a console-based secure chat system implementing a complete cryptographic protocol that achieves:

Confidentiality (AES-128 encryption)
Integrity (SHA-256 hashing)
Authenticity (RSA signatures with X.509 certificates)
Non-Repudiation (Signed session transcripts)
🏗️ Architecture
Protocol Phases
Control Plane - Certificate exchange and mutual authentication
Key Agreement - Diffie-Hellman key exchange
Data Plane - Encrypted message exchange with signatures
Teardown - Non-repudiation receipt generation
Technology Stack
Language: Python 3.8+
Cryptography: cryptography library
Database: MySQL 8.0+
Transport: TCP Sockets (no TLS/SSL)
📦 Installation
Prerequisites
bash

# Python 3.8 or higher

python3 --version

# MySQL 8.0 or higher

mysql --version

# pip package manager

pip3 --version
Setup Steps
Clone Repository
bash
git clone [your-repo-url]
cd securechat-skeleton
Install Dependencies
bash
pip install -r requirements.txt
Configure Database
bash

# Create .env file from template

cp .env.example .env

# Edit .env with your MySQL credentials

nano .env
Example .env:

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=securechat
Setup Database
bash
python scripts/setup_db.py
Generate PKI Certificates
bash

# Generate Root CA

python scripts/gen_ca.py

# Generate Server and Client Certificates

python scripts/gen_cert.py
🚀 Usage
Starting the Server
bash
python server.py
Expected output:

[*] Server initialized on 0.0.0.0:5555
[*] Server cert fingerprint: a1b2c3d4...
[✓] Server listening on 0.0.0.0:5555
Waiting for client connection...
Starting the Client
In a new terminal:

bash
python client.py
Registration Flow:

Choose: (1) Register (2) Login: 1
Email: user@example.com
Username: testuser
Password: **\*\*\*\***
Login Flow:

Choose: (1) Register (2) Login: 2
Email: user@example.com
Password: **\*\*\*\***
Chat Commands
Type any message and press Enter to send
Type /exit to end session and generate receipt
Ctrl+C to force quit
🧪 Testing
Run Security Tests
bash
python test_security.py
This runs automated tests for:

Certificate validation (valid, expired, self-signed)
Message tampering detection
Replay attack protection
AES encryption/decryption
Diffie-Hellman key exchange
Non-repudiation verification
Manual Testing Checklist
Test 1: Wireshark Capture
bash

# Start Wireshark on loopback interface

sudo wireshark

# Filter for SecureChat traffic

tcp.port == 5555

# Verify:

# - All message payloads are encrypted (base64, not plaintext)

# - No password visible in packets

# - Certificates transmitted but not private keys

Test 2: Invalid Certificate
bash

# Create self-signed certificate

openssl req -x509 -newkey rsa:2048 -keyout fake_key.pem \
 -out fake_cert.pem -days 365 -nodes

# Modify client to use fake cert

# Expected: Server rejects with "BAD_CERT"

Test 3: Tampering
bash

# Use Burp Suite or modify code to flip bits in ciphertext

# Expected: "SIG_FAIL" - signature verification fails

Test 4: Replay Attack
bash

# Capture a message packet and resend it

# Expected: "REPLAY" - sequence number check fails

Test 5: Non-Repudiation
bash

# Complete a chat session

# Check transcripts/ folder for:

# - client_transcript_YYYYMMDD_HHMMSS.txt

# - client_receipt_YYYYMMDD_HHMMSS.json

# - server_receipt_YYYYMMDD_HHMMSS.json

# Verify receipt:

python verify*receipt.py transcripts/client_receipt*_.json
📁 Project Structure
securechat-skeleton/
├── certs/ # PKI certificates (gitignored)
│ ├── ca*key.pem # Root CA private key
│ ├── ca_cert.pem # Root CA certificate
│ ├── server_key.pem # Server private key
│ ├── server_cert.pem # Server certificate
│ ├── client_key.pem # Client private key
│ └── client_cert.pem # Client certificate
├── scripts/
│ ├── gen_ca.py # CA generation script
│ ├── gen_cert.py # Certificate generation script
│ └── setup_db.py # Database setup script
├── transcripts/ # Session transcripts (gitignored)
│ ├── client_transcript*_.txt
│ ├── client*receipt*_.json
│ └── server*receipt*_.json
├── crypto_utils.py # Cryptographic functions
├── server.py # Secure chat server
├── client.py # Secure chat client
├── test_security.py # Security test suite
├── requirements.txt # Python dependencies
├── .env.example # Environment template
├── .gitignore # Git ignore rules
└── README.md # This file
🔐 Security Features
Certificate Validation
✅ Signature chain verification against Root CA
✅ Expiry date checking
✅ Common Name (CN) validation
✅ Rejection of self-signed/invalid certificates
Credential Security
✅ Per-user random salt (16 bytes)
✅ SHA-256 salted password hashing
✅ No plaintext passwords in storage or transit
✅ Constant-time comparison to prevent timing attacks
✅ Credentials transmitted only after certificate validation
Session Security
✅ Diffie-Hellman key agreement (2048-bit MODP group)
✅ AES-128 encryption with PKCS#7 padding
✅ Unique session keys per connection
✅ Forward separation between sessions
Message Integrity
✅ SHA-256 digest over (seqno || timestamp || ciphertext)
✅ RSA-PSS signatures with private keys
✅ Signature verification before decryption
✅ Strict sequence number enforcement
✅ Replay attack detection
Non-Repudiation
✅ Append-only session transcript
✅ Signed SessionReceipt with transcript hash
✅ Offline verifiability
✅ Certificate fingerprint in transcript
📊 Sample Input/Output
Server Console
[✓] Server listening on 0.0.0.0:5555
Waiting for client connection...

[*] New connection from ('127.0.0.1', 54321)
[*] Received client hello
[✓] Client certificate verified
Subject: CN=securechat-client,OU=SecureChat Client,O=FAST-NUCES
[✓] DH exchange complete
[*] Processing registration
[✓] User registered: alice (alice@example.com)
[✓] Session key established

[Client alice]: Hello from client!

[Server]: Message received!

[*] Generating session receipt...
[✓] Receipt generated and saved
Transcript hash: f4a3b2c1...
Client Console
[✓] Connected to server at localhost:5555
[✓] Server certificate verified
[✓] Temporary key established
Choose: (1) Register (2) Login: 1
Email: alice@example.com
Username: alice
Password: **\*\*\*\***
[✓] Registration successful!
[✓] Session key established

Secure chat session started!
Type messages to send. Use /exit to quit.
===============================================================

Hello from client!

[Server]: Message received!

/exit

[✓] Receipt generated and saved
Transcript hash: f4a3b2c1...
[*] Disconnected from server
🐛 Troubleshooting
Database Connection Error
[ERROR] Database connection failed: Access denied for user 'root'@'localhost'
Solution: Check your .env file credentials and MySQL service status.

Certificate Not Found
[ERROR] FileNotFoundError: certs/ca_cert.pem
Solution: Run python scripts/gen_ca.py and python scripts/gen_cert.py.

Port Already in Use
[ERROR] OSError: [Errno 48] Address already in use
Solution: Kill existing process on port 5555:

bash
lsof -ti:5555 | xargs kill -9
Module Not Found
ModuleNotFoundError: No module named 'cryptography'
Solution: Install dependencies:

bash
pip install -r requirements.txt
📚 References
Cryptography Library Documentation
SEED Security Labs - PKI
RFC 3526 - Diffie-Hellman Groups
NIST FIPS 197 - AES Standard
📝 License
This project is for educational purposes as part of FAST-NUCES Information Security coursework.

👤 Author
Rabab Alvi
Roll Number: 22i-1338
Email: rabab.alvi789@icloud.com
GitHub: Rabab-Alvi
