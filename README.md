# Secure Cloud File Sharing System using Hybrid Cryptography

A production-ready cybersecurity capstone project demonstrating real-world hybrid cryptographic security pipelines, file integrity assurance, authentic sharing workflows, rule-based threat monitoring, and performance evaluations.

---

## 📖 Project Overview & Description
The **Secure Cloud File Sharing System** is a secure file upload, hosting, and exchange platform. Traditional cloud storage providers often have access to raw user files. This project guarantees **zero-plaintext storage** in the cloud. Files are encrypted client-side/server-side using high-speed authenticated symmetric cryptography (**AES-256-GCM**). The corresponding file-specific encryption keys are wrapped using public-key cryptography (**RSA-2048-OAEP**), ensuring only authorized recipients can decrypt them. Authenticity is validated using digital signatures (**RSA-SHA256**), preventing untrusted uploads and catching tampered data before decryption starts.

### Problem Statement
Enterprise and personal cloud storage services are susceptible to server-side compromises, credential thefts, and unauthorized access. If an attacker breaches the cloud storage bucket or the database, they gain access to raw user files. There is a critical need for a cloud platform where:
1. Files are stored in an encrypted format.
2. Only authorized users can reconstruct the symmetric decryption key.
3. Cryptographic proof of origin (digital signatures) and integrity (hashes) are evaluated before the decryption sequence occurs.
4. Files can be shared outside the network (e.g., via WhatsApp) while preserving encryption and integrity.

### Objectives
- Eliminate permanent plaintext storage in the cloud database or local filesystem.
- Enforce rigid role-based access control (RBAC) separating Administrators from Members.
- Construct a secure external `.secure` package workflow for peer-to-peer distribution.
- Evaluate cryptographic overhead through real live benchmark metrics.
- Enforce security logging and threat scoring to detect dictionary logins, integrity violations, and suspicious download frequency.

---

## 🏗️ System Architecture & Workflow

```
[User Interface] (Responsive HTML5/CSS3/Vanilla JS)
       │ (HTTPS Requests with JWT)
       ▼
[Node.js / Express.js API Gateway]
       │
       ├─► [Auth & RBAC Middleware] (Validate Session / Token)
       │
       ├─► [Cryptographic Engine] (Node.js Crypto Module)
       │     ├─► AES-256-GCM Symmetric Cipher
       │     ├─► RSA-2048-OAEP Key Protection
       │     ├─► SHA-256 Integrity Verification
       │     └─► RSA-SHA256 Digital Signature
       │
       ├─► [MySQL Metadata Store] (Audit Logs, Performance, Shares, RBAC)
       │
       └─► [Amazon S3 Bucket] (Only Encrypted .enc Objects stored)
```

### The 4 Project Modules

#### Module 1: Secure File Encryption & Key Protection
Handles secure file selection, symmetric key generation (unique AES key per file), payload encryption (AES-256-GCM), key wrapping with the uploader's RSA-2048 public key, SHA-256 integrity hash calculation, RSA-SHA256 digital signing, and immediate S3 upload.

#### Module 2: File Integrity & Authenticity Verification
Triggers on decryption attempts or external package uploads. It recalculates the SHA-256 hash of the payload, comparing it to the stored integrity hash (detecting tampering). It verifies the RSA-SHA256 digital signature of the sender using their embedded public key. If either check fails, decryption is aborted.

#### Module 3: Secure File Sharing & Access Control
Enables file owners to authorize registered platform members. Permissions can be set as `PREVIEW ONLY` (view inline via secure blob frame, download disabled), `DOWNLOAD` (direct decrypt and pull original file), or `PREVIEW & DOWNLOAD`. Sharing entries can have expiration dates, and access can be revoked by the owner/admin at any time.

#### Module 4: Threat Monitoring & Security Performance
Captures all system events (login successes/failures, uploads, signature checks, revoked access attempts). Displays rule-based analytics indicating threat status (Healthy, Warning, Danger) and prints a live cryptographic benchmark evaluation tool to measure CPU execution speed for each hybrid crypto module.

---

## 🔐 Cryptographic Workflows

### A. File Upload & Encryption Pipeline (In-System)
1. Select file in browser.
2. Server generates a cryptographically secure 256-bit AES key and a 96-bit Initialization Vector (IV).
3. Payload is encrypted using **AES-256-GCM**, returning ciphertext and a 128-bit authentication tag.
4. Server generates a SHA-256 hash of the ciphertext.
5. Server wraps (encrypts) the AES key using the owner's RSA-2048 public key (OAEP padding).
6. Server signs the hash + filename payload using the owner's RSA-2048 private key (RSA-SHA256).
7. Ciphertext is streamed to S3 as an encrypted object; keys, signatures, and hashes are stored in MySQL.
8. Plaintext buffers are immediately garbage collected/deleted.

### B. External `.secure` Package Workflow
This workflow allows secure file transfer via messaging channels like WhatsApp or email:

```
[User A]
   │
   ├─► Encrypts "contract.pdf" setting passphrase "caps123"
   ├─► Downloads "contract.secure" package
   └─► Sends contract.secure via WhatsApp
                                           │
                                           ▼
                                    [User B (Friend)]
                                           │
                                           ├─► Opens Secure Cloud website
                                           ├─► Uploads contract.secure
                                           ├─► System verifies Signature & SHA-256
                                           ├─► Prompts for passphrase "caps123"
                                           ├─► Decrypts payload in-memory
                                           └─► Downloads contract.pdf
```

Inside the `.secure` package envelope (JSON formatted data):
```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "keyProtection": "PASSPHRASE-PBKDF2-SCRYPT",
  "originalFilename": "contract.pdf",
  "mimeType": "application/pdf",
  "iv": "hex_iv",
  "authTag": "hex_auth_tag",
  "saltHex": "hex_pbkdf2_salt",
  "wrappingIV": "hex_wrapping_iv",
  "wrappingAuthTag": "hex_wrapping_tag",
  "encryptedAesKeyHex": "aes_key_encrypted_with_passphrase_key",
  "sha256Hash": "ciphertext_sha256_hash",
  "signature": "rsa_signature_hex",
  "signerPublicKey": "owner_public_key_pem",
  "ciphertextBase64": "raw_encrypted_base64"
}
```

---

## 🗄️ Database Structure (MySQL)

We use exactly 7 relational tables with primary keys, indexes, and constraints.

1. **`users`**: Platform user accounts. Stores hashed credentials, roles (Admin/Member), and RSA public keys + encrypted private keys (wrapped using the application secret).
2. **`invitations`**: Invitations sent to new members by admins, carrying signup tokens.
3. **`files`**: Secure file metadata, storage keys, IVs, tags, hashes, and signatures.
4. **`file_keys`**: Wrapped symmetric key entries.
5. **`file_shares`**: Active sharing mappings, permission bounds, and expiry timestamps.
6. **`audit_logs`**: System security logs documenting event history, IP metadata, and outcomes.
7. **`performance_metrics`**: Chronological statistics mapping processing times.

---

## 🛠️ Local Installation & Setup

### Prerequisites
- Node.js (v18.0.0 or higher)
- MySQL Server (v8.0 or higher)
- AWS Account with an S3 Bucket (or compatible MinIO/LocalStack)

### 1. Database Configuration
Create a new schema in MySQL:
```sql
CREATE DATABASE secure_cloud_db;
```

### 2. Environment Setup
Copy `.env.example` to `.env` and fill out the values:
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=secure_cloud_db

AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-bucket-name

JWT_SECRET=use_a_long_random_jwt_key
APPLICATION_SECRET=use_a_long_app_secret_to_wrap_rsa_keys

PORT=5000
NODE_ENV=development
```

### 3. Install & Start Application
```bash
# Run npm install (bypassing execution policies if needed)
powershell -ExecutionPolicy Bypass -Command "npm install"

# Start the application
npm start
```
The system automatically connects to MySQL, applies DB migrations, and runs on `http://localhost:5000`.

---

## ☁️ Render Deployment Instructions

1. **Create Web Service**: Link your repository to Render.
2. **Setup Databases**: Provision a MySQL Database on Render.
3. **Attach render.yaml**: Use the provided `render.yaml` Blueprint to auto-configure services.
4. **Configure S3 Credentials**: Add S3 environment variables under the Web Service Environment tab on the Render Dashboard.

---

## 🧪 Testing

We use Jest to run extensive cryptographic test validations.

Run the test suite:
```bash
npm test
```
The suite evaluates AES ciphers, key wrapping, tampering rejection (modified payloads), signature verification, and wrong passphrase rejections.
