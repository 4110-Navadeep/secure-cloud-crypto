'use strict';
const { getPool } = require('./db');

const SCHEMA_SQL = `
-- Users table
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
  full_name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin','member') NOT NULL DEFAULT 'member',
  status ENUM('active','inactive','pending') NOT NULL DEFAULT 'active',
  rsa_public_key TEXT,
  rsa_private_key_enc TEXT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Invitations table
CREATE TABLE IF NOT EXISTS invitations (
  id VARCHAR(36) PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  role ENUM('admin','member') NOT NULL DEFAULT 'member',
  token VARCHAR(255) NOT NULL UNIQUE,
  status ENUM('pending','accepted','expired') NOT NULL DEFAULT 'pending',
  invited_by VARCHAR(36) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_token (token),
  INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Files table
CREATE TABLE IF NOT EXISTS files (
  id VARCHAR(36) PRIMARY KEY,
  owner_id VARCHAR(36) NOT NULL,
  original_filename VARCHAR(500) NOT NULL,
  original_size BIGINT NOT NULL,
  encrypted_size BIGINT,
  mime_type VARCHAR(255),
  storage_object_key VARCHAR(500) NOT NULL,
  encryption_algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
  key_protection_algorithm VARCHAR(50) NOT NULL DEFAULT 'RSA-2048-OAEP',
  iv_hex VARCHAR(64) NOT NULL,
  auth_tag_hex VARCHAR(64) NOT NULL,
  sha256_hash VARCHAR(64) NOT NULL,
  signature_hex TEXT NOT NULL,
  status ENUM('active','deleted') NOT NULL DEFAULT 'active',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_owner (owner_id),
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- File keys table (RSA-wrapped AES keys)
CREATE TABLE IF NOT EXISTS file_keys (
  id VARCHAR(36) PRIMARY KEY,
  file_id VARCHAR(36) NOT NULL UNIQUE,
  encrypted_aes_key_hex TEXT NOT NULL,
  key_size INT NOT NULL DEFAULT 256,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- File shares table
CREATE TABLE IF NOT EXISTS file_shares (
  id VARCHAR(36) PRIMARY KEY,
  file_id VARCHAR(36) NOT NULL,
  shared_by VARCHAR(36) NOT NULL,
  shared_with VARCHAR(36) NOT NULL,
  permission ENUM('preview','download','preview_download') NOT NULL DEFAULT 'preview',
  expires_at DATETIME,
  status ENUM('active','revoked','expired') NOT NULL DEFAULT 'active',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
  FOREIGN KEY (shared_by) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (shared_with) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_file (file_id),
  INDEX idx_shared_with (shared_with),
  INDEX idx_shared_by (shared_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36),
  event_type VARCHAR(100) NOT NULL,
  file_id VARCHAR(36),
  ip_address VARCHAR(45),
  user_agent VARCHAR(500),
  details JSON,
  status ENUM('success','failure','warning') NOT NULL DEFAULT 'success',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id),
  INDEX idx_event (event_type),
  INDEX idx_created (created_at),
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Performance metrics table
CREATE TABLE IF NOT EXISTS performance_metrics (
  id VARCHAR(36) PRIMARY KEY,
  file_id VARCHAR(36),
  user_id VARCHAR(36),
  operation VARCHAR(100) NOT NULL,
  file_size BIGINT,
  encrypted_size BIGINT,
  encryption_time_ms INT,
  decryption_time_ms INT,
  hashing_time_ms INT,
  signature_gen_time_ms INT,
  signature_ver_time_ms INT,
  upload_time_ms INT,
  download_time_ms INT,
  total_processing_time_ms INT,
  storage_overhead_percent DECIMAL(10,2),
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_file (file_id),
  INDEX idx_user (user_id),
  INDEX idx_operation (operation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

async function runMigrations() {
  const pool = getPool();
  const statements = SCHEMA_SQL
    .split(';')
    .map(s => s.trim())
    .filter(s => s.length > 0 && s.toUpperCase().startsWith('CREATE'));

  for (const stmt of statements) {
    await pool.execute(stmt);
  }
  console.log('[DB] Schema migrations applied successfully.');
}

module.exports = { runMigrations };
