'use strict';
/**
 * Performance Controller
 * Provides real measured performance metrics
 */

const { query } = require('../database/db');
const {
  generateAESKey, generateIV, aesEncrypt, aesDecrypt,
  generateRSAKeyPair, rsaWrapAESKey, rsaUnwrapAESKey,
  sha256Hash, signData, verifySignature,
} = require('../crypto/cryptoService');

// ---------------------------------------------------------------------------
// Get stored performance metrics from DB
// ---------------------------------------------------------------------------

async function getMetrics(req, res) {
  const isAdmin = req.user.role === 'admin';

  const metrics = await query(
    `SELECT pm.*, f.original_filename, u.full_name
     FROM performance_metrics pm
     LEFT JOIN files f ON f.id = pm.file_id
     LEFT JOIN users u ON u.id = pm.user_id
     ${isAdmin ? '' : 'WHERE pm.user_id = ?'}
     ORDER BY pm.created_at DESC LIMIT 100`,
    isAdmin ? [] : [req.user.id]
  );

  // Averages
  const [avgs] = await query(
    `SELECT
       AVG(encryption_time_ms) AS avg_encryption_ms,
       AVG(decryption_time_ms) AS avg_decryption_ms,
       AVG(hashing_time_ms) AS avg_hashing_ms,
       AVG(signature_gen_time_ms) AS avg_sig_gen_ms,
       AVG(signature_ver_time_ms) AS avg_sig_ver_ms,
       AVG(upload_time_ms) AS avg_upload_ms,
       AVG(download_time_ms) AS avg_download_ms,
       AVG(total_processing_time_ms) AS avg_total_ms,
       AVG(storage_overhead_percent) AS avg_overhead_pct
     FROM performance_metrics
     ${isAdmin ? '' : 'WHERE user_id = ?'}`,
    isAdmin ? [] : [req.user.id]
  );

  res.json({ metrics, averages: avgs });
}

// ---------------------------------------------------------------------------
// Run a live performance benchmark with a test payload
// ---------------------------------------------------------------------------

async function runBenchmark(req, res) {
  const { size_kb = 100 } = req.query; // default 100 KB test
  const sizeBytes = Math.min(parseInt(size_kb) * 1024, 50 * 1024 * 1024); // max 50MB

  // Generate test data
  const testData = require('crypto').randomBytes(sizeBytes);
  const results = {};

  // --- AES Key Generation ---
  const t0 = Date.now();
  const aesKey = generateAESKey();
  const iv = generateIV();
  results.key_generation_ms = Date.now() - t0;

  // --- AES-256-GCM Encryption ---
  const t1 = Date.now();
  const { ciphertext, authTag } = aesEncrypt(testData, aesKey, iv);
  results.encryption_time_ms = Date.now() - t1;

  // --- SHA-256 Hashing ---
  const t2 = Date.now();
  const hash = sha256Hash(ciphertext);
  results.hashing_time_ms = Date.now() - t2;

  // --- RSA Key Pair Generation ---
  const t3 = Date.now();
  const { publicKey, privateKey } = generateRSAKeyPair();
  results.rsa_keygen_ms = Date.now() - t3;

  // --- RSA-OAEP Key Wrapping ---
  const t4 = Date.now();
  const wrappedKey = rsaWrapAESKey(aesKey, publicKey);
  results.rsa_wrap_ms = Date.now() - t4;

  // --- Digital Signature Generation ---
  const t5 = Date.now();
  const signature = signData(hash, privateKey);
  results.signature_gen_time_ms = Date.now() - t5;

  // --- Digital Signature Verification ---
  const t6 = Date.now();
  const sigOk = verifySignature(hash, signature, publicKey);
  results.signature_ver_time_ms = Date.now() - t6;

  // --- RSA-OAEP Key Unwrapping ---
  const t7 = Date.now();
  const unwrappedKey = rsaUnwrapAESKey(wrappedKey, privateKey);
  results.rsa_unwrap_ms = Date.now() - t7;

  // --- AES-256-GCM Decryption ---
  const t8 = Date.now();
  const decrypted = aesDecrypt(ciphertext, unwrappedKey, iv, authTag);
  results.decryption_time_ms = Date.now() - t8;

  const totalMs = Object.values(results).reduce((a, b) => a + b, 0);
  const overhead = ((ciphertext.length - testData.length) / testData.length * 100).toFixed(4);

  res.json({
    benchmark: {
      input_size_bytes: sizeBytes,
      input_size_kb: (sizeBytes / 1024).toFixed(2),
      encrypted_size_bytes: ciphertext.length,
      storage_overhead_percent: overhead,
      signature_valid: sigOk,
      timing: results,
      total_crypto_time_ms: totalMs,
    },
  });
}

// ---------------------------------------------------------------------------
// Key Management Info (safe metadata only)
// ---------------------------------------------------------------------------

async function getKeyInfo(req, res) {
  const user = await require('../database/db').queryOne(
    'SELECT rsa_public_key, created_at FROM users WHERE id = ?',
    [req.user.id]
  );

  const keyInfo = {
    rsa: {
      algorithm: 'RSA-2048-OAEP',
      hash: 'SHA-256',
      key_size_bits: 2048,
      public_key_preview: user.rsa_public_key
        ? user.rsa_public_key.substring(0, 80) + '...'
        : 'Not generated',
      generated_at: user.created_at,
    },
    aes: {
      algorithm: 'AES-256-GCM',
      key_length_bits: 256,
      iv_length_bits: 96,
      auth_tag_length_bits: 128,
      note: 'Unique key generated per file. Never stored in plaintext.',
    },
    hashing: {
      algorithm: 'SHA-256',
      output_length_bits: 256,
    },
    signature: {
      algorithm: 'RSA-SHA256',
      padding: 'PKCS#1 v1.5',
    },
    pbkdf2: {
      algorithm: 'PBKDF2-SHA256',
      iterations: 310000,
      purpose: 'External .secure package passphrase key derivation',
    },
  };

  res.json({ key_info: keyInfo });
}

module.exports = { getMetrics, runBenchmark, getKeyInfo };
