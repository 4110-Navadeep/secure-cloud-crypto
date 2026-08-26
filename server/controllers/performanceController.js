'use strict';
/**
 * Performance Controller
 * Provides real measured performance metrics
 */

const db = require('../database/db');
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

  let list = db.performance.find();
  if (!isAdmin) {
    list = list.filter(pm => pm.user_id === req.user.id);
  }

  const enriched = list.map(pm => {
    const file = pm.file_id ? db.files.findOne({ id: pm.file_id }) : null;
    const user = pm.user_id ? db.users.findOne({ id: pm.user_id }) : null;
    return {
      ...pm,
      original_filename: file ? file.original_filename : null,
      full_name: user ? user.full_name : 'Guest'
    };
  }).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 100);

  // Compute averages
  let sumEnc = 0, countEnc = 0;
  let sumDec = 0, countDec = 0;
  let sumHash = 0, countHash = 0;
  let sumSigGen = 0, countSigGen = 0;
  let sumSigVer = 0, countSigVer = 0;
  let sumUp = 0, countUp = 0;
  let sumDown = 0, countDown = 0;
  let sumTotal = 0, countTotal = 0;
  let sumOverhead = 0, countOverhead = 0;

  list.forEach(pm => {
    if (pm.encryption_time_ms !== null && pm.encryption_time_ms !== undefined) { sumEnc += pm.encryption_time_ms; countEnc++; }
    if (pm.decryption_time_ms !== null && pm.decryption_time_ms !== undefined) { sumDec += pm.decryption_time_ms; countDec++; }
    if (pm.hashing_time_ms !== null && pm.hashing_time_ms !== undefined) { sumHash += pm.hashing_time_ms; countHash++; }
    if (pm.signature_gen_time_ms !== null && pm.signature_gen_time_ms !== undefined) { sumSigGen += pm.signature_gen_time_ms; countSigGen++; }
    if (pm.signature_ver_time_ms !== null && pm.signature_ver_time_ms !== undefined) { sumSigVer += pm.signature_ver_time_ms; countSigVer++; }
    if (pm.upload_time_ms !== null && pm.upload_time_ms !== undefined) { sumUp += pm.upload_time_ms; countUp++; }
    if (pm.download_time_ms !== null && pm.download_time_ms !== undefined) { sumDown += pm.download_time_ms; countDown++; }
    if (pm.total_processing_time_ms !== null && pm.total_processing_time_ms !== undefined) { sumTotal += pm.total_processing_time_ms; countTotal++; }
    if (pm.storage_overhead_percent !== null && pm.storage_overhead_percent !== undefined) { sumOverhead += pm.storage_overhead_percent; countOverhead++; }
  });

  const avgs = {
    avg_encryption_ms: countEnc > 0 ? sumEnc / countEnc : null,
    avg_decryption_ms: countDec > 0 ? sumDec / countDec : null,
    avg_hashing_ms: countHash > 0 ? sumHash / countHash : null,
    avg_sig_gen_ms: countSigGen > 0 ? sumSigGen / countSigGen : null,
    avg_sig_ver_ms: countSigVer > 0 ? sumSigVer / countSigVer : null,
    avg_upload_ms: countUp > 0 ? sumUp / countUp : null,
    avg_download_ms: countDown > 0 ? sumDown / countDown : null,
    avg_total_ms: countTotal > 0 ? sumTotal / countTotal : null,
    avg_overhead_pct: countOverhead > 0 ? sumOverhead / countOverhead : null,
  };

  res.json({ metrics: enriched, averages: avgs });
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
  const user = db.users.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'User not found' });

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
