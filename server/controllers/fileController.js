'use strict';
/**
 * File Controller
 * Module 1: Secure File Encryption & Key Protection
 * Handles: upload+encrypt, list files, download encrypted package, download decrypted original
 */

const { v4: uuidv4 } = require('uuid');
const path = require('path');

const { query, queryOne } = require('../database/db');
const {
  generateAESKey, generateIV, aesEncrypt, aesDecrypt,
  rsaWrapAESKey, rsaUnwrapAESKey,
  sha256Hash, signData, verifySignature,
  encryptPrivateKeyForStorage, decryptPrivateKeyFromStorage,
  createSecurePackage,
} = require('../crypto/cryptoService');
const { uploadEncryptedFile, downloadEncryptedFile } = require('../services/storageService');
const { logEvent, EventTypes, extractRequestMeta } = require('../services/auditService');

// ---------------------------------------------------------------------------
// Upload & Encrypt File (Module 1)
// ---------------------------------------------------------------------------

async function uploadAndEncrypt(req, res) {
  const meta = extractRequestMeta(req);
  const startTotal = Date.now();

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    const { passphrase } = req.body;
    if (!passphrase || passphrase.length < 6) {
      return res.status(400).json({ error: 'A passphrase of at least 6 characters is required for secure package creation' });
    }

    // Fetch uploader's RSA keys
    const userKeys = await queryOne(
      'SELECT rsa_public_key, rsa_private_key_enc FROM users WHERE id = ?',
      [req.user.id]
    );
    if (!userKeys?.rsa_public_key) {
      return res.status(500).json({ error: 'User RSA keys not found. Account may be corrupted.' });
    }
    const privateKey = decryptPrivateKeyFromStorage(userKeys.rsa_private_key_enc, req.user.id);

    const plaintext = req.file.buffer;
    const originalFilename = sanitizeFilename(req.file.originalname);
    const mimeType = req.file.mimetype;
    const originalSize = plaintext.length;

    // --- Step 1: Generate AES-256 key & IV ---
    const aesKey = generateAESKey();
    const iv = generateIV();

    // --- Step 2: Encrypt file with AES-256-GCM ---
    const tEncStart = Date.now();
    const { ciphertext, authTag } = aesEncrypt(plaintext, aesKey, iv);
    const encryptionTimeMs = Date.now() - tEncStart;

    // --- Step 3: Hash the ciphertext (SHA-256) ---
    const tHashStart = Date.now();
    const hash = sha256Hash(ciphertext);
    const hashingTimeMs = Date.now() - tHashStart;

    // --- Step 4: Wrap AES key with RSA-OAEP ---
    const encryptedAesKey = rsaWrapAESKey(aesKey, userKeys.rsa_public_key);

    // --- Step 5: Generate digital signature ---
    const tSigStart = Date.now();
    const signPayload = hash + ':' + originalFilename;
    const signature = signData(signPayload, privateKey);
    const sigGenTimeMs = Date.now() - tSigStart;

    // --- Step 6: Upload encrypted ciphertext to S3 ---
    const fileId = uuidv4();
    const objectKey = `secure-files/${fileId}.enc`;

    const tUpStart = Date.now();
    const { size: encryptedSize } = await uploadEncryptedFile(objectKey, ciphertext);
    const uploadTimeMs = Date.now() - tUpStart;

    // --- Step 7: Store metadata in MySQL ---
    await query(
      `INSERT INTO files (id, owner_id, original_filename, original_size, encrypted_size, mime_type,
        storage_object_key, encryption_algorithm, key_protection_algorithm,
        iv_hex, auth_tag_hex, sha256_hash, signature_hex)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'AES-256-GCM', 'RSA-2048-OAEP', ?, ?, ?, ?)`,
      [fileId, req.user.id, originalFilename, originalSize, encryptedSize, mimeType,
       objectKey, iv.toString('hex'), authTag.toString('hex'), hash, signature]
    );

    await query(
      `INSERT INTO file_keys (id, file_id, encrypted_aes_key_hex, key_size)
       VALUES (?, ?, ?, 256)`,
      [uuidv4(), fileId, encryptedAesKey.toString('hex')]
    );

    const totalMs = Date.now() - startTotal;
    const overhead = ((encryptedSize - originalSize) / originalSize * 100).toFixed(2);

    // Record performance metrics
    await query(
      `INSERT INTO performance_metrics
         (id, file_id, user_id, operation, file_size, encrypted_size,
          encryption_time_ms, hashing_time_ms, signature_gen_time_ms,
          upload_time_ms, total_processing_time_ms, storage_overhead_percent)
       VALUES (?, ?, ?, 'ENCRYPT_UPLOAD', ?, ?, ?, ?, ?, ?, ?, ?)`,
      [uuidv4(), fileId, req.user.id, originalSize, encryptedSize,
       encryptionTimeMs, hashingTimeMs, sigGenTimeMs, uploadTimeMs, totalMs, overhead]
    );

    await logEvent({ userId: req.user.id, eventType: EventTypes.FILE_UPLOAD, fileId, ...meta });
    await logEvent({ userId: req.user.id, eventType: EventTypes.FILE_ENCRYPTED, fileId, ...meta });

    res.status(201).json({
      message: 'File encrypted and uploaded successfully',
      file: {
        id: fileId,
        original_filename: originalFilename,
        original_size: originalSize,
        encrypted_size: encryptedSize,
        mime_type: mimeType,
        encryption_algorithm: 'AES-256-GCM',
        key_protection: 'RSA-2048-OAEP',
        sha256_hash: hash,
        signature_status: 'SIGNED',
        cloud_storage: objectKey,
        performance: {
          encryption_time_ms: encryptionTimeMs,
          hashing_time_ms: hashingTimeMs,
          signature_gen_time_ms: sigGenTimeMs,
          upload_time_ms: uploadTimeMs,
          total_processing_time_ms: totalMs,
          storage_overhead_percent: overhead,
        },
      },
    });
  } catch (err) {
    console.error('[FILE] Upload/encrypt error:', err);
    await logEvent({ userId: req.user?.id, eventType: EventTypes.FILE_UPLOAD, ...meta, status: 'failure', details: { error: err.message } });
    res.status(500).json({ error: 'File encryption failed: ' + err.message });
  }
}

// ---------------------------------------------------------------------------
// List My Files
// ---------------------------------------------------------------------------

async function listMyFiles(req, res) {
  const files = await query(
    `SELECT f.id, f.original_filename, f.original_size, f.encrypted_size, f.mime_type,
            f.encryption_algorithm, f.key_protection_algorithm, f.sha256_hash,
            f.status, f.created_at,
            (SELECT COUNT(*) FROM file_shares fs WHERE fs.file_id = f.id AND fs.status = 'active') AS share_count
     FROM files f
     WHERE f.owner_id = ? AND f.status = 'active'
     ORDER BY f.created_at DESC`,
    [req.user.id]
  );
  res.json({ files });
}

// ---------------------------------------------------------------------------
// Download .secure Package (for external sharing)
// ---------------------------------------------------------------------------

async function downloadSecurePackage(req, res) {
  const meta = extractRequestMeta(req);
  const tStart = Date.now();
  try {
    const { id } = req.params;
    const { passphrase } = req.query;

    if (!passphrase) {
      return res.status(400).json({ error: 'Passphrase required to create .secure package' });
    }

    // Check ownership or shared access
    const file = await getAuthorizedFile(id, req.user.id, 'download');
    if (!file) {
      await logEvent({ userId: req.user.id, eventType: EventTypes.ACCESS_DENIED, fileId: id, ...meta, status: 'failure' });
      return res.status(403).json({ error: 'Access denied or file not found' });
    }

    // Get the file owner's RSA keys for verification
    const ownerKeys = await queryOne(
      'SELECT rsa_public_key, rsa_private_key_enc FROM users WHERE id = ?',
      [file.owner_id]
    );

    // Download encrypted ciphertext from S3
    const tDownStart = Date.now();
    const ciphertext = await downloadEncryptedFile(file.storage_object_key);
    const downloadTimeMs = Date.now() - tDownStart;

    // Unwrap AES key using owner's private key
    const privateKey = decryptPrivateKeyFromStorage(ownerKeys.rsa_private_key_enc, file.owner_id);
    const fileKeyRow = await queryOne('SELECT encrypted_aes_key_hex FROM file_keys WHERE file_id = ?', [id]);
    const encryptedAesKey = Buffer.from(fileKeyRow.encrypted_aes_key_hex, 'hex');
    const aesKey = rsaUnwrapAESKey(encryptedAesKey, privateKey);

    // Build .secure package
    const secureBuffer = createSecurePackage({
      ciphertext,
      iv: Buffer.from(file.iv_hex, 'hex'),
      authTag: Buffer.from(file.auth_tag_hex, 'hex'),
      aesKey,
      passphrase,
      originalFilename: file.original_filename,
      mimeType: file.mime_type,
      signerPrivateKey: privateKey,
      signerPublicKey: ownerKeys.rsa_public_key,
    });

    const totalMs = Date.now() - tStart;
    await logEvent({ userId: req.user.id, eventType: EventTypes.FILE_DOWNLOAD, fileId: id, ...meta });

    const safeFilename = path.basename(file.original_filename, path.extname(file.original_filename));
    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}.secure"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(secureBuffer);
  } catch (err) {
    console.error('[FILE] Download .secure error:', err);
    res.status(500).json({ error: 'Failed to create secure package: ' + err.message });
  }
}

// ---------------------------------------------------------------------------
// Download Original File (authorized, after verification)
// ---------------------------------------------------------------------------

async function downloadOriginalFile(req, res) {
  const meta = extractRequestMeta(req);
  try {
    const { id } = req.params;

    const file = await getAuthorizedFile(id, req.user.id, 'download');
    if (!file) {
      await logEvent({ userId: req.user.id, eventType: EventTypes.ACCESS_DENIED, fileId: id, ...meta, status: 'failure' });
      return res.status(403).json({ error: 'Access denied or file not found' });
    }

    // Download encrypted file from S3
    const ciphertext = await downloadEncryptedFile(file.storage_object_key);

    // Verify integrity
    const calculatedHash = sha256Hash(ciphertext);
    if (calculatedHash !== file.sha256_hash) {
      await logEvent({ userId: req.user.id, eventType: EventTypes.INTEGRITY_FAILED, fileId: id, ...meta, status: 'failure' });
      return res.status(409).json({ error: 'File integrity check failed. File may have been tampered.' });
    }
    await logEvent({ userId: req.user.id, eventType: EventTypes.INTEGRITY_VERIFIED, fileId: id, ...meta });

    // Verify signature
    const ownerKeys = await queryOne('SELECT rsa_public_key FROM users WHERE id = ?', [file.owner_id]);
    const signPayload = file.sha256_hash + ':' + file.original_filename;
    const sigOk = verifySignature(signPayload, file.signature_hex, ownerKeys.rsa_public_key);
    if (!sigOk) {
      await logEvent({ userId: req.user.id, eventType: EventTypes.SIGNATURE_FAILED, fileId: id, ...meta, status: 'failure' });
      return res.status(409).json({ error: 'Digital signature verification failed.' });
    }
    await logEvent({ userId: req.user.id, eventType: EventTypes.SIGNATURE_VERIFIED, fileId: id, ...meta });

    // Unwrap AES key using owner's private RSA key
    const ownerFullKeys = await queryOne('SELECT rsa_private_key_enc FROM users WHERE id = ?', [file.owner_id]);
    const privateKey = decryptPrivateKeyFromStorage(ownerFullKeys.rsa_private_key_enc, file.owner_id);
    const fileKeyRow = await queryOne('SELECT encrypted_aes_key_hex FROM file_keys WHERE file_id = ?', [id]);
    const aesKey = rsaUnwrapAESKey(Buffer.from(fileKeyRow.encrypted_aes_key_hex, 'hex'), privateKey);

    // Decrypt
    const tDecStart = Date.now();
    const plaintext = aesDecrypt(
      ciphertext,
      aesKey,
      Buffer.from(file.iv_hex, 'hex'),
      Buffer.from(file.auth_tag_hex, 'hex')
    );
    const decryptionTimeMs = Date.now() - tDecStart;

    await logEvent({ userId: req.user.id, eventType: EventTypes.DECRYPTION_SUCCESS, fileId: id, ...meta });
    await logEvent({ userId: req.user.id, eventType: EventTypes.FILE_DOWNLOAD, fileId: id, ...meta });

    // Record performance
    await query(
      `INSERT INTO performance_metrics (id, file_id, user_id, operation, file_size, decryption_time_ms, total_processing_time_ms)
       VALUES (?, ?, ?, 'DECRYPT_DOWNLOAD', ?, ?, ?)`,
      [uuidv4(), id, req.user.id, file.original_size, decryptionTimeMs, decryptionTimeMs]
    );

    res.setHeader('Content-Disposition', `attachment; filename="${file.original_filename}"`);
    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
    res.send(plaintext);
  } catch (err) {
    console.error('[FILE] Download original error:', err);
    if (err.message.includes('authentication failed') || err.message.includes('DECRYPTION_FAILED')) {
      await logEvent({ userId: req.user?.id, eventType: EventTypes.DECRYPTION_FAILED, fileId: req.params.id, ...meta, status: 'failure' });
      return res.status(400).json({ error: 'Decryption failed' });
    }
    res.status(500).json({ error: 'Failed to download file' });
  }
}

// ---------------------------------------------------------------------------
// Delete File
// ---------------------------------------------------------------------------

async function deleteFile(req, res) {
  const { id } = req.params;
  const file = await queryOne(
    "SELECT id, owner_id, storage_object_key FROM files WHERE id = ? AND status = 'active'",
    [id]
  );
  if (!file) return res.status(404).json({ error: 'File not found' });
  if (file.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  // Soft delete
  await query("UPDATE files SET status = 'deleted' WHERE id = ?", [id]);
  // Optionally delete from S3 (background)
  const { deleteEncryptedFile } = require('../services/storageService');
  deleteEncryptedFile(file.storage_object_key).catch(console.error);

  await logEvent({ userId: req.user.id, eventType: EventTypes.FILE_DELETED, fileId: id });
  res.json({ message: 'File deleted successfully' });
}

// ---------------------------------------------------------------------------
// Get File Details
// ---------------------------------------------------------------------------

async function getFileDetails(req, res) {
  const { id } = req.params;
  const file = await getAuthorizedFile(id, req.user.id, 'preview');
  if (!file) return res.status(403).json({ error: 'File not found or access denied' });

  // Get owner info
  const owner = await queryOne('SELECT full_name, email FROM users WHERE id = ?', [file.owner_id]);
  res.json({ file: { ...file, owner } });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getAuthorizedFile(fileId, userId, requiredPermission) {
  // Owner has full access
  const ownedFile = await queryOne(
    "SELECT * FROM files WHERE id = ? AND owner_id = ? AND status = 'active'",
    [fileId, userId]
  );
  if (ownedFile) return ownedFile;

  // Check sharing permissions
  const now = new Date();
  const share = await queryOne(
    `SELECT fs.*, f.*, fs.id AS share_id
     FROM file_shares fs
     JOIN files f ON f.id = fs.file_id
     WHERE fs.file_id = ? AND fs.shared_with = ? AND fs.status = 'active'
       AND f.status = 'active'
       AND (fs.expires_at IS NULL OR fs.expires_at > ?)`,
    [fileId, userId, now]
  );

  if (!share) return null;

  // Check permission level
  if (requiredPermission === 'download') {
    if (!['download', 'preview_download'].includes(share.permission)) return null;
  }
  if (requiredPermission === 'preview') {
    if (!['preview', 'download', 'preview_download'].includes(share.permission)) return null;
  }

  return share;
}

function sanitizeFilename(filename) {
  return path.basename(filename).replace(/[^a-zA-Z0-9._\-\s]/g, '_');
}

module.exports = {
  uploadAndEncrypt,
  listMyFiles,
  downloadSecurePackage,
  downloadOriginalFile,
  deleteFile,
  getFileDetails,
  getAuthorizedFile,
};
