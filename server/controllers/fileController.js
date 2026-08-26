'use strict';
/**
 * File Controller
 * Module 1: Secure File Encryption & Key Protection
 * Handles: upload+encrypt, list files, download encrypted package, download decrypted original
 */

const { v4: uuidv4 } = require('uuid');
const path = require('path');

const db = require('../database/db');
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
    const userKeys = db.users.findOne({ id: req.user.id });
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

    // --- Step 6: Upload encrypted ciphertext to S3 or File Storage ---
    const fileId = uuidv4();
    const objectKey = `secure-files/${fileId}.enc`;

    const tUpStart = Date.now();
    const { size: encryptedSize } = await uploadEncryptedFile(objectKey, ciphertext);
    const uploadTimeMs = Date.now() - tUpStart;

    // --- Step 7: Store metadata in JSON DB ---
    db.files.insert({
      id: fileId,
      owner_id: req.user.id,
      original_filename: originalFilename,
      original_size: originalSize,
      encrypted_size: encryptedSize,
      mime_type: mimeType,
      storage_object_key: objectKey,
      encryption_algorithm: 'AES-256-GCM',
      key_protection_algorithm: 'RSA-2048-OAEP',
      iv_hex: iv.toString('hex'),
      auth_tag_hex: authTag.toString('hex'),
      sha256_hash: hash,
      signature_hex: signature,
      status: 'active'
    });

    db.access.insert({
      id: uuidv4(),
      file_id: fileId,
      encrypted_aes_key_hex: encryptedAesKey.toString('hex'),
      key_size: 256
    });

    const totalMs = Date.now() - startTotal;
    const overhead = ((encryptedSize - originalSize) / originalSize * 100).toFixed(2);

    // Record performance metrics
    db.performance.insert({
      id: uuidv4(),
      file_id: fileId,
      user_id: req.user.id,
      operation: 'ENCRYPT_UPLOAD',
      file_size: originalSize,
      encrypted_size: encryptedSize,
      encryption_time_ms: encryptionTimeMs,
      hashing_time_ms: hashingTimeMs,
      signature_gen_time_ms: sigGenTimeMs,
      upload_time_ms: uploadTimeMs,
      total_processing_time_ms: totalMs,
      storage_overhead_percent: parseFloat(overhead)
    });

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
  const files = db.files.find({ owner_id: req.user.id, status: 'active' }).map(f => {
    const shareCount = db.shares.find(s => s.file_id === f.id && s.status === 'active').length;
    return {
      id: f.id,
      original_filename: f.original_filename,
      original_size: f.original_size,
      encrypted_size: f.encrypted_size,
      mime_type: f.mime_type,
      encryption_algorithm: f.encryption_algorithm,
      key_protection_algorithm: f.key_protection_algorithm,
      sha256_hash: f.sha256_hash,
      status: f.status,
      created_at: f.created_at,
      share_count: shareCount
    };
  }).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

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
    const ownerKeys = db.users.findOne({ id: file.owner_id });
    if (!ownerKeys) {
      return res.status(500).json({ error: 'File owner keys not found' });
    }

    // Download encrypted ciphertext from S3/storage
    const tDownStart = Date.now();
    const ciphertext = await downloadEncryptedFile(file.storage_object_key);
    const downloadTimeMs = Date.now() - tDownStart;

    // Unwrap AES key using owner's private key
    const privateKey = decryptPrivateKeyFromStorage(ownerKeys.rsa_private_key_enc, file.owner_id);
    const fileKeyRow = db.access.findOne({ file_id: id });
    if (!fileKeyRow) {
      return res.status(500).json({ error: 'File AES key not found' });
    }
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

    // Download encrypted file from storage
    const ciphertext = await downloadEncryptedFile(file.storage_object_key);

    // Verify integrity
    const calculatedHash = sha256Hash(ciphertext);
    if (calculatedHash !== file.sha256_hash) {
      await logEvent({ userId: req.user.id, eventType: EventTypes.INTEGRITY_FAILED, fileId: id, ...meta, status: 'failure' });
      return res.status(409).json({ error: 'File integrity check failed. File may have been tampered.' });
    }
    await logEvent({ userId: req.user.id, eventType: EventTypes.INTEGRITY_VERIFIED, fileId: id, ...meta });

    // Verify signature
    const ownerKeys = db.users.findOne({ id: file.owner_id });
    if (!ownerKeys) {
      return res.status(500).json({ error: 'File owner keys not found' });
    }
    const signPayload = file.sha256_hash + ':' + file.original_filename;
    const sigOk = verifySignature(signPayload, file.signature_hex, ownerKeys.rsa_public_key);
    if (!sigOk) {
      await logEvent({ userId: req.user.id, eventType: EventTypes.SIGNATURE_FAILED, fileId: id, ...meta, status: 'failure' });
      return res.status(409).json({ error: 'Digital signature verification failed.' });
    }
    await logEvent({ userId: req.user.id, eventType: EventTypes.SIGNATURE_VERIFIED, fileId: id, ...meta });

    // Unwrap AES key using owner's private RSA key
    const privateKey = decryptPrivateKeyFromStorage(ownerKeys.rsa_private_key_enc, file.owner_id);
    const fileKeyRow = db.access.findOne({ file_id: id });
    if (!fileKeyRow) {
      return res.status(500).json({ error: 'File AES key not found' });
    }
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
    db.performance.insert({
      id: uuidv4(),
      file_id: id,
      user_id: req.user.id,
      operation: 'DECRYPT_DOWNLOAD',
      file_size: file.original_size,
      decryption_time_ms: decryptionTimeMs,
      total_processing_time_ms: decryptionTimeMs
    });

    res.setHeader('Content-Disposition', `attachment; filename="${file.original_filename}"`);
    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
    res.send(plaintext);
  } catch (err) {
    console.error('[FILE] Download original error:', err);
    if (err.message.includes('authentication failed') || err.message.includes('DECRYPTION_FAILED')) {
      await logEvent({ userId: req.user?.id, eventType: EventTypes.DECRYPTION_FAILED, fileId: req.params.id, ...meta, status: 'failure' });
      return res.status(400).json({ error: 'Decryption failed' });
    }
    res.status(500).json({ error: 'Failed to download file: ' + err.message });
  }
}

// ---------------------------------------------------------------------------
// Delete File
// ---------------------------------------------------------------------------

async function deleteFile(req, res) {
  const { id } = req.params;
  const file = db.files.findOne({ id, status: 'active' });
  if (!file) return res.status(404).json({ error: 'File not found' });
  if (file.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  // Soft delete
  db.files.update({ id }, { status: 'deleted' });

  // Delete from storage
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
  const owner = db.users.findOne({ id: file.owner_id });
  res.json({
    file: {
      ...file,
      owner: owner ? { full_name: owner.full_name, email: owner.email } : null
    }
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getAuthorizedFile(fileId, userId, requiredPermission) {
  // Owner has full access
  const ownedFile = db.files.findOne({ id: fileId, owner_id: userId, status: 'active' });
  if (ownedFile) return ownedFile;

  // Check sharing permissions
  const now = new Date();
  const share = db.shares.findOne(s => {
    return s.file_id === fileId &&
           s.shared_with === userId &&
           s.status === 'active' &&
           (!s.expires_at || new Date(s.expires_at) > now);
  });

  if (!share) return null;

  const file = db.files.findOne({ id: fileId, status: 'active' });
  if (!file) return null;

  // Check permission level
  if (requiredPermission === 'download') {
    if (!['download', 'preview_download'].includes(share.permission)) return null;
  }
  if (requiredPermission === 'preview') {
    if (!['preview', 'download', 'preview_download'].includes(share.permission)) return null;
  }

  return {
    ...file,
    share_id: share.id,
    permission: share.permission,
    expires_at: share.expires_at
  };
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
