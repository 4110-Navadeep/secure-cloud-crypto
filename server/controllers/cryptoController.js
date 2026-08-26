'use strict';
/**
 * Crypto Controller — Stateless Encrypt / Decrypt
 *
 * ENCRYPT:
 *   Input:  file (any type, ≤100 MB) + passphrase + optional signatureEnabled flag
 *   Output: .secure package (JSON envelope containing all crypto material)
 *
 * DECRYPT:
 *   Input:  .secure package + passphrase
 *   Output: original file binary
 *
 * Nothing is stored on the server. Every operation is in-memory.
 */

const path = require('path');
const {
  generateAESKey, generateIV, aesEncrypt, aesDecrypt,
  generateRSAKeyPair, rsaWrapAESKey, rsaUnwrapAESKey,
  sha256Hash, signData, verifySignature,
  deriveKeyFromPassphrase,
  createSecurePackage, parseSecurePackage, verifySecurePackage, decryptSecurePackage,
} = require('../crypto/cryptoService');

// ---------------------------------------------------------------------------
// POST /api/crypto/encrypt
// ---------------------------------------------------------------------------
async function encrypt(req, res) {
  const tStart = Date.now();

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    const { passphrase, signatureEnabled } = req.body;

    if (!passphrase || passphrase.length < 6) {
      return res.status(400).json({ error: 'Passphrase must be at least 6 characters' });
    }

    const enableSignature = signatureEnabled !== 'false' && signatureEnabled !== false;

    const plaintext = req.file.buffer;
    const originalFilename = sanitizeFilename(req.file.originalname);
    const mimeType = req.file.mimetype || 'application/octet-stream';
    const originalSize = plaintext.length;

    // --- Step 1: Generate ephemeral RSA key pair (for this operation only) ---
    const tRsaStart = Date.now();
    const { publicKey, privateKey } = generateRSAKeyPair();
    const rsaGenTimeMs = Date.now() - tRsaStart;

    // --- Step 2: Generate AES-256-GCM key & IV ---
    const aesKey = generateAESKey();
    const iv = generateIV();

    // --- Step 3: Encrypt file with AES-256-GCM ---
    const tEncStart = Date.now();
    const { ciphertext, authTag } = aesEncrypt(plaintext, aesKey, iv);
    const encryptionTimeMs = Date.now() - tEncStart;

    // --- Step 4: Wrap AES key with RSA-OAEP (key protection) ---
    const tRsaWrapStart = Date.now();
    const wrappedAesKey = rsaWrapAESKey(aesKey, publicKey);
    const rsaWrapTimeMs = Date.now() - tRsaWrapStart;

    // --- Step 5: Compute SHA-256 integrity hash ---
    const tHashStart = Date.now();
    const hash = sha256Hash(ciphertext);
    const hashingTimeMs = Date.now() - tHashStart;

    // --- Step 6: Digital signature (RSA-SHA256 over hash:filename) ---
    let signature = null;
    let sigGenTimeMs = 0;
    if (enableSignature) {
      const tSigStart = Date.now();
      const signPayload = hash + ':' + originalFilename;
      signature = signData(signPayload, privateKey);
      sigGenTimeMs = Date.now() - tSigStart;
    }

    // --- Step 7: Build .secure package ---
    // Wrap AES key with passphrase instead of raw RSA private key embedding
    const crypto = require('crypto');
    const salt = crypto.randomBytes(16);
    const passphraseKey = deriveKeyFromPassphrase(passphrase, salt.toString('hex'));
    const wrappingIV = crypto.randomBytes(12);
    const { ciphertext: encAesKey, authTag: wrappingAuthTag } = aesEncrypt(aesKey, passphraseKey, wrappingIV);

    const envelope = {
      version: 2,
      algorithm: 'AES-256-GCM',
      keyProtection: 'PASSPHRASE-PBKDF2-310000',
      originalFilename,
      mimeType,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      saltHex: salt.toString('hex'),
      wrappingIV: wrappingIV.toString('hex'),
      wrappingAuthTag: wrappingAuthTag.toString('hex'),
      encryptedAesKeyHex: encAesKey.toString('hex'),
      sha256Hash: hash,
      signatureEnabled: enableSignature,
      signature: signature || null,
      signerPublicKey: enableSignature ? publicKey : null,
      // Embed RSA-wrapped AES key for educational display purposes
      rsaWrappedAesKeyHex: wrappedAesKey.toString('hex'),
      // Ciphertext embedded in package
      ciphertextBase64: ciphertext.toString('base64'),
      // Metadata
      originalSize,
      encryptedSize: ciphertext.length,
      createdAt: new Date().toISOString(),
      performance: {
        rsaKeyGenTimeMs: rsaGenTimeMs,
        encryptionTimeMs,
        rsaWrapTimeMs,
        hashingTimeMs,
        sigGenTimeMs,
        totalTimeMs: Date.now() - tStart,
        storageOverheadPercent: parseFloat(((ciphertext.length - originalSize) / originalSize * 100).toFixed(2)),
      },
    };

    const packageBuffer = Buffer.from(JSON.stringify(envelope, null, 0), 'utf8');
    const safeBasename = path.basename(originalFilename, path.extname(originalFilename));

    res.setHeader('Content-Disposition', `attachment; filename="${safeBasename}.secure"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Original-Filename', originalFilename);
    res.setHeader('X-Original-Size', originalSize.toString());
    res.setHeader('X-Encrypted-Size', ciphertext.length.toString());
    res.setHeader('X-SHA256-Hash', hash);
    res.setHeader('X-Encryption-Time-Ms', encryptionTimeMs.toString());
    res.setHeader('X-Total-Time-Ms', (Date.now() - tStart).toString());
    res.setHeader('X-Signature-Status', enableSignature ? 'SIGNED' : 'UNSIGNED');
    res.send(packageBuffer);

  } catch (err) {
    console.error('[CRYPTO] Encrypt error:', err);
    res.status(500).json({ error: 'Encryption failed: ' + err.message });
  }
}

// ---------------------------------------------------------------------------
// POST /api/crypto/decrypt
// ---------------------------------------------------------------------------
async function decrypt(req, res) {
  const tStart = Date.now();

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No .secure package provided' });
    }

    const { passphrase } = req.body;
    if (!passphrase) {
      return res.status(400).json({ error: 'Passphrase is required' });
    }

    const packageBuffer = req.file.buffer;

    // --- Step 1: Parse the .secure envelope ---
    let envelope;
    try {
      envelope = JSON.parse(packageBuffer.toString('utf8'));
    } catch (e) {
      return res.status(400).json({
        error: 'INVALID_PACKAGE',
        message: 'This file is not a valid .secure package. Cannot parse structure.',
      });
    }

    // Validate required fields
    const required = ['version', 'algorithm', 'originalFilename', 'iv', 'authTag',
      'saltHex', 'wrappingIV', 'wrappingAuthTag', 'encryptedAesKeyHex',
      'sha256Hash', 'ciphertextBase64'];
    for (const field of required) {
      if (!envelope[field]) {
        return res.status(400).json({
          error: 'INVALID_PACKAGE',
          message: `Invalid secure package: missing required field '${field}'`,
        });
      }
    }

    const ciphertext = Buffer.from(envelope.ciphertextBase64, 'base64');

    // --- Step 2: Integrity verification (SHA-256) ---
    const tHashStart = Date.now();
    const calculatedHash = sha256Hash(ciphertext);
    const hashingTimeMs = Date.now() - tHashStart;
    const integrityOk = calculatedHash === envelope.sha256Hash;

    if (!integrityOk) {
      return res.status(409).json({
        error: 'INTEGRITY_FAILED',
        message: 'FILE INTEGRITY CHECK FAILED — The package has been tampered with or corrupted.',
        integrityOk: false,
        signatureOk: null,
        calculatedHash,
        expectedHash: envelope.sha256Hash,
      });
    }

    // --- Step 3: Digital signature verification (if signed) ---
    let signatureOk = null;
    let sigVerifyTimeMs = 0;
    if (envelope.signatureEnabled && envelope.signature && envelope.signerPublicKey) {
      const tSigStart = Date.now();
      const signPayload = envelope.sha256Hash + ':' + envelope.originalFilename;
      signatureOk = verifySignature(signPayload, envelope.signature, envelope.signerPublicKey);
      sigVerifyTimeMs = Date.now() - tSigStart;

      if (!signatureOk) {
        return res.status(409).json({
          error: 'SIGNATURE_INVALID',
          message: 'DIGITAL SIGNATURE INVALID — Package authenticity cannot be verified.',
          integrityOk: true,
          signatureOk: false,
        });
      }
    }

    // --- Step 4: Derive passphrase key and unwrap AES key ---
    const tDecStart = Date.now();
    const passphraseKey = deriveKeyFromPassphrase(passphrase, envelope.saltHex);
    const wrappingIV = Buffer.from(envelope.wrappingIV, 'hex');
    const encAesKey = Buffer.from(envelope.encryptedAesKeyHex, 'hex');
    const wrappingAuthTag = Buffer.from(envelope.wrappingAuthTag, 'hex');

    let aesKey;
    try {
      aesKey = aesDecrypt(encAesKey, passphraseKey, wrappingIV, wrappingAuthTag);
    } catch {
      return res.status(400).json({
        error: 'DECRYPTION_FAILED',
        message: 'Decryption failed. The passphrase is incorrect or the package is corrupted.',
        integrityOk: true,
        signatureOk,
      });
    }

    // --- Step 5: Decrypt the file ---
    const iv = Buffer.from(envelope.iv, 'hex');
    const authTag = Buffer.from(envelope.authTag, 'hex');
    let plaintext;
    try {
      plaintext = aesDecrypt(ciphertext, aesKey, iv, authTag);
    } catch {
      return res.status(400).json({
        error: 'DECRYPTION_FAILED',
        message: 'File decryption failed. The package may be corrupted.',
      });
    }
    const decryptionTimeMs = Date.now() - tDecStart;
    const totalTimeMs = Date.now() - tStart;

    // Stream back the original file
    res.setHeader('Content-Disposition', `attachment; filename="${envelope.originalFilename}"`);
    res.setHeader('Content-Type', envelope.mimeType || 'application/octet-stream');
    res.setHeader('X-Original-Filename', envelope.originalFilename);
    res.setHeader('X-Integrity-OK', 'true');
    res.setHeader('X-Signature-OK', signatureOk === null ? 'N/A' : String(signatureOk));
    res.setHeader('X-Decryption-Time-Ms', decryptionTimeMs.toString());
    res.setHeader('X-Total-Time-Ms', totalTimeMs.toString());
    res.setHeader('X-Hashing-Time-Ms', hashingTimeMs.toString());
    res.setHeader('Access-Control-Expose-Headers',
      'X-Original-Filename, X-Integrity-OK, X-Signature-OK, X-Decryption-Time-Ms, X-Total-Time-Ms, X-Hashing-Time-Ms');
    res.send(plaintext);

  } catch (err) {
    console.error('[CRYPTO] Decrypt error:', err);
    res.status(500).json({ error: 'Decryption failed: ' + err.message });
  }
}

function sanitizeFilename(filename) {
  return path.basename(filename).replace(/[^a-zA-Z0-9._\-\s]/g, '_');
}

module.exports = { encrypt, decrypt };
