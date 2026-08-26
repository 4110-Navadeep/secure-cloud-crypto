'use strict';
/**
 * Cryptographic Services
 * Real implementation using Node.js built-in crypto module.
 *
 * Algorithms:
 *  - AES-256-GCM  : Symmetric file encryption
 *  - RSA-2048-OAEP: AES key protection (wrapping)
 *  - SHA-256      : Integrity hashing
 *  - RSA-SHA256   : Digital signatures
 */

const crypto = require('crypto');
const config = require('../config/config');

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically secure 256-bit AES key.
 * @returns {Buffer}
 */
function generateAESKey() {
  return crypto.randomBytes(32); // 256 bits
}

/**
 * Generate a cryptographically secure 96-bit IV for AES-GCM.
 * @returns {Buffer}
 */
function generateIV() {
  return crypto.randomBytes(12); // 96 bits — recommended for GCM
}

/**
 * Encrypt a Buffer using AES-256-GCM.
 * @param {Buffer} plaintext
 * @param {Buffer} aesKey  - 32-byte key
 * @param {Buffer} iv      - 12-byte IV
 * @returns {{ ciphertext: Buffer, authTag: Buffer }}
 */
function aesEncrypt(plaintext, aesKey, iv) {
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes
  return { ciphertext, authTag };
}

/**
 * Decrypt a Buffer using AES-256-GCM.
 * @param {Buffer} ciphertext
 * @param {Buffer} aesKey
 * @param {Buffer} iv
 * @param {Buffer} authTag
 * @returns {Buffer} plaintext
 * @throws if authentication fails
 */
function aesDecrypt(ciphertext, aesKey, iv, authTag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);
  try {
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext;
  } catch (err) {
    throw new Error('AES-GCM authentication failed: data may be tampered or key is wrong');
  }
}

// ---------------------------------------------------------------------------
// RSA-2048 Key Pair
// ---------------------------------------------------------------------------

/**
 * Generate an RSA-2048 key pair.
 * @returns {{ publicKey: string, privateKey: string }} PEM strings
 */
function generateRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

// ---------------------------------------------------------------------------
// RSA-OAEP Key Wrapping / Unwrapping
// ---------------------------------------------------------------------------

/**
 * Wrap (encrypt) an AES key using RSA-OAEP-SHA256.
 * @param {Buffer} aesKey       - 32-byte AES key
 * @param {string} publicKeyPem - RSA public key PEM
 * @returns {Buffer} encrypted AES key
 */
function rsaWrapAESKey(aesKey, publicKeyPem) {
  return crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    aesKey
  );
}

/**
 * Unwrap (decrypt) an AES key using RSA-OAEP-SHA256.
 * @param {Buffer} encryptedAESKey - RSA-encrypted AES key
 * @param {string} privateKeyPem   - RSA private key PEM
 * @returns {Buffer} 32-byte AES key
 */
function rsaUnwrapAESKey(encryptedAESKey, privateKeyPem) {
  return crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    encryptedAESKey
  );
}

// ---------------------------------------------------------------------------
// RSA Private Key Storage Protection
// ---------------------------------------------------------------------------

/**
 * Encrypt an RSA private key PEM for safe database storage.
 * Uses AES-256-GCM with a key derived from the application secret + user id.
 * @param {string} privateKeyPem
 * @param {string} userId
 * @returns {string} hex-encoded JSON blob
 */
function encryptPrivateKeyForStorage(privateKeyPem, userId) {
  const appSecret = config.app.secret;
  if (!appSecret) throw new Error('APPLICATION_SECRET not configured');

  // Derive a 32-byte key from app secret + userId
  const derivedKey = crypto.scryptSync(
    appSecret + userId,
    'secure-cloud-salt-v1',
    32
  );
  const iv = crypto.randomBytes(12);
  const { ciphertext, authTag } = aesEncrypt(Buffer.from(privateKeyPem, 'utf8'), derivedKey, iv);

  const blob = {
    iv: iv.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
    authTag: authTag.toString('hex'),
  };
  return JSON.stringify(blob);
}

/**
 * Decrypt a stored RSA private key.
 * @param {string} storedBlob - JSON string from encryptPrivateKeyForStorage
 * @param {string} userId
 * @returns {string} PEM private key
 */
function decryptPrivateKeyFromStorage(storedBlob, userId) {
  const appSecret = config.app.secret;
  if (!appSecret) throw new Error('APPLICATION_SECRET not configured');

  const blob = JSON.parse(storedBlob);
  const derivedKey = crypto.scryptSync(
    appSecret + userId,
    'secure-cloud-salt-v1',
    32
  );
  const iv = Buffer.from(blob.iv, 'hex');
  const ciphertext = Buffer.from(blob.ciphertext, 'hex');
  const authTag = Buffer.from(blob.authTag, 'hex');

  const plaintext = aesDecrypt(ciphertext, derivedKey, iv, authTag);
  return plaintext.toString('utf8');
}

// ---------------------------------------------------------------------------
// SHA-256 Integrity Hashing
// ---------------------------------------------------------------------------

/**
 * Calculate SHA-256 hash of a Buffer.
 * @param {Buffer} data
 * @returns {string} hex string
 */
function sha256Hash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ---------------------------------------------------------------------------
// Digital Signatures (RSA-SHA256)
// ---------------------------------------------------------------------------

/**
 * Sign data with RSA-SHA256.
 * @param {Buffer|string} data
 * @param {string} privateKeyPem
 * @returns {string} hex-encoded signature
 */
function signData(data, privateKeyPem) {
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  sign.end();
  return sign.sign(privateKeyPem, 'hex');
}

/**
 * Verify an RSA-SHA256 signature.
 * @param {Buffer|string} data
 * @param {string} signatureHex
 * @param {string} publicKeyPem
 * @returns {boolean}
 */
function verifySignature(data, signatureHex, publicKeyPem) {
  try {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKeyPem, signatureHex, 'hex');
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Passphrase-Based Key Derivation (for .secure external packages)
// ---------------------------------------------------------------------------

/**
 * Derive a 32-byte AES key from a passphrase using PBKDF2.
 * @param {string} passphrase
 * @param {string} salt  - hex string (16 bytes)
 * @returns {Buffer} 32-byte key
 */
function deriveKeyFromPassphrase(passphrase, salt) {
  return crypto.pbkdf2Sync(passphrase, Buffer.from(salt, 'hex'), 310000, 32, 'sha256');
}

// ---------------------------------------------------------------------------
// .secure Package Creation & Parsing
// ---------------------------------------------------------------------------

/**
 * Create a .secure package Buffer containing all data needed for external decryption.
 *
 * Structure (JSON envelope + raw binary):
 * {
 *   version: 1,
 *   algorithm: 'AES-256-GCM',
 *   keyProtection: 'PASSPHRASE-PBKDF2',
 *   originalFilename: string,
 *   mimeType: string,
 *   iv: hex,
 *   authTag: hex,
 *   saltHex: hex,         // PBKDF2 salt for passphrase key
 *   encryptedAesKeyHex: hex,  // AES key wrapped with passphrase-derived key
 *   sha256Hash: hex,      // hash of ciphertext for integrity
 *   signature: hex,       // RSA-SHA256 signature over (sha256Hash + originalFilename)
 *   signerPublicKey: PEM, // embedded public key for verification
 *   ciphertextBase64: string  // the actual encrypted file data
 * }
 *
 * @param {object} params
 * @returns {Buffer}
 */
function createSecurePackage({
  ciphertext,
  iv,
  authTag,
  aesKey,
  passphrase,
  originalFilename,
  mimeType,
  signerPrivateKey,
  signerPublicKey,
}) {
  // Derive passphrase key and wrap AES key with it
  const salt = crypto.randomBytes(16);
  const passphraseKey = deriveKeyFromPassphrase(passphrase, salt.toString('hex'));
  const wrappingIV = crypto.randomBytes(12);
  const { ciphertext: encAesKey, authTag: wrappingAuthTag } = aesEncrypt(aesKey, passphraseKey, wrappingIV);

  // Integrity hash over ciphertext
  const hash = sha256Hash(ciphertext);

  // Sign: hash + filename
  const signPayload = hash + ':' + originalFilename;
  const signature = signData(signPayload, signerPrivateKey);

  const envelope = {
    version: 1,
    algorithm: 'AES-256-GCM',
    keyProtection: 'PASSPHRASE-PBKDF2-SCRYPT',
    originalFilename,
    mimeType: mimeType || 'application/octet-stream',
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    saltHex: salt.toString('hex'),
    wrappingIV: wrappingIV.toString('hex'),
    wrappingAuthTag: wrappingAuthTag.toString('hex'),
    encryptedAesKeyHex: encAesKey.toString('hex'),
    sha256Hash: hash,
    signature,
    signerPublicKey,
    ciphertextBase64: ciphertext.toString('base64'),
  };

  return Buffer.from(JSON.stringify(envelope), 'utf8');
}

/**
 * Parse and validate a .secure package Buffer.
 * @param {Buffer} packageBuffer
 * @returns {object} envelope
 * @throws if invalid JSON or missing fields
 */
function parseSecurePackage(packageBuffer) {
  let envelope;
  try {
    envelope = JSON.parse(packageBuffer.toString('utf8'));
  } catch {
    throw new Error('Invalid secure package: cannot parse');
  }

  const required = ['version', 'algorithm', 'originalFilename', 'iv', 'authTag',
    'saltHex', 'wrappingIV', 'wrappingAuthTag', 'encryptedAesKeyHex',
    'sha256Hash', 'signature', 'signerPublicKey', 'ciphertextBase64'];

  for (const field of required) {
    if (!envelope[field]) throw new Error(`Invalid secure package: missing field '${field}'`);
  }
  return envelope;
}

/**
 * Verify integrity and signature of a parsed .secure envelope.
 * @param {object} envelope - result of parseSecurePackage
 * @returns {{ integrityOk: boolean, signatureOk: boolean, ciphertext: Buffer }}
 */
function verifySecurePackage(envelope) {
  const ciphertext = Buffer.from(envelope.ciphertextBase64, 'base64');

  // Integrity check
  const calculatedHash = sha256Hash(ciphertext);
  const integrityOk = calculatedHash === envelope.sha256Hash;

  // Signature check
  const signPayload = envelope.sha256Hash + ':' + envelope.originalFilename;
  const signatureOk = verifySignature(signPayload, envelope.signature, envelope.signerPublicKey);

  return { integrityOk, signatureOk, ciphertext };
}

/**
 * Decrypt the contents of a verified .secure package using a passphrase.
 * @param {object} envelope
 * @param {string} passphrase
 * @returns {Buffer} original plaintext
 * @throws on wrong passphrase or decryption failure
 */
function decryptSecurePackage(envelope, passphrase) {
  const { ciphertext } = verifySecurePackage(envelope);

  // Derive passphrase key and unwrap AES key
  const passphraseKey = deriveKeyFromPassphrase(passphrase, envelope.saltHex);
  const wrappingIV = Buffer.from(envelope.wrappingIV, 'hex');
  const encAesKey = Buffer.from(envelope.encryptedAesKeyHex, 'hex');
  const wrappingAuthTag = Buffer.from(envelope.wrappingAuthTag, 'hex');

  let aesKey;
  try {
    aesKey = aesDecrypt(encAesKey, passphraseKey, wrappingIV, wrappingAuthTag);
  } catch {
    throw new Error('DECRYPTION_FAILED: wrong passphrase or corrupted package');
  }

  const iv = Buffer.from(envelope.iv, 'hex');
  const authTag = Buffer.from(envelope.authTag, 'hex');

  return aesDecrypt(ciphertext, aesKey, iv, authTag);
}

module.exports = {
  // AES
  generateAESKey,
  generateIV,
  aesEncrypt,
  aesDecrypt,
  // RSA
  generateRSAKeyPair,
  rsaWrapAESKey,
  rsaUnwrapAESKey,
  encryptPrivateKeyForStorage,
  decryptPrivateKeyFromStorage,
  // Hash
  sha256Hash,
  // Signatures
  signData,
  verifySignature,
  // Passphrase key derivation
  deriveKeyFromPassphrase,
  // .secure package
  createSecurePackage,
  parseSecurePackage,
  verifySecurePackage,
  decryptSecurePackage,
};
