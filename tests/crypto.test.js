'use strict';
process.env.APPLICATION_SECRET = 'super-secret-key-for-testing-only-12345';

const crypto = require('crypto');
const {
  generateAESKey,
  generateIV,
  aesEncrypt,
  aesDecrypt,
  generateRSAKeyPair,
  rsaWrapAESKey,
  rsaUnwrapAESKey,
  encryptPrivateKeyForStorage,
  decryptPrivateKeyFromStorage,
  sha256Hash,
  signData,
  verifySignature,
  createSecurePackage,
  parseSecurePackage,
  verifySecurePackage,
  decryptSecurePackage,
} = require('../server/crypto/cryptoService');


describe('Cryptographic Operations & Workflows', () => {
  let aesKey, iv, plaintext, rsaKeys;

  beforeAll(() => {
    // Set up mock APPLICATION_SECRET for private key storage tests
    process.env.APPLICATION_SECRET = 'super-secret-key-for-testing-only-12345';
    
    plaintext = Buffer.from('This is a test document payload for hybrid cryptography capstone.', 'utf8');
    aesKey = generateAESKey();
    iv = generateIV();
    rsaKeys = generateRSAKeyPair();
  });

  test('AES-256-GCM symmetric encryption and decryption', () => {
    const { ciphertext, authTag } = aesEncrypt(plaintext, aesKey, iv);
    expect(ciphertext).toBeDefined();
    expect(authTag).toBeDefined();
    expect(ciphertext.length).toBeGreaterThan(0);

    const decrypted = aesDecrypt(ciphertext, aesKey, iv, authTag);
    expect(decrypted.toString('utf8')).toBe(plaintext.toString('utf8'));
  });

  test('AES-256-GCM authentication failure on modification', () => {
    const { ciphertext, authTag } = aesEncrypt(plaintext, aesKey, iv);
    
    // Modify ciphertext (simulate tampering)
    ciphertext[0] ^= 0xFF;

    expect(() => {
      aesDecrypt(ciphertext, aesKey, iv, authTag);
    }).toThrow(/authentication failed/i);
  });

  test('RSA-2048 key pair generation', () => {
    expect(rsaKeys.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
    expect(rsaKeys.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
  });

  test('RSA-2048-OAEP AES key wrapping and unwrapping', () => {
    const wrapped = rsaWrapAESKey(aesKey, rsaKeys.publicKey);
    expect(wrapped).toBeDefined();
    expect(wrapped.length).toBe(256); // 2048-bit key wrap length

    const unwrapped = rsaUnwrapAESKey(wrapped, rsaKeys.privateKey);
    expect(unwrapped.toString('hex')).toBe(aesKey.toString('hex'));
  });

  test('RSA private key storage encryption/decryption', () => {
    const userId = 'user-test-uuid-999';
    const encryptedBlob = encryptPrivateKeyForStorage(rsaKeys.privateKey, userId);
    expect(encryptedBlob).toContain('ciphertext');
    expect(encryptedBlob).toContain('iv');

    const decryptedPem = decryptPrivateKeyFromStorage(encryptedBlob, userId);
    expect(decryptedPem).toBe(rsaKeys.privateKey);
  });

  test('SHA-256 integrity hashing', () => {
    const hash = sha256Hash(plaintext);
    expect(hash).toHaveLength(64); // 64 hex characters (32 bytes)
    
    const secondHash = sha256Hash(plaintext);
    expect(secondHash).toBe(hash);

    const modifiedHash = sha256Hash(Buffer.from('modified', 'utf8'));
    expect(modifiedHash).not.toBe(hash);
  });

  test('RSA-SHA256 Digital Signature generation and verification', () => {
    const hash = sha256Hash(plaintext);
    const signature = signData(hash, rsaKeys.privateKey);
    expect(signature).toBeDefined();
    expect(signature.length).toBeGreaterThan(64);

    const isValid = verifySignature(hash, signature, rsaKeys.publicKey);
    expect(isValid).toBe(true);

    const isInvalid = verifySignature(hash + 'tampered', signature, rsaKeys.publicKey);
    expect(isInvalid).toBe(false);
  });

  test('.secure package creation, verification and passphrase decryption', () => {
    const passphrase = 'my-safe-sharing-passphrase';
    const originalFilename = 'capstone_doc.pdf';
    const mimeType = 'application/pdf';

    const { ciphertext, authTag } = aesEncrypt(plaintext, aesKey, iv);

    // Create the package
    const securePkgBuffer = createSecurePackage({
      ciphertext,
      iv,
      authTag,
      aesKey,
      passphrase,
      originalFilename,
      mimeType,
      signerPrivateKey: rsaKeys.privateKey,
      signerPublicKey: rsaKeys.publicKey,
    });

    expect(securePkgBuffer).toBeDefined();

    // Parse the package
    const envelope = parseSecurePackage(securePkgBuffer);
    expect(envelope.originalFilename).toBe(originalFilename);
    expect(envelope.mimeType).toBe(mimeType);

    // Verify digital signature and integrity
    const { integrityOk, signatureOk } = verifySecurePackage(envelope);
    expect(integrityOk).toBe(true);
    expect(signatureOk).toBe(true);

    // Decrypt the package
    const decryptedPlaintext = decryptSecurePackage(envelope, passphrase);
    expect(decryptedPlaintext.toString('utf8')).toBe(plaintext.toString('utf8'));
  });

  test('.secure package wrong passphrase failure', () => {
    const passphrase = 'correct-passphrase';
    const { ciphertext, authTag } = aesEncrypt(plaintext, aesKey, iv);

    const securePkgBuffer = createSecurePackage({
      ciphertext,
      iv,
      authTag,
      aesKey,
      passphrase,
      originalFilename: 'test.txt',
      mimeType: 'text/plain',
      signerPrivateKey: rsaKeys.privateKey,
      signerPublicKey: rsaKeys.publicKey,
    });

    const envelope = parseSecurePackage(securePkgBuffer);
    
    expect(() => {
      decryptSecurePackage(envelope, 'wrong-passphrase');
    }).toThrow(/decryption_failed/i);
  });

  test('.secure package tampering detection', () => {
    const passphrase = 'correct-passphrase';
    const { ciphertext, authTag } = aesEncrypt(plaintext, aesKey, iv);

    const securePkgBuffer = createSecurePackage({
      ciphertext,
      iv,
      authTag,
      aesKey,
      passphrase,
      originalFilename: 'test.txt',
      mimeType: 'text/plain',
      signerPrivateKey: rsaKeys.privateKey,
      signerPublicKey: rsaKeys.publicKey,
    });

    const envelope = parseSecurePackage(securePkgBuffer);
    
    // Tamper the ciphertext base64 in envelope
    envelope.ciphertextBase64 = Buffer.from('tampered data', 'utf8').toString('base64');
    
    const { integrityOk } = verifySecurePackage(envelope);
    expect(integrityOk).toBe(false); // Integrity check fails!
  });
});
