'use strict';
/**
 * Rigorous Integration Test Suite for Stateless Hybrid Cryptography Architecture
 * Verifies stateless encrypt and decrypt endpoints.
 */

const request = require('supertest');
const fs = require('fs');
const path = require('path');
const app = require('../server/server');

describe('Stateless Cryptography API End-to-End Pipeline', () => {
  const originalPayload = 'This is a capstone project payload for secure cloud file sharing using hybrid cryptography.';
  const passphrase = 'correct-passphrase-123';
  let securePackageBuffer = null;

  test('1. Server health check works', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.storage).toContain('stateless');
  });

  test('2. Encrypt endpoint accepts a file and returns a .secure package', async () => {
    const res = await request(app)
      .post('/api/crypto/encrypt')
      .field('passphrase', passphrase)
      .field('signatureEnabled', 'true')
      .attach('file', Buffer.from(originalPayload, 'utf-8'), 'sample_document.pdf');

    expect(res.status).toBe(200);
    expect(res.header['content-type']).toBe('application/octet-stream');
    expect(res.header['content-disposition']).toContain('attachment');
    expect(res.header['content-disposition']).toContain('.secure');
    expect(res.header['x-original-filename']).toBe('sample_document.pdf');
    expect(res.header['x-signature-status']).toBe('SIGNED');
    expect(res.header['x-sha256-hash']).toBeDefined();

    securePackageBuffer = res.body; // Supertest parses binary response as a Buffer
    expect(securePackageBuffer).toBeDefined();
    expect(securePackageBuffer.length).toBeGreaterThan(0);

    // Validate that it parses as JSON and contains the ciphertext and metadata
    const envelope = JSON.parse(securePackageBuffer.toString('utf8'));
    expect(envelope.version).toBe(2);
    expect(envelope.algorithm).toBe('AES-256-GCM');
    expect(envelope.keyProtection).toBe('PASSPHRASE-PBKDF2-310000');
    expect(envelope.originalFilename).toBe('sample_document.pdf');
    expect(envelope.ciphertextBase64).toBeDefined();
    expect(envelope.signatureEnabled).toBe(true);
    expect(envelope.signature).toBeDefined();
    expect(envelope.signerPublicKey).toBeDefined();
  });

  test('3. Decrypt endpoint recovers the original file with correct passphrase', async () => {
    expect(securePackageBuffer).toBeDefined();

    const res = await request(app)
      .post('/api/crypto/decrypt')
      .field('passphrase', passphrase)
      .attach('package', securePackageBuffer, 'sample_document.secure');

    expect(res.status).toBe(200);
    expect(res.header['content-type']).toBe('application/pdf'); // inferred from original mimetype
    expect(res.header['content-disposition']).toContain('filename="sample_document.pdf"');
    expect(res.header['x-integrity-ok']).toBe('true');
    expect(res.header['x-signature-ok']).toBe('true');
    expect(res.body.toString('utf8')).toBe(originalPayload);
  });

  test('4. Encrypt endpoint validation errors (short passphrase)', async () => {
    const res = await request(app)
      .post('/api/crypto/encrypt')
      .field('passphrase', '123') // too short
      .attach('file', Buffer.from(originalPayload, 'utf-8'), 'sample_document.pdf');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Passphrase must be at least 6 characters');
  });

  test('5. Encrypt endpoint validation errors (missing file)', async () => {
    const res = await request(app)
      .post('/api/crypto/encrypt')
      .field('passphrase', passphrase);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('No file provided');
  });

  test('6. Decrypt endpoint fails with wrong passphrase', async () => {
    const res = await request(app)
      .post('/api/crypto/decrypt')
      .field('passphrase', 'wrong-passphrase')
      .attach('package', securePackageBuffer, 'sample_document.secure');

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('DECRYPTION_FAILED');
    expect(res.body.message).toContain('Decryption failed. The passphrase is incorrect');
  });

  test('7. Decrypt endpoint detects package tampering (integrity check)', async () => {
    // Parse package envelope, tamper the ciphertext, and re-serialize
    const envelope = JSON.parse(securePackageBuffer.toString('utf8'));
    envelope.ciphertextBase64 = Buffer.from('tampered payload data', 'utf-8').toString('base64');
    const tamperedBuffer = Buffer.from(JSON.stringify(envelope), 'utf8');

    const res = await request(app)
      .post('/api/crypto/decrypt')
      .field('passphrase', passphrase)
      .attach('package', tamperedBuffer, 'sample_document.secure');

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('INTEGRITY_FAILED');
    expect(res.body.message).toContain('FILE INTEGRITY CHECK FAILED');
  });

  test('8. Decrypt endpoint detects signature invalidation', async () => {
    // Parse package envelope, change the signature, and re-serialize
    const envelope = JSON.parse(securePackageBuffer.toString('utf8'));
    // Modify signature slightly
    envelope.signature = envelope.signature.replace(/[a-f0-9]/, '0');
    const tamperedBuffer = Buffer.from(JSON.stringify(envelope), 'utf8');

    const res = await request(app)
      .post('/api/crypto/decrypt')
      .field('passphrase', passphrase)
      .attach('package', tamperedBuffer, 'sample_document.secure');

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('SIGNATURE_INVALID');
    expect(res.body.message).toContain('DIGITAL SIGNATURE INVALID');
  });

  test('9. Decrypt endpoint handles unsigned packages correctly', async () => {
    // Create an unsigned package
    const resEncrypt = await request(app)
      .post('/api/crypto/encrypt')
      .field('passphrase', passphrase)
      .field('signatureEnabled', 'false')
      .attach('file', Buffer.from(originalPayload, 'utf-8'), 'sample_document.pdf');

    expect(resEncrypt.status).toBe(200);
    const unsignedBuffer = resEncrypt.body;

    const resDecrypt = await request(app)
      .post('/api/crypto/decrypt')
      .field('passphrase', passphrase)
      .attach('package', unsignedBuffer, 'sample_document.secure');

    expect(resDecrypt.status).toBe(200);
    expect(resDecrypt.header['x-signature-ok']).toBe('N/A');
    expect(resDecrypt.body.toString('utf8')).toBe(originalPayload);
  });
});
