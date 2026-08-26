'use strict';
/**
 * External Package Controller
 * Handles the .secure package upload → verify → decrypt workflow
 * Used by anyone (even without account) to open an externally received .secure package
 */

const { v4: uuidv4 } = require('uuid');
const {
  parseSecurePackage,
  verifySecurePackage,
  decryptSecurePackage,
  sha256Hash,
} = require('../crypto/cryptoService');
const { logEvent, EventTypes, extractRequestMeta } = require('../services/auditService');
const db = require('../database/db');

// ---------------------------------------------------------------------------
// Step 1: Parse and verify the .secure package
// ---------------------------------------------------------------------------

async function verifyPackage(req, res) {
  const meta = extractRequestMeta(req);
  const tStart = Date.now();

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No .secure package provided' });
    }

    const packageBuffer = req.file.buffer;

    // Parse the envelope
    let envelope;
    try {
      envelope = parseSecurePackage(packageBuffer);
    } catch (parseErr) {
      await logEvent({
        userId: req.user?.id,
        eventType: EventTypes.PACKAGE_TAMPERED,
        ...meta,
        details: { error: parseErr.message },
        status: 'failure',
      });
      return res.status(400).json({
        error: 'INVALID_PACKAGE',
        message: 'Invalid secure package: cannot parse structure',
      });
    }

    // Verify integrity and signature
    const { integrityOk, signatureOk } = verifySecurePackage(envelope);

    const tTotal = Date.now() - tStart;

    if (!integrityOk) {
      await logEvent({
        userId: req.user?.id,
        eventType: EventTypes.INTEGRITY_FAILED,
        ...meta,
        details: { filename: envelope.originalFilename },
        status: 'failure',
      });
      return res.status(409).json({
        error: 'INTEGRITY_FAILED',
        message: 'FILE INTEGRITY CHECK FAILED: The package has been tampered or corrupted.',
        integrityOk: false,
        signatureOk: false,
      });
    }

    if (!signatureOk) {
      await logEvent({
        userId: req.user?.id,
        eventType: EventTypes.SIGNATURE_FAILED,
        ...meta,
        details: { filename: envelope.originalFilename },
        status: 'failure',
      });
      return res.status(409).json({
        error: 'SIGNATURE_INVALID',
        message: 'DIGITAL SIGNATURE INVALID: Package authenticity cannot be verified.',
        integrityOk: true,
        signatureOk: false,
      });
    }

    await logEvent({ userId: req.user?.id, eventType: EventTypes.INTEGRITY_VERIFIED, ...meta });
    await logEvent({ userId: req.user?.id, eventType: EventTypes.SIGNATURE_VERIFIED, ...meta });
    await logEvent({ userId: req.user?.id, eventType: EventTypes.PACKAGE_VERIFIED, ...meta, details: { filename: envelope.originalFilename } });

    // Store envelope in session-like base64 for the next step
    // We return a temporary session token containing the envelope (it's the encrypted data, safe to echo back)
    const packageToken = Buffer.from(JSON.stringify({
      envelope,
      ts: Date.now(),
    })).toString('base64');

    res.json({
      verified: true,
      integrityOk: true,
      signatureOk: true,
      originalFilename: envelope.originalFilename,
      mimeType: envelope.mimeType,
      algorithm: envelope.algorithm,
      sha256Hash: envelope.sha256Hash,
      processingTimeMs: tTotal,
      packageToken, // pass this back in decrypt step
      message: 'Package verified successfully. Enter passphrase to decrypt.',
    });
  } catch (err) {
    console.error('[EXTERNAL] Verify error:', err);
    res.status(500).json({ error: 'Package verification failed: ' + err.message });
  }
}

// ---------------------------------------------------------------------------
// Step 2: Decrypt using passphrase
// ---------------------------------------------------------------------------

async function decryptPackage(req, res) {
  const meta = extractRequestMeta(req);
  const tStart = Date.now();

  try {
    const { packageToken, passphrase } = req.body;

    if (!packageToken || !passphrase) {
      return res.status(400).json({ error: 'packageToken and passphrase are required' });
    }

    // Parse the token
    let tokenData;
    try {
      tokenData = JSON.parse(Buffer.from(packageToken, 'base64').toString('utf8'));
    } catch (err) {
      return res.status(400).json({ error: 'Invalid package token' });
    }

    // Token expiry: 30 minutes
    if (Date.now() - tokenData.ts > 30 * 60 * 1000) {
      return res.status(400).json({ error: 'Package session expired. Please re-upload the .secure package.' });
    }

    const { envelope } = tokenData;

    // Re-verify (defense in depth)
    const { integrityOk, signatureOk } = verifySecurePackage(envelope);
    if (!integrityOk || !signatureOk) {
      return res.status(409).json({ error: 'Package verification failed' });
    }

    // Decrypt with passphrase
    let plaintext;
    try {
      plaintext = decryptSecurePackage(envelope, passphrase);
    } catch (decErr) {
      await logEvent({
        userId: req.user?.id,
        eventType: EventTypes.DECRYPTION_FAILED,
        ...meta,
        details: { filename: envelope.originalFilename, error: 'Wrong passphrase or corrupted package' },
        status: 'failure',
      });
      return res.status(400).json({
        error: 'DECRYPTION_FAILED',
        message: 'Decryption failed. The passphrase may be incorrect.',
      });
    }

    const tTotal = Date.now() - tStart;

    await logEvent({
      userId: req.user?.id,
      eventType: EventTypes.DECRYPTION_SUCCESS,
      ...meta,
      details: { filename: envelope.originalFilename, decryptionTimeMs: tTotal },
    });

    // Record performance metrics
    try {
      db.performance.insert({
        id: uuidv4(),
        user_id: req.user?.id || null,
        operation: 'EXTERNAL_DECRYPT',
        file_size: plaintext.length,
        decryption_time_ms: tTotal,
        total_processing_time_ms: tTotal
      });
    } catch (perfErr) {
      // ignore metrics saving errors
    }

    // Stream the decrypted file to the client
    res.setHeader('Content-Disposition', `attachment; filename="${envelope.originalFilename}"`);
    res.setHeader('Content-Type', envelope.mimeType || 'application/octet-stream');
    res.send(plaintext);
  } catch (err) {
    console.error('[EXTERNAL] Decrypt error:', err);
    res.status(500).json({ error: 'Decryption failed: ' + err.message });
  }
}

module.exports = { verifyPackage, decryptPackage };
