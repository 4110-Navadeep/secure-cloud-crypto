'use strict';
/**
 * Audit Log Service — records all security events to JSON DB.
 */

const db = require('../database/db');
const { v4: uuidv4 } = require('uuid');

const EventTypes = {
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILED: 'LOGIN_FAILED',
  LOGOUT: 'LOGOUT',
  REGISTER: 'REGISTER',
  INVITATION_SENT: 'INVITATION_SENT',
  INVITATION_ACCEPTED: 'INVITATION_ACCEPTED',
  FILE_UPLOAD: 'FILE_UPLOAD',
  FILE_ENCRYPTED: 'FILE_ENCRYPTED',
  FILE_DOWNLOAD: 'FILE_DOWNLOAD',
  FILE_DELETED: 'FILE_DELETED',
  FILE_SHARED: 'FILE_SHARED',
  FILE_SHARE_REVOKED: 'FILE_SHARE_REVOKED',
  SIGNATURE_VERIFIED: 'SIGNATURE_VERIFIED',
  SIGNATURE_FAILED: 'SIGNATURE_FAILED',
  INTEGRITY_VERIFIED: 'INTEGRITY_VERIFIED',
  INTEGRITY_FAILED: 'INTEGRITY_FAILED',
  DECRYPTION_SUCCESS: 'DECRYPTION_SUCCESS',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  ACCESS_DENIED: 'ACCESS_DENIED',
  ACCESS_EXPIRED: 'ACCESS_EXPIRED',
  ACCESS_REVOKED: 'ACCESS_REVOKED',
  PACKAGE_UPLOADED: 'PACKAGE_UPLOADED',
  PACKAGE_VERIFIED: 'PACKAGE_VERIFIED',
  PACKAGE_TAMPERED: 'PACKAGE_TAMPERED',
  UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
};

/**
 * Log a security event.
 * @param {object} params
 */
async function logEvent({ userId = null, eventType, fileId = null, ipAddress = null, userAgent = null, details = {}, status = 'success' }) {
  try {
    db.securityLogs.insert({
      id: uuidv4(),
      user_id: userId,
      event_type: eventType,
      file_id: fileId,
      ip_address: ipAddress,
      user_agent: userAgent,
      details: typeof details === 'string' ? JSON.parse(details) : details,
      status,
    });
  } catch (err) {
    console.error('[AUDIT] Failed to log event:', err.message);
  }
}

/**
 * Extract request metadata for logging.
 * @param {import('express').Request} req
 */
function extractRequestMeta(req) {
  return {
    ipAddress: req.ip || req.connection?.remoteAddress || null,
    userAgent: req.headers?.['user-agent']?.substring(0, 500) || null,
  };
}

module.exports = { logEvent, extractRequestMeta, EventTypes };
