'use strict';
/**
 * Security Controller — Module 4
 * Security activity logs, threat analytics, dashboard stats
 */

const db = require('../database/db');

// ---------------------------------------------------------------------------
// Security Activity Log
// ---------------------------------------------------------------------------

async function getActivityLog(req, res) {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;
  const eventFilter = req.query.event || null;
  const statusFilter = req.query.status || null;

  let allLogs = db.securityLogs.find();

  // Filter logs
  if (req.user.role !== 'admin') {
    allLogs = allLogs.filter(log => log.user_id === req.user.id);
  }

  if (eventFilter) {
    allLogs = allLogs.filter(log => log.event_type === eventFilter);
  }

  if (statusFilter) {
    allLogs = allLogs.filter(log => log.status === statusFilter);
  }

  // Enrich logs with user and file details
  let enrichedLogs = allLogs.map(log => {
    const user = log.user_id ? db.users.findOne({ id: log.user_id }) : null;
    const file = log.file_id ? db.files.findOne({ id: log.file_id }) : null;
    return {
      id: log.id,
      event_type: log.event_type,
      status: log.status,
      ip_address: log.ip_address,
      details: typeof log.details === 'string' ? JSON.parse(log.details) : log.details,
      created_at: log.created_at,
      file_id: log.file_id,
      user_name: user ? user.full_name : 'System',
      user_email: user ? user.email : null,
      original_filename: file ? file.original_filename : null
    };
  });

  // Sort by created_at desc
  enrichedLogs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  const total = enrichedLogs.length;
  const paginatedLogs = enrichedLogs.slice(offset, offset + limit);

  res.json({ logs: paginatedLogs, total, page, limit });
}

// ---------------------------------------------------------------------------
// Threat Analytics
// ---------------------------------------------------------------------------

async function getThreatAnalytics(req, res) {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000); // last 24h

  const logs = db.securityLogs.find(log => new Date(log.created_at) > since);

  const failedLogins = logs.filter(log => log.event_type === 'LOGIN_FAILED').length;
  const integrityFailures = logs.filter(log => log.event_type === 'INTEGRITY_FAILED').length;
  const sigFailures = logs.filter(log => log.event_type === 'SIGNATURE_FAILED').length;
  const decryptionFailures = logs.filter(log => log.event_type === 'DECRYPTION_FAILED').length;
  const accessDenied = logs.filter(log => log.event_type === 'ACCESS_DENIED').length;
  const expiredAccess = logs.filter(log => log.event_type === 'ACCESS_EXPIRED').length;
  const revokedAccess = logs.filter(log => log.event_type === 'ACCESS_REVOKED').length;
  const totalEvents = logs.length;

  const recentEvents = logs
    .filter(log => log.status !== 'success')
    .map(log => {
      const user = log.user_id ? db.users.findOne({ id: log.user_id }) : null;
      return {
        event_type: log.event_type,
        status: log.status,
        created_at: log.created_at,
        ip_address: log.ip_address,
        full_name: user ? user.full_name : 'Guest',
        email: user ? user.email : null
      };
    })
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 20);

  const threatScore = Math.min(100, (
    failedLogins * 10 +
    integrityFailures * 20 +
    sigFailures * 20 +
    decryptionFailures * 5 +
    accessDenied * 5
  ));

  const threatLevel = threatScore === 0 ? 'NONE'
    : threatScore < 20 ? 'LOW'
    : threatScore < 50 ? 'MEDIUM'
    : 'HIGH';

  res.json({
    period: '24 hours',
    threatLevel,
    threatScore,
    metrics: {
      failed_logins: failedLogins,
      integrity_failures: integrityFailures,
      signature_failures: sigFailures,
      decryption_failures: decryptionFailures,
      access_denied: accessDenied,
      expired_access: expiredAccess,
      revoked_access: revokedAccess,
      total_events: totalEvents,
    },
    recent_threats: recentEvents,
  });
}

// ---------------------------------------------------------------------------
// Dashboard Statistics
// ---------------------------------------------------------------------------

async function getDashboardStats(req, res) {
  const userId = req.user.id;
  const isAdmin = req.user.role === 'admin';

  const userFiles = isAdmin
    ? db.files.find({ status: 'active' })
    : db.files.find({ owner_id: userId, status: 'active' });

  const totalFiles = userFiles.length;
  const encryptedFiles = userFiles.filter(f => f.encryption_algorithm === 'AES-256-GCM').length;

  const sharedFiles = isAdmin
    ? db.shares.find({ status: 'active' }).length
    : db.shares.find(s => (s.shared_by === userId || s.shared_with === userId) && s.status === 'active').length;

  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const securityEvents = isAdmin
    ? db.securityLogs.find(log => new Date(log.created_at) > since24h).length
    : db.securityLogs.find(log => log.user_id === userId && new Date(log.created_at) > since24h).length;

  const recentActivity = db.securityLogs.find()
    .filter(log => isAdmin || log.user_id === userId)
    .map(log => {
      const user = log.user_id ? db.users.findOne({ id: log.user_id }) : null;
      const file = log.file_id ? db.files.findOne({ id: log.file_id }) : null;
      return {
        event_type: log.event_type,
        status: log.status,
        created_at: log.created_at,
        full_name: user ? user.full_name : 'System',
        original_filename: file ? file.original_filename : null
      };
    })
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 5);

  // System health check
  const since1h = new Date(Date.now() - 60 * 60 * 1000);
  const failedRecently = db.securityLogs.find(log => log.status === 'failure' && new Date(log.created_at) > since1h).length;
  const systemStatus = failedRecently > 10 ? 'WARNING' : 'HEALTHY';

  res.json({
    stats: {
      total_files: totalFiles,
      encrypted_files: encryptedFiles,
      shared_files: sharedFiles,
      security_events_24h: securityEvents,
    },
    system_status: systemStatus,
    recent_activity: recentActivity,
  });
}

module.exports = { getActivityLog, getThreatAnalytics, getDashboardStats };
