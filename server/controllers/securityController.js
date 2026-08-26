'use strict';
/**
 * Security Controller — Module 4
 * Security activity logs, threat analytics, dashboard stats
 */

const { query, queryOne } = require('../database/db');

// ---------------------------------------------------------------------------
// Security Activity Log
// ---------------------------------------------------------------------------

async function getActivityLog(req, res) {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;
  const eventFilter = req.query.event || null;
  const statusFilter = req.query.status || null;

  let sql = `
    SELECT al.id, al.event_type, al.status, al.ip_address, al.details,
           al.created_at, al.file_id,
           u.full_name AS user_name, u.email AS user_email,
           f.original_filename
    FROM audit_logs al
    LEFT JOIN users u ON u.id = al.user_id
    LEFT JOIN files f ON f.id = al.file_id
  `;
  const params = [];

  // Non-admins only see their own logs
  if (req.user.role !== 'admin') {
    sql += ' WHERE al.user_id = ?';
    params.push(req.user.id);
    if (eventFilter) { sql += ' AND al.event_type = ?'; params.push(eventFilter); }
    if (statusFilter) { sql += ' AND al.status = ?'; params.push(statusFilter); }
  } else {
    const conditions = [];
    if (eventFilter) { conditions.push('al.event_type = ?'); params.push(eventFilter); }
    if (statusFilter) { conditions.push('al.status = ?'); params.push(statusFilter); }
    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
  }

  sql += ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const logs = await query(sql, params);

  // Total count
  const [countRow] = await query(
    'SELECT COUNT(*) AS total FROM audit_logs' +
    (req.user.role !== 'admin' ? ' WHERE user_id = ?' : ''),
    req.user.role !== 'admin' ? [req.user.id] : []
  );

  res.json({ logs, total: countRow.total, page, limit });
}

// ---------------------------------------------------------------------------
// Threat Analytics
// ---------------------------------------------------------------------------

async function getThreatAnalytics(req, res) {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000); // last 24h

  const [
    failedLogins,
    integrityFailures,
    sigFailures,
    decryptionFailures,
    accessDenied,
    expiredAccess,
    revokedAccess,
    recentEvents,
    totalEvents,
  ] = await Promise.all([
    query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE event_type = 'LOGIN_FAILED' AND created_at > ?", [since]),
    query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE event_type = 'INTEGRITY_FAILED' AND created_at > ?", [since]),
    query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE event_type = 'SIGNATURE_FAILED' AND created_at > ?", [since]),
    query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE event_type = 'DECRYPTION_FAILED' AND created_at > ?", [since]),
    query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE event_type = 'ACCESS_DENIED' AND created_at > ?", [since]),
    query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE event_type = 'ACCESS_EXPIRED' AND created_at > ?", [since]),
    query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE event_type = 'ACCESS_REVOKED' AND created_at > ?", [since]),
    query(`SELECT al.event_type, al.status, al.created_at, al.ip_address,
                  u.full_name, u.email
           FROM audit_logs al
           LEFT JOIN users u ON u.id = al.user_id
           WHERE al.created_at > ? AND al.status != 'success'
           ORDER BY al.created_at DESC LIMIT 20`, [since]),
    query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE created_at > ?", [since]),
  ]);

  const failedLoginCount = failedLogins[0].cnt;
  const threatScore = Math.min(100, (
    failedLoginCount * 10 +
    integrityFailures[0].cnt * 20 +
    sigFailures[0].cnt * 20 +
    decryptionFailures[0].cnt * 5 +
    accessDenied[0].cnt * 5
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
      failed_logins: failedLoginCount,
      integrity_failures: integrityFailures[0].cnt,
      signature_failures: sigFailures[0].cnt,
      decryption_failures: decryptionFailures[0].cnt,
      access_denied: accessDenied[0].cnt,
      expired_access: expiredAccess[0].cnt,
      revoked_access: revokedAccess[0].cnt,
      total_events: totalEvents[0].cnt,
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

  const [
    totalFiles,
    encryptedFiles,
    sharedFiles,
    securityEvents,
    recentActivity,
  ] = await Promise.all([
    isAdmin
      ? query("SELECT COUNT(*) AS cnt FROM files WHERE status = 'active'")
      : query("SELECT COUNT(*) AS cnt FROM files WHERE owner_id = ? AND status = 'active'", [userId]),
    isAdmin
      ? query("SELECT COUNT(*) AS cnt FROM files WHERE status = 'active' AND encryption_algorithm = 'AES-256-GCM'")
      : query("SELECT COUNT(*) AS cnt FROM files WHERE owner_id = ? AND status = 'active' AND encryption_algorithm = 'AES-256-GCM'", [userId]),
    isAdmin
      ? query("SELECT COUNT(*) AS cnt FROM file_shares WHERE status = 'active'")
      : query("SELECT COUNT(*) AS cnt FROM file_shares WHERE (shared_by = ? OR shared_with = ?) AND status = 'active'", [userId, userId]),
    isAdmin
      ? query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)")
      : query("SELECT COUNT(*) AS cnt FROM audit_logs WHERE user_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)", [userId]),
    query(`SELECT al.event_type, al.status, al.created_at, u.full_name, f.original_filename
           FROM audit_logs al
           LEFT JOIN users u ON u.id = al.user_id
           LEFT JOIN files f ON f.id = al.file_id
           ${isAdmin ? '' : 'WHERE al.user_id = ?'}
           ORDER BY al.created_at DESC LIMIT 5`,
      isAdmin ? [] : [userId]),
  ]);

  // System health check
  const failedRecently = await query(
    "SELECT COUNT(*) AS cnt FROM audit_logs WHERE status = 'failure' AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)"
  );
  const systemStatus = failedRecently[0].cnt > 10 ? 'WARNING' : 'HEALTHY';

  res.json({
    stats: {
      total_files: totalFiles[0].cnt,
      encrypted_files: encryptedFiles[0].cnt,
      shared_files: sharedFiles[0].cnt,
      security_events_24h: securityEvents[0].cnt,
    },
    system_status: systemStatus,
    recent_activity: recentActivity,
  });
}

module.exports = { getActivityLog, getThreatAnalytics, getDashboardStats };
