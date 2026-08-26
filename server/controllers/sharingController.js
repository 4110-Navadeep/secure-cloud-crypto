'use strict';
/**
 * Sharing Controller — Module 3
 * Handles: share file, list shares, revoke access
 */

const { v4: uuidv4 } = require('uuid');
const { query, queryOne } = require('../database/db');
const { logEvent, EventTypes, extractRequestMeta } = require('../services/auditService');

// ---------------------------------------------------------------------------
// Share a File
// ---------------------------------------------------------------------------

async function shareFile(req, res) {
  const meta = extractRequestMeta(req);
  try {
    const { file_id, shared_with_email, permission, expires_at } = req.body;

    if (!file_id || !shared_with_email || !permission) {
      return res.status(400).json({ error: 'file_id, shared_with_email, and permission are required' });
    }
    if (!['preview', 'download', 'preview_download'].includes(permission)) {
      return res.status(400).json({ error: 'Invalid permission value' });
    }

    // Verify file ownership
    const file = await queryOne(
      "SELECT id, original_filename, owner_id FROM files WHERE id = ? AND owner_id = ? AND status = 'active'",
      [file_id, req.user.id]
    );
    if (!file) return res.status(404).json({ error: 'File not found or you are not the owner' });

    // Find recipient
    const recipient = await queryOne(
      "SELECT id, full_name, email FROM users WHERE email = ? AND status = 'active'",
      [shared_with_email.toLowerCase()]
    );
    if (!recipient) return res.status(404).json({ error: 'No active user found with that email' });

    // Cannot share with yourself
    if (recipient.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot share a file with yourself' });
    }

    // Check if already shared
    const existing = await queryOne(
      "SELECT id FROM file_shares WHERE file_id = ? AND shared_with = ? AND status = 'active'",
      [file_id, recipient.id]
    );
    if (existing) {
      // Update existing share
      await query(
        "UPDATE file_shares SET permission = ?, expires_at = ?, updated_at = NOW() WHERE id = ?",
        [permission, expires_at || null, existing.id]
      );
      return res.json({ message: `Share updated for ${recipient.email}` });
    }

    const shareId = uuidv4();
    await query(
      `INSERT INTO file_shares (id, file_id, shared_by, shared_with, permission, expires_at, status)
       VALUES (?, ?, ?, ?, ?, ?, 'active')`,
      [shareId, file_id, req.user.id, recipient.id, permission, expires_at || null]
    );

    await logEvent({
      userId: req.user.id,
      eventType: EventTypes.FILE_SHARED,
      fileId: file_id,
      ...meta,
      details: { sharedWith: recipient.email, permission },
      status: 'success',
    });

    res.status(201).json({
      message: `File shared with ${recipient.full_name} (${recipient.email})`,
      share: { id: shareId, file_id, shared_with: recipient, permission, expires_at: expires_at || null },
    });
  } catch (err) {
    console.error('[SHARE] Error:', err);
    res.status(500).json({ error: 'Failed to share file' });
  }
}

// ---------------------------------------------------------------------------
// List Files Shared By Me
// ---------------------------------------------------------------------------

async function sharedByMe(req, res) {
  const shares = await query(
    `SELECT fs.id AS share_id, fs.permission, fs.expires_at, fs.status, fs.created_at,
            f.id AS file_id, f.original_filename, f.mime_type, f.original_size,
            u.full_name AS recipient_name, u.email AS recipient_email
     FROM file_shares fs
     JOIN files f ON f.id = fs.file_id
     JOIN users u ON u.id = fs.shared_with
     WHERE fs.shared_by = ?
     ORDER BY fs.created_at DESC`,
    [req.user.id]
  );

  // Check expiration
  const now = new Date();
  const enriched = shares.map(s => ({
    ...s,
    effective_status: s.status === 'revoked' ? 'revoked'
      : (s.expires_at && new Date(s.expires_at) < now) ? 'expired'
      : s.status,
  }));

  res.json({ shares: enriched });
}

// ---------------------------------------------------------------------------
// List Files Shared With Me
// ---------------------------------------------------------------------------

async function sharedWithMe(req, res) {
  const shares = await query(
    `SELECT fs.id AS share_id, fs.permission, fs.expires_at, fs.status, fs.created_at,
            f.id AS file_id, f.original_filename, f.mime_type, f.original_size, f.owner_id,
            u.full_name AS owner_name, u.email AS owner_email
     FROM file_shares fs
     JOIN files f ON f.id = fs.file_id AND f.status = 'active'
     JOIN users u ON u.id = fs.shared_by
     WHERE fs.shared_with = ?
     ORDER BY fs.created_at DESC`,
    [req.user.id]
  );

  const now = new Date();
  const enriched = shares.map(s => ({
    ...s,
    effective_status: s.status === 'revoked' ? 'revoked'
      : (s.expires_at && new Date(s.expires_at) < now) ? 'expired'
      : s.status,
  }));

  res.json({ shares: enriched });
}

// ---------------------------------------------------------------------------
// Revoke Access
// ---------------------------------------------------------------------------

async function revokeAccess(req, res) {
  const meta = extractRequestMeta(req);
  const { share_id } = req.params;

  const share = await queryOne(
    `SELECT fs.*, f.owner_id FROM file_shares fs
     JOIN files f ON f.id = fs.file_id
     WHERE fs.id = ?`,
    [share_id]
  );

  if (!share) return res.status(404).json({ error: 'Share not found' });

  // Only file owner or admin can revoke
  if (share.shared_by !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only the file owner can revoke access' });
  }

  await query("UPDATE file_shares SET status = 'revoked', updated_at = NOW() WHERE id = ?", [share_id]);

  await logEvent({
    userId: req.user.id,
    eventType: EventTypes.FILE_SHARE_REVOKED,
    fileId: share.file_id,
    ...meta,
    details: { shareId: share_id },
  });

  res.json({ message: 'Access revoked successfully' });
}

// ---------------------------------------------------------------------------
// List Members (for share modal)
// ---------------------------------------------------------------------------

async function listShareableMembers(req, res) {
  const members = await query(
    "SELECT id, full_name, email, role FROM users WHERE status = 'active' AND id != ? ORDER BY full_name",
    [req.user.id]
  );
  res.json({ members });
}

module.exports = { shareFile, sharedByMe, sharedWithMe, revokeAccess, listShareableMembers };
