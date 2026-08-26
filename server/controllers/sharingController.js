'use strict';
/**
 * Sharing Controller — Module 3
 * Handles: share file, list shares, revoke access
 */

const { v4: uuidv4 } = require('uuid');
const db = require('../database/db');
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
    const file = db.files.findOne({ id: file_id, owner_id: req.user.id, status: 'active' });
    if (!file) return res.status(404).json({ error: 'File not found or you are not the owner' });

    // Find recipient
    const recipient = db.users.findOne({ email: shared_with_email.toLowerCase(), status: 'active' });
    if (!recipient) return res.status(404).json({ error: 'No active user found with that email' });

    // Cannot share with yourself
    if (recipient.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot share a file with yourself' });
    }

    // Check if already shared
    const existing = db.shares.findOne({ file_id, shared_with: recipient.id, status: 'active' });
    if (existing) {
      // Update existing share
      db.shares.update({ id: existing.id }, {
        permission,
        expires_at: expires_at || null,
        updated_at: new Date().toISOString()
      });
      return res.json({ message: `Share updated for ${recipient.email}` });
    }

    const shareId = uuidv4();
    db.shares.insert({
      id: shareId,
      file_id,
      shared_by: req.user.id,
      shared_with: recipient.id,
      permission,
      expires_at: expires_at || null,
      status: 'active'
    });

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
      share: {
        id: shareId,
        file_id,
        shared_with: { id: recipient.id, full_name: recipient.full_name, email: recipient.email },
        permission,
        expires_at: expires_at || null
      },
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
  const shares = db.shares.find({ shared_by: req.user.id }).map(s => {
    const file = db.files.findOne({ id: s.file_id });
    const recipient = db.users.findOne({ id: s.shared_with });
    return {
      share_id: s.id,
      permission: s.permission,
      expires_at: s.expires_at,
      status: s.status,
      created_at: s.created_at,
      file_id: s.file_id,
      original_filename: file ? file.original_filename : 'Unknown File',
      mime_type: file ? file.mime_type : null,
      original_size: file ? file.original_size : 0,
      recipient_name: recipient ? recipient.full_name : 'Deleted User',
      recipient_email: recipient ? recipient.email : 'deleted@user.com'
    };
  });

  // Check expiration
  const now = new Date();
  const enriched = shares.map(s => ({
    ...s,
    effective_status: s.status === 'revoked' ? 'revoked'
      : (s.expires_at && new Date(s.expires_at) < now) ? 'expired'
      : s.status,
  })).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  res.json({ shares: enriched });
}

// ---------------------------------------------------------------------------
// List Files Shared With Me
// ---------------------------------------------------------------------------

async function sharedWithMe(req, res) {
  const shares = db.shares.find({ shared_with: req.user.id }).map(s => {
    const file = db.files.findOne({ id: s.file_id, status: 'active' });
    const owner = db.users.findOne({ id: s.shared_by });
    if (!file) return null; // Only show active files
    return {
      share_id: s.id,
      permission: s.permission,
      expires_at: s.expires_at,
      status: s.status,
      created_at: s.created_at,
      file_id: s.file_id,
      original_filename: file.original_filename,
      mime_type: file.mime_type,
      original_size: file.original_size,
      owner_id: file.owner_id,
      owner_name: owner ? owner.full_name : 'System',
      owner_email: owner ? owner.email : 'system@cloud.app'
    };
  }).filter(Boolean);

  const now = new Date();
  const enriched = shares.map(s => ({
    ...s,
    effective_status: s.status === 'revoked' ? 'revoked'
      : (s.expires_at && new Date(s.expires_at) < now) ? 'expired'
      : s.status,
  })).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  res.json({ shares: enriched });
}

// ---------------------------------------------------------------------------
// Revoke Access
// ---------------------------------------------------------------------------

async function revokeAccess(req, res) {
  const meta = extractRequestMeta(req);
  const { share_id } = req.params;

  const share = db.shares.findOne({ id: share_id });
  if (!share) return res.status(404).json({ error: 'Share not found' });

  const file = db.files.findOne({ id: share.file_id });

  // Only file owner or admin can revoke
  if (share.shared_by !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only the file owner can revoke access' });
  }

  db.shares.update({ id: share_id }, {
    status: 'revoked',
    updated_at: new Date().toISOString()
  });

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
  const members = db.users.find(u => u.status === 'active' && u.id !== req.user.id)
    .map(m => ({
      id: m.id,
      full_name: m.full_name,
      email: m.email,
      role: m.role
    }))
    .sort((a, b) => a.full_name.localeCompare(b.full_name));

  res.json({ members });
}

module.exports = { shareFile, sharedByMe, sharedWithMe, revokeAccess, listShareableMembers };
