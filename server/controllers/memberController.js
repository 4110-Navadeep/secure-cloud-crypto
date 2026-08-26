'use strict';
/**
 * Member/Admin Management Controller
 * Handles: invite members, list members, view invitations, accept invitation, register
 */

const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const validator = require('validator');

const { query, queryOne } = require('../database/db');
const { generateRSAKeyPair, encryptPrivateKeyForStorage } = require('../crypto/cryptoService');
const { sendInvitationEmail } = require('../services/emailService');
const { logEvent, EventTypes, extractRequestMeta } = require('../services/auditService');

// ---------------------------------------------------------------------------
// Admin: Add/Invite Member
// ---------------------------------------------------------------------------

async function inviteMember(req, res) {
  const meta = extractRequestMeta(req);
  try {
    const { full_name, email, role = 'member' } = req.body;

    if (!full_name || !email) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    if (!['admin', 'member'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Check if user already exists
    const existing = await queryOne('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing) {
      return res.status(409).json({ error: 'A user with this email already exists' });
    }

    // Check for existing pending invitation
    const existingInvite = await queryOne(
      "SELECT id FROM invitations WHERE email = ? AND status = 'pending'",
      [email.toLowerCase()]
    );
    if (existingInvite) {
      return res.status(409).json({ error: 'An invitation for this email is already pending' });
    }

    // Generate secure token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

    const inviteId = uuidv4();
    await query(
      `INSERT INTO invitations (id, email, full_name, role, token, status, invited_by, expires_at)
       VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`,
      [inviteId, email.toLowerCase(), full_name.trim(), role, token, req.user.id, expiresAt]
    );

    // Send invitation email
    try {
      await sendInvitationEmail({
        to: email.toLowerCase(),
        name: full_name.trim(),
        token,
        invitedBy: req.user.full_name,
      });
    } catch (emailErr) {
      console.error('[MEMBER] Email send failed:', emailErr.message);
      // Don't fail the request — invitation is still created
    }

    await logEvent({
      userId: req.user.id,
      eventType: EventTypes.INVITATION_SENT,
      ...meta,
      details: { invitedEmail: email, role },
      status: 'success',
    });

    res.status(201).json({
      message: `Invitation sent to ${email}`,
      invitation: { id: inviteId, email, full_name, role, expires_at: expiresAt },
    });
  } catch (err) {
    console.error('[MEMBER] Invite error:', err);
    res.status(500).json({ error: 'Failed to send invitation' });
  }
}

// ---------------------------------------------------------------------------
// Public: Validate Invitation Token
// ---------------------------------------------------------------------------

async function validateInvitation(req, res) {
  const { token } = req.params;
  const inv = await queryOne(
    "SELECT id, email, full_name, role, expires_at, status FROM invitations WHERE token = ?",
    [token]
  );

  if (!inv) return res.status(404).json({ error: 'Invitation not found or invalid' });
  if (inv.status === 'accepted') return res.status(409).json({ error: 'Invitation already accepted' });
  if (inv.status === 'expired' || new Date(inv.expires_at) < new Date()) {
    return res.status(410).json({ error: 'Invitation has expired' });
  }

  res.json({ invitation: { email: inv.email, full_name: inv.full_name, role: inv.role } });
}

// ---------------------------------------------------------------------------
// Public: Register via Invitation
// ---------------------------------------------------------------------------

async function registerViainvitation(req, res) {
  const meta = extractRequestMeta(req);
  try {
    const { token, password, confirm_password } = req.body;

    if (!token || !password || !confirm_password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    if (password !== confirm_password) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const inv = await queryOne(
      "SELECT * FROM invitations WHERE token = ? AND status = 'pending'",
      [token]
    );
    if (!inv) return res.status(404).json({ error: 'Invalid or expired invitation' });
    if (new Date(inv.expires_at) < new Date()) {
      await query("UPDATE invitations SET status = 'expired' WHERE id = ?", [inv.id]);
      return res.status(410).json({ error: 'Invitation has expired' });
    }

    // Check user doesn't already exist
    const existing = await queryOne('SELECT id FROM users WHERE email = ?', [inv.email]);
    if (existing) return res.status(409).json({ error: 'Account already exists for this email' });

    const id = uuidv4();
    const password_hash = await bcrypt.hash(password, 12);

    // Generate RSA key pair
    const { publicKey, privateKey } = generateRSAKeyPair();
    const encryptedPrivateKey = encryptPrivateKeyForStorage(privateKey, id);

    await query(
      `INSERT INTO users (id, full_name, email, password_hash, role, status, rsa_public_key, rsa_private_key_enc)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`,
      [id, inv.full_name, inv.email, password_hash, inv.role, publicKey, encryptedPrivateKey]
    );

    await query("UPDATE invitations SET status = 'accepted' WHERE id = ?", [inv.id]);

    await logEvent({
      userId: id,
      eventType: EventTypes.INVITATION_ACCEPTED,
      ...meta,
      details: { email: inv.email, role: inv.role },
      status: 'success',
    });
    await logEvent({ userId: id, eventType: EventTypes.REGISTER, ...meta, status: 'success' });

    res.status(201).json({ message: 'Account created successfully. You can now log in.' });
  } catch (err) {
    console.error('[MEMBER] Registration error:', err);
    res.status(500).json({ error: 'Failed to create account' });
  }
}

// ---------------------------------------------------------------------------
// Admin: List All Members
// ---------------------------------------------------------------------------

async function listMembers(req, res) {
  const members = await query(
    `SELECT id, full_name, email, role, status, created_at FROM users ORDER BY created_at DESC`,
    []
  );
  res.json({ members });
}

// ---------------------------------------------------------------------------
// Admin: List All Invitations
// ---------------------------------------------------------------------------

async function listInvitations(req, res) {
  const invitations = await query(
    `SELECT i.id, i.email, i.full_name, i.role, i.status, i.expires_at, i.created_at,
            u.full_name AS invited_by_name
     FROM invitations i
     LEFT JOIN users u ON u.id = i.invited_by
     ORDER BY i.created_at DESC`,
    []
  );
  res.json({ invitations });
}

// ---------------------------------------------------------------------------
// Admin: Update Member Status
// ---------------------------------------------------------------------------

async function updateMemberStatus(req, res) {
  const { id } = req.params;
  const { status } = req.body;

  if (!['active', 'inactive'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  // Cannot deactivate self
  if (id === req.user.id) {
    return res.status(400).json({ error: 'Cannot change your own account status' });
  }

  await query('UPDATE users SET status = ? WHERE id = ?', [status, id]);
  res.json({ message: `Member status updated to ${status}` });
}

module.exports = {
  inviteMember,
  validateInvitation,
  registerViainvitation,
  listMembers,
  listInvitations,
  updateMemberStatus,
};
