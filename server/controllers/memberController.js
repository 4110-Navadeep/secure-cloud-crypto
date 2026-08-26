'use strict';
/**
 * Member/Admin Management Controller
 * Handles: invite members, list members, view invitations, accept invitation, register
 */

const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const validator = require('validator');

const db = require('../database/db');
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
    const existing = db.users.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ error: 'A user with this email already exists' });
    }

    // Check for existing pending invitation
    const existingInvite = db.members.findOne({
      email: email.toLowerCase(),
      status: 'pending'
    });
    if (existingInvite) {
      return res.status(409).json({ error: 'An invitation for this email is already pending' });
    }

    // Generate secure token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString(); // 48 hours

    const inviteId = uuidv4();
    db.members.insert({
      id: inviteId,
      email: email.toLowerCase(),
      full_name: full_name.trim(),
      role,
      token,
      status: 'pending',
      invited_by: req.user.id,
      expires_at: expiresAt
    });

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
  const inv = db.members.findOne({ token });

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

    const inv = db.members.findOne({ token, status: 'pending' });
    if (!inv) return res.status(404).json({ error: 'Invalid or expired invitation' });
    if (new Date(inv.expires_at) < new Date()) {
      db.members.update({ id: inv.id }, { status: 'expired' });
      return res.status(410).json({ error: 'Invitation has expired' });
    }

    // Check user doesn't already exist
    const existing = db.users.findOne({ email: inv.email });
    if (existing) return res.status(409).json({ error: 'Account already exists for this email' });

    const id = uuidv4();
    const password_hash = await bcrypt.hash(password, 12);

    // Generate RSA key pair
    const { publicKey, privateKey } = generateRSAKeyPair();
    const encryptedPrivateKey = encryptPrivateKeyForStorage(privateKey, id);

    db.users.insert({
      id,
      full_name: inv.full_name,
      email: inv.email,
      password_hash,
      role: inv.role,
      status: 'active',
      rsa_public_key: publicKey,
      rsa_private_key_enc: encryptedPrivateKey
    });

    db.members.update({ id: inv.id }, { status: 'accepted' });

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
  const members = db.users.find().map(m => ({
    id: m.id,
    full_name: m.full_name,
    email: m.email,
    role: m.role,
    status: m.status,
    created_at: m.created_at
  })).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  res.json({ members });
}

// ---------------------------------------------------------------------------
// Admin: List All Invitations
// ---------------------------------------------------------------------------

async function listInvitations(req, res) {
  const invitations = db.members.find().map(inv => {
    const inviter = db.users.findOne({ id: inv.invited_by });
    return {
      id: inv.id,
      email: inv.email,
      full_name: inv.full_name,
      role: inv.role,
      status: inv.status,
      expires_at: inv.expires_at,
      created_at: inv.created_at,
      invited_by_name: inviter ? inviter.full_name : 'System'
    };
  }).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

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

  db.users.update({ id }, { status });
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
