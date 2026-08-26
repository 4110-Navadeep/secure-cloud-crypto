'use strict';
/**
 * Authentication Controller
 * Handles: admin setup, login, logout, profile
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const validator = require('validator');

const { query, queryOne } = require('../database/db');
const config = require('../config/config');
const { generateRSAKeyPair, encryptPrivateKeyForStorage } = require('../crypto/cryptoService');
const { logEvent, EventTypes, extractRequestMeta } = require('../services/auditService');

// ---------------------------------------------------------------------------
// Admin Setup (first-run only)
// ---------------------------------------------------------------------------

async function setupAdmin(req, res) {
  try {
    // Check if any admin exists
    const existing = await queryOne("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
    if (existing) {
      return res.status(403).json({ error: 'Administrator account already exists. Setup is disabled.' });
    }

    const { full_name, email, password, confirm_password } = req.body;

    if (!full_name || !email || !password || !confirm_password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    if (password !== confirm_password) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const id = uuidv4();
    const password_hash = await bcrypt.hash(password, 12);

    // Generate RSA key pair for the admin
    const { publicKey, privateKey } = generateRSAKeyPair();
    const encryptedPrivateKey = encryptPrivateKeyForStorage(privateKey, id);

    await query(
      `INSERT INTO users (id, full_name, email, password_hash, role, status, rsa_public_key, rsa_private_key_enc)
       VALUES (?, ?, ?, ?, 'admin', 'active', ?, ?)`,
      [id, full_name.trim(), email.toLowerCase(), password_hash, publicKey, encryptedPrivateKey]
    );

    const meta = extractRequestMeta(req);
    await logEvent({ userId: id, eventType: EventTypes.REGISTER, ...meta, details: { role: 'admin' }, status: 'success' });

    res.status(201).json({ message: 'Administrator account created successfully.' });
  } catch (err) {
    console.error('[AUTH] Setup error:', err);
    res.status(500).json({ error: 'Failed to create administrator account' });
  }
}

// ---------------------------------------------------------------------------
// Check if admin exists (for frontend routing)
// ---------------------------------------------------------------------------

async function checkSetup(req, res) {
  const admin = await queryOne("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
  res.json({ setupRequired: !admin });
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

async function login(req, res) {
  const meta = extractRequestMeta(req);
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await queryOne(
      'SELECT id, full_name, email, password_hash, role, status FROM users WHERE email = ?',
      [email.toLowerCase()]
    );

    if (!user) {
      await logEvent({ eventType: EventTypes.LOGIN_FAILED, ...meta, details: { email }, status: 'failure' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.status === 'pending') {
      return res.status(403).json({ error: 'Account pending activation. Please accept your invitation.' });
    }
    if (user.status !== 'active') {
      return res.status(403).json({ error: 'Account is inactive. Contact your administrator.' });
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      await logEvent({ userId: user.id, eventType: EventTypes.LOGIN_FAILED, ...meta, details: { email }, status: 'failure' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    await logEvent({ userId: user.id, eventType: EventTypes.LOGIN_SUCCESS, ...meta, status: 'success' });

    // Set httpOnly cookie + return token in body
    res.cookie('token', token, {
      httpOnly: true,
      secure: config.app.nodeEnv === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24h
    });

    res.json({
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

async function logout(req, res) {
  const meta = extractRequestMeta(req);
  if (req.user) {
    await logEvent({ userId: req.user.id, eventType: EventTypes.LOGOUT, ...meta });
  }
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
}

// ---------------------------------------------------------------------------
// Get Profile
// ---------------------------------------------------------------------------

async function getProfile(req, res) {
  try {
    const user = await queryOne(
      'SELECT id, full_name, email, role, status, rsa_public_key, created_at FROM users WHERE id = ?',
      [req.user.id]
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
}

// ---------------------------------------------------------------------------
// Update Profile
// ---------------------------------------------------------------------------

async function updateProfile(req, res) {
  try {
    const { full_name, current_password, new_password } = req.body;

    if (full_name) {
      await query('UPDATE users SET full_name = ? WHERE id = ?', [full_name.trim(), req.user.id]);
    }

    if (current_password && new_password) {
      const user = await queryOne('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
      const valid = await bcrypt.compare(current_password, user.password_hash);
      if (!valid) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
      if (new_password.length < 8) {
        return res.status(400).json({ error: 'New password must be at least 8 characters' });
      }
      const hash = await bcrypt.hash(new_password, 12);
      await query('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.user.id]);
    }

    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('[AUTH] Update profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
}

module.exports = { setupAdmin, checkSetup, login, logout, getProfile, updateProfile };
