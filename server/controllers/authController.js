'use strict';
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const store = require('../store/jsonStore');
const { signToken } = require('../middleware/authMiddleware');

const BCRYPT_ROUNDS = 12;

// Seed default admin account automatically on startup
async function seedDefaultAdmin() {
  try {
    const defaultEmail = 'admin@securecrypt.com';
    const defaultPassword = 'SecureCrypt@123';
    const existing = store.findOne('admins', a => a.email.toLowerCase() === defaultEmail);
    if (!existing) {
      const passwordHash = await bcrypt.hash(defaultPassword, BCRYPT_ROUNDS);
      store.insert('admins', {
        id: uuidv4(),
        name: 'Default Admin',
        email: defaultEmail,
        passwordHash,
        role: 'primary_admin',
        createdAt: new Date().toISOString(),
      });
      console.log('[AUTH] Seeded default admin account successfully.');
    }
  } catch (err) {
    console.error('[AUTH] Seeding default admin failed:', err.message);
  }
}
seedDefaultAdmin();

// ---------------------------------------------------------------------------
// POST /api/auth/register
// ---------------------------------------------------------------------------
async function register(req, res) {
  try {
    const { name, email, password, confirmPassword } = req.body;

    // Validation
    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (!/(?=.*[A-Z])(?=.*[0-9])/.test(password)) {
      return res.status(400).json({ error: 'Password must contain at least one uppercase letter and one number.' });
    }

    // Duplicate check
    const existing = store.findOne('users', u => u.email.toLowerCase() === email.toLowerCase());
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const user = store.insert('users', {
      id: uuidv4(),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      passwordHash,
      role: 'user',
      status: 'active',
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: 'Account created successfully.',
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error('[AUTH] Register error:', err.message);
    return res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
}

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------
async function login(req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = store.findOne('users', u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    if (user.status === 'disabled') {
      return res.status(403).json({ error: 'Your account has been disabled. Please contact an administrator.' });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = signToken({ id: user.id, name: user.name, email: user.email, role: user.role });

    return res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err.message);
    return res.status(500).json({ error: 'Login failed. Please try again.' });
  }
}

// ---------------------------------------------------------------------------
// POST /api/auth/admin/login
// ---------------------------------------------------------------------------
async function adminLogin(req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const admin = store.findOne('admins', a => a.email.toLowerCase() === email.toLowerCase());
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const valid = await bcrypt.compare(password, admin.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = signToken({ id: admin.id, name: admin.name, email: admin.email, role: admin.role });

    return res.json({
      token,
      user: { id: admin.id, name: admin.name, email: admin.email, role: admin.role },
    });
  } catch (err) {
    console.error('[AUTH] Admin login error:', err.message);
    return res.status(500).json({ error: 'Login failed. Please try again.' });
  }
}

// ---------------------------------------------------------------------------
// POST /api/auth/admin/setup  (one-time bootstrap)
// ---------------------------------------------------------------------------
async function adminSetup(req, res) {
  return res.status(403).json({ error: 'Manual admin bootstrap is disabled. Please login directly using the default admin account.' });
}

// ---------------------------------------------------------------------------
// GET /api/auth/me
// ---------------------------------------------------------------------------
function me(req, res) {
  return res.json({ user: req.user });
}

module.exports = { register, login, adminLogin, adminSetup, me };
