'use strict';
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const store = require('../store/jsonStore');
const { signToken } = require('../middleware/authMiddleware');

const BCRYPT_ROUNDS = 12;

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
  try {
    const setupToken = process.env.ADMIN_SETUP_TOKEN;
    if (!setupToken) {
      return res.status(403).json({ error: 'Admin setup is not configured on this server.' });
    }

    const { token, name, email, password } = req.body;
    if (token !== setupToken) {
      return res.status(403).json({ error: 'Invalid setup token.' });
    }

    // Only allow setup if no admins exist yet
    const admins = store.readAll('admins');
    if (admins.length > 0) {
      return res.status(409).json({ error: 'Admin account already exists. Setup can only be run once.' });
    }

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }
    if (password.length < 10) {
      return res.status(400).json({ error: 'Admin password must be at least 10 characters.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const admin = store.insert('admins', {
      id: uuidv4(),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      passwordHash,
      role: 'primary_admin',
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: 'Primary administrator created successfully.',
      admin: { id: admin.id, name: admin.name, email: admin.email, role: admin.role },
    });
  } catch (err) {
    console.error('[AUTH] Admin setup error:', err.message);
    return res.status(500).json({ error: 'Setup failed.' });
  }
}

// ---------------------------------------------------------------------------
// GET /api/auth/me
// ---------------------------------------------------------------------------
function me(req, res) {
  return res.json({ user: req.user });
}

module.exports = { register, login, adminLogin, adminSetup, me };
