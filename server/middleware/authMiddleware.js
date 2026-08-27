'use strict';
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'secure-cloud-dev-secret-change-in-production-32c';
const JWT_EXPIRES = '8h';

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

/**
 * Middleware: require a valid user JWT.
 */
function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const payload = verifyToken(token);
    if (payload.role === 'admin' || payload.role === 'primary_admin') {
      // Admins can call user routes too
      req.user = payload;
    } else {
      req.user = payload;
    }
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session. Please log in again.' });
  }
}

/**
 * Middleware: require a valid admin JWT.
 */
function requireAdmin(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Admin authentication required' });
    const payload = verifyToken(token);
    if (payload.role !== 'admin' && payload.role !== 'primary_admin') {
      return res.status(403).json({ error: 'Administrator access required' });
    }
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired admin session.' });
  }
}

/**
 * Middleware: require primary admin role.
 */
function requirePrimaryAdmin(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Admin authentication required' });
    const payload = verifyToken(token);
    if (payload.role !== 'primary_admin') {
      return res.status(403).json({ error: 'Primary administrator access required' });
    }
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired admin session.' });
  }
}

module.exports = { signToken, verifyToken, requireAuth, requireAdmin, requirePrimaryAdmin };
