'use strict';
const jwt = require('jsonwebtoken');
const config = require('../config/config');
const db = require('../database/db');
const { logEvent, EventTypes, extractRequestMeta } = require('../services/auditService');

/**
 * Verify JWT token from Authorization header or cookie.
 * Attaches req.user = { id, email, role, full_name }
 */
async function authenticate(req, res, next) {
  try {
    let token = null;

    // Check Authorization header first
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7);
    }

    // Fallback to cookie
    if (!token && req.cookies?.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, config.jwt.secret);

    // Fetch fresh user from DB to catch deactivated accounts
    const user = db.users.findOne({ id: decoded.id });

    if (!user) {
      return res.status(401).json({ error: 'User account not found' });
    }
    if (user.status !== 'active') {
      return res.status(403).json({ error: 'Account is inactive' });
    }

    req.user = {
      id: user.id,
      full_name: user.full_name,
      email: user.email,
      role: user.role,
      status: user.status
    };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid authentication token' });
  }
}

/**
 * Require admin role.
 */
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    const { ipAddress } = extractRequestMeta(req);
    logEvent({
      userId: req.user?.id,
      eventType: EventTypes.UNAUTHORIZED_ACCESS,
      ipAddress,
      details: { path: req.path },
      status: 'failure',
    });
    return res.status(403).json({ error: 'Administrator access required' });
  }
  next();
}

/**
 * Require member or admin role.
 */
function requireMember(req, res, next) {
  if (!req.user || !['admin', 'member'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
}

module.exports = { authenticate, requireAdmin, requireMember };
