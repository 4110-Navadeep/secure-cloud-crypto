'use strict';
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const store = require('../store/jsonStore');

const BCRYPT_ROUNDS = 12;

// ---------------------------------------------------------------------------
// GET /api/admin/users
// ---------------------------------------------------------------------------
function listUsers(req, res) {
  const users = store.readAll('users').map(u => ({
    id: u.id, name: u.name, email: u.email,
    role: u.role, status: u.status, createdAt: u.createdAt,
  }));
  return res.json({ users });
}

// ---------------------------------------------------------------------------
// PATCH /api/admin/users/:id/status
// ---------------------------------------------------------------------------
function setUserStatus(req, res) {
  const { id } = req.params;
  const { status } = req.body;
  if (!['active', 'disabled'].includes(status)) {
    return res.status(400).json({ error: 'Status must be "active" or "disabled".' });
  }
  const user = store.findById('users', id);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const updated = store.updateById('users', id, { status });
  return res.json({ message: `User ${status}.`, user: { id: updated.id, name: updated.name, status: updated.status } });
}

// ---------------------------------------------------------------------------
// GET /api/admin/access-requests
// ---------------------------------------------------------------------------
function listAccessRequests(req, res) {
  const requests = store.readAll('access');
  const shares = store.readAll('shares');
  const users = store.readAll('users');

  const enriched = requests.map(r => {
    const file = shares.find(s => s.id === r.fileId) || {};
    const requester = users.find(u => u.id === r.requesterId) || {};
    return {
      id: r.id,
      fileId: r.fileId,
      filename: file.filename || 'Unknown',
      requesterName: requester.name || 'Unknown',
      requesterEmail: requester.email || '',
      status: r.status,
      requestedAt: r.requestedAt,
      reviewedAt: r.reviewedAt,
      reviewNote: r.reviewNote,
    };
  });
  return res.json({ requests: enriched });
}

// ---------------------------------------------------------------------------
// PATCH /api/admin/access-requests/:id
// ---------------------------------------------------------------------------
function reviewAccessRequest(req, res) {
  const { id } = req.params;
  const { status, reviewNote } = req.body;

  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Status must be "approved" or "rejected".' });
  }

  const request = store.findById('access', id);
  if (!request) return res.status(404).json({ error: 'Request not found.' });

  store.updateById('access', id, {
    status,
    reviewNote: reviewNote || '',
    reviewedAt: new Date().toISOString(),
  });

  // If approved, add requester to file's accessList
  if (status === 'approved') {
    const share = store.findById('shares', request.fileId);
    if (share) {
      const accessList = share.accessList || [];
      if (!accessList.includes(request.requesterId)) {
        store.updateById('shares', request.fileId, { accessList: [...accessList, request.requesterId] });
      }
    }
  }

  return res.json({ message: `Access request ${status}.` });
}

// ---------------------------------------------------------------------------
// GET /api/admin/stats
// ---------------------------------------------------------------------------
function getStats(req, res) {
  const users = store.readAll('users');
  const shares = store.readAll('shares');
  const requests = store.readAll('access');
  const admins = store.readAll('admins');

  return res.json({
    totalUsers: users.length,
    activeUsers: users.filter(u => u.status === 'active').length,
    disabledUsers: users.filter(u => u.status === 'disabled').length,
    totalPublishedFiles: shares.length,
    totalAccessRequests: requests.length,
    pendingRequests: requests.filter(r => r.status === 'pending').length,
    approvedRequests: requests.filter(r => r.status === 'approved').length,
    totalAdmins: admins.length,
  });
}

// ---------------------------------------------------------------------------
// POST /api/admin/admins  (primary admin only)
// ---------------------------------------------------------------------------
async function createAdmin(req, res) {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }
    const allowedRoles = ['admin', 'primary_admin'];
    const adminRole = allowedRoles.includes(role) ? role : 'admin';

    const existing = store.findOne('admins', a => a.email.toLowerCase() === email.toLowerCase());
    if (existing) return res.status(409).json({ error: 'An admin with this email already exists.' });

    if (password.length < 10) {
      return res.status(400).json({ error: 'Admin password must be at least 10 characters.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const admin = store.insert('admins', {
      id: uuidv4(),
      name: name.trim(),
      email: email.toLowerCase().trim(),
      passwordHash,
      role: adminRole,
      createdBy: req.user.id,
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: 'Administrator created.',
      admin: { id: admin.id, name: admin.name, email: admin.email, role: admin.role },
    });
  } catch (err) {
    console.error('[ADMIN] Create admin error:', err.message);
    return res.status(500).json({ error: 'Failed to create administrator.' });
  }
}

// ---------------------------------------------------------------------------
// GET /api/admin/admins
// ---------------------------------------------------------------------------
function listAdmins(req, res) {
  const admins = store.readAll('admins').map(a => ({
    id: a.id, name: a.name, email: a.email, role: a.role, createdAt: a.createdAt,
  }));
  return res.json({ admins });
}

module.exports = { listUsers, setUserStatus, listAccessRequests, reviewAccessRequest, getStats, createAdmin, listAdmins };
