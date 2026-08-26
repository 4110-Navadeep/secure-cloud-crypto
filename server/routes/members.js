'use strict';
const express = require('express');
const router = express.Router();

const {
  inviteMember, validateInvitation, registerViainvitation,
  listMembers, listInvitations, updateMemberStatus,
} = require('../controllers/memberController');
const { authenticate, requireAdmin } = require('../middleware/auth');

// Public routes (for invitation acceptance)
router.get('/invitations/:token', validateInvitation);
router.post('/register', registerViainvitation);

// Admin-only routes
router.post('/invite', authenticate, requireAdmin, inviteMember);
router.get('/', authenticate, requireAdmin, listMembers);
router.get('/invitations', authenticate, requireAdmin, listInvitations);
router.patch('/:id/status', authenticate, requireAdmin, updateMemberStatus);

module.exports = router;
