'use strict';
const express = require('express');
const router = express.Router();
const { requireAdmin, requirePrimaryAdmin } = require('../middleware/authMiddleware');
const {
  listUsers, setUserStatus,
  listAccessRequests, reviewAccessRequest,
  getStats, createAdmin, listAdmins,
} = require('../controllers/adminController');

router.get('/users', requireAdmin, listUsers);
router.patch('/users/:id/status', requireAdmin, setUserStatus);
router.get('/access-requests', requireAdmin, listAccessRequests);
router.patch('/access-requests/:id', requireAdmin, reviewAccessRequest);
router.get('/stats', requireAdmin, getStats);
router.get('/admins', requireAdmin, listAdmins);
router.post('/admins', requirePrimaryAdmin, createAdmin);

module.exports = router;
