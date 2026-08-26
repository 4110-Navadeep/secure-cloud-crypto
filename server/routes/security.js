'use strict';
const express = require('express');
const router = express.Router();

const { getActivityLog, getThreatAnalytics, getDashboardStats } = require('../controllers/securityController');
const { authenticate, requireAdmin } = require('../middleware/auth');

router.get('/logs', authenticate, getActivityLog);
router.get('/threats', authenticate, requireAdmin, getThreatAnalytics);
router.get('/dashboard', authenticate, getDashboardStats);

module.exports = router;
