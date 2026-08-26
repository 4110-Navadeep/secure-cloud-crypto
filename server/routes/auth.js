'use strict';
const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');

const { setupAdmin, checkSetup, login, logout, getProfile, updateProfile } = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

router.get('/setup-status', checkSetup);
router.post('/setup', setupAdmin);
router.post('/login', loginLimiter, login);
router.post('/logout', authenticate, logout);
router.get('/me', authenticate, getProfile);
router.put('/me', authenticate, updateProfile);

module.exports = router;
