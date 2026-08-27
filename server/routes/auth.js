'use strict';
const express = require('express');
const router = express.Router();
const { register, login, adminLogin, adminSetup, me } = require('../controllers/authController');
const { requireAuth } = require('../middleware/authMiddleware');

router.post('/register', register);
router.post('/login', login);
router.post('/admin/login', adminLogin);
router.post('/admin/setup', adminSetup);
router.get('/me', requireAuth, me);

module.exports = router;
