'use strict';
const express = require('express');
const router = express.Router();

const { verifyPackage, decryptPackage } = require('../controllers/externalPackageController');
const { securePackageUpload } = require('../middleware/upload');
const { authenticate } = require('../middleware/auth');

// Verify step: public (anyone can upload and verify a .secure package)
router.post('/verify', securePackageUpload.single('package'), verifyPackage);

// Decrypt step: public (passphrase-protected, no account needed)
router.post('/decrypt', decryptPackage);

module.exports = router;
