'use strict';
const express = require('express');
const router = express.Router();

const multer = require('multer');
const { encrypt, decrypt } = require('../controllers/cryptoController');

// In-memory file storage — files are processed and immediately streamed back
const storage = multer.memoryStorage();

// Upload for original file (to encrypt) — accept any type, max 100 MB
const fileUpload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024, files: 1 },
});

// Upload for .secure package (to decrypt) — accept any binary, max 200 MB
const packageUpload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024, files: 1 },
});

// POST /api/crypto/encrypt
// Body: multipart/form-data — file + passphrase + signatureEnabled
// Returns: .secure package binary stream
router.post('/encrypt', fileUpload.single('file'), encrypt);

// POST /api/crypto/decrypt
// Body: multipart/form-data — package (.secure file) + passphrase
// Returns: original file binary stream
router.post('/decrypt', packageUpload.single('package'), decrypt);

module.exports = router;
