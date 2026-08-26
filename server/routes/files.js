'use strict';
const express = require('express');
const router = express.Router();

const {
  uploadAndEncrypt, listMyFiles, downloadSecurePackage,
  downloadOriginalFile, deleteFile, getFileDetails,
} = require('../controllers/fileController');
const { authenticate } = require('../middleware/auth');
const { upload } = require('../middleware/upload');

router.get('/', authenticate, listMyFiles);
router.post('/upload', authenticate, upload.single('file'), uploadAndEncrypt);
router.get('/:id', authenticate, getFileDetails);
router.get('/:id/download-secure', authenticate, downloadSecurePackage);
router.get('/:id/download-original', authenticate, downloadOriginalFile);
router.delete('/:id', authenticate, deleteFile);

module.exports = router;
