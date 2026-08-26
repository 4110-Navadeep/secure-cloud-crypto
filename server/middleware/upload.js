'use strict';
const multer = require('multer');
const config = require('../config/config');

// Store files in memory — we encrypt immediately and stream to S3, no disk storage
const storage = multer.memoryStorage();

function fileFilter(req, file, cb) {
  const allowed = config.upload.allowedMimeTypes;
  if (allowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type '${file.mimetype}' is not allowed`), false);
  }
}

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: config.upload.maxFileSizeMB * 1024 * 1024,
    files: 1,
  },
});

// Multer for .secure package uploads — allow any binary
const securePackageUpload = multer({
  storage,
  limits: {
    fileSize: 200 * 1024 * 1024, // 200 MB for .secure packages
    files: 1,
  },
});

module.exports = { upload, securePackageUpload };
