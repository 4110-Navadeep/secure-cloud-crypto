'use strict';
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');

const cryptoRoutes = require('./routes/crypto');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const filesRoutes = require('./routes/files');

const app = express();

// ---------------------------------------------------------------------------
// Security Headers
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
    },
  },
}));

// ---------------------------------------------------------------------------
// CORS — allow same origin + optional APP_URL
// ---------------------------------------------------------------------------
app.use(cors({
  origin: process.env.APP_URL || true,
  credentials: false,
}));

// ---------------------------------------------------------------------------
// Body Parsing
// ---------------------------------------------------------------------------
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// ---------------------------------------------------------------------------
// Rate Limiting — encrypt/decrypt endpoints
// ---------------------------------------------------------------------------
const cryptoLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait before retrying.' },
});
app.use('/api/crypto', cryptoLimiter);

// ---------------------------------------------------------------------------
// Static Files
// ---------------------------------------------------------------------------
app.use(express.static(path.join(__dirname, '..', 'public'), {
  index: false,
  maxAge: '1h',
}));

// ---------------------------------------------------------------------------
// Health Check
// ---------------------------------------------------------------------------
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Secure Cloud File Sharing System — Hybrid Cryptography',
    timestamp: new Date().toISOString(),
    algorithms: ['AES-256-GCM', 'RSA-2048-OAEP', 'SHA-256', 'RSA-SHA256', 'PBKDF2'],
    storage: 'stateless — no files stored server-side',
  });
});

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------
app.use('/api/crypto', cryptoRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/files', filesRoutes);

// ---------------------------------------------------------------------------
// SPA Fallback — serve index.html for all non-API routes
// ---------------------------------------------------------------------------
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Not found' });
  }
  const htmlFile = req.path === '/' ? 'index.html' : req.path.slice(1);
  const fullPath = path.join(__dirname, '..', 'public', htmlFile);
  res.sendFile(fullPath, err => {
    if (err) {
      res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
    }
  });
});

// ---------------------------------------------------------------------------
// Error Handler
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('[SERVER] Unhandled error:', err.message);
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large. Maximum 100 MB.' });
  }
  res.status(500).json({ error: 'An internal server error occurred' });
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
async function start() {
  const PORT = Number(process.env.PORT || 5000);
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SERVER] Secure Cloud Cryptography System started.`);
    console.log(`[SERVER] Listening on http://0.0.0.0:${PORT}`);
    console.log(`[SERVER] Mode: ${process.env.NODE_ENV || 'development'}`);
    console.log(`[SERVER] Architecture: Stateless — no server-side file storage.`);
  });
}

if (process.env.NODE_ENV !== 'test') {
  start();
}

module.exports = app;
