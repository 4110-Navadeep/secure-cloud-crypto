'use strict';
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const rateLimit = require('express-rate-limit');

const config = require('./config/config');
const { testConnection } = require('./database/db');
const { runMigrations } = require('./database/migrate');

// Routes
const authRoutes = require('./routes/auth');
const memberRoutes = require('./routes/members');
const fileRoutes = require('./routes/files');
const sharingRoutes = require('./routes/sharing');
const externalPackageRoutes = require('./routes/externalPackage');
const securityRoutes = require('./routes/security');
const performanceRoutes = require('./routes/performance');

const app = express();

// ---------------------------------------------------------------------------
// Security Headers
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'", "blob:"],
    },
  },
}));

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------
app.use(cors({
  origin: config.app.url,
  credentials: true,
}));

// ---------------------------------------------------------------------------
// Body Parsing
// ---------------------------------------------------------------------------
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ---------------------------------------------------------------------------
// Global Rate Limit
// ---------------------------------------------------------------------------
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});
app.use('/api', globalLimiter);

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
app.get('/health', async (req, res) => {
  try {
    await testConnection();
    res.json({ status: 'ok', database: 'connected', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'error', database: 'disconnected', message: err.message });
  }
});

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------
app.use('/api/auth', authRoutes);
app.use('/api/members', memberRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/sharing', sharingRoutes);
app.use('/api/external-package', externalPackageRoutes);
app.use('/api/security', securityRoutes);
app.use('/api/performance', performanceRoutes);

// ---------------------------------------------------------------------------
// SPA Fallback — serve index.html for all non-API routes
// ---------------------------------------------------------------------------
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Not found' });
  }
  // Try to serve specific HTML files
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
  console.error('[SERVER] Unhandled error:', err);

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: `File too large. Maximum size is ${config.upload.maxFileSizeMB} MB.` });
  }
  if (err.message && err.message.includes('File type')) {
    return res.status(400).json({ error: err.message });
  }

  res.status(500).json({ error: 'An internal server error occurred' });
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
async function start() {
  try {
    // -----------------------------------------------------------------------
    // PORT separation:
    //   process.env.PORT    → Express web server (provided by Render)
    //   process.env.DB_PORT → MySQL database port (default 3306)
    //   THESE MUST NEVER BE MIXED.
    // -----------------------------------------------------------------------
    const EXPRESS_PORT = Number(process.env.PORT || 5000);

    // Validate required env vars. DB_PORT is optional (defaults to 3306 in db.js).
    const requiredVars = [
      { name: 'JWT_SECRET',          val: config.jwt.secret },
      { name: 'APPLICATION_SECRET',  val: config.app.secret },
      { name: 'DB_HOST',             val: config.db.host },
      { name: 'DB_USER',             val: config.db.user },
      { name: 'DB_PASSWORD',         val: config.db.password },
      { name: 'DB_NAME',             val: config.db.database },
    ];

    for (const v of requiredVars) {
      if (!v.val && v.val !== 0) {
        console.error(`[SERVER] Missing required environment variable: ${v.name}`);
        process.exit(1);
      }
    }

    const dbPort = Number(process.env.DB_PORT || 3306);
    console.log(`[DATABASE] Connecting to configured MySQL server at ${config.db.host}:${dbPort} ...`);

    await testConnection();
    console.log('[DATABASE] MySQL connection successful.');

    await runMigrations();

    // Express listens on process.env.PORT (provided by Render), NOT on DB_PORT
    app.listen(EXPRESS_PORT, '0.0.0.0', () => {
      console.log(`[SERVER] Application started successfully. Listening on http://0.0.0.0:${EXPRESS_PORT}`);
      console.log(`[SERVER] Environment: ${config.app.nodeEnv}`);
    });
  } catch (err) {
    console.error('[SERVER] Fatal startup error:', err.message);
    process.exit(1);
  }
}

start();

module.exports = app; // for testing
