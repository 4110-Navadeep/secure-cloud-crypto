'use strict';
const express = require('express');
const router = express.Router();

const { getMetrics, runBenchmark, getKeyInfo } = require('../controllers/performanceController');
const { authenticate } = require('../middleware/auth');

router.get('/', authenticate, getMetrics);
router.get('/benchmark', authenticate, runBenchmark);
router.get('/keys', authenticate, getKeyInfo);

module.exports = router;
