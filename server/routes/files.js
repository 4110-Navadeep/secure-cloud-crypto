'use strict';
const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/authMiddleware');
const { publishFile, listPublished, myFiles, requestAccess, myRequests, sharedWithMe, deleteFile } = require('../controllers/filesController');

router.post('/publish', requireAuth, publishFile);
router.get('/published', requireAuth, listPublished);
router.get('/my-files', requireAuth, myFiles);
router.post('/request-access/:fileId', requireAuth, requestAccess);
router.get('/my-requests', requireAuth, myRequests);
router.get('/shared-with-me', requireAuth, sharedWithMe);
router.delete('/:id', requireAuth, deleteFile);

module.exports = router;
