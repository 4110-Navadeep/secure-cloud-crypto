'use strict';
const express = require('express');
const router = express.Router();

const { shareFile, sharedByMe, sharedWithMe, revokeAccess, listShareableMembers } = require('../controllers/sharingController');
const { authenticate } = require('../middleware/auth');

router.get('/members', authenticate, listShareableMembers);
router.post('/', authenticate, shareFile);
router.get('/by-me', authenticate, sharedByMe);
router.get('/with-me', authenticate, sharedWithMe);
router.patch('/:share_id/revoke', authenticate, revokeAccess);

module.exports = router;
