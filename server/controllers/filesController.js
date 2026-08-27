'use strict';
const { v4: uuidv4 } = require('uuid');
const store = require('../store/jsonStore');

// ---------------------------------------------------------------------------
// POST /api/files/publish
// Stores only metadata — the actual .secure file stays with the user.
// ---------------------------------------------------------------------------
function publishFile(req, res) {
  try {
    const { filename, description, originalSize, encryptionAlgorithm, hasSignature } = req.body;
    if (!filename) return res.status(400).json({ error: 'Filename is required.' });

    const share = store.insert('shares', {
      id: uuidv4(),
      ownerId: req.user.id,
      ownerName: req.user.name,
      filename: filename.trim(),
      description: (description || '').trim(),
      originalSize: originalSize || null,
      encryptionAlgorithm: encryptionAlgorithm || 'AES-256-GCM',
      hasSignature: !!hasSignature,
      status: 'published',
      accessList: [],
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({ message: 'File published.', file: share });
  } catch (err) {
    console.error('[FILES] Publish error:', err.message);
    return res.status(500).json({ error: 'Failed to publish file.' });
  }
}

// ---------------------------------------------------------------------------
// GET /api/files/published
// All published files (visible to authenticated users)
// ---------------------------------------------------------------------------
function listPublished(req, res) {
  const shares = store.readAll('shares').map(s => ({
    id: s.id,
    ownerId: s.ownerId,
    ownerName: s.ownerName,
    filename: s.filename,
    description: s.description,
    encryptionAlgorithm: s.encryptionAlgorithm,
    hasSignature: s.hasSignature,
    status: s.status,
    createdAt: s.createdAt,
    isOwner: s.ownerId === req.user.id,
    hasAccess: s.ownerId === req.user.id || (s.accessList || []).includes(req.user.id),
  }));
  return res.json({ files: shares });
}

// ---------------------------------------------------------------------------
// GET /api/files/my-files
// Files published by the current user
// ---------------------------------------------------------------------------
function myFiles(req, res) {
  const shares = store.findMany('shares', s => s.ownerId === req.user.id);
  return res.json({ files: shares });
}

// ---------------------------------------------------------------------------
// POST /api/files/request-access/:fileId
// ---------------------------------------------------------------------------
function requestAccess(req, res) {
  try {
    const { fileId } = req.params;
    const file = store.findById('shares', fileId);
    if (!file) return res.status(404).json({ error: 'File not found.' });

    if (file.ownerId === req.user.id) {
      return res.status(400).json({ error: 'You already own this file.' });
    }
    if ((file.accessList || []).includes(req.user.id)) {
      return res.status(400).json({ error: 'You already have access to this file.' });
    }

    // Check if already requested
    const existing = store.findOne('access', r =>
      r.fileId === fileId && r.requesterId === req.user.id && r.status === 'pending'
    );
    if (existing) return res.status(400).json({ error: 'You already have a pending request for this file.' });

    const request = store.insert('access', {
      id: uuidv4(),
      fileId,
      requesterId: req.user.id,
      requesterName: req.user.name,
      status: 'pending',
      requestedAt: new Date().toISOString(),
      reviewedAt: null,
      reviewNote: '',
    });

    return res.status(201).json({ message: 'Access request submitted.', request });
  } catch (err) {
    console.error('[FILES] Request access error:', err.message);
    return res.status(500).json({ error: 'Failed to submit request.' });
  }
}

// ---------------------------------------------------------------------------
// GET /api/files/my-requests
// Access requests submitted by the current user
// ---------------------------------------------------------------------------
function myRequests(req, res) {
  const requests = store.findMany('access', r => r.requesterId === req.user.id);
  const shares = store.readAll('shares');
  const enriched = requests.map(r => {
    const file = shares.find(s => s.id === r.fileId) || {};
    return { ...r, filename: file.filename || 'Unknown', ownerName: file.ownerName || '' };
  });
  return res.json({ requests: enriched });
}

// ---------------------------------------------------------------------------
// GET /api/files/shared-with-me
// Files the user has been granted access to (approved requests)
// ---------------------------------------------------------------------------
function sharedWithMe(req, res) {
  const shares = store.findMany('shares', s =>
    s.ownerId !== req.user.id && (s.accessList || []).includes(req.user.id)
  );
  return res.json({ files: shares });
}

// ---------------------------------------------------------------------------
// DELETE /api/files/:id  (owner only)
// ---------------------------------------------------------------------------
function deleteFile(req, res) {
  const { id } = req.params;
  const file = store.findById('shares', id);
  if (!file) return res.status(404).json({ error: 'File not found.' });
  if (file.ownerId !== req.user.id) return res.status(403).json({ error: 'Not authorized.' });
  store.removeById('shares', id);
  return res.json({ message: 'File removed.' });
}

module.exports = { publishFile, listPublished, myFiles, requestAccess, myRequests, sharedWithMe, deleteFile };
