function normalizeWorkshopKeys(rawValue) {
  const values = Array.isArray(rawValue) ? rawValue : String(rawValue || '').split(',');
  return [...new Set(values
    .map((value) => String(value).trim())
    .filter((value) => value === '*' || /^[a-z0-9_-]{1,100}$/i.test(value))
  )].slice(0, 50);
}

function createRevisionSnapshotHandler(store, { hasPermission } = {}) {
  if (!store || typeof store.getSnapshot !== 'function') throw new TypeError('Change revision store is required');

  return async function revisionSnapshotHandler(req, res) {
    if (!req.user?.id) return res.status(401).json({ error: 'Authentication required' });
    try {
      const includeAdminProgress = ['admin', 'super_admin'].includes(req.user.role)
        && req.user.admin_level >= 1
        && typeof hasPermission === 'function'
        && await hasPermission(req.user.id, 'manage_progress');
      const revisions = await store.getSnapshot({
        userId: req.user.id,
        workshopKeys: normalizeWorkshopKeys(req.query?.workshops),
        ...(includeAdminProgress ? { includeAdminProgress: true } : {}),
      });
      res.set?.('Cache-Control', 'no-store');
      return res.json({ success: true, revisions });
    } catch (error) {
      console.error('Failed to read change revisions:', error);
      return res.status(500).json({ error: 'Failed to read change revisions' });
    }
  };
}

function createChangeRevisionsRouter({ store, authenticateToken, hasPermission }) {
  const express = require('express');
  const router = express.Router();
  router.get('/revisions', authenticateToken, createRevisionSnapshotHandler(store, { hasPermission }));
  return router;
}

module.exports = { createChangeRevisionsRouter, createRevisionSnapshotHandler, normalizeWorkshopKeys };
