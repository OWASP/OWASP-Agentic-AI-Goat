const express = require('express');
const { createWorkshopConfigService } = require('../services/workshopConfigService');

function createWorkshopConfigRouter(service = createWorkshopConfigService()) {
  const router = express.Router();
  router.get('/revision', async (_req, res) => {
    try { res.json({ revision: await service.getRevision() }); }
    catch { res.status(500).json({ error: 'Failed to fetch workshop configuration revision' }); }
  });
  router.get('/snapshot', async (_req, res) => {
    try { res.json(await service.getSnapshot()); }
    catch { res.status(500).json({ error: 'Failed to fetch workshop configuration' }); }
  });
  return router;
}

module.exports = { createWorkshopConfigRouter };
