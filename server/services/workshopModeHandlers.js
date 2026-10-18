'use strict';

const workshopModeService = require('./workshopModeService');
const { projectWorkshopModeCapability } = require('./workshopModeCapability');

function createWorkshopModeHandlers({ workshopKey, modeService = workshopModeService }) {
  if (!workshopKey) throw new TypeError('Workshop key is required');
  if (!modeService || typeof modeService.getMode !== 'function' || typeof modeService.setMode !== 'function') {
    throw new TypeError('Workshop mode service is required');
  }

  async function getMode(req, res) {
    if (!req.user?.id) return res.status(401).json({ error: 'Authentication required' });
    try {
      const mode = await modeService.getMode({ userId: req.user.id, workshopKey });
      res.set?.('Cache-Control', 'no-store');
      return res.json(projectWorkshopModeCapability(workshopKey, mode));
    } catch (error) {
      return res.status(error instanceof TypeError ? 400 : 500).json({ error: error instanceof TypeError ? error.message : 'Failed to read workshop mode' });
    }
  }

  async function setMode(req, res) {
    if (!req.user?.id) return res.status(401).json({ error: 'Authentication required' });
    try {
      const mode = await modeService.setMode({ userId: req.user.id, workshopKey, mode: req.body?.mode });
      res.set?.('Cache-Control', 'no-store');
      return res.json(projectWorkshopModeCapability(workshopKey, mode));
    } catch (error) {
      return res.status(error instanceof TypeError ? 400 : 500).json({ error: error instanceof TypeError ? error.message : 'Failed to save workshop mode' });
    }
  }

  return { get: getMode, set: setMode };
}

module.exports = { createWorkshopModeHandlers };
