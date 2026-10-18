'use strict';

const express = require('express');
const PANEL_KEYS = Object.freeze(['catalog','review','storedBrowser','personaInbox','mcpTrust','controlledSsrf']);

function mountedReadiness(composition) {
  const panels = Object.freeze({
    catalog: typeof composition?.catalog?.listProducts === 'function',
    review: typeof composition?.router === 'function',
    storedBrowser: typeof composition?.browserRouter === 'function',
    personaInbox: composition?.personaInbox?.ready === true && typeof composition.personaInbox.router === 'function',
    mcpTrust: composition?.mcpTrust?.ready === true && typeof composition.mcpTrust.router === 'function',
    controlledSsrf: composition?.ssrf?.ready === true && typeof composition.ssrf.router === 'function',
  });
  const value = Object.freeze({ ready: PANEL_KEYS.every(key => panels[key] === true), panels });
  if (!value.ready) throw new TypeError('Bound SecureShop panel readiness incomplete');
  return value;
}

function createRouter({ authenticateToken, requireAdminLevel, getReadiness } = {}) {
  if (typeof authenticateToken !== 'function' || typeof requireAdminLevel !== 'function'
      || typeof getReadiness !== 'function') throw new TypeError('SecureShop readiness dependencies required');
  const router = express.Router();
  router.use(authenticateToken, requireAdminLevel(1));
  router.get('/', (req, res) => {
    res.set('Cache-Control', 'no-store');
    const readiness = getReadiness();
    if (!readiness || readiness.ready !== true || !readiness.panels
        || !PANEL_KEYS.every(key => readiness.panels[key] === true)) {
      return res.status(503).json({ error: 'Bound SecureShop application unavailable' });
    }
    return res.json(readiness);
  });
  return router;
}

module.exports = { PANEL_KEYS, mountedReadiness, createRouter };
