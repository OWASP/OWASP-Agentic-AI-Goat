'use strict';
const express = require('express');
function createBoundSystemHealthRouter({ service, authenticatePersona } = {}) {
  if (typeof service?.health !== 'function' || typeof authenticatePersona !== 'function') throw new TypeError('Bound System health route dependencies required');
  const router = express.Router();
  router.get('/admin/system/health', authenticatePersona, (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (Object.keys(req.query || {}).length) return res.status(400).json({ ok: false, error: 'Invalid health request' });
    if (!req.ssLaunch || !req.ssPersonaSession?.sessionId || !req.ssUser) return res.status(401).json({ ok: false, error: 'Shop authentication required' });
    if (req.ssUser.role !== 'admin') return res.status(403).json({ ok: false, error: 'Shop admin required' });
    const context = { scope: req.ssLaunch, persona: { id: req.ssUser.id, role: req.ssUser.role }, personaSession: { sessionId: req.ssPersonaSession.sessionId, authorityVersion: req.ssPersonaSession.authorityVersion } };
    const controller = new AbortController();
    const close = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', close); res.once('close', close);
    service.health(context, { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted && !res.destroyed) res.json(value);
    }).catch(error => {
      if (controller.signal.aborted || res.destroyed) return;
      const status = ['SHOP_AUTH_INVALID', 'SESSION_UNAVAILABLE', 'STALE_AUTHORITY', 'SYSTEM_HEALTH_AUTH_INVALID'].includes(error.code) ? 401
        : error.code === 'ADMIN_REQUIRED' ? 403 : 503;
      res.status(status).json({ ok: false, error: 'Bound System health unavailable' });
    }).finally(() => { req.off('aborted', close); res.off('close', close); });
    return undefined;
  });
  return router;
}
module.exports = { createBoundSystemHealthRouter };
