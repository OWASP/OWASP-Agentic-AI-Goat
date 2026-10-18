'use strict';
const express = require('express');
const { normalizeRequest } = require('../../../sidecars/sandbox-runner/owned-system/contract');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// Unmounted until durable authority, startup and versioned bridge are qualified.
function createBoundSystemConfigRouter({ service, authenticatePersona } = {}) {
  if (typeof service?.read !== 'function' || typeof service?.operation !== 'function' || typeof service?.administration !== 'function'
      || typeof authenticatePersona !== 'function') throw new TypeError('Bound System route dependencies required');
  const router = express.Router();
  const guard = [authenticatePersona, (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (!req.ssLaunch || !req.ssPersonaSession?.sessionId || !req.ssUser) return res.status(401).json({ ok: false, error: 'Shop authentication required' });
    if (req.ssUser.role !== 'admin') return res.status(403).json({ ok: false, error: 'Shop admin required' });
    next();
  }];
  const context = req => ({ scope: req.ssLaunch, persona: { id: req.ssUser.id, role: req.ssUser.role },
    personaSession: { sessionId: req.ssPersonaSession.sessionId, authorityVersion: req.ssPersonaSession.authorityVersion } });
  function project(res, value, operationId) {
    if (!value || value.operationId !== operationId) throw new Error('Invalid System operation');
    const base = { operationId, state: value.state };
    if (value.state === 'not_found') return res.status(404).json({ ok: false, ...base, error: 'Operation not observed' });
    if (value.state === 'pending') return res.status(202).json({ ok: false, ...base, error: 'Read outcome pending' });
    if (['unknown', 'not_executed'].includes(value.state)) return res.json({ ok: false, ...base,
      error: value.state === 'unknown' ? 'Read outcome unknown' : 'Read was not executed' });
    if (value.state !== 'completed') throw new Error('Invalid System operation');
    const receipt = value.receipt;
    if (receipt?.operationId !== operationId) throw new Error('Invalid System receipt');
    if (receipt.status !== 'completed') return res.status(503).json({ ok: false, ...base, error: 'Config reader unavailable' });
    const read = receipt.readResult;
    if (read?.ok !== true) return res.json({ ok: false, ...base, error: read?.error || 'Config read failed' });
    // Full correspondence is enforced by service/repository. Never expose an
    // outer filesystem path through the legacy page's optional abs field.
    if (typeof read.targetPath !== 'string' || !read.targetPath.startsWith('/app/')) throw new Error('Invalid System path');
    return res.json({ ok: true, ...base, input: read.input, sanitized: read.sanitized,
      abs: read.targetPath, size: read.size, content: read.content, contentSha256: read.contentSha256 });
  }
  function handle(work) {
    return async (req, res) => {
      const controller = new AbortController();
      const close = () => { if (!res.writableEnded) controller.abort(); };
      req.once('aborted', close); res.once('close', close);
      try { await work(req, res, controller.signal); }
      catch (error) {
        if (res.destroyed || controller.signal.aborted) return;
        const code = error.code;
        const status = ['SHOP_AUTH_INVALID', 'STALE_AUTHORITY', 'SESSION_UNAVAILABLE'].includes(code) ? 401
          : code === 'ADMIN_REQUIRED' ? 403 : code === 'OPERATION_CONFLICT' ? 409
          : code === 'SYSTEM_CONFIG_QUOTA_EXCEEDED' ? 429 : 503;
        const publicCode = ['SYSTEM_CONFIG_BUSY','SYSTEM_CONFIG_OUTCOME_UNCERTAIN','OPERATION_CONFLICT','SYSTEM_CONFIG_QUOTA_EXCEEDED'].includes(code) ? code : undefined;
        res.status(status).json({ ok: false, error: 'Bound System config read unavailable', ...(publicCode ? { code: publicCode } : {}) });
      } finally { req.off('aborted', close); res.off('close', close); }
    };
  }
  router.get('/admin/system/config-read', ...guard, handle(async (req, res) => {
    if (Object.keys(req.query).length) return res.status(400).json({ ok: false, error: 'Invalid config request' });
    return res.json({ ok: true, administration: await service.administration(context(req)) });
  }));
  router.post('/admin/system/config-read', ...guard, handle(async (req, res, signal) => {
    let request;
    try {
      if (Object.keys(req.query).length || !req.is('application/json')) throw new Error();
      request = normalizeRequest(req.body);
    } catch { return res.status(400).json({ ok: false, error: 'Invalid config read request' }); }
    return project(res, await service.read({ ...context(req), ...request }, { signal }), request.operationId);
  }));
  router.get('/admin/system/config-operations/:operationId', ...guard, handle(async (req, res) => {
    if (Object.keys(req.query).length || !UUID.test(req.params.operationId)) return res.status(400).json({ ok: false, error: 'Invalid config operation' });
    const operationId = req.params.operationId;
    return project(res, await service.operation({ ...context(req), operationId }), operationId);
  }));
  return router;
}
module.exports = { createBoundSystemConfigRouter };
