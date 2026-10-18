'use strict';
const express = require('express');
const { markSecureShopLaunchUnavailable } = require('../../middleware/secureshopLaunch');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function createBoundAccessControlRouter({ service, authenticatePersona } = {}) {
  if (['read', 'mutate', 'operation'].some(key => typeof service?.[key] !== 'function')
    || typeof authenticatePersona !== 'function') throw new TypeError('Bound ACL route dependencies required');
  const router = express.Router();
  const guarded = [authenticatePersona, (req, res, next) => {
    if (!req.ssLaunch || req.ssUser?.role !== 'admin') return res.status(403).json({ error: 'Shop admin required' });
    if (!req.ssPersonaSession?.sessionId || !req.ssPersonaSession?.authorityVersion) return res.status(401).json({ error: 'Shop authentication required' });
    next();
  }];
  const context = req => ({ scope: req.ssLaunch,
    persona: { id: req.ssUser.id, role: req.ssUser.role },
    personaSession: { sessionId: req.ssPersonaSession.sessionId, authorityVersion: req.ssPersonaSession.authorityVersion } });
  const invalid = res => res.status(400).json({ error: 'Invalid access control request' });
  const handle = work => async (req, res) => {
    try { await work(req, res); }
    catch (error) {
      const code = error?.code;
      if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE'].includes(code)) {
        markSecureShopLaunchUnavailable(res);
        return res.status(401).json({ error: 'Shop authentication required' });
      }
      const status = ['ACL_VERSION_CONFLICT', 'ACL_OPERATION_CONFLICT'].includes(code) ? 409
        : code === 'SHOP_AUTH_INVALID' ? 401 : code === 'ADMIN_REQUIRED' ? 403
          : code === 'ACL_OPERATION_UNAVAILABLE' ? 404 : code === 'INVALID_ARGUMENT' ? 400 : 503;
      res.status(status).json({ error: 'Bound access control unavailable',
        ...(['ACL_VERSION_CONFLICT', 'ACL_OPERATION_CONFLICT', 'ACL_RECEIPT_OUTCOME_UNCERTAIN'].includes(code) ? { code } : {}) });
    }
  };
  router.get('/admin/access-control', ...guarded, handle(async (req, res) => {
    if (Object.keys(req.query).length) return invalid(res);
    res.json({ ok: true, ...await service.read(context(req)) });
  }));
  router.get('/admin/access-control/operations/:operationId', ...guarded, handle(async (req, res) => {
    if (!UUID.test(req.params.operationId) || Object.keys(req.query).length) return invalid(res);
    const receipt = await service.operation({ ...context(req), operationId: req.params.operationId.toLowerCase() });
    return receipt ? res.json({ ok: true, receipt }) : res.status(404).json({ error: 'Operation not observed' });
  }));
  for (const kind of ['permission', 'enforcement']) {
    router.post(`/admin/access-control/${kind}`, ...guarded, handle(async (req, res) => {
      const body = req.body;
      const keys = kind === 'permission' ? ['allowed', 'expectedVersion', 'operationId', 'role', 'tool_name']
        : ['enabled', 'expectedVersion', 'operationId'];
      if (!req.is('application/json') || !body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).sort().join(',') !== keys.sort().join(',') || Object.keys(req.query).length
        || typeof body.operationId !== 'string' || !UUID.test(body.operationId)
        || typeof body.expectedVersion !== 'string' || !/^[1-9]\d{0,18}$/.test(body.expectedVersion)
        || (kind === 'permission' && (typeof body.tool_name !== 'string' || body.tool_name.length > 160
          || !['customer', 'merchant', 'admin'].includes(body.role) || typeof body.allowed !== 'boolean'))
        || (kind === 'enforcement' && typeof body.enabled !== 'boolean')) return invalid(res);
      const change = kind === 'permission'
        ? { kind, toolKey: body.tool_name, role: body.role, allowed: body.allowed } : { kind, enabled: body.enabled };
      res.json({ ok: true, ...await service.mutate({ ...context(req), operationId: body.operationId.toLowerCase(),
        expectedVersion: body.expectedVersion, change }) });
    }));
  }
  return router;
}
module.exports = { createBoundAccessControlRouter };
