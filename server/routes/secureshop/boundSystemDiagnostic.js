'use strict';

const express = require('express');
const { normalizeDiagnosticRequest } = require('../../../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// Unmounted until the bound System composition supplies the durable service.
// The command/template sink remains intentional teaching behavior; this route
// only binds it to the original admin launch/session and projects its receipt.
function createBoundSystemDiagnosticRouter({ service, authenticatePersona } = {}) {
  if (typeof service?.administration !== 'function' || typeof service?.execute !== 'function'
      || typeof service?.operation !== 'function' || typeof authenticatePersona !== 'function') {
    throw new TypeError('Bound System diagnostic route dependencies required');
  }
  const router = express.Router();
  const context = req => ({ scope: req.ssLaunch, persona: { id: req.ssUser.id, role: req.ssUser.role },
    personaSession: { sessionId: req.ssPersonaSession.sessionId, authorityVersion: req.ssPersonaSession.authorityVersion } });
  const guard = [(req, res, next) => { res.set('Cache-Control', 'no-store'); next(); }, authenticatePersona, (req, res, next) => {
    if (!req.ssLaunch || !req.ssPersonaSession?.sessionId || !req.ssUser) return res.status(401).json({ ok: false, error: 'Shop authentication required' });
    if (req.ssUser.role !== 'admin') return res.status(403).json({ ok: false, error: 'Shop admin required' });
    next();
  }];
  const status = code => ['SHOP_AUTH_INVALID', 'SHOP_AUTH_REVOKED', 'STALE_AUTHORITY', 'SESSION_UNAVAILABLE'].includes(code) ? 401
    : ['ADMIN_REQUIRED', 'SYSTEM_DIAGNOSTIC_FIXED_DENIED'].includes(code) ? 403 : code === 'OPERATION_CONFLICT' ? 409
    : code === 'SYSTEM_DIAGNOSTIC_QUOTA_EXCEEDED' ? 429
    : ['SYSTEM_DIAGNOSTIC_BUSY', 'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN', 'SYSTEM_DIAGNOSTIC_UNAVAILABLE', 'SYSTEM_DIAGNOSTIC_NOT_READY'].includes(code) ? 503 : 503;
  const publicCode = code => ['OPERATION_CONFLICT', 'SYSTEM_DIAGNOSTIC_QUOTA_EXCEEDED', 'SYSTEM_DIAGNOSTIC_BUSY', 'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN', 'SYSTEM_DIAGNOSTIC_FIXED_DENIED'].includes(code) ? code : undefined;
  function handle(work) {
    return async (req, res) => {
      const controller = new AbortController();
      const close = () => { if (!res.writableEnded) controller.abort(); };
      req.once('aborted', close); res.once('close', close);
      try { await work(req, res, controller.signal); }
      catch (error) {
        if (res.destroyed || controller.signal.aborted) return;
        const code = error?.code;
        const message = code === 'SYSTEM_DIAGNOSTIC_FIXED_DENIED'
          ? 'Shell diagnostics are disabled in Fixed mode.' : 'Bound System diagnostic unavailable';
        res.status(status(code)).json({ ok: false, error: message, ...(publicCode(code) ? { code: publicCode(code) } : {}) });
      } finally { req.off('aborted', close); res.off('close', close); }
    };
  }
  function project(res, value, operationId) {
    if (!value || value.operationId !== operationId) throw new Error('Invalid System diagnostic operation');
    const base = { operationId, state: value.state };
    if (value.state === 'not_found') return res.status(404).json({ ok: false, ...base, error: 'Operation not observed' });
    if (value.state === 'pending') return res.status(202).json({ ok: false, ...base, error: 'Diagnostic outcome pending' });
    if (value.state === 'unknown' || value.state === 'not_executed') return res.json({ ok: false, ...base,
      error: value.state === 'unknown' ? 'Diagnostic outcome unknown' : 'Diagnostic was not executed', automaticRetry: false });
    if (value.state !== 'completed' || !value.receipt?.result) throw new Error('Invalid System diagnostic receipt');
    const receipt = value.receipt, result = receipt.result;
    const decode = field => Buffer.from(result[field], 'base64').toString('utf8');
    return res.json({ ok: true, ...base, executed: result.executed, cmd: result.command,
      stdout: decode('stdout'), stderr: decode('stderr'), exitCode: result.exitCode, signal: result.signal,
      timedOut: result.timedOut, truncated: result.truncated, drained: result.drained,
      targetId: receipt.targetId, hostname: receipt.hostname, bindingSha256: receipt.bindingSha256,
      requestSha256: value.requestSha256, receipt });
  }
  router.get('/admin/system/diagnostic', ...guard, handle(async (req, res) => {
    if (Object.keys(req.query).length) return res.status(400).json({ ok: false, error: 'Invalid diagnostic request' });
    return res.json({ ok: true, administration: await service.administration(context(req)) });
  }));
  router.post('/admin/system/diagnostic', ...guard, handle(async (req, res, signal) => {
    let request;
    try {
      if (Object.keys(req.query).length || !req.is('application/json')) throw new Error();
      request = normalizeDiagnosticRequest(req.body);
    } catch { return res.status(400).json({ ok: false, error: 'Invalid diagnostic request' }); }
    return project(res, await service.execute({ ...context(req), ...request }, { signal }), request.operationId);
  }));
  router.get('/admin/system/diagnostic-operations/:operationId', ...guard, handle(async (req, res) => {
    if (Object.keys(req.query).length || !UUID.test(req.params.operationId)) return res.status(400).json({ ok: false, error: 'Invalid diagnostic operation' });
    const operationId = req.params.operationId;
    return project(res, await service.operation({ ...context(req), operationId }), operationId);
  }));
  return router;
}
module.exports = { createBoundSystemDiagnosticRouter };
