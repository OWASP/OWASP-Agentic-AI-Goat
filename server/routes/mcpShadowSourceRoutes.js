'use strict';
const express = require('express');
const { ownerWorkflowRoute, getOwnerExecution } = require('../agent-runtime/ownerWorkflowRoutes');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
function validate(body, write) {
  const keys = write ? ['expectedSha256', 'operationId', 'text'] : [];
  if (!body || Array.isArray(body) || typeof body !== 'object'
      || Object.keys(body).sort().join(',') !== keys.sort().join(',')) return false;
  return !write || (typeof body.text === 'string' && Buffer.byteLength(body.text, 'utf8') <= 16384
    && Buffer.from(body.text, 'utf8').toString('utf8') === body.text
    && typeof body.expectedSha256 === 'string' && SHA.test(body.expectedSha256)
    && typeof body.operationId === 'string' && UUID.test(body.operationId));
}
function createMcpShadowSourceRouter({ coordinator, requireUser, requireRuntime, ownerId, getResources, visible } = {}) {
  if (!coordinator || [requireUser, requireRuntime, ownerId, getResources, visible].some(fn => typeof fn !== 'function')) throw TypeError('Current owned shadow route dependencies required');
  const router = express.Router();
  for (const write of [false, true]) router.post(write ? '/write' : '/read', requireUser, requireRuntime,
    ownerWorkflowRoute(coordinator, ownerId, async (req, res) => {
      const body = req.body || {};
      if (!validate(body, write)) return res.status(400).json({ error: 'Invalid shadow source request' });
      if (!await visible()) return res.status(403).json({ error: 'Shadow server exercise is unavailable' });
      try {
        const execution = getOwnerExecution();
        const resources = await getResources(req, execution);
        const method = write ? 'writeShadowSource' : 'readShadowSource';
        if (typeof resources?.[method] !== 'function') return res.status(503).json({ error: 'Owned shadow source is unavailable' });
        const result = await resources[method](...(write ? [body] : []));
        await execution.check();
        if (write) res.json({ success: true, operationId: result.operationId, sha256: result.sha256 });
        else res.json({ success: true, text: result.text, sha256: result.sha256 });
      } catch (error) {
        const code = error.code || 'SHADOW_SOURCE_UNAVAILABLE';
        res.status(code === 'SHADOW_SOURCE_CONFLICT' ? 409 : error.statusCode || 503).json({ error: code });
      }
    }, { reset: false }));
  return router;
}
module.exports = { createMcpShadowSourceRouter, validate };
