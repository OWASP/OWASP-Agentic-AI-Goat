'use strict';
const express = require('express');
const { request, UUID, closed } = require('../../services/secureshopPricingContract');
const { pricingDenialReceipt } = require('../../services/secureshopPricingReceipt');

// New, unmounted bound protocol. Existing standalone merchant routes remain
// untouched until the versioned bridge/UI adapter is qualified.
function createBoundPricingRouter({ application, authenticatePersona } = {}) {
  if (typeof application?.run !== 'function' || typeof application?.operation !== 'function'
      || typeof authenticatePersona !== 'function') throw TypeError('Trusted pricing route dependencies required');
  const router = express.Router();
  router.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const context = req => ({ scope: req.ssLaunch, persona: { id: req.ssUser.id, role: req.ssUser.role },
    personaSession: { sessionId: req.ssPersonaSession.sessionId, authorityVersion: req.ssPersonaSession.authorityVersion } });
  function guard(role) {
    return [authenticatePersona, (req, res, next) => {
      if (!req.ssLaunch || !req.ssUser || !req.ssPersonaSession?.sessionId) return res.status(401).json({ ok: false, error: 'Shop authentication required' });
      if (req.ssUser.role !== role) return res.status(403).json({ ok: false, error: 'Pricing role unavailable' });
      next();
    }];
  }
  function project(res, value, operationId) {
    if (value?.operationId !== operationId) throw Error('Pricing operation mismatch');
    if (value.state === 'not_found') return res.status(404).json({ ok: false, operationId, state: value.state });
    if (value.state === 'pending') return res.status(202).json({ ok: false, operationId, state: value.state });
    if (['unknown', 'not_executed'].includes(value.state)) return res.json({ ok: false, operationId, state: value.state });
    if (value.state === 'blocked') {
      const receipt = pricingDenialReceipt(value.receipt, { targetId: value.targetId,
        operationId, runId: value.runId, requestSha256: value.requestSha256,
        productId: value.receipt?.productId, competitorUrl: value.receipt?.competitorUrl });
      return res.json({ ok: false, operationId, state: 'blocked', requestSha256: value.requestSha256,
        receipt, ...(value.modeCapability ? { modeCapability: value.modeCapability } : {}) });
    }
    if (value.state !== 'completed' || value.receipt?.operationId !== operationId) throw Error('Pricing receipt mismatch');
    return res.json({ ok: true, operationId, state: value.state, requestSha256: value.requestSha256, receipt: value.receipt,...(value.modeCapability?{modeCapability:value.modeCapability}:{}) });
  }
  const handle = work => async (req, res) => {
    const controller = new AbortController();
    const close = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', close); res.once('close', close);
    try { await work(req, res, controller.signal); }
    catch (error) {
      if (res.destroyed || controller.signal.aborted) return;
      const code = ['OPERATION_CONFLICT', 'PRICING_QUOTA_EXCEEDED', 'PRICING_OUTCOME_UNCERTAIN'].includes(error.code) ? error.code : undefined;
      const status = code === 'OPERATION_CONFLICT' ? 409 : code === 'PRICING_QUOTA_EXCEEDED' ? 429
        : ['SHOP_AUTH_INVALID', 'SHOP_AUTH_REVOKED', 'STALE_AUTHORITY', 'SESSION_UNAVAILABLE'].includes(error.code) ? 401 : 503;
      res.status(status).json({ ok: false, error: 'Bound pricing unavailable', ...(code ? { code } : {}) });
    } finally { req.off('aborted', close); res.off('close', close); }
  };
  for (const [prefix, task, role] of [['/merchant/pricing', 'pricing-strategy', 'merchant'], ['/pricing/advisor', 'price-advisor', 'customer']]) {
    router.get(prefix + '/history', ...guard(role), handle(async (req, res) => {
      if (Object.keys(req.query).join(',') !== 'product_id' || !/^[1-9][0-9]{0,9}$/.test(req.query.product_id) || Number(req.query.product_id) > 2147483647) return res.status(400).json({ok:false,error:'Invalid product'});
      return res.json(await application.history({...context(req),productId:Number(req.query.product_id)}));
    }));
    router.get(prefix + '/run', ...guard(role), handle(async (req, res) => {
      if (Object.keys(req.query).length) return res.status(400).json({ok:false,error:'Invalid pricing capability request'});
      const administration = await application.administration(context(req));
      if (administration?.versionedPricing !== true || !/^[a-f0-9]{64}$/.test(administration.scopeKey)) throw Error('Pricing capability unavailable');
      return res.json({ok:true,administration});
    }));
    router.post(prefix + '/run', ...guard(role), handle(async (req, res, signal) => {
      let selected;
      try {
        if (Object.keys(req.query).length || !req.is('application/json')
            || !(closed(req.body, ['operationId', 'productId', 'message'])
              || closed(req.body, ['operationId', 'productId', 'message','experiment'])
              || closed(req.body, ['operationId', 'productId', 'message','competitorUrl']))) throw Error();
        selected = request({ ...req.body, task });
      } catch { return res.status(400).json({ ok: false, error: 'Invalid pricing request' }); }
      return project(res, await application.run({ ...context(req), ...selected, signal }), selected.operationId);
    }));
    router.get(prefix + '/operations/:operationId', ...guard(role), handle(async (req, res) => {
      const operationId = req.params.operationId;
      if (Object.keys(req.query).length || !UUID.test(operationId)) return res.status(400).json({ ok: false, error: 'Invalid pricing operation' });
      return project(res, await application.operation({ ...context(req), operationId }), operationId);
    }));
  }
  return router;
}
module.exports = { createBoundPricingRouter };
