'use strict';

// Unmounted V49 confirmation route. Authentication and launch selection match
// the customer chat router; no coupon code or operation ID crosses this API.
const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } = require('../../middleware/secureshopLaunch');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));
function closedConfirmation(body) {
  if (!exact(body, ['sessionId', 'requestId', 'proposalId'])
    || ![body.sessionId, body.requestId, body.proposalId]
      .every(value => typeof value === 'string' && UUID.test(value))) return null;
  return Object.freeze({ sessionId: body.sessionId.toLowerCase(),
    requestId: body.requestId.toLowerCase(), proposalId: body.proposalId.toLowerCase() });
}
function couponResult(value) {
  if (exact(value, ['ok', 'error']) && value.ok === false
    && value.error === 'coupon not found')
    return Object.freeze({ ok: false, error: 'coupon not found' });
  if (exact(value, ['ok', 'code', 'discount_percent', 'subtotal', 'applied_amount'])
    && value.ok === true && typeof value.code === 'string'
    && value.code.length > 0 && Buffer.byteLength(value.code, 'utf8') <= 1024
    && Number.isFinite(value.discount_percent)
    && value.discount_percent >= 0 && value.discount_percent <= 100
    && Number.isFinite(value.subtotal) && value.subtotal >= 0
    && Number.isFinite(value.applied_amount) && value.applied_amount >= 0
    && value.applied_amount <= value.subtotal)
    return Object.freeze({ ok: true, code: value.code,
      discount_percent: value.discount_percent, subtotal: value.subtotal,
      applied_amount: value.applied_amount });
  throw new TypeError('Invalid coupon result');
}
function publicError(error) {
  if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE',
    'CONVERSATION_UNAVAILABLE', 'SHOP_AUTH_INVALID', 'SHOP_SCENE_STALE'].includes(error?.code))
    return Object.freeze({ status: 401, unavailable: true, message: 'Shop session unavailable' });
  if (['COUPON_AGENT_SOURCE_INVALID', 'TURN_REQUEST_CONFLICT',
    'COMMERCE_OPERATION_CONFLICT'].includes(error?.code))
    return Object.freeze({ status: 409, unavailable: false, message: 'Coupon proposal unavailable' });
  return Object.freeze({ status: 503, unavailable: false, message: 'Coupon confirmation unavailable' });
}
function createBoundCouponAgentConfirmRouter({ launches, authenticatePersona, confirmation } = {}) {
  if (typeof launches?.resolveCapability !== 'function'
    || typeof authenticatePersona !== 'function'
    || typeof confirmation?.confirm !== 'function'
    || typeof confirmation?.readSaved !== 'function')
    throw new TypeError('Coupon confirmation route dependencies required');
  const router = express.Router(), launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => {
    const names = (req.rawHeaders || []).filter((_, index) => index % 2 === 0)
      .filter(name => String(name).toLowerCase() === 'x-owasp-ai-goat-secureshop-launch');
    return names.length === 1 ? launch(req, res, next) : next('route');
  };
  const customer = [authenticatePersona, (req, res, next) => {
    if (req.ssUser?.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id)
      || req.ssUser.id < 1 || !req.ssPersonaSession?.sessionId)
      return res.status(403).json({ error: 'Customer persona unavailable' });
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: 'customer' });
    next();
  }];
  router.post('/agents/customer/coupons/confirm', select, ...customer, async (req, res) => {
    const request = closedConfirmation(req.body);
    if (Object.keys(req.query || {}).length || !req.is('application/json') || !request)
      return res.status(400).json({ error: 'Invalid coupon confirmation request' });
    try {
      const confirmed = await confirmation.confirm(Object.freeze({ scope: req.ssLaunch,
        persona: req.boundPersona, personaSession: req.ssPersonaSession }), request);
      const result = couponResult(confirmed?.result);
      res.set('Cache-Control', 'no-store');
      return res.status(result.ok ? 200 : 404).json(result);
    } catch (error) {
      const reply = publicError(error);
      if (reply.unavailable) markSecureShopLaunchUnavailable(res);
      return res.status(reply.status).json({ error: reply.message });
    }
  });
  router.get('/agents/customer/coupons/confirm/:sessionId/:requestId/:proposalId',
    select, ...customer, async (req, res) => {
      const request = closedConfirmation({ sessionId: req.params.sessionId,
        requestId: req.params.requestId, proposalId: req.params.proposalId });
      if (Object.keys(req.query || {}).length || !request)
        return res.status(400).json({ error: 'Invalid coupon confirmation request' });
      try {
        const saved = await confirmation.readSaved(Object.freeze({ scope: req.ssLaunch,
          persona: req.boundPersona, personaSession: req.ssPersonaSession }), request);
        if (!exact(saved, ['status']) && !exact(saved, ['status', 'result']))
          throw new TypeError('Invalid saved coupon confirmation');
        const body = saved.status === 'unconfirmed' && !Object.hasOwn(saved, 'result')
          ? Object.freeze({ status: 'unconfirmed' })
          : saved.status === 'completed' && Object.hasOwn(saved, 'result')
            ? Object.freeze({ status: 'completed', result: couponResult(saved.result) })
            : null;
        if (!body) throw new TypeError('Invalid saved coupon confirmation');
        res.set('Cache-Control', 'no-store');
        return res.status(200).json(body);
      } catch (error) {
        const reply = publicError(error);
        if (reply.unavailable) markSecureShopLaunchUnavailable(res);
        return res.status(reply.status).json({ error: reply.message });
      }
    });
  return router;
}

module.exports = { createBoundCouponAgentConfirmRouter, closedConfirmation, couponResult, publicError };
