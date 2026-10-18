'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } =
  require('../../middleware/secureshopLaunch');
const { closedConfirmation } = require('./boundCouponAgentConfirm');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));
const VERDICTS = new Set(['pass', 'fail', 'inconclusive', 'unavailable']);
function assessmentError(error) {
  if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE',
    'CONVERSATION_UNAVAILABLE', 'SHOP_AUTH_INVALID', 'SHOP_SCENE_STALE'].includes(error?.code))
    return { status: 401, unavailable: true, message: 'Shop session unavailable' };
  if (['COUPON_AGENT_SOURCE_INVALID', 'TURN_REQUEST_CONFLICT',
    'COMMERCE_OPERATION_CONFLICT'].includes(error?.code))
    return { status: 409, unavailable: false, message: 'Coupon proposal unavailable' };
  return { status: 503, unavailable: false, message: 'Coupon assessment unavailable' };
}

function publicAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated'])
    && value.completed === false && value.modelEvaluated === false
    && ['ineligible', 'unconfirmed'].includes(value.status))
    return Object.freeze({ completed: false, status: value.status,
      modelEvaluated: false });
  if (!exact(value, ['completed', 'judgment', 'replayed'])
    || typeof value.completed !== 'boolean' || typeof value.replayed !== 'boolean'
    || !VERDICTS.has(value.judgment?.verdict)
    || !UUID.test(value.judgment.evaluationId || '')
    || typeof value.judgment.canRetry !== 'boolean')
    throw new TypeError('Invalid coupon assessment');
  return Object.freeze({ completed: value.completed,
    judgment: Object.freeze({ verdict: value.judgment.verdict,
      evaluationId: value.judgment.evaluationId,
      canRetry: value.judgment.canRetry }), replayed: value.replayed });
}

function createBoundCouponAgentAssessmentRouter({ launches, authenticatePersona,
  assessment } = {}) {
  if (typeof launches?.resolveCapability !== 'function'
    || typeof authenticatePersona !== 'function'
    || typeof assessment?.runAttempt !== 'function'
    || typeof assessment?.readOutcome !== 'function')
    throw new TypeError('Coupon assessment route dependencies required');
  const router = express.Router(), launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => {
    const names = (req.rawHeaders || []).filter((_, index) => index % 2 === 0)
      .filter(name => String(name).toLowerCase() === 'x-dvaia-secureshop-launch');
    return names.length === 1 ? launch(req, res, next) : next('route');
  };
  const customer = [authenticatePersona, (req, res, next) => {
    if (req.ssUser?.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id)
      || req.ssUser.id < 1 || !req.ssPersonaSession?.sessionId)
      return res.status(403).json({ error: 'Customer persona unavailable' });
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: 'customer' });
    next();
  }];
  async function respond(req, res, ids, method) {
    try {
      const result = await assessment[method]({ scope: req.ssLaunch,
        persona: req.boundPersona, personaSession: req.ssPersonaSession,
        ...ids, signal: req.signal });
      res.set('Cache-Control', 'no-store');
      return res.status(200).json(publicAssessment(result));
    } catch (error) {
      const reply = assessmentError(error);
      if (reply.unavailable) markSecureShopLaunchUnavailable(res);
      return res.status(reply.status).json({ error: reply.message });
    }
  }
  router.post('/agents/customer/coupons/assessment-retry', select,
    ...customer, async (req, res) => {
      const ids = closedConfirmation(req.body);
      if (Object.keys(req.query || {}).length || !req.is('application/json') || !ids)
        return res.status(400).json({ error: 'Invalid coupon assessment request' });
      return respond(req, res, ids, 'runAttempt');
    });
  router.get('/agents/customer/coupons/assessment/:sessionId/:requestId/:proposalId',
    select, ...customer, async (req, res) => {
      const ids = closedConfirmation({ ...req.params });
      if (Object.keys(req.query || {}).length || !ids)
        return res.status(400).json({ error: 'Invalid coupon assessment request' });
      return respond(req, res, ids, 'readOutcome');
    });
  return router;
}

module.exports = { createBoundCouponAgentAssessmentRouter,
  publicAssessment };
