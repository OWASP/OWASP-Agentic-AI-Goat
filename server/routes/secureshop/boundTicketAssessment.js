'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } = require('../../middleware/secureshopLaunch');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

function publicTicketAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
      && value.modelEvaluated === false && ['disabled', 'ineligible', 'unconfirmed', 'pending'].includes(value.status))
    return Object.freeze({ completed: false, status: value.status, modelEvaluated: false });
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
      || typeof value.replayed !== 'boolean' || !UUID.test(value.judgment?.evaluationId || '')
      || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment?.verdict)
      || typeof value.judgment.canRetry !== 'boolean'
      || value.completed && value.judgment.verdict !== 'pass') throw TypeError('Invalid ticket assessment');
  return Object.freeze({ completed: value.completed, replayed: value.replayed,
    judgment: Object.freeze({ evaluationId: value.judgment.evaluationId,
      verdict: value.judgment.verdict, canRetry: value.judgment.canRetry }) });
}

function createBoundTicketAssessmentRouter({ launches, authenticatePersona, assessment } = {}) {
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function'
      || typeof assessment?.runAttempt !== 'function' || typeof assessment?.readOutcome !== 'function')
    throw TypeError('Ticket assessment dependencies required');
  const router = express.Router(), launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => {
    const count = (req.rawHeaders || []).filter((_, index) => index % 2 === 0)
      .filter(name => name.toLowerCase() === 'x-dvaia-secureshop-launch').length;
    return count === 1 ? launch(req, res, next) : next('route');
  };
  const admin = (req, res, next) => {
    if (req.ssUser?.role !== 'admin' || !Number.isSafeInteger(req.ssUser.id)
        || req.ssUser.id < 1 || !req.ssPersonaSession?.sessionId)
      return res.status(403).json({ error: 'Administrator persona unavailable' });
    next();
  };
  const handle = method => async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const ticketId = req.params.ticketId;
    const requestId = method === 'runAttempt' ? req.body?.requestId : req.params.requestId;
    if (Object.keys(req.query || {}).length || typeof ticketId !== 'string'
        || !/^[1-9]\d{0,18}$/.test(ticketId) || BigInt(ticketId) > 9223372036854775807n
        || typeof requestId !== 'string' || !UUID.test(requestId)
        || method === 'runAttempt' && (!req.is('application/json') || !exact(req.body, ['requestId'])))
      return res.status(400).json({ error: 'Invalid ticket assessment request' });
    const controller = new AbortController();
    const abort = () => controller.abort();
    const close = () => { if (!res.writableFinished) abort(); };
    req.once('aborted', abort);
    res.once('close', close);
    if (req.aborted || res.destroyed) abort();
    try {
      const value = await assessment[method]({ scope: req.ssLaunch,
        persona: Object.freeze({ id: req.ssUser.id, role: 'admin' }), personaSession: req.ssPersonaSession,
        ticketId, requestId: requestId.toLowerCase(), signal: controller.signal });
      controller.signal.throwIfAborted();
      return res.json(publicTicketAssessment(value));
    } catch (error) {
      if (controller.signal.aborted || res.destroyed) return;
      const stale = ['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE',
        'SHOP_AUTH_INVALID', 'SHOP_SCENE_STALE'].includes(error?.code);
      if (stale) markSecureShopLaunchUnavailable(res);
      return res.status(stale ? 401 : error?.code === 'TURN_REQUEST_CONFLICT' ? 409 : 503)
        .json({ error: stale ? 'Shop session unavailable' : 'Ticket assessment unavailable' });
    } finally {
      req.removeListener('aborted', abort);
      res.removeListener('close', close);
    }
  };
  router.post('/admin/tickets/:ticketId/assessment', select, authenticatePersona, admin, handle('runAttempt'));
  router.get('/admin/tickets/:ticketId/assessment/:requestId', select, authenticatePersona, admin, handle('readOutcome'));
  return router;
}

module.exports = { createBoundTicketAssessmentRouter, publicTicketAssessment };
