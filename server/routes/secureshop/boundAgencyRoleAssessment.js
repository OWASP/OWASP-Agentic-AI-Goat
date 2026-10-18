'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } =
  require('../../middleware/secureshopLaunch');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

function sourceIds(value, path = false) {
  // Express route parameters use a null-prototype record. Bodies remain strict.
  const record = path && value && Object.getPrototypeOf(value) === null ? { ...value } : value;
  if (!exact(record, ['sessionId', 'requestId']) || !UUID.test(record.sessionId || '')
      || !UUID.test(record.requestId || '')) return null;
  return Object.freeze({ sessionId: record.sessionId, requestId: record.requestId });
}

function publicAgencyRoleAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
      && value.modelEvaluated === false && ['ineligible', 'unconfirmed', 'pending'].includes(value.status)) {
    return Object.freeze({ completed: false, status: value.status, modelEvaluated: false });
  }
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
      || typeof value.replayed !== 'boolean' || !UUID.test(value.judgment?.evaluationId || '')
      || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment?.verdict)
      || typeof value.judgment.canRetry !== 'boolean'
      || value.completed && value.judgment.verdict !== 'pass') throw TypeError('Invalid agency role assessment');
  return Object.freeze({ completed: value.completed, replayed: value.replayed,
    judgment: Object.freeze({ evaluationId: value.judgment.evaluationId,
      verdict: value.judgment.verdict, canRetry: value.judgment.canRetry }) });
}

function createBoundAgencyRoleAssessmentRouter({ launches, authenticatePersona, assessment } = {}) {
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function'
      || typeof assessment?.runAttempt !== 'function' || typeof assessment?.readOutcome !== 'function') {
    throw TypeError('Agency role assessment dependencies required');
  }
  const router = express.Router();
  const launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => {
    const headers = (req.rawHeaders || []).filter((_, index) => index % 2 === 0)
      .filter(name => String(name).toLowerCase() === 'x-dvaia-secureshop-launch');
    return headers.length === 1 ? launch(req, res, next) : next('route');
  };
  const customer = (req, res, next) => {
    if (req.ssUser?.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id) || req.ssUser.id < 1
        || !req.ssPersonaSession?.sessionId) {
      return res.status(403).json({ error: 'Customer persona unavailable' });
    }
    next();
  };
  const handle = method => async (req, res) => {
    const reading = method === 'readOutcome';
    const ids = sourceIds(reading ? req.params : req.body, reading);
    if (!ids || Object.keys(req.query || {}).length || (!reading && !req.is('application/json'))
        || (reading && req.body !== undefined && (!req.body || Object.keys(req.body).length))) {
      return res.status(400).json({ error: 'Invalid agency role assessment request' });
    }
    res.set('Cache-Control', 'no-store');
    const controller = new AbortController();
    const abort = () => controller.abort();
    const close = () => { if (!res.writableFinished) abort(); };
    req.once('aborted', abort);
    res.once('close', close);
    if (req.aborted || res.destroyed) abort();
    try {
      controller.signal.throwIfAborted();
      const result = await assessment[method]({ scope: req.ssLaunch,
        persona: Object.freeze({ id: req.ssUser.id, role: 'customer' }),
        personaSession: req.ssPersonaSession, ...ids, signal: controller.signal });
      controller.signal.throwIfAborted();
      return res.status(200).json(publicAgencyRoleAssessment(result));
    } catch (error) {
      if (controller.signal.aborted || res.destroyed) return;
      if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE', 'CONVERSATION_UNAVAILABLE',
        'SHOP_AUTH_INVALID', 'SHOP_SCENE_STALE'].includes(error?.code)) {
        markSecureShopLaunchUnavailable(res);
        return res.status(401).json({ error: 'Shop session unavailable' });
      }
      return res.status(503).json({ error: 'Agency role assessment unavailable' });
    } finally {
      req.removeListener('aborted', abort);
      res.removeListener('close', close);
    }
  };
  router.post('/agents/customer/agency-role/assess', select, authenticatePersona, customer, handle('runAttempt'));
  router.get('/agents/customer/sessions/:sessionId/requests/:requestId/agency-role/assessment',
    select, authenticatePersona, customer, handle('readOutcome'));
  return router;
}

module.exports = { createBoundAgencyRoleAssessmentRouter, publicAgencyRoleAssessment, sourceIds };
