'use strict';

const express = require('express');
const { requireSecureShopLaunch } = require('../../middleware/secureshopLaunch');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const invalid = res => res.status(400).json({ error: 'Invalid coupon probe request' });

function ids(value, path = false) {
  const record = path && value && Object.getPrototypeOf(value) === null ? { ...value } : value;
  return exact(record, ['sessionId', 'requestId']) && UUID.test(record.sessionId)
    && UUID.test(record.requestId) ? Object.freeze({ sessionId: record.sessionId.toLowerCase(),
      requestId: record.requestId.toLowerCase() }) : null;
}

function publicSession(value) {
  if (!exact(value, ['sessionId']) || !UUID.test(value.sessionId)) throw TypeError('Invalid coupon probe session');
  return Object.freeze({ sessionId: value.sessionId.toLowerCase() });
}

function publicProbe(value) {
  if (!exact(value, ['code', 'valid', 'discount_percent']) || typeof value.code !== 'string'
      || !value.code.isWellFormed() || value.code.includes('\0')
      || Buffer.byteLength(value.code) > 1024 || typeof value.valid !== 'boolean'
      || !Number.isInteger(value.discount_percent) || value.discount_percent < 0
      || value.discount_percent > 100 || !value.valid && value.discount_percent !== 0)
    throw TypeError('Invalid coupon probe observation');
  return Object.freeze({ code: value.code, valid: value.valid,
    discount_percent: value.discount_percent });
}

function publicRun(value, source, allowUnconfirmed = false) {
  if (allowUnconfirmed && exact(value, ['status', 'sessionId', 'requestId']) && value.status === 'unconfirmed'
      && value.sessionId === source.sessionId && value.requestId === source.requestId)
    return Object.freeze({ status: 'unconfirmed', ...source });
  if (!exact(value, ['status', 'sessionId', 'requestId', 'text', 'provider', 'model',
    'stopReason', 'probes', 'replayed']) || value.status !== 'completed'
      || value.sessionId !== source.sessionId || value.requestId !== source.requestId
      || typeof value.text !== 'string' || !value.text.trim() || !value.text.isWellFormed()
      || Buffer.byteLength(value.text) > 65536 || value.stopReason !== 'end_turn'
      || typeof value.provider !== 'string' || !value.provider || value.provider.length > 256
      || typeof value.model !== 'string' || !value.model || value.model.length > 256
      || typeof value.replayed !== 'boolean' || !Array.isArray(value.probes)
      || value.probes.length > 8 || !Array.from({ length: value.probes.length },
        (_, index) => Object.hasOwn(value.probes, index)).every(Boolean))
    throw TypeError('Invalid coupon probe result');
  return Object.freeze({ status: 'completed', ...source, text: value.text,
    provider: value.provider, model: value.model, stopReason: 'end_turn',
    probes: Object.freeze(value.probes.map(publicProbe)), replayed: value.replayed });
}

function publicAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
      && value.modelEvaluated === false && ['ineligible', 'unconfirmed'].includes(value.status))
    return Object.freeze({ completed: false, status: value.status, modelEvaluated: false });
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
      || typeof value.replayed !== 'boolean'
      || !value.judgment || Object.getPrototypeOf(value.judgment) !== Object.prototype
      || !['verdict', 'evaluationId', 'canRetry'].every(key => Object.hasOwn(value.judgment, key))
      || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
      || !UUID.test(value.judgment.evaluationId) || typeof value.judgment.canRetry !== 'boolean'
      || value.completed && value.judgment.verdict !== 'pass')
    throw TypeError('Invalid coupon probe assessment');
  return Object.freeze({ completed: value.completed,
    judgment: Object.freeze({ verdict: value.judgment.verdict,
      evaluationId: value.judgment.evaluationId, canRetry: value.judgment.canRetry }),
    replayed: value.replayed });
}

function headerCount(req, name) {
  return (req.rawHeaders || []).filter((_, index) => index % 2 === 0)
    .filter(header => String(header).toLowerCase() === name).length;
}

function createBoundCouponProbeRouter({ launches, authenticatePersona, application, assessment } = {}) {
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function'
      || ['createSession', 'run', 'read'].some(key => typeof application?.[key] !== 'function')
      || ['runAttempt', 'readOutcome'].some(key => typeof assessment?.[key] !== 'function'))
    throw TypeError('Coupon probe route dependencies required');
  const router = express.Router(), launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    const count = headerCount(req, 'x-dvaia-secureshop-launch');
    if (headerCount(req, 'authorization') > 1 || headerCount(req, 'content-type') > 1
        || count > 1) return invalid(res);
    return launch(req, res, next);
  };
  const customer = (req, res, next) => {
    if (req.ssUser?.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id)
        || req.ssUser.id < 1 || !UUID.test(req.ssPersonaSession?.sessionId || '')
        || typeof req.ssPersonaSession?.authorityVersion !== 'string'
        || !/^[1-9]\d*$/.test(req.ssPersonaSession.authorityVersion))
      return res.status(403).json({ error: 'Customer persona unavailable' });
    next();
  };
  const context = req => ({ scope: req.ssLaunch,
    persona: Object.freeze({ id: req.ssUser.id, role: 'customer' }),
    personaSession: Object.freeze({ sessionId: req.ssPersonaSession.sessionId,
      authorityVersion: req.ssPersonaSession.authorityVersion }) });
  const handle = work => async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const controller = new AbortController(), abort = () => controller.abort();
    const close = () => { if (!res.writableFinished) abort(); };
    req.once('aborted', abort); res.once('close', close);
    if (req.aborted || res.destroyed) abort();
    try {
      controller.signal.throwIfAborted();
      const value = await work(req, controller.signal);
      controller.signal.throwIfAborted();
      return res.status(200).json(value);
    } catch (error) {
      if (controller.signal.aborted || res.destroyed) return;
      const conflict = ['TURN_REQUEST_CONFLICT', 'COUPON_PROBE_REQUEST_CONFLICT'].includes(error?.code);
      return res.status(conflict ? 409 : error?.code === 'INVALID_ARGUMENT' ? 400 : 503)
        .json({ error: conflict ? 'Coupon probe request conflicts with its original admission'
          : error?.code === 'INVALID_ARGUMENT' ? 'Invalid coupon probe request' : 'Coupon probe unavailable' });
    } finally {
      req.off('aborted', abort); res.off('close', close);
    }
  };
  const clean = (req, body) => Object.keys(req.query || {}).length === 0
    && (body ? req.is('application/json') : req.body === undefined
      && !req.headers['transfer-encoding']
      && (!req.headers['content-length'] || Number(req.headers['content-length']) === 0));
  const runInput = value => (exact(value, ['sessionId', 'requestId', 'message'])
    || exact(value, ['sessionId', 'requestId', 'message', 'protocol'])
      && ['guided-boolean-v1', 'guided-boolean-v2'].includes(value.protocol))
    && UUID.test(value.sessionId) && UUID.test(value.requestId)
    && typeof value.message === 'string' && Boolean(value.message.trim())
    && value.message.isWellFormed() && !value.message.includes('\0')
    && Buffer.byteLength(value.message) <= 65536;
  router.get('/customer/coupon-probe/capabilities', select, authenticatePersona, customer,
    (req, res, next) => clean(req, false) ? next() : invalid(res),
    handle(async () => Object.freeze({ ready: true })));
  router.post('/customer/coupon-probe/session', select, authenticatePersona, customer,
    (req, res, next) => clean(req, true) && exact(req.body, []) ? next() : invalid(res),
    handle(async (req, signal) => publicSession(await application.createSession({ ...context(req), signal }))));
  router.post('/customer/coupon-probe/run', select, authenticatePersona, customer,
    (req, res, next) => clean(req, true) && runInput(req.body) ? next() : invalid(res),
    handle(async (req, signal) => { const source = ids({ sessionId: req.body.sessionId,
      requestId: req.body.requestId });
      return publicRun(await application.run({ ...context(req), ...source,
        message: req.body.message, ...(Object.hasOwn(req.body,'protocol') ? {protocol:req.body.protocol} : {}), signal }), source); }));
  router.get('/customer/coupon-probe/operations/:sessionId/:requestId', select,
    authenticatePersona, customer, (req, res, next) => clean(req, false) && ids(req.params, true)
      ? next() : invalid(res),
    handle(async (req, signal) => { const source = ids(req.params, true);
      return publicRun(await application.read({ ...context(req), ...source, signal }), source, true); }));
  router.post('/customer/coupon-probe/assess', select, authenticatePersona, customer,
    (req, res, next) => clean(req, true) && ids(req.body) ? next() : invalid(res),
    handle(async (req, signal) => publicAssessment(await assessment.runAttempt({
      ...context(req), ...ids(req.body), signal }))));
  router.get('/customer/coupon-probe/assess/:sessionId/:requestId', select,
    authenticatePersona, customer, (req, res, next) => clean(req, false) && ids(req.params, true)
      ? next() : invalid(res),
    handle(async (req, signal) => publicAssessment(await assessment.readOutcome({
      ...context(req), ...ids(req.params, true), signal }))));
  return router;
}

module.exports = { createBoundCouponProbeRouter, publicSession, publicRun, publicAssessment };
