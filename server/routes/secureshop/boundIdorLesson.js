'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } =
  require('../../middleware/secureshopLaunch');
const { normalizeIdorLessonSelection } =
  require('../../services/secureshopIdorLessonContract');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERDICTS = new Set(['pass','fail','inconclusive','unavailable']);
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const invalid = () => Object.assign(new Error('Invalid isolated lesson response'),
  { code: 'IDOR_LESSON_UNAVAILABLE' });
const singleLaunchHeader = req => (req.rawHeaders || [])
  .filter((_, i) => i % 2 === 0)
  .filter(value => String(value).toLowerCase() === 'x-owasp-ai-goat-secureshop-launch').length === 1;

function mode(value) {
  if (!exact(value, ['version','featureId','policyVersion','effectiveMode','scope'])
      || value.version !== 1 || value.featureId !== 'customer_idor'
      || value.policyVersion !== 'reserved-synthetic-cart-and-order-ownership-v1'
      || !['vuln','fixed'].includes(value.effectiveMode)
      || !exact(value.scope, ['kind','id'])
      || value.scope.kind !== 'launch_feature'
      || value.scope.id !== 'customer_idor') throw invalid();
  return Object.freeze({ version: 1, featureId: 'customer_idor',
    policyVersion: value.policyVersion, effectiveMode: value.effectiveMode,
    scope: Object.freeze({ kind: 'launch_feature', id: 'customer_idor' }) });
}
function cards(value) {
  if (!exact(value, ['cards','modeCapability']) || !Array.isArray(value.cards)
      || value.cards.length !== 2) throw invalid();
  const found = value.cards.map(card => {
    if (!exact(card, ['action','numericId','label']) || typeof card.label !== 'string'
        || !card.label.trim() || card.label.length > 120) throw invalid();
    const selected = normalizeIdorLessonSelection({ action: card.action,
      numericId: card.numericId });
    return Object.freeze({ ...selected, label: card.label });
  });
  if (new Set(found.map(card => card.action)).size !== 2) throw invalid();
  return Object.freeze({ cards: Object.freeze(found),
    modeCapability: mode(value.modeCapability) });
}
function saved(value, sessionId, requestId) {
  if (value?.sessionId !== sessionId || value.requestId !== requestId) throw invalid();
  if (exact(value, ['sessionId','requestId','status'])
      && value.status === 'unconfirmed') return Object.freeze({ sessionId, requestId,
    status: 'unconfirmed' });
  if (!exact(value, ['sessionId','requestId','status','text','result','modeCapability'])
      || value.status !== 'completed' || typeof value.text !== 'string'
      || !value.text.isWellFormed() || Buffer.byteLength(value.text, 'utf8') > 2048)
    throw invalid();
  const result = value.result;
  const modeCapability = mode(value.modeCapability);
  if (result === null) return Object.freeze({ sessionId, requestId,
    status: 'completed', text: value.text, result: null, modeCapability });
  if (!result || typeof result !== 'object') throw invalid();
  normalizeIdorLessonSelection({ action: result.action, numericId: result.numericId });
  if (result.action === 'cart_remove'
      ? !exact(result, ['action','numericId','status'])
        || !['deleted','denied'].includes(result.status)
      : result.status === 'denied'
        ? !exact(result, ['action','numericId','status'])
        : !exact(result, ['action','numericId','status','order'])
          || result.status !== 'disclosed'
          || !exact(result.order, ['orderId','totalAmount','status',
            'paymentMethod','paymentStatus','shippingAddress'])
          || !Number.isSafeInteger(result.order.orderId)
          || result.order.orderId !== result.numericId
          || ['totalAmount','status','paymentMethod','paymentStatus','shippingAddress']
            .some(key => typeof result.order[key] !== 'string'
              || !result.order[key] || result.order[key].length > 512)) throw invalid();
  return Object.freeze({ sessionId, requestId, status: 'completed',
    text: value.text, result: Object.freeze(structuredClone(result)), modeCapability });
}
function assessment(value) {
  if (exact(value, ['completed','status','modelEvaluated'])
      && value.completed === false && value.modelEvaluated === false
      && ['ineligible','unconfirmed'].includes(value.status))
    return Object.freeze({ completed: false, status: value.status,
      modelEvaluated: false });
  if (!exact(value, ['completed','judgment','replayed'])
      || typeof value.completed !== 'boolean' || typeof value.replayed !== 'boolean'
      || typeof value.judgment !== 'object' || !value.judgment
      || !UUID.test(value.judgment.evaluationId || '')
      || !VERDICTS.has(value.judgment.verdict)
      || typeof value.judgment.canRetry !== 'boolean') throw invalid();
  return Object.freeze({ completed: value.completed,
    judgment: Object.freeze({ evaluationId: value.judgment.evaluationId.toLowerCase(),
      verdict: value.judgment.verdict, canRetry: value.judgment.canRetry }),
    replayed: value.replayed });
}
function publicError(error) {
  if (['STALE_LAUNCH','LAUNCH_UNAVAILABLE','SESSION_UNAVAILABLE',
    'CONVERSATION_UNAVAILABLE','SHOP_AUTH_INVALID','SHOP_SCENE_STALE',
    'SECURESHOP_FEATURE_MODE_STALE'].includes(error?.code))
    return [401, true, 'Shop session unavailable'];
  if (['INVALID_ARGUMENT','INVALID_TURN_REQUEST',
    'IDOR_LESSON_SELECTION_INVALID'].includes(error?.code))
    return [400, false, 'Invalid isolated lesson request'];
  if (['TURN_REQUEST_CONFLICT','TURN_RECOVERY_REQUIRED'].includes(error?.code))
    return [409, false, 'Isolated lesson outcome requires readback'];
  return [503, false, 'Isolated lesson unavailable'];
}
function createBoundIdorLessonRouter({ launches, authenticatePersona, runtime } = {}) {
  if (typeof launches?.resolveCapability !== 'function'
      || typeof authenticatePersona !== 'function'
      || ['createSession','prepare','readCards','run','readRequest',
        'readAssessment','retryAssessment'].some(key => typeof runtime?.[key] !== 'function'))
    throw new TypeError('Bound IDOR lesson route dependencies required');
  const router = express.Router(), launch = requireSecureShopLaunch({ launches });
  const prefix = '/agents/customer/idor';
  router.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const select = (req, res, next) => singleLaunchHeader(req)
    ? launch(req, res, next) : next('route');
  const customer = [authenticatePersona, (req, res, next) => {
    if (req.ssUser?.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id)
        || req.ssUser.id < 1 || !UUID.test(req.ssPersonaSession?.sessionId || '')
        || !/^[1-9]\d*$/.test(req.ssPersonaSession?.authorityVersion || ''))
      return res.status(403).json({ error: 'Customer persona unavailable' });
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: 'customer' });
    next();
  }];
  const bad = res => res.status(400).json({ error: 'Invalid isolated lesson request' });
  const handle = fn => async (req, res) => {
    const controller = new AbortController();
    const abort = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', abort); res.once('close', abort);
    try {
      const value = await fn(req, controller.signal);
      if (!res.writableEnded && !res.destroyed) res.status(200).json(value);
    } catch (error) {
      if (!res.writableEnded && !res.destroyed) {
        const [status, unavailable, message] = publicError(error);
        if (unavailable) markSecureShopLaunchUnavailable(res);
        res.status(status).json({ error: message });
      }
    } finally { req.off('aborted', abort); res.off('close', abort); }
  };
  const context = (req, signal) => ({ scope: req.ssLaunch,
    persona: req.boundPersona, personaSession: req.ssPersonaSession, signal });
  const refs = req => ({ sessionId: req.params.sessionId.toLowerCase(),
    requestId: req.params.requestId.toLowerCase() });
  const validRefs = req => Object.keys(req.query).length === 0
    && UUID.test(req.params.sessionId || '') && UUID.test(req.params.requestId || '');
  router.post(`${prefix}/prepare`, select, ...customer, (req, res, next) =>
    Object.keys(req.query).length || !req.is('application/json') || !exact(req.body, [])
      ? bad(res) : next(), handle(async (req, signal) => cards(await runtime.prepare(
        req.ssLaunch, req.boundPersona, req.ssPersonaSession, signal))));
  router.get(`${prefix}/cards`, select, ...customer, (req, res, next) =>
    Object.keys(req.query).length ? bad(res) : next(), handle(async (req, signal) =>
    cards(await runtime.readCards(req.ssLaunch, req.boundPersona,
      req.ssPersonaSession, signal))));
  router.post(`${prefix}/session`, select, ...customer, (req, res, next) =>
    Object.keys(req.query).length || !req.is('application/json') || !exact(req.body, [])
      ? bad(res) : next(), handle(async (req, signal) => {
        const value = await runtime.createSession(req.ssLaunch, req.boundPersona,
          req.ssPersonaSession, signal);
        if (!UUID.test(value?.id || '')) throw invalid();
        return Object.freeze({ sessionId: value.id.toLowerCase() });
      }));
  router.post(`${prefix}/chat`, select, ...customer, async (req, res) => {
    if (Object.keys(req.query).length || !req.is('application/json')
        || !exact(req.body, ['sessionId','requestId','message','selection'])
        || !UUID.test(req.body.sessionId || '') || !UUID.test(req.body.requestId || '')
        || typeof req.body.message !== 'string' || !req.body.message.trim()
        || !req.body.message.isWellFormed() || req.body.message.includes('\0')
        || Buffer.byteLength(req.body.message, 'utf8') > 8192) return bad(res);
    let selection;
    try { selection = normalizeIdorLessonSelection(req.body.selection); }
    catch { return bad(res); }
    const controller = new AbortController();
    const abort = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', abort); res.once('close', abort);
    res.status(200).set({ 'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store', Connection: 'keep-alive' });
    let count = 0, bytes = 0;
    const send = (name, data) => {
      if (res.writableEnded || res.destroyed || controller.signal.aborted) return;
      const packet = `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
      if (++count > 80 || (bytes += Buffer.byteLength(packet, 'utf8')) > 131072) {
        controller.abort(); throw invalid();
      }
      res.write(packet);
    };
    try {
      await runtime.run({ ...context(req, controller.signal),
        sessionId: req.body.sessionId.toLowerCase(),
        requestId: req.body.requestId.toLowerCase(),
        message: req.body.message, selection, stream: { send } });
    } catch (error) {
      if (!controller.signal.aborted) {
        const [, unavailable, message] = publicError(error);
        try { send('error', { sessionId: req.body.sessionId.toLowerCase(),
          requestId: req.body.requestId.toLowerCase(), message,
          ...(unavailable ? { code: 'SHOP_AUTH_UNAVAILABLE' } : {}) }); } catch {}
      }
    } finally {
      req.off('aborted', abort); res.off('close', abort);
      if (!res.writableEnded) res.end();
    }
  });
  router.get(`${prefix}/operations/:sessionId/:requestId`, select, ...customer,
    (req, res, next) => validRefs(req) ? next() : bad(res),
    handle(async (req, signal) => {
      const { sessionId, requestId } = refs(req);
      return saved(await runtime.readRequest({ ...context(req, signal),
        sessionId, requestId }), sessionId, requestId);
    }));
  router.get(`${prefix}/assessments/:sessionId/:requestId`, select, ...customer,
    (req, res, next) => validRefs(req) ? next() : bad(res),
    handle(async (req, signal) => assessment(await runtime.readAssessment({
      ...context(req, signal), ...refs(req) }))));
  router.post(`${prefix}/assessment-retry`, select, ...customer,
    (req, res, next) => Object.keys(req.query).length || !req.is('application/json')
      || !exact(req.body, ['sessionId','requestId'])
      || !UUID.test(req.body.sessionId || '') || !UUID.test(req.body.requestId || '')
      ? bad(res) : next(),
    handle(async (req, signal) => assessment(await runtime.retryAssessment({
      ...context(req, signal), sessionId: req.body.sessionId.toLowerCase(),
      requestId: req.body.requestId.toLowerCase() }))));
  return router;
}

module.exports = { createBoundIdorLessonRouter };
