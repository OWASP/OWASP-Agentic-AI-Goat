'use strict';
const express = require('express');
const { randomUUID } = require('node:crypto');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } = require('../../middleware/secureshopLaunch');
const PURPOSE = 'secureshop_refund_request';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function exactBody(body, keys, required = keys) {
  return body && typeof body === 'object' && !Array.isArray(body)
    && Object.keys(body).every(key => keys.includes(key)) && required.every(key => Object.hasOwn(body, key));
}
function header(req) { return (req.rawHeaders || []).filter((_, index) => index % 2 === 0)
  .filter(name => String(name).toLowerCase() === 'x-dvaia-secureshop-launch').length === 1; }
function publicError(error) {
  if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE', 'CONVERSATION_UNAVAILABLE', 'SHOP_AUTH_INVALID'].includes(error?.code)) return [401, true, 'SecureShop launch unavailable'];
  if (error?.code === 'INVALID_ARGUMENT') return [400, false, 'Invalid refund request'];
  return [503, false, 'Refund service unavailable'];
}
function createBoundRefundRouter({ launches, authenticatePersona, runtime } = {}) {
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function'
      || typeof runtime?.createSession !== 'function' || typeof runtime?.runner?.run !== 'function') {
    throw new TypeError('Bound refund router dependencies required');
  }
  const router = express.Router();
  const launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => header(req) ? launch(req, res, next) : next('route');
  const customer = [authenticatePersona, (req, res, next) => {
    if (!req.ssUser || req.ssUser.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id) || req.ssUser.id < 1) return res.status(403).json({ error: 'Shop persona unavailable' });
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: 'customer' }); next();
  }];
  router.post('/agents/customer/refund/session', select, ...customer, async (req, res) => {
    try {
      if (!exactBody(req.body, ['userId'], [])) return res.status(400).json({ error: 'Invalid refund session request' });
      const session = await runtime.createSession(req.ssLaunch, req.boundPersona,
        req.ssPersonaSession);
      res.type('application/json').json({ sessionId: session.id });
    } catch (error) {
      const [status, unavailable, message] = publicError(error); if (unavailable) markSecureShopLaunchUnavailable(res); res.status(status).json({ error: message });
    }
  });
  router.post('/agents/customer/refund/chat', select, ...customer, async (req, res) => {
    if (!exactBody(req.body, ['sessionId', 'message', 'requestId'], ['sessionId', 'message']) || typeof req.body.sessionId !== 'string'
      || !req.body.sessionId.trim() || typeof req.body.message !== 'string' || !req.body.message.trim()) return res.status(400).json({ error: 'Invalid refund chat request' });
    if (req.body.requestId !== undefined && (typeof req.body.requestId !== 'string' || !UUID.test(req.body.requestId))) return res.status(400).json({ error: 'Invalid refund chat request' });
    res.status(200).set({ 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache', connection: 'keep-alive' });
    const send = (name, data) => { if (!res.writableEnded) res.write(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`); };
    const requestId = req.body.requestId?.toLowerCase() || randomUUID();
    try {
      await runtime.runner.run({ sessionId: req.body.sessionId, requestId, scope: req.ssLaunch,
        persona: req.boundPersona, ...(req.ssPersonaSession?{personaSession:req.ssPersonaSession}:{}), message: req.body.message, signal: req.signal,
        localToolAuthority: Object.freeze({ requestId }), stream: { send } });
    } catch (error) {
      const [status, unavailable, message] = publicError(error);
      if (unavailable) markSecureShopLaunchUnavailable(res);
      if (!res.writableEnded) { send('error', { message }); send('done', { stopReason: 'error' }); }
      if (!res.headersSent) res.status(status);
    } finally { if (!res.writableEnded) res.end(); }
  });
  router.get('/agents/customer/refund/operations/:sessionId/:requestId', select, ...customer, async (req, res) => {
    if (!UUID.test(req.params.sessionId || '') || !UUID.test(req.params.requestId || '')) {
      return res.status(400).json({ error: 'Invalid refund reference' });
    }
    try {
      const result = await runtime.readRequest(req.ssLaunch, req.boundPersona, req.ssPersonaSession,
        req.params.sessionId.toLowerCase(), req.params.requestId.toLowerCase());
      res.type('application/json').json(result);
    } catch (error) {
      const [status, unavailable, message] = publicError(error);
      if (unavailable) markSecureShopLaunchUnavailable(res);
      res.status(status).json({ error: message });
    }
  });
  return router;
}
module.exports = { createBoundRefundRouter, PURPOSE };
