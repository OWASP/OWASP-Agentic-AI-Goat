'use strict';
const express = require('express');
const { requireSecureShopLaunch } = require('../middleware/secureshopLaunch');
const { createConversationBinding } = require('../services/secureshopConversationBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LAUNCH_UNAVAILABLE = new Set(['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE', 'OWNER_MISMATCH']);
const TURN_ERRORS = Object.freeze({
  TURN_REQUEST_CONFLICT: [409, 'Turn request conflicts with its original message'],
  TURN_RECOVERY_REQUIRED: [409, 'Turn outcome requires recovery'],
  TURN_CAPACITY: [409, 'Conversation turn limit reached'],
  INVALID_TURN_REQUEST: [400, 'Invalid turn request'],
  INVALID_MESSAGE: [400, 'Invalid message'],
});

function publicError(error) {
  if (Object.hasOwn(TURN_ERRORS, error?.code)) return TURN_ERRORS[error.code];
  if (error?.code === 'CONVERSATION_CAPACITY') return [409, 'Launch conversation limit reached'];
  if (LAUNCH_UNAVAILABLE.has(error?.code)) return [401, 'SecureShop launch unavailable'];
  if (error?.code === 'CONVERSATION_UNAVAILABLE') return [404, 'Conversation unavailable'];
  return [503, 'Conversation service unavailable'];
}

function createLazyStream(res) {
  let opened = false;
  const writable = () => !res.destroyed && !res.writableEnded;
  const open = () => {
    if (opened || !writable()) return writable();
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.write(': stream open\n\n');
    opened = true;
    return true;
  };
  return Object.freeze({
    get opened() { return opened; },
    send(name, data) {
      if (!open() || !writable()) return false;
      res.write(`event: ${name}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
      return true;
    },
    close() { if (writable()) res.end(); },
  });
}

// Prepared isolated route tree. Its caller must supply the existing shop-role
// authentication middleware; a shop persona never replaces launch authority.
// The optional chat route remains unmounted until its complete live execution
// boundary is qualified; omitting runner leaves only lifecycle/read routes.
function buildBoundConversationRouter({ launches, service, authenticatePersona, role, runner }) {
  if (!['customer', 'merchant', 'admin'].includes(role) || typeof authenticatePersona !== 'function') {
    throw new TypeError('Shop role authentication required');
  }
  if (runner !== undefined && typeof runner?.run !== 'function') throw new TypeError('Bound agent runner required');
  const router = express.Router();
  router.use(requireSecureShopLaunch({ launches }), authenticatePersona);
  router.use((req, res, next) => {
    if (Object.keys(req.query).length) return res.status(400).json({ error: 'Query parameters are not supported' });
    if (req.ssUser?.role !== role) return res.status(403).json({ error: 'Shop persona unavailable' });
    try {
      const binding = createConversationBinding(req.ssLaunch, req.ssUser);
      req.boundPersona = Object.freeze({ id: binding.shopUserId, role: binding.role });
      next();
    } catch {
      res.status(401).json({ error: 'Shop persona unavailable' });
    }
  });
  const handle = operation => async (req, res) => {
    try { await operation(req, res); }
    catch (error) {
      if (error?.code === 'CONVERSATION_CAPACITY') return res.status(409).json({ error: 'Launch conversation limit reached' });
      if (LAUNCH_UNAVAILABLE.has(error?.code)) return res.status(401).json({ error: 'SecureShop launch unavailable' });
      const unavailable = error?.code === 'CONVERSATION_UNAVAILABLE';
      res.status(unavailable ? 404 : 503).json({ error: unavailable ? 'Conversation unavailable' : 'Conversation service unavailable' });
    }
  };
  router.post('/sessions', handle(async (req, res) => {
    if (!req.is('application/json')) return res.status(415).json({ error: 'application/json required' });
    if (!req.body || Array.isArray(req.body) || typeof req.body !== 'object' || Object.keys(req.body).length) {
      return res.status(400).json({ error: 'Empty request body required' });
    }
    const result = await service.create(req.ssLaunch, req.boundPersona);
    res.json({ sessionId: result.id });
  }));
  router.get('/trace', handle(async (req, res) => {
    res.json({ trace: await service.latestTrace(req.ssLaunch, req.boundPersona, 20) });
  }));
  router.param('sessionId', (req, res, next, id) => {
    if (!UUID.test(id)) return res.status(404).json({ error: 'Conversation unavailable' });
    req.params.sessionId = id.toLowerCase();
    next();
  });
  router.get('/sessions/:sessionId/messages', handle(async (req, res) => {
    res.json({ messages: await service.getMessages(req.params.sessionId, req.ssLaunch, req.boundPersona) });
  }));
  router.get('/sessions/:sessionId/trace', handle(async (req, res) => {
    res.json({ trace: await service.getTrace(req.params.sessionId, req.ssLaunch, req.boundPersona, 100) });
  }));
  if (runner) router.post('/sessions/:sessionId/chat', async (req, res) => {
    if (!req.is('application/json')) return res.status(415).json({ error: 'application/json required' });
    const body = req.body;
    if (!body || Array.isArray(body) || typeof body !== 'object'
      || Object.keys(body).sort().join(',') !== 'message,requestId'
      || typeof body.requestId !== 'string' || !UUID.test(body.requestId)
      || typeof body.message !== 'string' || !body.message.trim()
      || Buffer.byteLength(body.message, 'utf8') > 64 * 1024) {
      return res.status(400).json({ error: 'requestId and message required' });
    }
    const controller = new AbortController();
    const abort = () => controller.abort();
    const onClose = () => { if (!res.writableFinished) abort(); };
    req.once('aborted', abort);
    res.once('close', onClose);
    const stream = createLazyStream(res);
    try {
      if (req.aborted || res.destroyed) abort();
      controller.signal.throwIfAborted();
      await runner.run({
        sessionId: req.params.sessionId,
        requestId: body.requestId,
        scope: req.ssLaunch,
        persona: req.boundPersona,
        message: body.message,
        signal: controller.signal,
        stream,
      });
    } catch (error) {
      if (!controller.signal.aborted && !res.destroyed && !res.writableEnded) {
        const [status, message] = publicError(error);
        if (stream.opened) stream.send('error', { message });
        else res.status(status).json({ error: message });
      }
    } finally {
      req.off('aborted', abort);
      res.off('close', onClose);
      stream.close();
    }
  });
  return router;
}
module.exports = { buildBoundConversationRouter };
