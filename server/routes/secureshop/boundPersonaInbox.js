'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable }
  = require('../../middleware/secureshopLaunch');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES = new Set(['customer', 'merchant', 'admin']);
const LAUNCH_ERRORS = new Set(['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE']);
const AUTHORITY = new Set([...LAUNCH_ERRORS,
  'SHOP_AUTH_INVALID', 'OWNER_MISMATCH', 'CONVERSATION_UNAVAILABLE', 'PERSONA_INBOX_TARGET_UNAVAILABLE']);
function exact(value, keys) { return value && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)); }
function publicError(error) {
  if (AUTHORITY.has(error?.code)) return [error.code === 'OWNER_MISMATCH' ? 403 : 401,
    error.code === 'OWNER_MISMATCH' ? 'Shop persona unavailable' : 'SecureShop launch unavailable',
    LAUNCH_ERRORS.has(error.code)];
  if (error?.code === 'TURN_REQUEST_CONFLICT') return [409, 'This request ID was already used for a different action'];
  if (error?.code === 'TURN_CAPACITY') return [409, 'This exercise has reached its request limit'];
  if (error?.code === 'INVALID_ARGUMENT') return [400, 'Invalid persona inbox request'];
  return [503, 'Persona inbox exercise unavailable'];
}

function createBoundPersonaInboxRouter({ launches, authenticatePersona, application } = {}) {
  if (typeof authenticatePersona !== 'function' || typeof launches?.resolveCapability !== 'function'
      || !application || ['status', 'run', 'enforce'].some(name => typeof application[name] !== 'function')) {
    throw new TypeError('Bound persona inbox route dependencies required');
  }
  const router = express.Router();
  const launch = requireSecureShopLaunch({ launches });
  const persona = [authenticatePersona, (req, res, next) => {
    if (!req.ssUser || !Number.isSafeInteger(req.ssUser.id) || req.ssUser.id < 1 || !ROLES.has(req.ssUser.role)) {
      return res.status(403).json({ error: 'Shop persona unavailable' });
    }
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: req.ssUser.role }); next();
  }];
  const handle = operation => async (req, res) => {
    try { await operation(req, res); } catch (error) {
      const [status, message, launchUnavailable] = publicError(error);
      if (!res.headersSent) {
        if (launchUnavailable) markSecureShopLaunchUnavailable(res);
        res.status(status).json({ error: message });
      }
    }
  };
  const noQuery = req => Object.keys(req.query).length === 0;

  router.get('/v2/persona-inbox/readiness', launch, ...persona, handle(async (req, res) => {
    if (!noQuery(req)) return res.status(400).json({ error: 'Invalid persona inbox request' });
    res.json(await application.status({ scope: req.ssLaunch, persona: req.boundPersona, ...(req.ssPersonaSession?{personaSession:req.ssPersonaSession}:{}) }));
  }));
  router.post('/v2/persona-inbox/read', launch, ...persona, handle(async (req, res) => {
    if (!noQuery(req) || !req.is('application/json') || !exact(req.body, ['request_id', 'message_id'])
        || typeof req.body.request_id !== 'string' || !UUID.test(req.body.request_id)
        || !Number.isSafeInteger(req.body.message_id) || req.body.message_id < 1) {
      return res.status(400).json({ error: 'Invalid persona inbox request' });
    }
    const controller = new AbortController();
    const abort = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', abort); res.once('close', abort);
    try {
      const result = await application.run({ scope: req.ssLaunch, persona: req.boundPersona, ...(req.ssPersonaSession?{personaSession:req.ssPersonaSession}:{}),
        requestId: req.body.request_id.toLowerCase(), messageId: req.body.message_id,
        signal: controller.signal });
      controller.signal.throwIfAborted(); res.json(result);
    } finally { req.off('aborted', abort); res.off('close', abort); }
  }));
  router.post('/v2/persona-inbox/enforce', launch, ...persona, handle(async (req, res) => {
    if (!noQuery(req) || !req.is('application/json') || !exact(req.body, [])) {
      return res.status(400).json({ error: 'Invalid persona inbox request' });
    }
    res.json({ ok: true, acl: await application.enforce({ scope: req.ssLaunch, persona: req.boundPersona, ...(req.ssPersonaSession?{personaSession:req.ssPersonaSession}:{}) }) });
  }));
  return router;
}

module.exports = { createBoundPersonaInboxRouter };
