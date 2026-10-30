'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } = require('../../middleware/secureshopLaunch');
const Ticket = require('../../services/secureshopTicketContract');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requestIds(value) {
  const keys = ['sessionId', 'requestId', 'proposalId'];
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== keys.length
      || !keys.every(key => typeof value[key] === 'string' && UUID.test(value[key]))) return null;
  return Object.freeze(Object.fromEntries(keys.map(key => [key, value[key].toLowerCase()])));
}

function createBoundTicketConfirmationRouter({ launches, authenticatePersona, confirmation } = {}) {
  if (typeof launches?.resolveCapability !== 'function'
      || typeof authenticatePersona !== 'function'
      || typeof confirmation?.confirm !== 'function'
      || typeof confirmation?.readSaved !== 'function') {
    throw new TypeError('Ticket confirmation dependencies required');
  }
  const router = express.Router();
  const launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => {
    const count = (req.rawHeaders || []).filter((_, index) => index % 2 === 0)
      .filter(name => name.toLowerCase() === 'x-owasp-ai-goat-secureshop-launch').length;
    return count === 1 ? launch(req, res, next) : next('route');
  };
  const customer = (req, res, next) => {
    if (req.ssUser?.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id)
        || req.ssUser.id < 1 || !req.ssPersonaSession?.sessionId) {
      return res.status(403).json({ error: 'Customer persona unavailable' });
    }
    next();
  };
  const handle = readOnly => async (req, res) => {
    const ids = requestIds(readOnly ? { sessionId: req.params.sessionId,
      requestId: req.params.requestId, proposalId: req.params.proposalId } : req.body);
    if (!ids || Object.keys(req.query || {}).length || !readOnly && !req.is('application/json')) {
      return res.status(400).json({ error: 'Invalid ticket confirmation request' });
    }
    const context = Object.freeze({ scope: req.ssLaunch,
      persona: Object.freeze({ id: req.ssUser.id, role: 'customer' }),
      personaSession: req.ssPersonaSession });
    res.set('Cache-Control', 'no-store');
    try {
      if (readOnly) return res.json(Ticket.publicSaved(await confirmation.readSaved(context, ids)));
      const confirmed = await confirmation.confirm(context, ids);
      return res.json(Ticket.publicResult(confirmed?.result));
    } catch (error) {
      const stale = ['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE',
        'CONVERSATION_UNAVAILABLE', 'SHOP_AUTH_INVALID', 'SHOP_SCENE_STALE'].includes(error?.code);
      if (stale) markSecureShopLaunchUnavailable(res);
      return res.status(stale ? 401 : 503).json({
        error: stale ? 'Shop session unavailable' : 'Ticket confirmation unavailable',
      });
    }
  };
  router.post('/agents/customer/tickets/confirm', select, authenticatePersona, customer, handle(false));
  router.get('/agents/customer/tickets/confirm/:sessionId/:requestId/:proposalId',
    select, authenticatePersona, customer, handle(true));
  return router;
}

module.exports = { createBoundTicketConfirmationRouter };
