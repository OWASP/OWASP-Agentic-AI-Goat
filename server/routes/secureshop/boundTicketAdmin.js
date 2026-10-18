'use strict';
const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } = require('../../middleware/secureshopLaunch');
const Ticket = require('../../services/secureshopTicketContract');
const MAX_TICKET_ID = 9223372036854775807n;

function createBoundTicketAdminRouter({ launches, authenticatePersona, administration } = {}) {
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function'
      || typeof administration?.list !== 'function' || typeof administration?.read !== 'function') {
    throw new TypeError('Ticket administration dependencies required');
  }
  const router = express.Router();
  const launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => {
    const count = (req.rawHeaders || []).filter((_, index) => index % 2 === 0)
      .filter(name => name.toLowerCase() === 'x-dvaia-secureshop-launch').length;
    return count === 1 ? launch(req, res, next) : next('route');
  };
  const admin = (req, res, next) => {
    if (req.ssUser?.role !== 'admin' || !Number.isSafeInteger(req.ssUser.id)
        || req.ssUser.id < 1 || !req.ssPersonaSession?.sessionId) {
      return res.status(403).json({ error: 'Administrator persona unavailable' });
    }
    next();
  };
  const handle = detail => async (req, res) => {
    const keys = Object.keys(req.query || {});
    const cursor = req.query?.cursor ?? null;
    const ticketId = req.params.ticketId;
    const validTicketId = typeof ticketId === 'string' && /^[1-9]\d{0,18}$/.test(ticketId)
      && BigInt(ticketId) <= MAX_TICKET_ID;
    if (detail ? keys.length || !validTicketId
      : keys.some(key => key !== 'cursor') || cursor !== null &&
        (typeof cursor !== 'string' || !cursor || Buffer.byteLength(cursor, 'utf8') > 1024)) {
      return res.status(400).json({ error: 'Invalid ticket read request' });
    }
    const context = Object.freeze({ scope: req.ssLaunch,
      persona: Object.freeze({ id: req.ssUser.id, role: 'admin' }),
      personaSession: req.ssPersonaSession });
    res.set('Cache-Control', 'no-store');
    try {
      const value = detail ? await administration.read(context, Object.freeze({ ticketId }))
        : await administration.list(context, Object.freeze({ cursor }));
      if (detail && value === null) return res.status(404).json({ error: 'Ticket unavailable' });
      return res.json(detail ? Ticket.publicAdminDetail(value) : Ticket.adminList(value));
    } catch (error) {
      const stale = ['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE',
        'SHOP_AUTH_INVALID', 'SHOP_SCENE_STALE'].includes(error?.code);
      if (stale) markSecureShopLaunchUnavailable(res);
      return res.status(stale ? 401 : 503).json({
        error: stale ? 'Shop session unavailable' : 'Ticket read unavailable',
      });
    }
  };
  router.get('/admin/tickets', select, authenticatePersona, admin, handle(false));
  router.get('/admin/tickets/:ticketId', select, authenticatePersona, admin, handle(true));
  return router;
}
module.exports = { createBoundTicketAdminRouter };
