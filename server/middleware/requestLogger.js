'use strict';

const morgan = require('morgan');
const crypto = require('crypto');
const logger = require('../utils/logger');

// ── Request ID ────────────────────────────────────────────────────────────────
const requestId = (req, res, next) => {
  req.requestId = req.headers['x-request-id'] || crypto.randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
  next();
};

// ── Morgan → Winston (structured) ────────────────────────────────────────────
// Morgan collects on res.finish, so :user-id is read AFTER auth middleware has
// set req.user — even though httpLogger is registered before auth middleware.
morgan.token('request-id', (req) => req.requestId || '-');
morgan.token('user-id',    (req) => (req.user && req.user.id) ? String(req.user.id) : '-');

const httpLogger = morgan(
  // The format string is still used as the human-readable message field
  ':request-id :method :url :status :response-time ms :remote-addr ":user-agent" user=:user-id',
  {
    stream: {
      write: (message) => {
        // Parse structured fields out of Morgan tokens that were already captured
        // by the time res.finish fires (after auth middleware runs).
        const parts = message.trim().split(' ');
        const reqId    = parts[0] || '-';
        const method   = parts[1] || '-';
        const url      = parts[2] || '-';
        const status   = parseInt(parts[3], 10) || 0;
        const respTime = parseFloat(parts[4]) || 0;
        // parts[5] == 'ms'
        const ip       = parts[6] || '-';

        logger.info(message.trim(), {
          component: 'http',
          requestId: reqId !== '-' ? reqId : undefined,
          method,
          url,
          status,
          responseTimeMs: respTime,
          ip: ip !== '-' ? ip : undefined
        });
      }
    },
    // Suppress ALB / ECS liveness ping to keep logs clean
    skip: (req) => req.path === '/api/monitoring/ping'
  }
);

module.exports = { requestId, httpLogger };
