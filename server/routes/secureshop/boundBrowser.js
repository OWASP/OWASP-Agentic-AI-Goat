'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable }
  = require('../../middleware/secureshopLaunch');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function id(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) return 0;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= 2147483647 ? parsed : 0;
}
function plainExact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function occurrences(req) {
  let count = 0;
  for (let index = 0; index < (req.rawHeaders || []).length; index += 2) {
    if (String(req.rawHeaders[index]).toLowerCase() === 'x-dvaia-secureshop-launch') count++;
  }
  return count;
}
function publicError(error) {
  if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE'].includes(error?.code)) {
    return [401, 'SecureShop launch unavailable', true];
  }
  if (['OWNER_MISMATCH', 'CONVERSATION_UNAVAILABLE'].includes(error?.code)) {
    return [401, 'SecureShop launch unavailable', false];
  }
  if (error?.code === 'SHOP_AUTH_INVALID') return [401, 'Shop persona unavailable'];
  if (error?.code === 'REVIEW_NOT_FOUND') return [404, 'Review unavailable'];
  if (error?.code === 'TURN_REQUEST_CONFLICT') return [409, 'This request ID was already used for a different action'];
  if (error?.code === 'TURN_CAPACITY' || error?.code === 'TURN_RECOVERY_REQUIRED') {
    return [409, 'Browser attempt requires recovery'];
  }
  if (error?.code === 'INVALID_ARGUMENT') return [400, 'Invalid browser attempt'];
  return [503, 'Browser assessment unavailable'];
}

// Selective route: missing launch headers fall through to the legacy router,
// while a present invalid or duplicate header always fails closed.
function createBoundBrowserRouter({ launches, authenticatePersona, assessment,
  observeLifecycle = () => {} } = {}) {
  if (typeof authenticatePersona !== 'function' || typeof assessment?.runAttempt !== 'function') {
    throw new TypeError('Bound browser route dependencies required');
  }
  if (typeof observeLifecycle !== 'function') throw new TypeError('Browser lifecycle observer must be a function');
  const observe = event => {
    try { observeLifecycle(Object.freeze({ ...event })); } catch { /* diagnostics never affect the request */ }
  };
  const router = express.Router();
  const launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => occurrences(req) === 0 ? next('route') : launch(req, res, next);
  router.post('/products/:productId/reviews/:reviewId/browser-attempt', select,
    authenticatePersona, async (req, res) => {
      try {
        if (!req.ssUser || req.ssUser.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id)
            || req.ssUser.id < 1) return res.status(403).json({ error: 'Shop persona unavailable' });
        if (Object.keys(req.query).length || !req.is('application/json')
            || !plainExact(req.body, ['request_id']) || !UUID.test(req.body.request_id)) {
          return res.status(400).json({ error: 'Invalid browser attempt' });
        }
        const productId = id(req.params.productId), reviewId = id(req.params.reviewId);
        if (!productId || !reviewId) return res.status(400).json({ error: 'Invalid browser attempt' });
        const controller = new AbortController();
        const abort = source => {
          observe({ type: 'transport_abort', source, headersSent: res.headersSent,
            writableEnded: res.writableEnded });
          if (!res.writableEnded) controller.abort();
        };
        const requestAborted = () => abort('request_aborted');
        const responseClosed = () => abort('response_close');
        req.once('aborted', requestAborted); res.once('close', responseClosed);
        observe({ type: 'assessment_start' });
        try {
          const result = await assessment.runAttempt({ scope: req.ssLaunch,
            persona: Object.freeze({ id: req.ssUser.id, role: req.ssUser.role }),
            ...(req.ssPersonaSession ? {personaSession: Object.freeze({sessionId:req.ssPersonaSession.sessionId,
              authorityVersion:req.ssPersonaSession.authorityVersion})} : {}),
            requestId: req.body.request_id.toLowerCase(), productId, reviewId,
            signal: controller.signal });
          observe({ type: 'assessment_settled', outcome: 'fulfilled' });
          controller.signal.throwIfAborted();
          res.json(result);
        } catch (error) {
          observe({ type: 'assessment_settled', outcome: 'rejected',
            errorName: typeof error?.name === 'string' ? error.name : null,
            errorCode: typeof error?.code === 'string' ? error.code : null });
          throw error;
        } finally {
          req.off('aborted', requestAborted); res.off('close', responseClosed);
        }
      } catch (error) {
        const [status, message, launchUnavailable] = publicError(error);
        if (!res.headersSent) {
          if (launchUnavailable) markSecureShopLaunchUnavailable(res);
          res.status(status).json({ error: message });
        }
      }
    });
  return router;
}

module.exports = { createBoundBrowserRouter };
