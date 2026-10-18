'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable }
  = require('../../middleware/secureshopLaunch');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES = new Set(['customer', 'merchant', 'admin']);
const LAUNCH_ERRORS = new Set(['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE']);
const AUTHORITY_ERRORS = new Set([...LAUNCH_ERRORS,
  'OWNER_MISMATCH', 'SHOP_AUTH_INVALID', 'REVIEW_TARGET_UNAVAILABLE', 'CONVERSATION_UNAVAILABLE']);

function positive(value, fallback, max = 2147483647) {
  const number = Math.trunc(Number(value));
  return Number.isSafeInteger(number) && number >= 1 ? Math.min(number, max) : fallback;
}
function resourceId(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) return 0;
  const id = Number(value);
  return Number.isSafeInteger(id) && id <= 2147483647 ? id : 0;
}
function exactObject(value, keys, required = keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).every(key => keys.includes(key))
    && required.every(key => Object.hasOwn(value, key));
}
function headerOccurrences(req) {
  let count = 0;
  for (let index = 0; index < (req.rawHeaders || []).length; index += 2) {
    if (String(req.rawHeaders[index]).toLowerCase() === 'x-dvaia-secureshop-launch') count += 1;
  }
  return count;
}
function productReview(row) {
  return Object.freeze({ id: row.id, body: row.body, rating: row.rating, status: row.status,
    moderator_kind: row.moderator_kind ?? null, created_at: row.created_at,
    ...(row.author_name === undefined ? {} : { author_name: row.author_name }) });
}
function merchantReview(row) {
  return Object.freeze({ id: row.id, product_id: row.product_id, author_id: row.author_id,
    body: row.body, rating: row.rating, status: row.status,
    moderator_kind: row.moderator_kind ?? null, moderator_notes: row.moderator_notes ?? null,
    created_at: row.created_at, moderated_at: row.moderated_at ?? null });
}
function publicError(error) {
  if (error?.code === 'REVIEW_TARGET_CAPACITY') return [409,
    'SecureShop retained review limit reached. Ask your administrator to review retained sessions before opening another.'];
  if (AUTHORITY_ERRORS.has(error?.code)) {
    return [401, 'SecureShop launch unavailable', LAUNCH_ERRORS.has(error.code)];
  }
  if (error?.code === 'REVIEW_OPERATION_CONFLICT' || error?.code === 'TURN_REQUEST_CONFLICT') return [409, 'This request ID was already used for a different action'];
  if (error?.code === 'TURN_CAPACITY') return [409, 'This exercise has reached its request limit'];
  if (error?.code === 'REVIEW_NOT_FOUND') return [404, 'Review unavailable'];
  if (error?.code === 'REVIEW_SUBMISSION_CONFLICT' || error?.code === 'REVIEW_CAPACITY') {
    return [409, 'Review request could not be completed'];
  }
  if (error?.code === 'INVALID_ARGUMENT') return [400, 'Invalid review request'];
  return [503, 'Review service unavailable'];
}

// Selective launch-bound adapter. With no launch header, the route is skipped
// and the established ungraded SecureShop router handles the request. Once a
// launch header is present, invalid authority must never fall back to it.
function createBoundReviewsRouter({ launches, authenticatePersona, service, moderation, manualDecisions } = {}) {
  if (typeof authenticatePersona !== 'function' || !service
    || ['listProductReviews', 'submitReview', 'listMerchantReviews', 'approveReview', 'rejectReview']
      .some(name => typeof service[name] !== 'function')) {
    throw new TypeError('Bound review route dependencies required');
  }
  if (moderation !== undefined && typeof moderation?.moderateReviews !== 'function') {
    throw new TypeError('Bound moderation service required');
  }
  const router = express.Router();
  const launch = requireSecureShopLaunch({ launches });
  const select = (req, res, next) => headerOccurrences(req) === 0 ? next('route') : launch(req, res, next);
  const persona = (requiredRole = null) => [authenticatePersona, (req, res, next) => {
    if (!req.ssUser || !Number.isSafeInteger(req.ssUser.id) || req.ssUser.id < 1
      || !ROLES.has(req.ssUser.role) || (requiredRole && req.ssUser.role !== requiredRole)) {
      return res.status(403).json({ error: 'Shop persona unavailable' });
    }
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: req.ssUser.role });
    next();
  }];
  const handle = operation => async (req, res) => {
    try { await operation(req, res); }
    catch (error) {
      const [status, message, launchUnavailable] = publicError(error);
      if (!res.headersSent) {
        if (launchUnavailable) markSecureShopLaunchUnavailable(res);
        res.status(status).json({ error: message });
      }
    }
  };
  const noUnexpectedQuery = (req, res, allowed) => {
    if (Object.keys(req.query).some(key => !allowed.includes(key))) {
      res.status(400).json({ error: 'Invalid review request' });
      return false;
    }
    return true;
  };

  router.get('/products/:id/reviews', select, ...persona(), handle(async (req, res) => {
    if (!noUnexpectedQuery(req, res, ['limit', 'offset'])) return;
    const productId = resourceId(req.params.id);
    if (!productId) return res.status(400).json({ error: 'Invalid review request' });
    const result = await service.listProductReviews({ scope: req.ssLaunch, persona: req.boundPersona,
      personaSession: req.ssPersonaSession,
      productId, limit: positive(req.query.limit, 10, 50),
      offset: Math.max(0, Math.trunc(Number(req.query.offset)) || 0) });
    res.json({ reviews: (result.reviews || []).map(productReview), total: Number(result.total) || 0 });
  }));

  router.post('/products/:id/reviews', select, ...persona(), handle(async (req, res) => {
    if (!noUnexpectedQuery(req, res, []) || !req.is('application/json')
      || !exactObject(req.body, ['submission_id', 'author_id', 'body', 'rating'])) {
      if (!res.headersSent) res.status(400).json({ error: 'Invalid review request' });
      return;
    }
    const { submission_id: submissionId, author_id: authorId, body, rating } = req.body;
    const productId = resourceId(req.params.id);
    if (typeof submissionId !== 'string' || !UUID.test(submissionId)
      || !productId
      || !Number.isSafeInteger(authorId) || authorId < 1
      || typeof body !== 'string' || !body.trim() || Buffer.byteLength(body, 'utf8') > 65536
      || !Number.isSafeInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Invalid review request' });
    }
    // Raw body and caller-selected author are deliberate teaching inputs. The
    // service records req.boundPersona separately and returns no provenance.
    const result = await service.submitReview({ scope: req.ssLaunch, persona: req.boundPersona,
      personaSession: req.ssPersonaSession,
      submissionId: submissionId.toLowerCase(), productId,
      authorId, body, rating });
    if (!Number.isSafeInteger(result?.id) || result.id < 1) throw new Error('Invalid submission projection');
    res.json({ ok: true, review_id: result.id });
  }));

  for (const path of ['/merchant/reviews/moderate', '/merchant/reviews/moderate-all']) {
    router.post(path, select, ...persona('merchant'), handle(async (req, res) => {
      if (!moderation) return res.status(503).json({ error: 'Bound model moderation unavailable' });
      if (!noUnexpectedQuery(req, res, []) || !req.is('application/json')
          || !exactObject(req.body, ['request_id', 'limit'], ['request_id'])
          || typeof req.body.request_id !== 'string' || !UUID.test(req.body.request_id)
          || (req.body.limit !== undefined && (!Number.isInteger(req.body.limit) || req.body.limit < 1 || req.body.limit > 100))) {
        if (!res.headersSent) res.status(400).json({ error: 'Invalid moderation request' });
        return;
      }
      const controller = new AbortController();
      const abort = () => { if (!res.writableEnded) controller.abort(); };
      req.once('aborted', abort); res.once('close', abort);
      try {
        const result = await moderation.moderateReviews({ scope: req.ssLaunch, persona: req.boundPersona,
          ...(req.ssPersonaSession ? {personaSession:req.ssPersonaSession} : {}),
          requestId: req.body.request_id.toLowerCase(), limit: req.body.limit ?? 100, signal: controller.signal });
        controller.signal.throwIfAborted();
        res.json(result);
      } finally {
        req.off('aborted', abort); res.off('close', abort);
      }
    }));
  }

  router.get('/merchant/reviews', select, ...persona('merchant'), handle(async (req, res) => {
    if (!noUnexpectedQuery(req, res, ['status', 'product_id', 'min_rating', 'max_rating', 'page', 'per_page'])) return;
    const page = positive(req.query.page, 1);
    const perPage = positive(req.query.per_page, 25, 100);
    const result = await service.listMerchantReviews({ scope: req.ssLaunch, persona: req.boundPersona,
      personaSession: req.ssPersonaSession,
      filters: { status: req.query.status || null,
        productId: req.query.product_id ? Number(req.query.product_id) : null,
        minRating: req.query.min_rating ? Number(req.query.min_rating) : null,
        maxRating: req.query.max_rating ? Number(req.query.max_rating) : null,
        limit: perPage, offset: (page - 1) * perPage } });
    const reviews = (result.rows || []).map(merchantReview);
    const counts = Object.freeze({ pending: Number(result.counts?.pending) || 0,
      approved: Number(result.counts?.approved) || 0, rejected: Number(result.counts?.rejected) || 0 });
    res.json({ reviews, count: reviews.length, total: Number(result.total) || 0,
      page, per_page: perPage, counts, ...(manualDecisions ? {manual_decisions:await manualDecisions.capability({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession})} : {}) });
  }));

  if(manualDecisions)router.get('/merchant/reviews/operations/:operationId',select,...persona('merchant'),handle(async(req,res)=>{
    if(!noUnexpectedQuery(req,res,[])||!UUID.test(req.params.operationId))return res.status(400).json({error:'Invalid review operation'});
    const acknowledged=await manualDecisions.read({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,operationId:req.params.operationId});
    if(!acknowledged)return res.status(404).json({error:'Review operation unavailable'});res.json({ok:true,...acknowledged});
  }));

  router.post('/merchant/reviews/:id/approve', select, ...persona('merchant'), handle(async (req, res) => {
    if (!noUnexpectedQuery(req, res, []) || (req.body !== undefined && !exactObject(req.body, manualDecisions?['operationId']:[], manualDecisions?['operationId']:[]))) {
      if (!res.headersSent) res.status(400).json({ error: 'Invalid review request' });
      return;
    }
    const reviewId = resourceId(req.params.id);
    if (!reviewId) return res.status(400).json({ error: 'Invalid review request' });
    if(manualDecisions){if(!req.is('application/json')||!UUID.test(req.body?.operationId))return res.status(400).json({error:'Invalid review operation'});const result=await manualDecisions.decide({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,reviewId,operationId:req.body.operationId,decision:'approve'});return res.json({ok:true,applied:result.applied,review_id:reviewId,receipt:result.receipt,replayed:result.replayed,executionScopeKey:result.executionScopeKey});}
    const result = await service.approveReview({ scope: req.ssLaunch, persona: req.boundPersona,
      personaSession: req.ssPersonaSession, reviewId });
    if (!result || typeof result.applied !== 'boolean') throw new Error('Invalid manual review projection');
    res.json({ ok: result.applied, review_id: reviewId });
  }));

  router.post('/merchant/reviews/:id/reject', select, ...persona('merchant'), handle(async (req, res) => {
    if (!noUnexpectedQuery(req, res, []) || !req.is('application/json')
      || !exactObject(req.body, manualDecisions?['reason','operationId']:['reason'], manualDecisions?['operationId']:[])) {
      if (!res.headersSent) res.status(400).json({ error: 'Invalid review request' });
      return;
    }
    const reason = req.body.reason ?? null;
    if (reason !== null && (typeof reason !== 'string' || Buffer.byteLength(reason, 'utf8') > 16384)) {
      return res.status(400).json({ error: 'Invalid review request' });
    }
    const reviewId = resourceId(req.params.id);
    if (!reviewId) return res.status(400).json({ error: 'Invalid review request' });
    if(manualDecisions){if(!UUID.test(req.body?.operationId))return res.status(400).json({error:'Invalid review operation'});const result=await manualDecisions.decide({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,reviewId,operationId:req.body.operationId,decision:'reject',reason});return res.json({ok:true,applied:result.applied,review_id:reviewId,receipt:result.receipt,replayed:result.replayed,executionScopeKey:result.executionScopeKey});}
    const result = await service.rejectReview({ scope: req.ssLaunch, persona: req.boundPersona,
      personaSession: req.ssPersonaSession, reviewId, reason });
    if (!result || typeof result.applied !== 'boolean') throw new Error('Invalid manual review projection');
    res.json({ ok: result.applied, review_id: reviewId });
  }));

  return router;
}

module.exports = { createBoundReviewsRouter };
