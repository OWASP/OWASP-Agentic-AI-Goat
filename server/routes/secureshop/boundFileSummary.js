'use strict';

const express = require('express');
const multer = require('multer');
const {
  requireSecureShopLaunch
} = require('../../middleware/secureshopLaunch');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function cancellation(req, res) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  req.once('aborted', abort);
  res.once('close', abort);
  if (req.aborted || res.destroyed || res.writableEnded) abort();
  return {
    signal: controller.signal,
    close() {
      req.off('aborted', abort);
      res.off('close', abort);
    }
  };
}
function createBoundFileSummaryRouter({
  launches,
  authenticatePersona,
  graph,
  saved,
  assessment,
  modeAuthority
} = {}) {
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function' || typeof graph?.createSession !== 'function' || typeof graph?.run !== 'function') throw new TypeError('Bound file summary route dependencies required');
  const router = express.Router(),
    launch = requireSecureShopLaunch({
      launches
    });
  const parse = multer({
    storage: multer.memoryStorage(),
    limits: {
      files: 1,
      fileSize: 8192,
      fields: 3, fieldSize: 8193, parts: 5
    }
  }).single('file');
  const customer = (req, res, next) => req.ssUser?.role === 'customer' && Number.isSafeInteger(req.ssUser.id) && UUID.test(req.ssPersonaSession?.sessionId || '') ? next() : res.status(403).json({
    error: 'Customer persona unavailable'
  });
  const context = req => ({
    scope: req.ssLaunch,
    persona: {
      id: req.ssUser.id,
      role: 'customer'
    },
    personaSession: {
      sessionId: req.ssPersonaSession.sessionId,
      authorityVersion: req.ssPersonaSession.authorityVersion
    }
  });
  function handle(work) {
    return async (req, res) => {
      const pending = cancellation(req, res);
      try {
        pending.signal.throwIfAborted();
        const out = await work(req, pending.signal);
        pending.signal.throwIfAborted();
        res.status(200).json(out);
      } catch (error) {
        if (!pending.signal.aborted && !res.destroyed && !res.writableEnded) res.status(error?.code === 'INVALID_ARGUMENT' ? 400 : 503).json({
          error: 'File summary unavailable'
        });
      } finally {
        pending.close();
      }
    };
  }
  const invalid = () => Object.assign(Error('Invalid upload request'), {
    code: 'INVALID_ARGUMENT'
  });
  router.post('/agents/customer/file-summary/session', launch, authenticatePersona, customer, handle(async (req, signal) => {
    if (!req.is('application/json') || Object.keys(req.query || {}).length || Object.keys(req.body || {}).length) throw invalid();
    return graph.createSession({
      ...context(req),
      signal
    });
  }));
  const exact = (value, keys, multipart = false) => value && typeof value === 'object'
    && (Object.getPrototypeOf(value) === Object.prototype || multipart && Object.getPrototypeOf(value) === null)
    && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
    && Object.values(Object.getOwnPropertyDescriptors(value)).every(descriptor => Object.hasOwn(descriptor, 'value'));
  const { projectFileSummaryTurn } = require('../../services/secureshopV19FileSummarySavedTurn');
  if (typeof saved?.read !== 'function' || typeof assessment?.runAttempt !== 'function'
    || typeof assessment?.readOutcome !== 'function' || typeof modeAuthority?.capture !== 'function'
    || typeof modeAuthority?.assertToken !== 'function') throw TypeError('Complete summary application required');
  router.get('/agents/customer/file-summary/capability', launch, authenticatePersona, customer, handle(async (req, signal) => {
    if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length) throw invalid();
    const { captureFeatureMode, projectFeatureMode } = require('../../services/secureshopFeatureModeAuthority');
    const mode = await captureFeatureMode(modeAuthority, req.ssLaunch, 'file_summary');
    signal.throwIfAborted(); await mode.assertCurrent(); return projectFeatureMode(mode);
  }));
  router.post('/agents/customer/file-summary/run', launch, authenticatePersona, customer, handle(async (req, signal) => {
    await new Promise((resolve, reject) => parse(req, {}, error => error ? reject(invalid()) : resolve()));
    signal.throwIfAborted(); const body = req.body || {};
    if (Object.keys(req.query || {}).length || !req.file || !exact(body, ['sessionId','requestId','message'], true)
      || !UUID.test(body.sessionId || '') || !UUID.test(body.requestId || '')
      || typeof body.message !== 'string' || !body.message.trim() || Buffer.byteLength(body.message) > 8192) throw invalid();
    const filename = req.file.originalname, bytes = req.file.buffer;
    if (typeof filename !== 'string' || Buffer.byteLength(filename) > 255
      || !/\.(txt|md)$/i.test(filename) || !Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 8192
      || !['text/plain','text/markdown','','application/octet-stream'].includes(req.file.mimetype)) throw invalid();
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw invalid(); }
    if (text.includes(String.fromCharCode(0))) throw invalid();
    const mime = /\.md$/i.test(filename) ? 'text/markdown' : 'text/plain';
    const sessionId = body.sessionId.toLowerCase(), requestId = body.requestId.toLowerCase();
    const result = await graph.run({ ...context(req), sessionId, requestId, message: body.message,
      attachment: { bytes, filename, mime }, signal });
    return projectFileSummaryTurn({ sessionId, requestId, result, replayed: result.replayed === true });
  }));
  const reference = req => {
    if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length
      || !UUID.test(req.params.sessionId || '') || !UUID.test(req.params.requestId || '')) throw invalid();
    return { ...context(req), sessionId: req.params.sessionId.toLowerCase(), requestId: req.params.requestId.toLowerCase() };
  };
  router.get('/agents/customer/file-summary/requests/:sessionId/:requestId', launch, authenticatePersona, customer,
    handle((req, signal) => saved.read({ ...reference(req), signal })));
  const assessmentResult = value => {
    if (exact(value, ['completed','status','modelEvaluated','reason']) && value.completed === false
      && value.status === 'unavailable' && value.modelEvaluated === false
      && value.reason === 'evidence_size_limit') return value;
    if (exact(value, ['completed','status','modelEvaluated']) && value.completed === false
      && value.modelEvaluated === false && ['ineligible','unconfirmed'].includes(value.status)) return value;
    if (!exact(value, ['completed','judgment','replayed']) || typeof value.completed !== 'boolean'
      || typeof value.replayed !== 'boolean' || !UUID.test(value.judgment?.evaluationId || '')
      || !['pass','fail','inconclusive','unavailable'].includes(value.judgment?.verdict)
      || typeof value.judgment.canRetry !== 'boolean' || value.completed && value.judgment.verdict !== 'pass') throw invalid();
    return Object.freeze({ completed: value.completed, replayed: value.replayed,
      judgment: Object.freeze({ verdict: value.judgment.verdict, evaluationId: value.judgment.evaluationId,
        canRetry: value.judgment.canRetry }) });
  };
  router.post('/agents/customer/file-summary/assess', launch, authenticatePersona, customer, handle(async (req, signal) => {
    if (Object.keys(req.query || {}).length || !req.is('application/json') || !exact(req.body, ['sessionId','requestId'])
      || !UUID.test(req.body.sessionId || '') || !UUID.test(req.body.requestId || '')) throw invalid();
    return assessmentResult(await assessment.runAttempt({ ...context(req), signal,
      sessionId: req.body.sessionId.toLowerCase(), requestId: req.body.requestId.toLowerCase() }));
  }));
  router.get('/agents/customer/file-summary/assess/:sessionId/:requestId', launch, authenticatePersona, customer,
    handle(async (req, signal) => assessmentResult(await assessment.readOutcome({ ...reference(req), signal }))));
  return router;
}
module.exports = { createBoundFileSummaryRouter };
