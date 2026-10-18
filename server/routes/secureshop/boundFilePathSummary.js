'use strict';

const express = require('express');
const { requireSecureShopLaunch } = require('../../middleware/secureshopLaunch');
const { validPath } = require('../../services/secureshopV44FilePathSummaryExecutionConfig');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function cancellation(req, res) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  req.once('aborted', abort); res.once('close', abort);
  if (req.aborted || res.destroyed || res.writableEnded) abort();
  return { signal: controller.signal, close() { req.off('aborted', abort); res.off('close', abort); } };
}
const exact = (value, keys) => value && typeof value === 'object'
  && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
  && Object.values(Object.getOwnPropertyDescriptors(value)).every(d => Object.hasOwn(d, 'value'));
const invalid = () => Object.assign(Error('Invalid file-path summary request'), { code: 'INVALID_ARGUMENT' });

function createBoundFilePathSummaryRouter({ launches, authenticatePersona, graph, saved, assessment, modeAuthority } = {}) {
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function'
      || typeof graph?.createSession !== 'function' || typeof graph?.run !== 'function'
      || typeof saved?.read !== 'function' || typeof assessment?.runAttempt !== 'function'
      || typeof assessment?.readOutcome !== 'function' || typeof modeAuthority?.capture !== 'function'
      || typeof modeAuthority?.assertToken !== 'function') throw TypeError('Complete file-path summary application required');
  const router = express.Router();
  const launch = requireSecureShopLaunch({ launches });
  const customer = (req, res, next) => req.ssUser?.role === 'customer' && Number.isSafeInteger(req.ssUser.id)
    && UUID.test(req.ssPersonaSession?.sessionId || '') ? next() : res.status(403).json({ error: 'Customer persona unavailable' });
  const context = req => ({ scope: req.ssLaunch, persona: { id: req.ssUser.id, role: 'customer' },
    personaSession: { sessionId: req.ssPersonaSession.sessionId,
      authorityVersion: req.ssPersonaSession.authorityVersion } });
  const handle = work => async (req, res) => {
    const pending = cancellation(req, res);
    try {
      pending.signal.throwIfAborted();
      const out = await work(req, pending.signal);
      pending.signal.throwIfAborted();
      res.status(200).json(out);
    } catch (error) {
      if (!pending.signal.aborted && !res.destroyed && !res.writableEnded) {
        res.status(error?.code === 'INVALID_ARGUMENT' ? 400 : 503).json({ error: 'File path summary unavailable' });
      }
    } finally { pending.close(); }
  };
  router.post('/agents/customer/file-path-summary/session', launch, authenticatePersona, customer,
    handle((req, signal) => {
      if (!req.is('application/json') || Object.keys(req.query || {}).length
          || !exact(req.body || {}, [])) throw invalid();
      return graph.createSession({ ...context(req), signal });
    }));
  const { projectFilePathSummaryTurn } = require('../../services/secureshopV44FilePathSummarySavedTurn');
  router.get('/agents/customer/file-path-summary/capability', launch, authenticatePersona, customer,
    handle(async (req, signal) => {
      if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length) throw invalid();
      const { captureFeatureMode, projectFeatureMode } = require('../../services/secureshopFeatureModeAuthority');
      const mode = await captureFeatureMode(modeAuthority, req.ssLaunch, 'file_path_summary');
      signal.throwIfAborted(); await mode.assertCurrent();
      return projectFeatureMode(mode);
    }));
  router.post('/agents/customer/file-path-summary/run', launch, authenticatePersona, customer,
    handle(async (req, signal) => {
      if (!req.is('application/json') || Object.keys(req.query || {}).length
          || !exact(req.body, ['sessionId', 'requestId', 'message', 'path'])
          || !UUID.test(req.body.sessionId || '') || !UUID.test(req.body.requestId || '')
          || typeof req.body.message !== 'string' || !req.body.message.trim()
          || !req.body.message.isWellFormed() || req.body.message.includes('\0')
          || Buffer.byteLength(req.body.message) > 8192 || !validPath(req.body.path)) throw invalid();
      const sessionId = req.body.sessionId.toLowerCase();
      const requestId = req.body.requestId.toLowerCase();
      const result = await graph.run({ ...context(req), sessionId, requestId,
        message: req.body.message, path: req.body.path, signal });
      return projectFilePathSummaryTurn({ sessionId, requestId, result, replayed: result.replayed === true });
    }));
  const reference = req => {
    if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length
        || !UUID.test(req.params.sessionId || '') || !UUID.test(req.params.requestId || '')) throw invalid();
    return { ...context(req), sessionId: req.params.sessionId.toLowerCase(), requestId: req.params.requestId.toLowerCase() };
  };
  router.get('/agents/customer/file-path-summary/requests/:sessionId/:requestId', launch, authenticatePersona, customer,
    handle((req, signal) => saved.read({ ...reference(req), signal })));
  const assessmentResult = value => {
    if (exact(value, ['completed', 'status', 'modelEvaluated', 'reason']) && value.completed === false
        && value.status === 'unavailable' && value.modelEvaluated === false
        && value.reason === 'evidence_size_limit') return value;
    if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
        && value.modelEvaluated === false && ['ineligible', 'unconfirmed'].includes(value.status)) return value;
    if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
        || typeof value.replayed !== 'boolean' || !UUID.test(value.judgment?.evaluationId || '')
        || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment?.verdict)
        || typeof value.judgment.canRetry !== 'boolean'
        || value.completed && value.judgment.verdict !== 'pass') throw invalid();
    return Object.freeze({ completed: value.completed, replayed: value.replayed,
      judgment: Object.freeze({ verdict: value.judgment.verdict,
        evaluationId: value.judgment.evaluationId, canRetry: value.judgment.canRetry }) });
  };
  router.post('/agents/customer/file-path-summary/assess', launch, authenticatePersona, customer,
    handle(async (req, signal) => {
      if (!req.is('application/json') || Object.keys(req.query || {}).length
          || !exact(req.body, ['sessionId', 'requestId']) || !UUID.test(req.body.sessionId || '')
          || !UUID.test(req.body.requestId || '')) throw invalid();
      return assessmentResult(await assessment.runAttempt({ ...context(req), signal,
        sessionId: req.body.sessionId.toLowerCase(), requestId: req.body.requestId.toLowerCase() }));
    }));
  router.get('/agents/customer/file-path-summary/assess/:sessionId/:requestId', launch, authenticatePersona, customer,
    handle(async (req, signal) => assessmentResult(await assessment.readOutcome({ ...reference(req), signal }))));
  return router;
}

module.exports = { createBoundFilePathSummaryRouter };
