'use strict';
const express = require('express');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const invalid = () => { throw Object.assign(Error('Invalid mail inline request'), { code: 'INVALID_ARGUMENT' }); };
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join() === [...keys].sort().join();
}
function project(value, kind) {
  if (exact(value, ['ok', 'status', 'requestId']) && value.ok === true
    && value.status === 'unconfirmed' && UUID.test(value.requestId)) return value;
  if (kind === 'teaching' && exact(value, ['ok', 'status', 'requestId', 'messageId', 'threadId', 'replayed'])
    && value.ok === true && value.status === 'saved' && UUID.test(value.requestId)
    && Number.isSafeInteger(value.messageId) && value.messageId > 0
    && Number.isSafeInteger(value.threadId) && value.threadId > 0 && typeof value.replayed === 'boolean') return value;
  if (kind === 'summary' && exact(value, ['ok', 'status', 'requestId', 'sessionId', 'text', 'replayed', 'assessmentStatus'])
    && value.ok === true && value.status === 'completed' && UUID.test(value.requestId) && UUID.test(value.sessionId)
    && typeof value.text === 'string' && value.text.trim() && Buffer.byteLength(value.text) <= 32768
    && typeof value.replayed === 'boolean' && value.assessmentStatus === 'pending') return value;
  throw Error('Invalid mail inline response');
}
function projectAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
    && value.modelEvaluated === false && ['ineligible', 'unconfirmed'].includes(value.status)) return value;
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
    || typeof value.replayed !== 'boolean' || !value.judgment
    || Object.getPrototypeOf(value.judgment) !== Object.prototype
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    || !UUID.test(value.judgment.evaluationId || '') || typeof value.judgment.canRetry !== 'boolean'
    || value.completed && value.judgment.verdict !== 'pass') throw Error('Invalid mail assessment response');
  return { completed: value.completed, judgment: { verdict: value.judgment.verdict,
    evaluationId: value.judgment.evaluationId, canRetry: value.judgment.canRetry }, replayed: value.replayed };
}
function createBoundMailInlineRouter({ application, assessment, authenticatePersona } = {}) {
  if (['saveTeaching', 'readTeaching', 'summarize', 'readSummary'].some(key => typeof application?.[key] !== 'function')
    || typeof authenticatePersona !== 'function') throw TypeError('Mail inline route dependencies required');
  const router = express.Router();
  const guard = [(req, res, next) => { res.set('Cache-Control', 'no-store'); next(); }, authenticatePersona,
    (req, res, next) => {
      if (!req.ssLaunch || !req.ssUser || !req.ssPersonaSession?.sessionId)
        return res.status(401).json({ ok: false, error: 'Shop authentication required' });
      if (req.ssUser.role !== 'merchant') return res.status(403).json({ ok: false, error: 'Merchant required' });
      next();
    }];
  const context = req => ({ scope: req.ssLaunch, persona: { id: req.ssUser.id, role: req.ssUser.role },
    personaSession: { sessionId: req.ssPersonaSession.sessionId, authorityVersion: req.ssPersonaSession.authorityVersion } });
  const handle = (method, kind, keys, post) => async (req, res) => {
    const controller = new AbortController(), abort = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', abort); res.once('close', abort);
    try {
      if (Object.keys(req.query).length || post && !req.is('application/json')) invalid();
      const value = post ? req.body : { ...req.params };
      if (!exact(value, keys) || !UUID.test(value.requestId || '')) invalid();
      if (kind === 'summary' && post && (!UUID.test(value.readOperationId || '')
        || value.requestId === value.readOperationId || !Number.isSafeInteger(value.messageId) || value.messageId < 1)) invalid();
      const result = project(await application[method](context(req), value, { signal: controller.signal }), kind);
      if (result.requestId !== value.requestId) throw Error('Response source mismatch');
      res.json(result);
    } catch (error) {
      if (!res.destroyed && !controller.signal.aborted) {
        const fixed = error.code === 'MAIL_INLINE_FIXED_DENIED';
        res.status(fixed ? 403 : error.code === 'INVALID_ARGUMENT' ? 400 : error.code === 'SHOP_AUTH_INVALID' ? 401 : 503)
          .json(fixed ? { ok: false, code: error.code, error: 'Inline image fetch blocked in fixed mode' }
            : { ok: false, error: 'Mail inline workflow unavailable' });
      }
    } finally { req.off('aborted', abort); res.off('close', abort); }
  };
  router.post('/email/inline/teaching-message', ...guard, handle('saveTeaching', 'teaching', ['requestId'], true));
  router.get('/email/inline/teaching-message/:requestId', ...guard, handle('readTeaching', 'teaching', ['requestId'], false));
  router.post('/email/inline/summary', ...guard, handle('summarize', 'summary', ['requestId', 'readOperationId', 'messageId'], true));
  router.get('/email/inline/summary/:requestId', ...guard, handle('readSummary', 'summary', ['requestId'], false));
  if (assessment !== undefined) {
    if (['runAttempt', 'readOutcome'].some(key => typeof assessment?.[key] !== 'function')) throw TypeError('Mail assessment required');
    const assess = post => async (req, res) => {
      const controller = new AbortController(), abort = () => { if (!res.writableEnded) controller.abort(); };
      req.once('aborted', abort); res.once('close', abort);
      try {
        if (Object.keys(req.query).length || post && !req.is('application/json')) invalid();
        const value = post ? req.body : { ...req.params };
        if (!exact(value, ['sessionId', 'requestId']) || !UUID.test(value.sessionId || '') || !UUID.test(value.requestId || '')) invalid();
        const result = await assessment[post ? 'runAttempt' : 'readOutcome']({ ...context(req), ...value, signal: controller.signal });
        res.json(projectAssessment(result));
      } catch (error) {
        if (!res.destroyed && !controller.signal.aborted) res.status(error.code === 'INVALID_ARGUMENT' ? 400
          : error.code === 'SHOP_AUTH_INVALID' ? 401 : 503).json({ ok: false, error: 'Mail inline assessment unavailable' });
      } finally { req.off('aborted', abort); res.off('close', abort); }
    };
    router.post('/email/inline/assessment', ...guard, assess(true));
    router.get('/email/inline/assessment/:sessionId/:requestId', ...guard, assess(false));
  }
  return router;
}
module.exports = { createBoundMailInlineRouter, projectAssessment };
