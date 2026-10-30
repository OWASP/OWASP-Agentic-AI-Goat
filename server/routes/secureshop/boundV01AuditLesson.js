'use strict';

const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable } =
  require('../../middleware/secureshopLaunch');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const singleLaunchHeader = req => (req.rawHeaders || [])
  .filter((_, i) => i % 2 === 0)
  .filter(value => String(value).toLowerCase() === 'x-owasp-ai-goat-secureshop-launch').length === 1;

function createBoundV01AuditLessonRouter({ launches, authenticatePersona, runtime, assessment } = {}) {
  if (typeof launches?.resolveCapability !== 'function'
      || typeof authenticatePersona !== 'function'
      || ['createSession','issueToken','readRequest','run'].some(key => typeof runtime?.[key] !== 'function')
      || ['runAttempt','readOutcome'].some(key => typeof assessment?.[key] !== 'function'))
    throw new TypeError('Bound checkout audit lesson dependencies required');
  const router = express.Router(), launch = requireSecureShopLaunch({ launches });
  const prefix = '/agents/customer/checkout-audit';
  router.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const select = (req, res, next) => singleLaunchHeader(req)
    ? launch(req, res, next) : next('route');
  const customer = [authenticatePersona, (req, res, next) => {
    if (req.ssUser?.role !== 'customer' || !Number.isSafeInteger(req.ssUser.id)
        || req.ssUser.id < 1 || !UUID.test(req.ssPersonaSession?.sessionId || '')
        || !/^[1-9]\d*$/.test(req.ssPersonaSession?.authorityVersion || ''))
      return res.status(403).json({ error: 'Customer persona unavailable' });
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: 'customer' });
    next();
  }];
  const bad = res => res.status(400).json({ error: 'Invalid checkout audit lesson request' });
  const mode = value => exact(value,['version','featureId','policyVersion','effectiveMode','scope'])
    && value.version===1 && value.featureId==='checkout_audit_jwt'
    && value.policyVersion==='owned-checkout-admin-audit-practice-jwt-v1'
    && ['vuln','fixed'].includes(value.effectiveMode)
    && exact(value.scope,['kind','id'])
    && value.scope.kind==='launch_feature' && value.scope.id==='checkout_audit_jwt';
  const context = (req, signal) => ({ scope: req.ssLaunch,
    persona: req.boundPersona, personaSession: req.ssPersonaSession, signal });
  const streamData = (name, data) => {
    if (name !== 'tool_result' || data?.tool !== 'auth.audit_probe') return data;
    const result = data.result, content = result?.content;
    if (!Array.isArray(content) || content.length !== 1
        || !exact(content[0], ['type','text']) || content[0].type !== 'text')
      throw new Error('Checkout audit stream unavailable');
    let payload; try { payload = JSON.parse(content[0].text); } catch { throw new Error('Checkout audit stream unavailable'); }
    if (exact(payload, ['status']) && payload.status === 'denied') return data;
    if (!exact(payload, ['status','eventId','sourceSha256','report'])
        || payload.status !== 'disclosed' || !UUID.test(payload.eventId || ''))
      throw new Error('Checkout audit stream unavailable');
    return Object.freeze({...data,result:Object.freeze({...result,
      content:Object.freeze([Object.freeze({type:'text',text:JSON.stringify({
        status:payload.status,eventId:payload.eventId,report:payload.report,
      })})])})});
  };
  const assessmentResult = value => {
    if (exact(value,['completed','status','modelEvaluated'])
        && value.completed === false && value.modelEvaluated === false
        && ['ineligible','unconfirmed'].includes(value.status)) return value;
    if (!exact(value,['completed','judgment','replayed'])
        || typeof value.completed !== 'boolean' || typeof value.replayed !== 'boolean'
        || !['pass','fail','inconclusive','unavailable'].includes(value.judgment?.verdict)
        || !UUID.test(value.judgment?.evaluationId || '')
        || typeof value.judgment?.canRetry !== 'boolean'
        || value.completed && value.judgment.verdict !== 'pass')
      throw new Error('Checkout audit assessment unavailable');
    return Object.freeze({completed:value.completed,
      judgment:Object.freeze({verdict:value.judgment.verdict,
        evaluationId:value.judgment.evaluationId,canRetry:value.judgment.canRetry}),
      replayed:value.replayed});
  };
  const handle = fn => async (req, res) => {
    const controller = new AbortController();
    const abort = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', abort); res.once('close', abort);
    if (req.aborted || res.destroyed) abort();
    try {
      controller.signal.throwIfAborted();
      const value = await fn(req, controller.signal);
      controller.signal.throwIfAborted();
      if (!res.writableEnded && !res.destroyed) res.status(200).json(value);
    } catch (error) {
      if (!controller.signal.aborted && !res.writableEnded && !res.destroyed) {
        if (['STALE_LAUNCH','LAUNCH_UNAVAILABLE','SHOP_AUTH_INVALID',
          'SHOP_SCENE_STALE','SECURESHOP_FEATURE_MODE_STALE'].includes(error?.code))
          markSecureShopLaunchUnavailable(res);
        res.status(503).json({ error: 'Checkout audit lesson unavailable' });
      }
    } finally { req.off('aborted', abort); res.off('close', abort); }
  };
  router.post(`${prefix}/session`, select, ...customer, (req, res, next) =>
    Object.keys(req.query).length || !req.is('application/json') || !exact(req.body, [])
      ? bad(res) : next(), handle(async (req, signal) => {
      const session = await runtime.createSession(req.ssLaunch, req.boundPersona,
        req.ssPersonaSession, signal);
      if (!UUID.test(session?.id || '')) throw new Error('Session unavailable');
      return { sessionId: session.id.toLowerCase() };
    }));
  router.post(`${prefix}/practice-token`, select, ...customer, (req, res, next) =>
    Object.keys(req.query).length || !req.is('application/json')
      || !exact(req.body, ['checkoutOperationId'])
      || !UUID.test(req.body.checkoutOperationId || '') ? bad(res) : next(),
    handle(async (req, signal) => {
      const value = await runtime.issueToken({ ...context(req, signal),
        checkoutOperationId: req.body.checkoutOperationId.toLowerCase() });
      if (!exact(value, ['orderId','operationId','token','modeCapability'])
          || !mode(value.modeCapability)
          || value.operationId !== req.body.checkoutOperationId.toLowerCase()
          || !Number.isSafeInteger(value.orderId) || value.orderId < 1
          || typeof value.token !== 'string' || !value.token.isWellFormed()
          || Buffer.byteLength(value.token, 'utf8') > 4096) throw new Error('Token unavailable');
      return value;
    }));
  router.get(`${prefix}/operations/:sessionId/:requestId`, select, ...customer,
    (req,res,next)=> Object.keys(req.query).length
      || !UUID.test(req.params.sessionId||'') || !UUID.test(req.params.requestId||'')
      ? bad(res) : next(),
    handle(async(req,signal)=>{
      const sessionId=req.params.sessionId.toLowerCase(),requestId=req.params.requestId.toLowerCase();
      const value=await runtime.readRequest({...context(req,signal),sessionId,requestId});
      if(value?.sessionId!==sessionId||value.requestId!==requestId)throw new Error('Saved turn unavailable');
      if(exact(value,['sessionId','requestId','status'])&&value.status==='unconfirmed')return value;
      if(!exact(value,['sessionId','requestId','status','text','result','checkoutOperationId','modeCapability'])
          ||value.status!=='completed'||!UUID.test(value.checkoutOperationId||'')
          ||typeof value.text!=='string'||!value.text.isWellFormed()
          ||Buffer.byteLength(value.text,'utf8')>2048||!mode(value.modeCapability))throw new Error('Saved turn unavailable');
      const result=value.result;
      if(result!==null && !exact(result,['status']) && !exact(result,['status','eventId','report']))
        throw new Error('Saved turn unavailable');
      if(result?.status==='denied'&&exact(result,['status']))return value;
      if(result!==null){
        const report=result.report;
        if(result.status!=='disclosed'||!UUID.test(result.eventId||'')
            ||!exact(report,['eventId','timestamp','actor','action','outcome','orderId','total'])
            ||report.eventId!==result.eventId
            ||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(report.timestamp||'')
            ||report.actor!=='customer'||report.action!=='checkout'||report.outcome!=='completed'
            ||!Number.isSafeInteger(report.orderId)||report.orderId<1
            ||typeof report.total!=='number'||!Number.isFinite(report.total)||report.total<0)
          throw new Error('Saved turn unavailable');
      }
      return value;
    }));
  router.post(`${prefix}/assess`, select, ...customer,
    (req,res,next)=> Object.keys(req.query).length || !req.is('application/json')
      || !exact(req.body,['sessionId','requestId'])
      || !UUID.test(req.body.sessionId||'') || !UUID.test(req.body.requestId||'')
      ? bad(res) : next(),
    handle(async(req,signal)=>assessmentResult(await assessment.runAttempt({
      ...context(req,signal),sessionId:req.body.sessionId.toLowerCase(),
      requestId:req.body.requestId.toLowerCase()}))));
  router.get(`${prefix}/assess/:sessionId/:requestId`, select, ...customer,
    (req,res,next)=> Object.keys(req.query).length
      || !UUID.test(req.params.sessionId||'') || !UUID.test(req.params.requestId||'')
      ? bad(res) : next(),
    handle(async(req,signal)=>assessmentResult(await assessment.readOutcome({
      ...context(req,signal),sessionId:req.params.sessionId.toLowerCase(),
      requestId:req.params.requestId.toLowerCase()}))));
  router.post(`${prefix}/chat`, select, ...customer, async (req, res) => {
    if (Object.keys(req.query).length || !req.is('application/json')
        || !exact(req.body, ['sessionId','requestId','checkoutOperationId','teachingToken','message'])
        || ![req.body.sessionId,req.body.requestId,req.body.checkoutOperationId]
          .every(value => UUID.test(value || ''))
        || typeof req.body.teachingToken !== 'string' || !req.body.teachingToken
        || Buffer.byteLength(req.body.teachingToken, 'utf8') > 4096
        || typeof req.body.message !== 'string' || !req.body.message.trim()
        || !req.body.message.isWellFormed() || req.body.message.includes('\0')
        || Buffer.byteLength(req.body.message, 'utf8') > 8192) return bad(res);
    const controller = new AbortController();
    const abort = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', abort); res.once('close', abort);
    if (req.aborted || res.destroyed) abort();
    let count = 0, bytes = 0;
    const send = (name, data) => {
      if (res.writableEnded || res.destroyed || controller.signal.aborted) return;
      const packet = `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
      if (++count > 80 || (bytes += Buffer.byteLength(packet, 'utf8')) > 131072) {
        controller.abort(); throw new Error('Stream unavailable');
      }
      res.write(packet);
    };
    try {
      controller.signal.throwIfAborted();
      res.status(200).set({ 'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-store', Connection: 'keep-alive' });
      await runtime.run({ ...context(req, controller.signal),
        sessionId: req.body.sessionId.toLowerCase(),
        requestId: req.body.requestId.toLowerCase(),
        checkoutOperationId: req.body.checkoutOperationId.toLowerCase(),
        teachingToken: req.body.teachingToken,
        message: req.body.message, stream: { send: (name, data) => send(name, streamData(name, data)) } });
    } catch {
      if (!controller.signal.aborted) try { send('error', {
        sessionId: req.body.sessionId.toLowerCase(),
        requestId: req.body.requestId.toLowerCase(),
        message: 'Checkout audit lesson unavailable' }); } catch {}
    } finally {
      req.off('aborted', abort); res.off('close', abort);
      if (!controller.signal.aborted && !res.writableEnded && !res.destroyed) res.end();
    }
  });
  return router;
}
module.exports = { createBoundV01AuditLessonRouter };
