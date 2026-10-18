'use strict';

const express = require('express');
const multer = require('multer');
const {
  requireSecureShopLaunch
} = require('../../middleware/secureshopLaunch');
const {
  validateSecureShopV46OperationRelativePath
} = require('../../services/secureshopV46TraversalDestination');
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
function createBoundAvatarUploadRouter({
  launches,
  authenticatePersona,
  graph,
  traversalGraph,
  saved,
  assessment,
  traversalAssessment,
  svgAssessment,polyglotPreview,polyglotAssessment
} = {}) {
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function' || typeof graph?.createSession !== 'function' || typeof graph?.run !== 'function') throw new TypeError('Bound avatar upload route dependencies required');
  const hasTraversalGraph = typeof traversalGraph?.createSession === 'function' && typeof traversalGraph?.run === 'function';
  const hasTraversalAssessment = typeof traversalAssessment?.runAttempt === 'function'
    && typeof traversalAssessment?.readOutcome === 'function';
  if (hasTraversalGraph !== hasTraversalAssessment || traversalGraph && !hasTraversalGraph
      || traversalAssessment && !hasTraversalAssessment) throw new TypeError('Complete traversal upload route dependencies required');
  const router = express.Router(),
    launch = requireSecureShopLaunch({
      launches
    });
  const parse = multer({
    storage: multer.memoryStorage(),
    limits: {
      files: 1,
      fileSize: 20 * 1024 * 1024,
      fields: 4
    }
  }).single('file');
  const parseTraversal = multer({
    storage: multer.memoryStorage(),
    limits: {
      files: 1,
      fileSize: 20 * 1024 * 1024,
      fields: 5
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
          error: 'Avatar upload unavailable'
        });
      } finally {
        pending.close();
      }
    };
  }
  const invalid = () => Object.assign(Error('Invalid upload request'), {
    code: 'INVALID_ARGUMENT'
  });
  router.post('/agents/customer/avatar-upload/session', launch, authenticatePersona, customer, handle(async (req, signal) => {
    if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length) throw invalid();
    return graph.createSession({
      ...context(req),
      signal
    });
  }));
  router.post('/agents/customer/avatar-upload/run', launch, authenticatePersona, customer, handle(async (req, signal) => {
    await new Promise((resolve, reject) => parse(req, {}, error => error ? reject(invalid()) : resolve()));
    signal.throwIfAborted();
    const body = req.body || {};
    if (Object.keys(req.query || {}).length || !req.file || JSON.stringify(Object.keys(body).sort()) !== JSON.stringify(['message', 'public', 'requestId', 'sessionId']) || !UUID.test(body.sessionId || '') || !UUID.test(body.requestId || '') || typeof body.message !== 'string' || !body.message.trim() || !['true', 'false'].includes(body.public)) throw invalid();
    const result = await graph.run({
      ...context(req),
      sessionId: body.sessionId.toLowerCase(),
      requestId: body.requestId.toLowerCase(),
      message: body.message,
      attachment: {
        bytes: req.file.buffer,
        filename: req.file.originalname,
        mime: req.file.mimetype,
        public: body.public === 'true'
      },
      signal
    });
    const upload = result?.taskMetadata?.boundUpload;
    if (!UUID.test(upload?.operationId || '') || !UUID.test(upload?.uploadRequestId || '') || !['completed', 'denied'].includes(upload.outcome) || typeof result.text !== 'string') throw invalid();
    // Graph traces and immutable provenance stay in the protected turn journal.
    // Public upload responses contain only the learner's file and saved IDs.
    return Object.freeze({
      operationId: upload.operationId,
      uploadRequestId: upload.uploadRequestId,
      status: upload.outcome,
      text: result.text,
      filename: req.file.originalname,
      byteCount: req.file.size,
      replayed: result.replayed === true,
      ...(typeof upload.assetUrl === 'string' && Number.isSafeInteger(upload.assetCapabilityExpiresAt) && upload.assetCapabilityExpiresAt > Date.now() ? {
        assetUrl: upload.assetUrl,
        expiresAt: upload.assetCapabilityExpiresAt
      } : {})
    });
  }));
  if (hasTraversalGraph) router.post('/agents/customer/avatar-upload/path-traversal/session', launch, authenticatePersona, customer, handle(async (req, signal) => {
    if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length) throw invalid();
    return traversalGraph.createSession({
      ...context(req),
      signal
    });
  }));
  if (hasTraversalGraph) router.post('/agents/customer/avatar-upload/path-traversal/run', launch, authenticatePersona, customer, handle(async (req, signal) => {
    await new Promise((resolve, reject) => parseTraversal(req, {}, error => error ? reject(invalid()) : resolve()));
    signal.throwIfAborted();
    const body = req.body || {};
    if (Object.keys(req.query || {}).length || !req.file
        || JSON.stringify(Object.keys(body).sort()) !== JSON.stringify(['logicalFilename', 'message', 'public', 'requestId', 'sessionId'])
        || !UUID.test(body.sessionId || '') || !UUID.test(body.requestId || '')
        || typeof body.message !== 'string' || !body.message.trim()
        || typeof body.logicalFilename !== 'string' || !body.logicalFilename
        || !['true', 'false'].includes(body.public)) throw invalid();
    const result = await traversalGraph.run({
      ...context(req),
      sessionId: body.sessionId.toLowerCase(),
      requestId: body.requestId.toLowerCase(),
      message: body.message,
      attachment: {
        bytes: req.file.buffer,
        filename: req.file.originalname,
        logicalFilename: body.logicalFilename,
        mime: req.file.mimetype,
        public: body.public === 'true'
      },
      signal
    });
    const upload = result?.taskMetadata?.boundUpload;
    if (upload?.version !== 2 || upload.variant !== 'path_traversal_upload'
        || !UUID.test(upload.operationId || '') || !UUID.test(upload.uploadRequestId || '')
        || !['completed', 'denied'].includes(upload.outcome) || typeof result.text !== 'string'
        || upload.outcome === 'completed' && (upload.escapedAvatarSubdirectory !== true
          || (() => { try { validateSecureShopV46OperationRelativePath(upload.operationRelativePath); return false; } catch { return true; } })())
        || upload.outcome === 'denied' && (Object.hasOwn(upload, 'escapedAvatarSubdirectory')
          || Object.hasOwn(upload, 'operationRelativePath'))
        || Object.hasOwn(upload, 'assetUrl') || Object.hasOwn(upload, 'assetCapabilityExpiresAt')) throw invalid();
    return Object.freeze({
      operationId: upload.operationId,
      uploadRequestId: upload.uploadRequestId,
      status: upload.outcome,
      text: result.text,
      sourceFilename: req.file.originalname,
      filename: body.logicalFilename,
      byteCount: req.file.size,
      replayed: result.replayed === true,
      ...(upload.outcome === 'completed' ? {
        operationRelativePath: upload.operationRelativePath,
        escapedAvatarSubdirectory: true
      } : {})
    });
  }));
  if (typeof saved?.read !== 'function' || typeof saved?.asset !== 'function') throw new TypeError('Saved upload reader required');
  const savedInput = (req, signal) => {
    if (!UUID.test(req.params.operationId || '') || Object.keys(req.query || {}).length || Object.keys(req.body || {}).length) throw invalid();
    return {
      ...context(req),
      operationId: req.params.operationId.toLowerCase(),
      signal
    };
  };
  router.get('/agents/customer/avatar-upload/operations/:operationId', launch, authenticatePersona, customer, handle((req, signal) => saved.read(savedInput(req, signal))));
  router.get('/agents/customer/avatar-upload/requests/:requestId', launch, authenticatePersona, customer, handle((req, signal) => {
    if (!UUID.test(req.params.requestId || '') || Object.keys(req.query || {}).length || Object.keys(req.body || {}).length) throw invalid();
    return saved.read({
      ...context(req),
      uploadRequestId: req.params.requestId.toLowerCase(),
      signal
    });
  }));
  if (hasTraversalGraph) router.get('/agents/customer/avatar-upload/path-traversal/requests/:requestId', launch, authenticatePersona, customer, handle((req, signal) => {
    if (!UUID.test(req.params.requestId || '') || Object.keys(req.query || {}).length || Object.keys(req.body || {}).length) throw invalid();
    return saved.read({
      ...context(req),
      uploadRequestId: req.params.requestId.toLowerCase(),
      signal
    });
  }));
  router.post('/agents/customer/avatar-upload/operations/:operationId/asset', launch, authenticatePersona, customer, handle((req, signal) => saved.asset(savedInput(req, signal))));
  if (typeof assessment?.runAttempt !== 'function' || typeof assessment?.readOutcome !== 'function')
    throw new TypeError('Upload canonical assessment required');
  const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
  const assessmentResult = (value, allowPending = false) => {
    if (exact(value,['completed','status','modelEvaluated']) && value.completed === false
        && value.modelEvaluated === false && ['ineligible','unconfirmed',...(allowPending?['pending']:[])].includes(value.status)) return value;
    if (!exact(value,['completed','judgment','replayed']) || typeof value.completed !== 'boolean'
        || typeof value.replayed !== 'boolean' || !UUID.test(value.judgment?.evaluationId || '')
        || !['pass','fail','inconclusive','unavailable'].includes(value.judgment?.verdict)
        || typeof value.judgment?.canRetry !== 'boolean'
        || value.completed && value.judgment.verdict !== 'pass') throw invalid();
    return Object.freeze({completed:value.completed,replayed:value.replayed,
      judgment:Object.freeze({verdict:value.judgment.verdict,evaluationId:value.judgment.evaluationId,
        canRetry:value.judgment.canRetry})});
  };
  router.post('/agents/customer/avatar-upload/assess', launch, authenticatePersona, customer, handle(async(req,signal) => {
    if (Object.keys(req.query || {}).length || !req.is('application/json')
        || !exact(req.body,['sessionId','requestId'])
        || !UUID.test(req.body.sessionId || '') || !UUID.test(req.body.requestId || '')) throw invalid();
    return assessmentResult(await assessment.runAttempt({...context(req),signal,
      sessionId:req.body.sessionId.toLowerCase(),requestId:req.body.requestId.toLowerCase()}));
  }));
  router.get('/agents/customer/avatar-upload/assess/:sessionId/:requestId', launch, authenticatePersona, customer, handle(async(req,signal) => {
    if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length
        || !UUID.test(req.params.sessionId || '') || !UUID.test(req.params.requestId || '')) throw invalid();
    return assessmentResult(await assessment.readOutcome({...context(req),signal,
      sessionId:req.params.sessionId.toLowerCase(),requestId:req.params.requestId.toLowerCase()}));
  }));
  if (hasTraversalGraph) router.post('/agents/customer/avatar-upload/path-traversal/assess', launch, authenticatePersona, customer, handle(async(req,signal) => {
    if (Object.keys(req.query || {}).length || !req.is('application/json')
        || !exact(req.body,['sessionId','requestId'])
        || !UUID.test(req.body.sessionId || '') || !UUID.test(req.body.requestId || '')) throw invalid();
    return assessmentResult(await traversalAssessment.runAttempt({...context(req),signal,
      sessionId:req.body.sessionId.toLowerCase(),requestId:req.body.requestId.toLowerCase()}));
  }));
  if (hasTraversalGraph) router.get('/agents/customer/avatar-upload/path-traversal/assessment/:sessionId/:requestId', launch, authenticatePersona, customer, handle(async(req,signal) => {
    if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length
        || !UUID.test(req.params.sessionId || '') || !UUID.test(req.params.requestId || '')) throw invalid();
    return assessmentResult(await traversalAssessment.readOutcome({...context(req),signal,
      sessionId:req.params.sessionId.toLowerCase(),requestId:req.params.requestId.toLowerCase()}));
  }));
  if (typeof svgAssessment?.runAttempt !== 'function' || typeof svgAssessment?.readOutcome !== 'function')
    throw new TypeError('SVG browser canonical assessment required');
  router.post('/agents/customer/avatar-upload/svg-assess', launch, authenticatePersona, customer, handle(async(req,signal) => {
    if (Object.keys(req.query || {}).length || !req.is('application/json')
        || !exact(req.body,['sessionId','requestId'])
        || !UUID.test(req.body.sessionId || '') || !UUID.test(req.body.requestId || '')) throw invalid();
    return assessmentResult(await svgAssessment.runAttempt({...context(req),signal,
      sessionId:req.body.sessionId.toLowerCase(),requestId:req.body.requestId.toLowerCase()}));
  }));
  router.get('/agents/customer/avatar-upload/svg-assess/:sessionId/:requestId', launch, authenticatePersona, customer, handle(async(req,signal) => {
    if (Object.keys(req.query || {}).length || Object.keys(req.body || {}).length
        || !UUID.test(req.params.sessionId || '') || !UUID.test(req.params.requestId || '')) throw invalid();
    return assessmentResult(await svgAssessment.readOutcome({...context(req),signal,
      sessionId:req.params.sessionId.toLowerCase(),requestId:req.params.requestId.toLowerCase()}));
  }));
  const hasPolyglot = polyglotPreview !== undefined || polyglotAssessment !== undefined;
  if (hasPolyglot && (!['run','read','readiness'].every(k=>typeof polyglotPreview?.[k]==='function')
      || !['runAttempt','readOutcome'].every(k=>typeof polyglotAssessment?.[k]==='function')))
    throw new TypeError('Complete polyglot preview dependencies required');
  router.get('/agents/customer/avatar-upload/polyglot-readiness', launch, authenticatePersona, customer, handle(async(req,signal)=>{
    if(Object.keys(req.query||{}).length||Object.keys(req.body||{}).length)throw invalid();
    const out=hasPolyglot?await polyglotPreview.readiness({...context(req),signal}):{ready:false};
    if(!exact(out,['ready'])||typeof out.ready!=='boolean')throw invalid();return out;
  }));
  if(hasPolyglot){
    const ids=(req,signal,post)=>{
      const value=post?req.body:req.params;
      if(Object.keys(req.query||{}).length||post&&(!req.is('application/json')||!exact(value,['sessionId','requestId']))
        ||!post&&Object.keys(req.body||{}).length||!UUID.test(value?.sessionId||'')||!UUID.test(value?.requestId||''))throw invalid();
      return {...context(req),signal,sessionId:value.sessionId.toLowerCase(),requestId:value.requestId.toLowerCase()};
    };
    const preview=value=>{
      if(!exact(value,['operationId','uploadOperationId','status','sourceSha256','text','replayed'])
        ||!UUID.test(value.operationId||'')||!UUID.test(value.uploadOperationId||'')||!/^[a-f0-9]{64}$/.test(value.sourceSha256||'')
        ||typeof value.replayed!=='boolean'||!['executed','image_only','fixed_reencoded','invalid_image','failed','pending','unconfirmed'].includes(value.status)
        ||(['pending','unconfirmed'].includes(value.status)?value.text!==null:typeof value.text!=='string'))throw invalid();return value;
    };
    router.post('/agents/customer/avatar-upload/polyglot-preview',launch,authenticatePersona,customer,handle(async(req,signal)=>preview(await polyglotPreview.run(ids(req,signal,true)))));
    router.get('/agents/customer/avatar-upload/polyglot-preview/:sessionId/:requestId',launch,authenticatePersona,customer,handle(async(req,signal)=>preview(await polyglotPreview.read(ids(req,signal,false)))));
    router.post('/agents/customer/avatar-upload/polyglot-assess',launch,authenticatePersona,customer,handle(async(req,signal)=>assessmentResult(await polyglotAssessment.runAttempt(ids(req,signal,true)),true)));
    router.get('/agents/customer/avatar-upload/polyglot-assess/:sessionId/:requestId',launch,authenticatePersona,customer,handle(async(req,signal)=>assessmentResult(await polyglotAssessment.readOutcome(ids(req,signal,false)),true)));
  }
  return router;
}
module.exports = {
  createBoundAvatarUploadRouter
};
