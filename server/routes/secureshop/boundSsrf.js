'use strict';
const express = require('express');
const { requireSecureShopLaunch, markSecureShopLaunchUnavailable }
  = require('../../middleware/secureshopLaunch');
const { projectSecureShopFailure } = require('../../services/secureshopFailureDiagnostic');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES = new Set(['customer', 'merchant', 'admin']);

function createBoundSsrfRouter({ launches, authenticatePersona, feature, logger } = {}) {
  logger ||= require('../../utils/logger');
  if (typeof launches?.resolveCapability !== 'function' || typeof authenticatePersona !== 'function'
    || feature?.ready !== true || typeof feature.availability?.read !== 'function'
    || typeof feature.application?.run !== 'function' || typeof logger?.error !== 'function') {
    throw new TypeError('Bound SSRF route dependencies required');
  }
  const router = express.Router();
  router.use('/v2/controlled-ssrf', requireSecureShopLaunch({ launches }), authenticatePersona, (req, res, next) => {
    if (!Number.isSafeInteger(req.ssUser?.id) || req.ssUser.id < 1 || !ROLES.has(req.ssUser.role)) {
      return res.status(403).json({ error: 'Shop persona unavailable' });
    }
    req.boundPersona = Object.freeze({ id: req.ssUser.id, role: req.ssUser.role });
    next();
  });
  const handle = operation => async (req, res) => {
    try { await operation(req, res); }
    catch (error) {
      if (res.headersSent || res.destroyed) return;
      const status = ['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE', 'OWNER_MISMATCH', 'SHOP_AUTH_INVALID'].includes(error?.code) ? 401 : 503;
      if (status === 503) {
        const diagnostic = projectSecureShopFailure(error);
        const resourceKind = ['public-policy', 'private-policy'].includes(req.body?.resource)
          ? req.body.resource : null;
        const requestId = typeof req.requestId === 'string' && UUID.test(req.requestId)
          ? req.requestId.toLowerCase() : null;
        try {
          logger.error('secureshop_controlled_ssrf_failure', {
            component: 'secureshop_controlled_ssrf', requestId, resourceKind, ...diagnostic,
          });
        } catch { /* diagnostics never alter the public route */ }
      }
      if (['STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SESSION_UNAVAILABLE'].includes(error?.code)) {
        markSecureShopLaunchUnavailable(res);
      }
      res.status(status).json({ error: status === 401 ? 'SecureShop launch unavailable' : 'Controlled SSRF exercise unavailable' });
    }
  };
  router.get('/v2/controlled-ssrf/readiness', handle(async (req, res) => {
    if (Object.keys(req.query).length) return res.status(400).json({ error: 'Invalid SSRF request' });
    const state = await feature.availability.read();
    res.json({ ready: state.registered === true && state.visible === true && state.enabled === true });
  }));
  router.post('/v2/controlled-ssrf/run', handle(async (req, res) => {
    const body = req.body;
    if (Object.keys(req.query).length || !req.is('application/json') || !body || Array.isArray(body)
      || Object.getPrototypeOf(body) !== Object.prototype || Object.keys(body).length !== 2
      || !Object.hasOwn(body, 'request_id') || !Object.hasOwn(body, 'resource')
      || typeof body.request_id !== 'string' || !UUID.test(body.request_id)
      || !['public-policy', 'private-policy'].includes(body.resource)) {
      return res.status(400).json({ error: 'Invalid SSRF request' });
    }
    const controller = new AbortController();
    const abort = () => { if (!res.writableEnded) controller.abort(); };
    req.once('aborted', abort); res.once('close', abort);
    try {
      const result = await feature.application.run({ scope: req.ssLaunch, persona: req.boundPersona, ...(req.ssPersonaSession ? {personaSession:req.ssPersonaSession} : {}),
        requestId: body.request_id.toLowerCase(), resourceKind: body.resource, signal: controller.signal });
      controller.signal.throwIfAborted();
      res.json(result);
    } finally { req.off('aborted', abort); res.off('close', abort); }
  }));
  const htmlInput=(req)=>({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession});
  const htmlAvailable=()=>{if(!feature.htmlAssessment)throw new Error('Policy final response unavailable');};
  router.get('/v2/controlled-ssrf/html/readiness',handle(async(req,res)=>{
    if(Object.keys(req.query).length)return res.status(400).json({error:'Invalid SSRF request'});
    const state=await feature.availability.read('ss_policy_final_html_execution');
    res.json({ready:!!feature.htmlAssessment&&state.registered===true&&state.visible===true&&state.enabled===true});
  }));
  const htmlOperation=operation=>handle(async(req,res)=>{
    htmlAvailable();const controller=new AbortController();const abort=()=>{if(!res.writableEnded)controller.abort();};
    req.once('aborted',abort);res.once('close',abort);
    try{await operation(req,res,controller.signal);controller.signal.throwIfAborted();}
    finally{req.off('aborted',abort);res.off('close',abort);}
  });
  const closedBody=(req,keys)=>req.is('application/json')&&!Object.keys(req.query).length&&req.body
    &&Object.getPrototypeOf(req.body)===Object.prototype&&Object.keys(req.body).sort().join(',')===[...keys].sort().join(',');
  router.post('/v2/controlled-ssrf/html/run',htmlOperation(async(req,res,signal)=>{
    if(!closedBody(req,['request_id','policy_html'])||!UUID.test(req.body.request_id||''))return res.status(400).json({error:'Invalid SSRF request'});
    try{require('../../services/secureshopPolicyFinalHtmlContract').policyHtml(req.body.policy_html);}
    catch{return res.status(400).json({error:'Invalid SSRF request'});}
    const result=await feature.application.run({...htmlInput(req),signal,requestId:req.body.request_id.toLowerCase(),
      resourceKind:'html-policy',policyHtml:req.body.policy_html});res.json(result);
  }));
  router.get('/v2/controlled-ssrf/html/run/:requestId',htmlOperation(async(req,res,signal)=>{
    if(Object.keys(req.query).length||!UUID.test(req.params.requestId||''))return res.status(400).json({error:'Invalid SSRF request'});
    res.json(await feature.htmlAssessment.readRun({...htmlInput(req),signal,requestId:req.params.requestId.toLowerCase()}));
  }));
  router.post('/v2/controlled-ssrf/html/assess',htmlOperation(async(req,res,signal)=>{
    if(!closedBody(req,['session_id','request_id'])||![req.body.session_id,req.body.request_id].every(v=>UUID.test(v||'')))return res.status(400).json({error:'Invalid SSRF request'});
    res.json(await feature.htmlAssessment.runAttempt({...htmlInput(req),signal,sessionId:req.body.session_id.toLowerCase(),requestId:req.body.request_id.toLowerCase()}));
  }));
  router.get('/v2/controlled-ssrf/html/assessment/:sessionId/:requestId',htmlOperation(async(req,res,signal)=>{
    if(Object.keys(req.query).length||![req.params.sessionId,req.params.requestId].every(v=>UUID.test(v||'')))return res.status(400).json({error:'Invalid SSRF request'});
    res.json(await feature.htmlAssessment.readOutcome({...htmlInput(req),signal,sessionId:req.params.sessionId.toLowerCase(),requestId:req.params.requestId.toLowerCase()}));
  }));
  return router;
}

module.exports = { createBoundSsrfRouter };
