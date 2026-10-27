'use strict';
const express = require('express');
const { requireSecureShopLaunch } = require('../middleware/secureshopLaunch');
const C = require('../services/secureshopExternalMailContract');

function createExternalMailRouter({ application, authService, launches, personaAuth, allowedOrigins }) {
  if (!application || typeof authService?.authenticate !== 'function'
      || typeof personaAuth?.authenticatePersona !== 'function' || !Array.isArray(allowedOrigins))
    throw TypeError('External mail parent authority required');
  const origins = new Set(allowedOrigins.map(value=>{
    if (new URL(value).origin !== value) throw TypeError('Exact parent origin required');
    return value;
  }));
  const router = express.Router();
  router.use((_req,res,next)=>{res.set('Cache-Control','no-store');next();});
  router.use((req,res,next)=>{
    const origin = req.get('Origin');
    if ((req.method !== 'GET' || origin !== undefined) && !origins.has(origin))
      return res.status(403).json({error:'External mail parent origin required'});
    if (!['GET','POST'].includes(req.method)) return res.status(405).json({error:'External mail method unavailable'});
    if (req.method === 'POST' && !req.is('application/json'))
      return res.status(415).json({error:'JSON required'});
    if (Object.keys(req.query||{}).length) return res.status(400).json({error:'Invalid external mail request'});
    next();
  });
  // Bound JSON, no descriptor/recipient in query strings or logging middleware.
  router.use(express.json({limit:'2kb',strict:true}));
  router.use((req,res,next)=>{
    if (req.method === 'POST' && (!C.exact(req.body,Object.keys(req.body||{}))
        || Buffer.byteLength(JSON.stringify(req.body))>2048))
      return res.status(400).json({error:'Invalid external mail request'});
    next();
  });
  router.use(async(req,res,next)=>{
    try {
      const token = require('./secureshopStandaloneAuth').readShopCookie(req);
      if (!token) throw C.error('SHOP_AUTH_INVALID');
      req.externalMailPrincipal = await authService.authenticate(token);
      if (req.externalMailPrincipal?.role !== 'merchant') throw C.error('SHOP_AUTH_INVALID');
      next();
    } catch {res.status(401).json({error:'Shop merchant authentication required'});}
  });
  router.use(requireSecureShopLaunch({launches}),personaAuth.authenticatePersona);
  const context = req=>({principal:req.externalMailPrincipal,scope:req.ssLaunch,
    persona:req.ssUser,personaSession:req.ssPersonaSession});
  const wrap = work=>async(req,res)=>{
    const controller = new AbortController();
    const disconnected = ()=>{if(!res.writableEnded)controller.abort();};
    req.once('aborted',disconnected);res.once('close',disconnected);
    try {res.json(await work(req,controller.signal));}
    catch(error) {
      const status = {
        INVALID_ARGUMENT:400,SHOP_AUTH_INVALID:401,EXTERNAL_MAIL_NOT_FOUND:404,
        EXTERNAL_MAIL_SCOPE_STALE:409,EXTERNAL_MAIL_CONFLICT:409,
        EXTERNAL_MAIL_RECOVERY_REQUIRED:409,EXTERNAL_MAIL_RATE_LIMIT:429,
      }[error?.code] || 503;
      res.status(status).json({error:'External test mail unavailable',code:
        status===503?'EXTERNAL_MAIL_UNAVAILABLE':error.code});
    } finally {req.removeListener('aborted',disconnected);res.removeListener('close',disconnected);}
  };
  router.get('/readiness',wrap(req=>application.readiness(context(req))));
  router.get('/operations/:operationId',wrap(req=>application.read(context(req),req.params.operationId)));
  router.post('/prepare',wrap(req=>application.prepare(context(req),req.body)));
  router.post('/cancel',wrap(req=>application.cancel(context(req),req.body)));
  router.post('/confirm',wrap((req,signal)=>application.confirm(context(req),req.body,{signal})));
  router.use((_error,_req,res,_next)=>res.status(400).json({error:'Invalid external mail request'}));
  return router;
}
module.exports = { createExternalMailRouter };
