'use strict';
// Unmounted adapter: production composition must supply canonical conversation
// and runner authority. No legacy agentSession or global manifest fallback.
const express = require('express');
const {randomUUID} = require('node:crypto');
const {requireSecureShopLaunch, markSecureShopLaunchUnavailable} = require('../../middleware/secureshopLaunch');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function exact(body, keys, required=keys) {
  return body && typeof body==='object' && !Array.isArray(body)
    && Object.keys(body).every(key=>keys.includes(key)) && required.every(key=>Object.hasOwn(body,key));
}
function createBoundAdminChatRouter({launches, authenticatePersona, runtime}={}) {
  if(typeof launches?.resolveCapability!=='function' || typeof authenticatePersona!=='function'
    || typeof runtime?.createSession!=='function' || typeof runtime?.runner?.run!=='function'
    || typeof runtime?.readRequest!=='function') throw TypeError('Bound admin chat dependencies required');
  const router=express.Router(), launch=requireSecureShopLaunch({launches});
  const admin=(req,res,next)=>{
    if(req.ssUser?.role!=='admin' || !Number.isSafeInteger(req.ssUser.id) || req.ssUser.id<1 || !req.ssPersonaSession?.sessionId) return res.status(403).json({error:'Admin persona unavailable'});
    req.boundPersona=Object.freeze({id:req.ssUser.id,role:'admin'});next();
  };
  function failure(res,error,send) {
    const unavailable=['STALE_LAUNCH','LAUNCH_UNAVAILABLE','SESSION_UNAVAILABLE','CONVERSATION_UNAVAILABLE','SHOP_AUTH_INVALID'].includes(error?.code);
    if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
    const message=unavailable?'SecureShop launch unavailable':'Admin chat unavailable';
    if(!res.headersSent)res.status(unavailable?401:503);
    if(send){send('error',{message});send('done',{stopReason:'error'});}else res.json({error:message});
  }
  router.post('/agents/admin/session',launch,authenticatePersona,admin,async(req,res)=>{
    try {
      if(Object.keys(req.query).length || !req.is('application/json') || !exact(req.body,['userId'],[]))return res.status(400).json({error:'Invalid admin session request'});
      // The legacy userId wire field is not authority; use authenticated persona.
      const session=await runtime.createSession(req.ssLaunch,req.boundPersona,req.ssPersonaSession);
      if(typeof session?.id!=='string'||!session.id.trim())throw Error('Invalid canonical conversation');
      res.type('application/json').json({sessionId:session.id});
    }catch(error){failure(res,error);}
  });
  router.get('/agents/admin/chat/requests/:sessionId/:requestId',launch,authenticatePersona,admin,async(req,res)=>{
    try{
      if(Object.keys(req.query).length||!UUID.test(req.params.sessionId)||!UUID.test(req.params.requestId))
        return res.status(400).json({error:'Invalid admin recovery request'});
      const saved=await runtime.readRequest(req.ssLaunch,req.boundPersona,req.ssPersonaSession,
        req.params.sessionId.toLowerCase(),req.params.requestId.toLowerCase());
      res.set('cache-control','no-store').json(saved);
    }catch(error){failure(res,error);}
  });
  async function assess(req,res,method,ids){
    const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort();};
    req.once('aborted',abort);res.once('close',abort);
    try{
      if(typeof runtime[method]!=='function')throw Error('Assessment unavailable');
      const value=await runtime[method]({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,
        sessionId:ids.sessionId.toLowerCase(),requestId:ids.requestId.toLowerCase(),signal:controller.signal});
      if(!res.writableEnded&&!res.destroyed){
        let projected=value;
        if(['readMcpDescriptionAssessment','assessMcpDescription'].includes(method)){
          if(value?.completed===false&&['unconfirmed','ineligible'].includes(value.status)&&value.modelEvaluated===false)projected={completed:false,status:value.status,modelEvaluated:false};
          else if(typeof value?.completed==='boolean'&&typeof value.replayed==='boolean'&&['pass','fail','unavailable'].includes(value.judgment?.verdict)&&UUID.test(value.judgment.evaluationId||'')&&typeof value.judgment.canRetry==='boolean'&&value.completed===(value.judgment.verdict==='pass'))projected={completed:value.completed,replayed:value.replayed,judgment:{verdict:value.judgment.verdict,evaluationId:value.judgment.evaluationId,canRetry:value.judgment.canRetry}};
          else throw Error('Description assessment projection unavailable');
        }
        res.set('cache-control','no-store').json(projected);
      }
    }catch(error){if(!res.writableEnded&&!res.destroyed)failure(res,error);}
    finally{req.off('aborted',abort);res.off('close',abort);}
  }
  router.get('/agents/admin/chat/description-assessment/:sessionId/:requestId',launch,authenticatePersona,admin,async(req,res)=>{
    if(Object.keys(req.query).length||![req.params.sessionId,req.params.requestId].every(id=>UUID.test(id||'')))return res.status(400).json({error:'Invalid description assessment request'});
    return assess(req,res,'readMcpDescriptionAssessment',req.params);
  });
  router.post('/agents/admin/chat/description-assessment',launch,authenticatePersona,admin,async(req,res)=>{
    if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId'])||![req.body.sessionId,req.body.requestId].every(id=>UUID.test(id||'')))return res.status(400).json({error:'Invalid description assessment request'});
    return assess(req,res,'assessMcpDescription',req.body);
  });
  router.get('/agents/admin/chat/assessment/:sessionId/:requestId',launch,authenticatePersona,admin,async(req,res)=>{
    if(Object.keys(req.query).length||![req.params.sessionId,req.params.requestId].every(id=>UUID.test(id||'')))
      return res.status(400).json({error:'Invalid admin assessment request'});
    return assess(req,res,'readMcpImpersonationAssessment',req.params);
  });
  router.post('/agents/admin/chat/assessment-retry',launch,authenticatePersona,admin,async(req,res)=>{
    if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId'])
      ||![req.body.sessionId,req.body.requestId].every(id=>UUID.test(id||'')))
      return res.status(400).json({error:'Invalid admin assessment request'});
    return assess(req,res,'retryMcpImpersonationAssessment',req.body);
  });
  router.post('/agents/admin/chat',launch,authenticatePersona,admin,async(req,res)=>{
    if(Object.keys(req.query).length || !req.is('application/json') || !exact(req.body,['sessionId','message','requestId'],['sessionId','message'])
      || typeof req.body.sessionId!=='string'||!req.body.sessionId.trim()||req.body.sessionId.length>128
      || (Object.hasOwn(req.body,'requestId')&&(typeof req.body.requestId!=='string'||!UUID.test(req.body.requestId)))
      || typeof req.body.message!=='string'||!req.body.message.trim()||Buffer.byteLength(req.body.message)>8192)return res.status(400).json({error:'Invalid admin chat request'});
    const controller=new AbortController(), abort=()=>{if(!res.writableEnded)controller.abort();};
    req.once('aborted',abort);res.once('close',abort);
    res.status(200).set({'content-type':'text/event-stream; charset=utf-8','cache-control':'no-store',connection:'keep-alive'});
    const send=(name,data)=>{if(!res.writableEnded&&!res.destroyed&&!controller.signal.aborted)res.write(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`);};
    const requestId=Object.hasOwn(req.body,'requestId')?req.body.requestId.toLowerCase():randomUUID();
    try {await runtime.runner.run({sessionId:req.body.sessionId,requestId,scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,message:req.body.message,signal:controller.signal,localToolAuthority:Object.freeze({requestId}),stream:{send}});}
    catch(error){if(!controller.signal.aborted)failure(res,error,send);}
    finally{req.off('aborted',abort);res.off('close',abort);if(!res.writableEnded)res.end();}
  });
  return router;
}
module.exports={createBoundAdminChatRouter};
