'use strict';
const express=require('express');const {requireSecureShopLaunch,markSecureShopLaunchUnavailable}=require('../../middleware/secureshopLaunch');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function plain(value){return value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;}
function exact(value,keys){return plain(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));}
function publicError(error){if(error?.code==='SHOP_AUTH_INVALID')return[401,'Shop authentication required'];
  if(error?.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN')return[503,'MCP operation outcome is unknown; do not automatically retry',false,{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',outcome:'unknown',automaticRetry:false}];
  if(error?.code==='OWNER_MISMATCH')return[403,'Admin persona required'];
  if(['STALE_LAUNCH','LAUNCH_UNAVAILABLE','SESSION_UNAVAILABLE'].includes(error?.code))return[401,'SecureShop launch unavailable',true];
  if(error?.code==='INVALID_ARGUMENT')return[400,'Invalid MCP trust request'];return[503,'MCP trust exercise unavailable'];}
function createBoundMcpTrustRouter({launches,authenticatePersona,application}={}){if(typeof launches?.resolveCapability!=='function'
  ||typeof authenticatePersona!=='function'||['status','discover','rotate','run'].some(name=>typeof application?.[name]!=='function'))throw new TypeError('Bound MCP trust route dependencies required');
  const router=express.Router(),launch=requireSecureShopLaunch({launches}),persona=[authenticatePersona,(req,res,next)=>{
    if(!Number.isSafeInteger(req.ssUser?.id)||req.ssUser.id<1||req.ssUser.role!=='admin')return res.status(403).json({error:'Admin persona required'});
    req.boundPersona=Object.freeze({id:req.ssUser.id,role:req.ssUser.role});next();}],handle=operation=>async(req,res)=>{try{await operation(req,res);}catch(error){const[status,message,launchUnavailable,metadata]=publicError(error);if(!res.headersSent){if(launchUnavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message,...metadata});}}};
  const context=req=>({scope:req.ssLaunch,persona:req.boundPersona,...(req.ssPersonaSession?{personaSession:req.ssPersonaSession}:{})});
  router.get('/v2/mcp-trust/readiness',launch,...persona,handle(async(req,res)=>{if(Object.keys(req.query).length)return res.status(400).json({error:'Invalid MCP trust request'});res.json(await application.status(context(req)));}));
  router.post('/v2/mcp-trust/discover',launch,...persona,handle(async(req,res)=>{if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['scenario']))return res.status(400).json({error:'Invalid MCP trust request'});res.json(await application.discover({...context(req),trustScenario:req.body.scenario}));}));
  router.post('/v2/mcp-trust/rotate',launch,...persona,handle(async(req,res)=>{if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,[]))return res.status(400).json({error:'Invalid MCP trust request'});res.json(await application.rotate(context(req)));}));
  router.post('/v2/mcp-trust/run',launch,...persona,handle(async(req,res)=>{if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['scenario','request_id'])||!UUID.test(req.body.request_id||''))return res.status(400).json({error:'Invalid MCP trust request'});
    const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort();};req.once('aborted',abort);res.once('close',abort);
    try{const result=await application.run({...context(req),trustScenario:req.body.scenario,requestId:req.body.request_id.toLowerCase(),signal:controller.signal});controller.signal.throwIfAborted();res.json(result);}
    finally{req.off('aborted',abort);res.off('close',abort);}}));return router;}
module.exports={createBoundMcpTrustRouter};
