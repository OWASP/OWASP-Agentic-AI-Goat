'use strict';
const express=require('express');
const {normalizeListingRequest}=require('../../services/secureshopListingRequestContract');
const {UUID}=require('../../services/secureshopListingJournalContract');
function createBoundListingsRouter({application,authenticatePersona,readReadiness,browserAssessment,templateWorkflow}={}){
 if(['run','operation','resume'].some(k=>typeof application?.[k]!=='function')||typeof authenticatePersona!=='function')throw TypeError('Listings route dependencies required');
 const router=express.Router();router.use((_req,res,next)=>{res.set('Cache-Control','no-store');next();});
 const guard=[authenticatePersona,(req,res,next)=>{
  if(!req.ssLaunch||!req.ssUser||!req.ssPersonaSession?.sessionId)return res.status(401).json({ok:false,error:'Shop authentication required'});
  if(req.ssUser.role!=='merchant')return res.status(403).json({ok:false,error:'Listings role unavailable'});next();
 }];
 const context=req=>({scope:req.ssLaunch,persona:{id:req.ssUser.id,role:req.ssUser.role},personaSession:{sessionId:req.ssPersonaSession.sessionId,authorityVersion:req.ssPersonaSession.authorityVersion}});
 const handle=(work,{template=false}={})=>async(req,res)=>{
  const controller=new AbortController(),close=()=>{if(!res.writableEnded)controller.abort();};req.once('aborted',close);res.once('close',close);
  try{const result=await work(req,controller.signal);res.status((template
    ? ['admitted','running','effect_received','unknown'].includes(result.state)
    : ['admitted','running'].includes(result.state))?202:200).json(result);}
  catch(error){if(res.destroyed||controller.signal.aborted)return;
   if(error.code==='LISTING_MODE_TARGET_CONFLICT')return res.status(409).json({ok:false,code:error.code,error:'This listings target belongs to another mode. Switch back to recover its work, or use the lab reset control before starting in this mode.'});
   const retryTerminal=req.path.endsWith('/browser-retry')&&['EVIDENCE_EXPIRED','RETRY_NOT_ALLOWED','RETRY_EXHAUSTED','MODE_CHANGED'].includes(error.code);
   const status=retryTerminal?409:['INVALID_ARGUMENT','LISTING_SAVE_INVALID'].includes(error.code)?400:
    ['LISTING_NOT_FOUND','LISTING_RETIRED','LISTING_TEMPLATE_NOT_FOUND'].includes(error.code)?404:
    ['LISTING_OPERATION_CONFLICT','LISTING_STATE_CONFLICT','TURN_RECOVERY_REQUIRED','LISTING_TEMPLATE_CONFLICT','LISTING_MODE_TARGET_CONFLICT'].includes(error.code)?409:
    ['SHOP_AUTH_INVALID','SHOP_AUTH_REVOKED','STALE_AUTHORITY','SHOP_SCENE_STALE'].includes(error.code)?401:503;
   res.status(status).json({ok:false,error:'Listings unavailable',...(retryTerminal?{code:error.code}: {})});
  }finally{req.off('aborted',close);res.off('close',close);}
 };
 const invalid=()=>{throw Object.assign(Error('Invalid request'),{code:'INVALID_ARGUMENT'});};
 router.get('/merchant/listings/readiness',...guard,handle(async(req)=>{
  if(Object.keys(req.query).length||(req.body&&Object.keys(req.body).length))invalid();
  if(typeof readReadiness!=='function')return{ready:false};
  const result=await readReadiness(context(req));
  if(result?.ready!==true)return{ready:false};
  if(result.versionedListings!==true||!/^[a-f0-9]{64}$/.test(result.scopeKey))throw Error('Listings readiness unavailable');
  return{ready:true,versionedListings:true,scopeKey:result.scopeKey,...(result.modeCapability?{modeCapability:result.modeCapability}:{})};
 }));
 for(const [path,action]of[['assist-write','rewrite'],['import-bulk','import'],['optimize-images','optimize']])router.post('/merchant/listings/'+path,...guard,handle((req,signal)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!req.body||Object.hasOwn(req.body,'version')||Object.hasOwn(req.body,'action'))invalid();
  if(Object.hasOwn(req.body,'chatSource')){
   if(Object.keys(req.body).sort().join(',')!=='chatSource,operationId'||typeof req.body.operationId!=='string'||!UUID.test(req.body.operationId))invalid();
   return application.run({...context(req),request:{action,operationId:req.body.operationId},chatSource:req.body.chatSource,signal});
  }
  if(action==='optimize')invalid();
  const request=normalizeListingRequest({...req.body,version:1,action});return application.run({...context(req),request,signal});
 }));
 if(typeof application.save==='function')router.post('/merchant/listings/rewrite-save',...guard,handle((req,signal)=>{
  if(Object.keys(req.query).length||!req.is('application/json'))invalid();
  if(Object.hasOwn(req.body||{},'chatSource')){
   if(Object.keys(req.body).sort().join(',')!=='chatSource,rewriteOperationId,saveOperationId'
    ||![req.body.rewriteOperationId,req.body.saveOperationId].every(id=>typeof id==='string'&&UUID.test(id)))invalid();
   return application.save({...context(req),request:{rewriteOperationId:req.body.rewriteOperationId,
    saveOperationId:req.body.saveOperationId},chatSource:req.body.chatSource,signal});
  }
  const request=require('../../services/secureshopListingsApplication').normalizeListingSaveRequest(req.body);
  return application.save({...context(req),request,signal});
 }));
 if(typeof application.savedRewrite==='function')router.get('/merchant/listings/rewrite-saves/:saveOperationId',...guard,handle((req,signal)=>{
  if(!UUID.test(req.params.saveOperationId)||(req.body&&Object.keys(req.body).length))invalid();
  const keys=Object.keys(req.query).sort().join(',');let chatSource,rewriteOperationId;
  if(keys==='proposalId,requestId,sessionId')chatSource={sessionId:req.query.sessionId,requestId:req.query.requestId,proposalId:req.query.proposalId};
  else if(keys==='rewriteOperationId')rewriteOperationId=req.query.rewriteOperationId;
  else invalid();
  return application.savedRewrite({...context(req),saveOperationId:req.params.saveOperationId,chatSource,rewriteOperationId,signal});
 }));
 if(browserAssessment!==undefined){
  if(typeof browserAssessment?.runAttempt!=='function')throw TypeError('Listings browser assessment required');
  for(const [path,method,keys]of [['browser-attempt','runAttempt',['requestId','rewriteOperationId','saveOperationId']],['browser-retry','retryAttempt',['evaluationId','requestId','rewriteOperationId','saveOperationId']]])router.post('/merchant/listings/'+path,...guard,handle((req,signal)=>{
   if(Object.keys(req.query).length||!req.is('application/json')||!req.body||Array.isArray(req.body)
    ||Object.keys(req.body).sort().join(',')!==keys.join(',')
    ||!keys.every(key=>typeof req.body[key]==='string'&&UUID.test(req.body[key])))invalid();
   if(typeof browserAssessment[method]!=='function')throw Error('Listings grading unavailable');
   return browserAssessment[method]({...context(req),...req.body,signal});
  }));
 }
 const selected=req=>{if(Object.keys(req.query).length||!UUID.test(req.params.operationId))invalid();return req.params.operationId;};
 router.get('/merchant/listings/operations/:operationId',...guard,handle((req,signal)=>{
  const operationId=selected(req);if(req.body&&Object.keys(req.body).length)invalid();return application.operation({...context(req),operationId,signal});
 }));
 router.post('/merchant/listings/operations/:operationId/resume',...guard,handle((req,signal)=>{
  const operationId=selected(req);if(!req.is('application/json')||!req.body||Array.isArray(req.body)||Object.keys(req.body).length)invalid();return application.resume({...context(req),operationId,signal});
 }));
 if(templateWorkflow!==undefined){
  if(['run','read','readiness'].some(key=>typeof templateWorkflow?.[key]!=='function'))
   throw TypeError('Owned listing template workflow required');
  router.get('/merchant/listings/template-readiness',...guard,handle(async(req,signal)=>{
   if(Object.keys(req.query).length||(req.body&&Object.keys(req.body).length))invalid();
   if(typeof readReadiness!=='function'||(await readReadiness(context(req)))?.ready!==true)return{ready:false};
   const result=await templateWorkflow.readiness(context(req),signal);
   if(!result||Object.keys(result).join(',')!=='ready'||typeof result.ready!=='boolean')throw Error('Template readiness unavailable');
   return result;
  }));
  router.post('/merchant/listings/template-render',...guard,handle((req,signal)=>{
   if(Object.keys(req.query).length||!req.is('application/json')||!req.body
    ||Array.isArray(req.body)||Object.keys(req.body).sort().join(',')!=='operationId,productId')invalid();
   const request=require('../../services/secureshopListingTemplateContract').normalizeListingTemplateRequest({
    version:1,operationId:req.body.operationId,productId:req.body.productId});
   return templateWorkflow.run({...context(req),request},{signal});
  },{template:true}));
  router.get('/merchant/listings/template-operations/:operationId',...guard,handle((req)=>{
   if(Object.keys(req.query).length||!UUID.test(req.params.operationId)
    ||(req.body&&Object.keys(req.body).length))invalid();
   return templateWorkflow.read({...context(req),operationId:req.params.operationId});
  },{template:true}));
 }
 return router;
}
module.exports={createBoundListingsRouter};
