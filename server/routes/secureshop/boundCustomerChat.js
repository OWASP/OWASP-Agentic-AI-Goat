'use strict';
const express=require('express');
const {requireSecureShopLaunch,markSecureShopLaunchUnavailable}=require('../../middleware/secureshopLaunch');
const {customerSelection}=require('../../services/secureshopBoundCustomerCommerceTools');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact=(v,keys,required=keys)=>v&&Object.getPrototypeOf(v)===Object.prototype
 &&Object.keys(v).every(k=>keys.includes(k))&&required.every(k=>Object.hasOwn(v,k));
const header=req=>(req.rawHeaders||[]).filter((_,i)=>i%2===0).filter(x=>String(x).toLowerCase()==='x-owasp-ai-goat-secureshop-launch').length===1;
function publicError(error){
 if(['STALE_LAUNCH','LAUNCH_UNAVAILABLE','SESSION_UNAVAILABLE','CONVERSATION_UNAVAILABLE','SHOP_AUTH_INVALID','SHOP_SCENE_STALE'].includes(error?.code))return[401,true,'Shop session unavailable'];
 if(['INVALID_ARGUMENT','INVALID_TURN_REQUEST'].includes(error?.code))return[400,false,'Invalid customer chat request'];
 if(['TURN_REQUEST_CONFLICT'].includes(error?.code))return[409,false,'Customer chat reference conflicts'];
 return[503,false,'Customer chat unavailable'];
}
function createBoundCustomerChatRouter({launches,authenticatePersona,runtime}={}){
 if(typeof launches?.resolveCapability!=='function'||typeof authenticatePersona!=='function'
  ||typeof runtime?.createSession!=='function'||typeof runtime?.run!=='function'||typeof runtime?.readRequest!=='function'
  ||typeof runtime?.confirmProfile!=='function')throw new TypeError('Bound customer chat dependencies required');
 const router=express.Router(),launch=requireSecureShopLaunch({launches});
 const select=(req,res,next)=>header(req)?launch(req,res,next):next('route');
 const customer=[authenticatePersona,(req,res,next)=>{if(req.ssUser?.role!=='customer'||!Number.isSafeInteger(req.ssUser.id)||req.ssUser.id<1||!req.ssPersonaSession?.sessionId)return res.status(403).json({error:'Customer persona unavailable'});req.boundPersona=Object.freeze({id:req.ssUser.id,role:'customer'});next()}];
 const invalid=res=>res.status(400).json({error:'Invalid customer chat request'});
 router.post('/agents/customer/session',select,...customer,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['userId'],[]))return invalid(res);
  try{const value=await runtime.createSession(req.ssLaunch,req.boundPersona,req.ssPersonaSession);res.set('Cache-Control','no-store').json({sessionId:value.id})}
  catch(error){const[status,unavailable,message]=publicError(error);if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message})}
 });
 router.post('/agents/customer/chat',select,...customer,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','message','requestId','selection','catalogContinuation'],['sessionId','message','requestId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||typeof req.body.message!=='string'
   ||!req.body.message.trim()||!req.body.message.isWellFormed()||req.body.message.includes('\0')||Buffer.byteLength(req.body.message,'utf8')>8192
   ||(req.body.selection!==undefined&&req.body.catalogContinuation!==undefined)
   ||(req.body.catalogContinuation!==undefined&&(!exact(req.body.catalogContinuation,['intent','sourceRequestId'])
    ||req.body.catalogContinuation.intent!=='catalog_next'||!UUID.test(req.body.catalogContinuation.sourceRequestId||''))))return invalid(res);
  let selection;
  try{if(req.body.selection!==undefined)selection=customerSelection(req.body.selection)}catch{return invalid(res)}
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};req.once('aborted',abort);res.once('close',abort);
  res.status(200).set({'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-store',Connection:'keep-alive'});
  let eventCount=0,bytes=0;
  const send=(name,data)=>{if(res.writableEnded||res.destroyed||controller.signal.aborted)return;
   const packet=`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
   if(++eventCount>80||(bytes+=Buffer.byteLength(packet,'utf8'))>131072){controller.abort();throw Object.assign(new Error('Chat stream limit'),{code:'CUSTOMER_CHAT_STREAM_LIMIT'})}
   res.write(packet)};
  try{await runtime.run({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,
    sessionId:req.body.sessionId.toLowerCase(),requestId:req.body.requestId.toLowerCase(),message:req.body.message,
    ...(selection?{selection}:{}),
    ...(req.body.catalogContinuation?{catalogContinuation:{intent:'catalog_next',
     sourceRequestId:req.body.catalogContinuation.sourceRequestId.toLowerCase()}}:{}),
    signal:controller.signal,stream:{send}})}
  catch(error){if(!controller.signal.aborted){const[,unavailable,message]=publicError(error);if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);try{send('error',{sessionId:req.body.sessionId.toLowerCase(),requestId:req.body.requestId.toLowerCase(),message,...(unavailable?{code:'SHOP_AUTH_UNAVAILABLE'}:{})})}catch{}}}
  finally{req.off('aborted',abort);res.off('close',abort);if(!res.writableEnded)res.end()}
 });
 router.get('/agents/customer/operations/:sessionId/:requestId',select,...customer,async(req,res)=>{
  if(Object.keys(req.query).length||!UUID.test(req.params.sessionId||'')||!UUID.test(req.params.requestId||''))return invalid(res);
  try{const value=await runtime.readRequest(req.ssLaunch,req.boundPersona,req.ssPersonaSession,req.params.sessionId,req.params.requestId);
   res.set('Cache-Control','no-store').json(value)}
  catch(error){const[status,unavailable,message]=error?.code==='CUSTOMER_CHAT_REFERENCE_STALE'
   ?[401,false,'Shop session unavailable']:publicError(error);
   if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message})}
 });
 router.post('/agents/customer/profile/confirm',select,...customer,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')
   ||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')
   ||!UUID.test(req.body.proposalId||''))return invalid(res);
  try{const value=await runtime.confirmProfile(req.ssLaunch,req.boundPersona,req.ssPersonaSession,
   req.body.sessionId.toLowerCase(),req.body.requestId.toLowerCase(),req.body.proposalId.toLowerCase());
   res.set('Cache-Control','no-store').json(value)}
  catch(error){const[status,unavailable,message]=publicError(error);if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message})}
 });
 return router;
}
module.exports={createBoundCustomerChatRouter};
