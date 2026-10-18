'use strict';
const express=require('express');
const {withOwnerExecution}=require('../agent-runtime/ownerWorkflowRoutes');
const REQUEST_ID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const conflicts=new Set(['STALE_GENERATION','STALE_RUN','STALE_REQUEST','IDEMPOTENCY_CONFLICT','REQUEST_UNCERTAIN','REQUEST_OWNER_MISMATCH','CONVERSATION_LIMIT']);
function failure(res,error){
 const code=error?.name==='AbortError'?'REQUEST_CANCELLED':error?.code;
 if(code==='BAD_REQUEST')return res.status(400).json({code,error:'Invalid conversation request'});
 if(conflicts.has(code)||code==='REQUEST_CANCELLED')return res.status(409).json({code,error:'Conversation request cannot be resumed; refresh its current state'});
 return res.status(503).json({code:'CONVERSATION_UNAVAILABLE',error:'Conversation service is unavailable'});
}
function safeDiagnostic(error,{ownerId,requestId,runId}){
 const rawCode=typeof error?.code==='string'?error.code:'UNCLASSIFIED';
 const rawType=typeof error?.constructor?.name==='string'?error.constructor.name:'Error';
 return Object.freeze({version:1,ownerId,requestId,runId:runId||null,
  stage:typeof error?.mcpConversationStage==='string'?error.mcpConversationStage:'coordination',
  errorCode:/^[A-Z][A-Z0-9_]{0,79}$/.test(rawCode)?rawCode:'UNCLASSIFIED',
  errorType:/^[A-Za-z][A-Za-z0-9]{0,79}$/.test(rawType)?rawType:'Error'});
}
// Factory remains unmounted until startup migration and actual actor wiring are ready.
function createMcpConversationRouter({coordinator,service,conversations,perform,admit,diagnose=event=>console.error('[MCP Conversation Internal]',JSON.stringify(event))}){
 if(typeof admit!=='function')throw new TypeError('Conversation resource admission is required');
 if(typeof diagnose!=='function')throw new TypeError('Conversation diagnostics callback is required');
 const router=express.Router();
 router.use((req,res,next)=>{
  res.set('Cache-Control','no-store');
  const userId=Number(req.user?.id);
  if(!Number.isSafeInteger(userId)||userId<1||userId>2147483647)return res.status(401).json({error:'login_required'});
  res.locals.conversationUserId=userId;next();
 });
 router.use(express.json({limit:'20kb'}));
 const coordinated=handler=>async(req,res)=>{
  const controller=new AbortController();
  let runId=null;
  const closed=()=>{if(!res.writableEnded)controller.abort();};res.once('close',closed);
  try{
   const result=await coordinator.run(String(res.locals.conversationUserId),{signal:controller.signal},execution=>{
    runId=execution.runId;
    return withOwnerExecution(execution,()=>handler(req,res,execution));
   });
   if(!res.destroyed)res.json(result);
  }catch(error){
   try{diagnose(safeDiagnostic(error,{ownerId:res.locals.conversationUserId,
    requestId:REQUEST_ID.test(String(req.body?.requestId||''))?req.body.requestId.toLowerCase():null,runId}));}catch{}
   if(!res.destroyed)failure(res,error);
  }
  finally{res.removeListener('close',closed);}
 };
 router.post('/chat',(req,res,next)=>{
  const body=req.body;
  if(Object.keys(req.query).length||!body||Array.isArray(body)||Object.keys(body).sort().join(',')!=='message,requestId'
   ||typeof body.message!=='string'||!body.message.trim()||Buffer.byteLength(body.message)>16384
   ||typeof body.requestId!=='string'||!REQUEST_ID.test(body.requestId))return failure(res,{code:'BAD_REQUEST'});
  next();
 },coordinated(async(req,res,execution)=>{
  // Readiness and canonical owner/session admission precede the durable request
  // row. A mounted conversation must never fall through to legacy resources.
  const resources=await admit(req,execution);
  return service.execute({userId:res.locals.conversationUserId,
   requestId:req.body.requestId.toLowerCase(),message:req.body.message,execution:resources.execution||execution},({history})=>
   perform({userId:res.locals.conversationUserId,message:req.body.message,history,execution:resources.execution||execution,
    sandbox:resources?.sandbox,protocolManager:resources?.protocol,
    stateReader:typeof resources?.state==='function'?resources.state:null,
    objectiveObserver:typeof resources?.observeObjective==='function'?resources.observeObjective:null}));
 }));
 router.get('/history',(req,res,next)=>Object.keys(req.query).length?failure(res,{code:'BAD_REQUEST'}):next(),coordinated(async(_req,res,execution)=>{
  const turns=await conversations.list(res.locals.conversationUserId);await execution.check();
  return {generation:String(execution.durableGeneration),turns};
 }));
 router.post('/clear',async(req,res)=>{
  if(Object.keys(req.query).length||(req.body!=null&&(Array.isArray(req.body)||Object.keys(req.body).length)))return failure(res,{code:'BAD_REQUEST'});
  // service.clear owns reset serialization; wrapping it in run would deadlock.
  try{res.json({success:true,...await service.clear(res.locals.conversationUserId)});}catch(error){failure(res,error);}
 });
 router.use((error,_req,res,_next)=>{
  if(error?.type==='entity.too.large'||error?.type==='entity.parse.failed')return failure(res,{code:'BAD_REQUEST'});
  return failure(res,error);
 });
 return router;
}
module.exports={createMcpConversationRouter,_internals:{safeDiagnostic}};
