'use strict';
const {ownerWorkflowRoute,getOwnerExecution}=require('../agent-runtime/ownerWorkflowRoutes');
const {validateRegistrationLocator}=require('../database/postgres/ctfAttemptRegistrationLocator');
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const id=x=>/^[1-9][0-9]*$/.test(String(x))&&BigInt(x)<=2147483647n;
function createCtfAuthorityAttemptRoute({runtime,coordinator}){
 for(const name of ['attempt','recoverOperation','recoverDecision','publishDecision','publishBlocked','recoverPredefense','resumePredefense'])if(typeof runtime?.[name]!=='function')throw TypeError('Complete trusted CTF runtime required');
 if(typeof coordinator?.run!=='function')throw TypeError('CTF coordinator required');
 const limits=new Map(),inputs=new WeakMap();
 const authenticated=(req,res)=>{if(!id(req.user?.id)||!id(req.identitySession?.id)){res.status(401).json({error:'Authentication required'});return false;}return true;};
 const error=(res,e)=>{const status=e?.code==='42501'?403:e?.code==='SESSION_REVOKED'||['28000','28P01'].includes(e?.code)?401:e?.code==='PCT01'||e?.name==='AbortError'?409:Number.isInteger(e?.statusCode)&&e.statusCode>=400&&e.statusCode<=599?e.statusCode:503;return res.status(status).json({error:status===401?'Session is no longer current':status===409?'CTF request is no longer current':'CTF service temporarily unavailable'});};
 const send=(res,value)=>{if(!value||!Number.isInteger(value.status)||value.status<200||value.status>599||!value.body)throw Error('Invalid CTF runtime response');return res.status(value.status).json(value.body);};
 const coordinated=ownerWorkflowRoute(coordinator,req=>req.user.id,async(req,res)=>{
  const execution=getOwnerExecution();
  try{const result=await runtime.attempt({req,runId:execution.runId,execution,signal:execution.signal,request:{runId:execution.runId,...inputs.get(req)}});send(res,result);}catch(e){error(res,e);}
 });
 function attempt(req,res,next){
  if(!authenticated(req,res))return;
  const stageId=req.params?.stageId,payload=req.body?.payload;
  if(typeof stageId!=='string'||!id(stageId)||typeof payload!=='string'||!payload.trim()||!payload.isWellFormed()||payload.includes('\0')||Buffer.byteLength(payload)>16384)return res.status(400).json({error:'Invalid CTF attempt'});
  let registrationToken;try{registrationToken=validateRegistrationLocator(req.body.sessionToken??null);}catch{return res.status(400).json({error:'Invalid CTF registration locator'});}
  const now=Date.now();for(const [key,values] of limits)if(values.at(-1)<=now-60000)limits.delete(key);
  const key=JSON.stringify([String(req.user.id),stageId]),recent=(limits.get(key)||[]).filter(t=>t>now-60000);
  if(recent.length>=10)return res.status(429).json({error:'Rate limit exceeded',retryAfter:Math.ceil((recent[0]+60000-now)/1000)});
  recent.push(now);limits.set(key,recent);
  // Capture only validated transport bytes before asynchronous graph admission.
  inputs.set(req,Object.freeze({stageId,payload,registrationToken}));
  return coordinated(req,res,next);
 }
 function recover(method,param,resumeAuthorization=false){return async(req,res)=>{
  if(!authenticated(req,res))return;
  const reference=req.params?.[param];if(typeof reference!=='string'||!uuid.test(reference))return res.status(400).json({error:'Invalid CTF reference'});
  if(method==='resumePredefense'){
   if(!req.body||Array.isArray(req.body)||Object.keys(req.body).length||Object.keys(req.query||{}).length)return res.status(400).json({error:'Invalid CTF recovery request'});
   const now=Date.now(),key='resume:'+JSON.stringify([String(req.user.id),reference]);
   for(const [k,v] of limits)if(v.at(-1)<=now-60000)limits.delete(k);
   const recent=(limits.get(key)||[]).filter(t=>t>now-60000);
   if(recent.length>=10)return res.status(429).json({error:'Rate limit exceeded'});
   recent.push(now);limits.set(key,recent);
  }
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort();};req.once('aborted',abort);res.once('close',abort);
  try{const result=await runtime[method]({req,[param]:reference,signal:controller.signal,...(resumeAuthorization?{resumeAuthorization:true}:{})});controller.signal.throwIfAborted();if(method==='recoverDecision')return res.status(200).json({state:result.state,admissionId:reference,...(typeof result.decisionId==='string'&&uuid.test(result.decisionId)?{decisionId:result.decisionId}:{}),currentCompletion:false});return send(res,result);}catch(e){if(!res.destroyed)error(res,e);}finally{req.removeListener('aborted',abort);res.removeListener('close',abort);}
 };}
 return Object.freeze({attempt,recoverOperation:recover('recoverOperation','operationId'),recoverDecision:recover('recoverDecision','admissionId'),authorizeDecision:recover('recoverDecision','admissionId',true),publishDecision:recover('publishDecision','decisionId'),publishBlocked:recover('publishBlocked','runId'),recoverPredefense:recover('recoverPredefense','runId'),resumePredefense:recover('resumePredefense','runId')});
}
module.exports={createCtfAuthorityAttemptRoute};
