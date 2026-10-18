'use strict';
// Unmounted orchestration. All database authority remains in the injected
// canonical repositories; there is no direct CTF write or provider fallback.
const {randomUUID}=require('node:crypto');
const {readBearerAuthorization}=require('../middleware/bearerToken');
const {validateCtfProjectionResult}=require('./ctfProjectionResults');
const kinds=new Set(['register','start','hint','admit_attempt','record_blocked_attempt','catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear']);
const error=(code,statusCode=503)=>Object.assign(new Error(code),{code,statusCode});
const uncertain=e=>e?.code==='CTF_TRANSACTION_UNCERTAIN'||/^08[A-Z0-9]{3}$/.test(e?.code||'')||['ECONNRESET','EPIPE','ETIMEDOUT','57P01','57P02','57P03'].includes(e?.code);
const id=value=>{if(!/^[1-9][0-9]*$/.test(String(value))||BigInt(value)>2147483647n)throw error('SESSION_REVOKED',401);return String(value);};
function capture(req){const rawToken=readBearerAuthorization(req).token;if(!rawToken)throw error('SESSION_REVOKED',401);return Object.freeze({actorId:id(req?.user?.id),sessionId:id(req?.identitySession?.id),rawToken});}
function createCtfAuthorityFacade({readiness,prepare,lifecycle,operations,worker,responses,recovery,publication,validateSession,uuid=randomUUID},{waitMs=2000,maxPolls=3}={}){
 for(const fn of [readiness?.read,prepare,lifecycle?.enqueue,operations?.readAuthorized,worker?.pump,responses?.project,recovery?.recover,publication?.authorize,validateSession])if(typeof fn!=='function')throw TypeError('CTF facade canonical dependencies required');
 if(!Number.isInteger(waitMs)||waitMs<1||waitMs>5000||!Number.isInteger(maxPolls)||maxPolls<1||maxPolls>8)throw TypeError('Invalid CTF facade bounds');
 const checkAbort=signal=>{if(signal?.aborted)throw error('CTF_REQUEST_CANCELLED');};
 async function current(session,signal){checkAbort(signal);const value=await validateSession(session.rawToken,{signal});checkAbort(signal);if(!value||id(value.user?.id)!==session.actorId||id(value.session?.id)!==session.sessionId||id(value.session?.user_id)!==session.actorId)throw error('SESSION_REVOKED',401);}
 async function ready(signal){checkAbort(signal);const state=await readiness.read({signal});checkAbort(signal);if(state?.runtimeReady!==true)throw error('CTF_AUTHORITY_UNAVAILABLE');}
 const pending=operationId=>Object.freeze({status:202,body:Object.freeze({success:false,pending:true,operationId,message:'CTF operation is pending. No completion is being reported.'})});
 async function wait(operationId,session,signal,{recovering=false}={}){
  for(let n=0;n<maxPolls;n++){
   await current(session,signal);await ready(signal);
   const row=await operations.readAuthorized({operationId,session},{signal});
   if(!row&&recovering)throw error('CTF_OPERATION_NOT_FOUND',404);
   if(row){
    if(String(row.actorId)!==session.actorId||String(row.sessionId)!==session.sessionId||row.command?.operationId!==operationId)throw error('CTF_OPERATION_UNAVAILABLE',403);
    if(row.state==='blocked')throw error('CTF_PROJECTION_RECOVERY_REQUIRED');
    if(row.state==='applied'){
     const receipt=validateCtfProjectionResult(row.command,String(row.sequence),row.canonicalResult,row.resultHash);
     if(receipt.value.outcome!=='applied')throw error('CTF_PROJECTION_RECOVERY_REQUIRED');
     const response=await responses.project({command:row.command,receipt:receipt.value,session},{signal});
     await current(session,signal);await ready(signal);
     if(!response||!Number.isInteger(response.status)||!response.body)throw error('CTF_RESPONSE_INVALID');
     return response;
    }
    if(row.state!=='pending')throw error('CTF_OPERATION_STATE_INVALID');
   }
   if(n+1<maxPolls)await worker.pump({maxEvents:1,signal});
  }
  return pending(operationId);
 }
 async function bounded(operationId,session,outerSignal,work,phase={enqueueAttempted:true}){
  const deadline=AbortSignal.timeout(waitMs),signal=outerSignal?AbortSignal.any([outerSignal,deadline]):deadline;
  let listener;const aborted=new Promise((_,reject)=>{listener=()=>reject(error(deadline.aborted?'CTF_FACADE_DEADLINE':'CTF_REQUEST_CANCELLED'));if(signal.aborted)listener();else signal.addEventListener('abort',listener,{once:true});});
  try{return await Promise.race([work(signal),aborted]);}
  catch(e){if(e.code==='CTF_FACADE_DEADLINE'||uncertain(e)){if(!phase.enqueueAttempted)throw Object.assign(error('CTF_NOT_ADMITTED'),{admitted:false,cause:e});return pending(operationId);}if(e.code==='CTF_REQUEST_CANCELLED'&&phase.enqueueAttempted)e.operationId=operationId;throw e;}
  finally{signal.removeEventListener('abort',listener);}
 }
 return Object.freeze({
  async execute({req,kind,input,signal}){
   if(!kinds.has(kind))throw TypeError('Unsupported CTF facade command');
   const session=capture(req),operationId=uuid(),snapshot=structuredClone(input),phase={enqueueAttempted:false};
   return bounded(operationId,session,signal,async boundedSignal=>{
    await current(session,boundedSignal);await ready(boundedSignal);
    // prepare is server-owned: derive current IDs/revisions/config and whitelist
    // body fields. Never spread request authority into enqueue arguments.
    const command=await prepare({kind,input:snapshot,session},{signal:boundedSignal});
    if(boundedSignal.aborted)throw error('CTF_REQUEST_CANCELLED');
    phase.enqueueAttempted=true;
    try{await lifecycle.enqueue({kind,body:command.body,scope:command.scope,operationId,...session},{signal:boundedSignal});}
    catch(e){
     if(kind==='register'&&e.code==='P0001'&&['CTF registration closed','CTF capacity reached'].includes(e.message))return{status:403,body:{error:e.message==='CTF registration closed'?'CTF registration is currently closed':'CTF participant limit reached'}};
     if(kind==='hint'&&e.code==='P0001'&&e.message==='CTF hint eligibility changed')return{status:409,body:{error:'Hint availability changed; refresh stage status'}};
     throw e;
    }
    return wait(operationId,session,boundedSignal);
   },phase);
  },
  async recoverOperation({req,operationId,signal}){
   if(typeof operationId!=='string'||!(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/).test(operationId))throw TypeError('Invalid CTF operation reference');
   const session=capture(req);return bounded(operationId,session,signal,s=>wait(operationId,session,s,{recovering:true}));
  },
  async recoverDecision({req,admissionId,resumeAuthorization=false,signal}){
   const session=capture(req);await current(session,signal);await ready(signal);
   const result=await recovery.recover({admissionId,session,resumeAuthorization,signal});
   await current(session,signal);await ready(signal);
   return Object.freeze({...result,currentCompletion:false});
  },
  async authorizePublication({req,decisionId,signal}){
   const session=capture(req);await current(session,signal);await ready(signal);
   return publication.authorize({decisionId,session},{signal});
  }
 });
}
module.exports={createCtfAuthorityFacade};
