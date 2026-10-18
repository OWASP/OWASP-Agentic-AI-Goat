'use strict';
// Inert composition. Borrowed pools are never closed; no migration, bootstrap,
// activation, route registration or provider call occurs during construction.
const {randomUUID}=require('node:crypto');
const {readBearerAuthorization}=require('../middleware/bearerToken');
const {createCtfDeliveryPool}=require('../database/postgres/ctfDeliveryPool');
const {createCtfDeliveryActivation,validateCtfDeliveryTuple}=require('../database/postgres/ctfDeliveryActivation');
const {createCtfLifecycleRepository}=require('../database/postgres/ctfLifecycleRepository');
const {createCtfOperationRecoveryRepository}=require('../database/postgres/ctfOperationRecoveryRepository');
const {createCtfAuthorityRequestRepository}=require('../database/postgres/ctfAuthorityRequestRepository');
const {createCtfCurrentResponseRepository}=require('../database/postgres/ctfCurrentResponseRepository');
const {createCtfCurrentReadRepository}=require('../database/postgres/ctfCurrentReadRepository');
const {createCtfCurrentPublicationRepository}=require('../database/postgres/ctfCurrentPublicationRepository');
const {createCtfProjectionDecisionRepository}=require('../database/postgres/ctfDecisionProjectionRepository');
const {createCtfDecisionRecoveryRepository}=require('../database/postgres/ctfDecisionRecoveryRepository');
const {createCtfPredefenseRecoveryRepository}=require('../database/postgres/ctfPredefenseRecoveryRepository');
const {createCtfPredefenseRecoveryService,validateCtfPredefenseRecoveryResult}=require('./ctfPredefenseRecoveryService');
const {createCtfPredefenseRepository}=require('../database/postgres/ctfPredefenseRepository');
const {createCtfPredefenseRequestLoader}=require('../database/postgres/ctfPredefenseRequestLoader');
const {createCtfBlockedPredefenseRepository}=require('../database/postgres/ctfBlockedPredefenseRepository');
const {createCtfBlockedCurrentResponseRepository}=require('../database/postgres/ctfBlockedCurrentResponseRepository');
const {createCtfTelemetryRepository}=require('../database/postgres/ctfTelemetryRepository');
const {createCtfDeletionRepository}=require('../database/postgres/ctfDeletionRepository');
const {createCtfAuthorityPrepare}=require('./ctfAuthorityPrepare');
const {createCtfAuthorityResponseProjection}=require('./ctfAuthorityResponseProjection');
const {createCtfAuthorityFacade}=require('./ctfAuthorityFacade');
const {createCtfProjectionWorkerLifecycle}=require('./ctfProjectionWorkerLifecycle');
const {createCtfDecisionRecoveryService}=require('./ctfDecisionRecoveryService');
const {createCtfDecisionService}=require('./ctfDecisionService');
const {createCtfPredefenseOrchestrator}=require('./ctfPredefenseOrchestrator');
const {createCtfBlockedResponseProjector}=require('./ctfBlockedResponseProjector');
const {createCtfDeletionService}=require('./ctfDeletionService');
const {createCtfAdminSolutionsRead}=require('./ctfAdminSolutionsRead');
const {createCtfAdminPreviewSnapshot}=require('./ctfAdminPreviewSnapshot');
const {createCtfFixedPracticeSnapshot}=require('../database/postgres/ctfFixedPracticeSnapshot');
const {heartbeatPublicResponse}=require('./ctfTelemetryContract');
const commands=new Set(['register','start','hint','catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear']);
const fail=(code='CTF_RUNTIME_UNAVAILABLE',statusCode=503)=>{throw Object.assign(Error(code),{code,statusCode});};
const uuidPattern=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function sessionFrom(req){const rawToken=readBearerAuthorization(req).token;const actorId=String(req?.user?.id),sessionId=String(req?.identitySession?.id);if(!rawToken||![actorId,sessionId].every(x=>/^[1-9][0-9]*$/.test(x)&&BigInt(x)<=2147483647n))fail('SESSION_REVOKED',401);return Object.freeze({actorId,sessionId,rawToken});}
function snapshotArgs(args){
 const copy={...args};
 if(args?.req){const s=sessionFrom(args.req);copy.req=Object.freeze({headers:Object.freeze({authorization:'Bearer '+s.rawToken}),user:Object.freeze({id:s.actorId}),identitySession:Object.freeze({id:s.sessionId})});}
 if(Object.hasOwn(copy,'input'))copy.input=structuredClone(copy.input);
 if(Object.hasOwn(copy,'request'))copy.request=structuredClone(copy.request);
 return copy;
}
function createTransactionLocalPublicationReadiness({activation,isRunning}){
 const expected=validateCtfDeliveryTuple(activation);
 if(typeof isRunning!=='function')throw TypeError('Runtime state predicate required');
 return async function publicationReady(client){
  if(!isRunning())return false;
  // Same SELECT predicate as qualified0115; the caller already holds global
  // publication locks. Never borrow a second store/client inside this callback.
  const row=(await client.query(`SELECT a.activation_id::text,a.identity_store_id::text,a.ctf_store_id::text,a.bootstrap_operation_id::text,a.source_revision::text,a.manifest_sha256,a.protocol_version,a.authority_sha256
   FROM identity.ctf_delivery_control c JOIN identity.ctf_delivery_activations a USING(activation_id)
   JOIN identity.ctf_bootstrap_sessions b ON b.operation_id=a.bootstrap_operation_id
   JOIN identity.ctf_bootstrap_store s ON s.singleton
   WHERE c.singleton AND a.protocol_version=1 AND a.identity_store_id=s.store_id AND b.state='prepared'
   AND b.source_store_id=a.ctf_store_id AND b.source_revision=a.source_revision AND b.manifest_sha256=a.manifest_sha256`)).rows[0];
  return isRunning()&&!!row&&Object.keys(expected).every(k=>row[k]===expected[k]);
  };
}
function createOwnedCtfExecution(execution,signal){
 if(!execution||typeof execution.check!=='function'||!signal)throw TypeError('Owned CTF execution required');
 const composed=execution.signal?AbortSignal.any([signal,execution.signal]):signal;
 const facade={};
 // Coordinator context is normally plain; bind prototype methods too so trusted
 // class adapters retain their private receiver/budget rather than facade this.
 for(let current=execution;current&&current!==Object.prototype;current=Object.getPrototypeOf(current)){
  for(const key of Reflect.ownKeys(current)){
   if(key==='constructor'||key==='signal'||key==='check'||Object.hasOwn(facade,key))continue;
   const value=Reflect.get(execution,key);Object.defineProperty(facade,key,{value:typeof value==='function'?value.bind(execution):value,enumerable:true});
  }
 }
 Object.defineProperties(facade,{signal:{value:composed,enumerable:true},check:{value:async()=>{composed.throwIfAborted();await execution.check.call(execution);composed.throwIfAborted();},enumerable:true}});
 return Object.freeze(facade);
}
function validAttemptPublication(response,authorization){
 if(!response||!authorization)return false;
 if(response.status===200)return typeof response.body?.success==='boolean'&&response.body.success===authorization.currentCompletion;
 if(Reflect.ownKeys(response).length!==2||!Object.hasOwn(response,'status')||!Object.hasOwn(response,'body'))return false;
 if(response.status!==503||authorization.verdict!=='unavailable'||authorization.currentCompletion!==false)return false;
 const body=response.body;
 if(!body||typeof body!=='object'||Array.isArray(body))return false;
 const expected=['error','retryable','attemptNumber','judgment',...(Object.hasOwn(body,'lessonState')?['lessonState']:[])];
 if(Reflect.ownKeys(body).length!==expected.length||!expected.every(k=>Object.hasOwn(body,k)))return false;
 if(body.error!=='AI system temporarily unavailable. Please try again.'||body.retryable!==true||!Number.isSafeInteger(body.attemptNumber)||body.attemptNumber<1)return false;
 if(!body.judgment||typeof body.judgment!=='object'||Array.isArray(body.judgment)||Reflect.ownKeys(body.judgment).length!==1||body.judgment.verdict!=='unavailable')return false;
 if(Object.hasOwn(body,'lessonState')){
  const flags=['input_guard_observed','reviewer_observed','category_consumed','category_reuse_blocked','shared_similarity_blocked'];
  if(!body.lessonState||typeof body.lessonState!=='object'||Reflect.ownKeys(body.lessonState).length!==flags.length||!flags.every(k=>Object.hasOwn(body.lessonState,k)&&typeof body.lessonState[k]==='boolean'))return false;
 }
 return true;
}
function createCtfAuthorityRuntime({identityPool,ctfPool,deliveryPool,deliveryDatabaseUrl,activation,validateSession,attempts=null},{workerOptions={},facadeOptions={},drainMs=5000}={}){
 for(const pool of [identityPool,ctfPool,deliveryPool])if(typeof pool?.connect!=='function')throw TypeError('Three explicit CTF runtime pools required');
 if(deliveryPool===ctfPool||deliveryPool===identityPool||typeof validateSession!=='function'||!Number.isInteger(drainMs)||drainMs<1||drainMs>30000)throw TypeError('Invalid CTF runtime ownership');
 if(Object.keys(workerOptions).some(k=>!['pollMs','maxEvents','batchTimeoutMs','drainMs'].includes(k)))throw TypeError('Unsupported worker option');
 if(Object.keys(facadeOptions).some(k=>!['waitMs','maxPolls'].includes(k)))throw TypeError('Unsupported facade option');
 const expected=validateCtfDeliveryTuple(activation),url=new URL(deliveryDatabaseUrl);
 if(decodeURIComponent(url.username)!=='dvaia_ctf_delivery')throw TypeError('Dedicated delivery URL required');
 const productionAttempts=attempts==='production';
 if(productionAttempts){
  const admitted=require('../database/postgres/ctfAdmittedAttemptRepository').createCtfAdmittedAttemptRepository(identityPool);
  const responses=require('../database/postgres/ctfCurrentAttemptResponseRepository').createCtfCurrentAttemptResponseRepository(identityPool);
  attempts={loadAdmittedAttempt:admitted.loadAdmittedAttempt,runGuardian:require('./ctfProductionGuardian').createCtfProductionGuardian(),buildCurrentResponse:responses.read};
 }
 if(attempts!==null&&Object.keys(attempts).some(k=>!['loadAdmittedAttempt','runGuardian','buildCurrentResponse','judge','defend','languageModel'].includes(k)))throw TypeError('Unsupported attempt adapter');
 if(attempts!==null&&['loadAdmittedAttempt','runGuardian','buildCurrentResponse'].some(k=>typeof attempts[k]!=='function'))throw TypeError('Complete trusted attempt adapters required');
 // Snapshot function references; later caller mutation cannot change composition.
 attempts=attempts===null?null:Object.freeze({...attempts});
 async function validateCanonicalSession(token,options={}){try{return await validateSession(token,options);}catch(error){options.signal?.throwIfAborted();if(error?.name==='AccountLocked')fail('ACCOUNT_LOCKED',423);if(['TokenExpiredError','JsonWebTokenError','NotBeforeError'].includes(error?.name))fail('SESSION_REVOKED',401);throw error;}}
 const verify=createCtfDeliveryActivation({identityPool,ctfPool});
 let state='paused',epoch=0,controller=new AbortController(),starting=null;
 const outstanding=new Set();
 const identity=createCtfLifecycleRepository(identityPool),operations=createCtfOperationRecoveryRepository(identityPool);
 async function ready({signal}={}){signal?.throwIfAborted();if(state!=='running')return false;await verify.verify(expected,{signal});signal?.throwIfAborted();return state==='running'&&worker.status().state==='running';}
 const worker=createCtfProjectionWorkerLifecycle({...workerOptions,identity,ctfPool:deliveryPool,readiness:ready});
 const predefenseRecovery=createCtfPredefenseRecoveryService({repository:createCtfPredefenseRecoveryRepository(identityPool),worker});
 const publication=createCtfCurrentPublicationRepository(identityPool),decisions=productionAttempts?require('../database/postgres/ctfDiagnosticDecisionRepository').createCtfDiagnosticDecisionRepository(identityPool):createCtfProjectionDecisionRepository(identityPool);
 const recovery=createCtfDecisionRecoveryService({recovery:createCtfDecisionRecoveryRepository(identityPool),decisions});
 const facade=createCtfAuthorityFacade({readiness:{async read(options){return{runtimeReady:await ready(options)};}},prepare:createCtfAuthorityPrepare({repository:createCtfAuthorityRequestRepository(identityPool)}),lifecycle:identity,operations,worker,responses:createCtfAuthorityResponseProjection({repository:createCtfCurrentResponseRepository({identityPool,ctfPool})}),recovery,publication,validateSession:validateCanonicalSession},facadeOptions);
 const reads=createCtfCurrentReadRepository({identityPool,ctfPool,readiness:ready});
 const solutions=createCtfAdminSolutionsRead({current:reads}),preview=createCtfAdminPreviewSnapshot({current:reads});
 const practice=createCtfFixedPracticeSnapshot({identityPool,ctfPool});
 const telemetry=createCtfTelemetryRepository(identityPool),deletion=createCtfDeletionService({identity:createCtfDeletionRepository(identityPool),ctfPool:deliveryPool});
 const predefense=createCtfPredefenseRepository(identityPool),blocked=createCtfBlockedPredefenseRepository(identityPool);
 const publicationReady=createTransactionLocalPublicationReadiness({activation:expected,isRunning:()=>state==='running'&&!controller.signal.aborted});
 const blockedResponses=createCtfBlockedResponseProjector({current:createCtfBlockedCurrentResponseRepository(identityPool,{readiness:publicationReady})});
 const decision=attempts?createCtfDecisionService({repository:decisions,loadAdmittedAttempt:attempts.loadAdmittedAttempt,runGuardian:attempts.runGuardian,...(attempts.judge?{judge:attempts.judge}:{})}):null;
 function predefenseResult(args,resume){
  args=snapshotArgs(args);
  if(typeof args.runId!=='string'||!uuidPattern.test(args.runId))return Promise.reject(TypeError('Invalid predefense run reference'));
  return ingress(args.signal,async signal=>{
   if(!await ready({signal}))fail('CTF_RUNTIME_UNAVAILABLE');
   const session=await canonical(args.req,signal);
   const value=validateCtfPredefenseRecoveryResult(await predefenseRecovery[resume?'resume':'read']({runId:args.runId,session},{signal}),args.runId);
   return Object.freeze({status:value.state==='recovery_pending'?202:200,body:value});
  });
 }
 const status=()=>Object.freeze({state,requests:outstanding.size,starting:starting!==null,worker:worker.status(),attemptsSupported:attempts!==null});
 function ingress(signal,fn){
  if(state!=='running')return Promise.reject(Object.assign(Error('CTF_RUNTIME_UNAVAILABLE'),{code:'CTF_RUNTIME_UNAVAILABLE',statusCode:503}));
  const owned=AbortSignal.any([controller.signal,...(signal?[signal]:[])]);
  const work=Promise.resolve().then(async()=>{owned.throwIfAborted();if(!await ready({signal:owned}))fail();const value=await fn(owned);owned.throwIfAborted();return value;});
  outstanding.add(work);work.then(()=>outstanding.delete(work),()=>outstanding.delete(work));return work;
 }
 async function canonical(req,signal){const session=sessionFrom(req);let checked;try{checked=await validateCanonicalSession(session.rawToken,{signal});}catch(error){signal.throwIfAborted();if(['TokenExpiredError','JsonWebTokenError','NotBeforeError'].includes(error?.name))fail('SESSION_REVOKED',401);throw error;}signal.throwIfAborted();if(String(checked?.user?.id)!==session.actorId||String(checked?.session?.id)!==session.sessionId||String(checked?.session?.user_id)!==session.actorId)fail('SESSION_REVOKED',401);return session;}
 async function publish({req,decisionId},signal){
  if(!attempts)fail('CTF_ATTEMPT_COMPOSITION_UNAVAILABLE');
  if(!uuidPattern.test(decisionId))throw TypeError('Invalid decision reference');
  const session=await canonical(req,signal);
  const pending=await publication.pending({decisionId,session},{signal});
  signal.throwIfAborted();
  if(pending)return{status:202,body:{success:false,pending:true,decisionId}};
  // Build privately, then perform the canonical publication fence LAST. No raw
  // historical recovery receipt is ever spread into a public response.
  const response=structuredClone(await attempts.buildCurrentResponse({decisionId,session},{signal}));
  const authorization=await publication.authorize({decisionId,session},{signal});
  signal.throwIfAborted();
  if(!validAttemptPublication(response,authorization))fail('CTF_ATTEMPT_RESPONSE_INVALID');
  return response;
 }
 return Object.freeze({status,
  start(){
   if(state==='stopped')return Promise.reject(Error('CTF runtime stopped'));
   if(starting)return starting;if(state==='running'&&worker.status().state==='running')return Promise.resolve(status());
   if(worker.status().active)return Promise.reject(Object.assign(Error('CTF worker still draining'),{code:'CTF_WORKER_DRAINING'}));
   state='starting';const ticket=++epoch;
   starting=Promise.resolve().then(async()=>{
    // Reuse actual role/login/database/checkpoint validation; the borrowed-pool
    // adapter's end is intentionally a no-op, even on validation failure.
    await createCtfDeliveryPool({env:{CTF_DELIVERY_DATABASE_URL:url.href},activation:expected,create:()=>({connect:()=>deliveryPool.connect(),end:async()=>{}})});
    await verify.verify(expected,{signal:controller.signal});
    if(ticket!==epoch||state!=='starting'||controller.signal.aborted)fail();
    state='running';worker.start();return status();
   }).catch(async error=>{if(state!=='stopped')state='paused';await worker.pause();throw error;}).finally(()=>{starting=null;});return starting;
  },
  async stop(){
   state='stopped';epoch++;controller.abort();
   const workerDrain=worker.stop(),pending=[...outstanding,...(starting?[starting.catch(()=>{})]:[])];
   let timer;const requestsDrained=await Promise.race([Promise.allSettled(pending).then(()=>true),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),drainMs);})]);clearTimeout(timer);
   const result=await workerDrain;return Object.freeze({...status(),drained:requestsDrained&&result.drained,requestsDrained,workerDrained:result.drained});
  },
  readiness:options=>ingress(options?.signal,async signal=>({runtimeReady:await ready({signal})})),
  mutate(args){args=snapshotArgs(args);if(!commands.has(args?.kind))return Promise.reject(TypeError('Unsupported public CTF lifecycle command'));return ingress(args.signal,signal=>facade.execute({...args,signal}));},
  recoverOperation:args=>{args=snapshotArgs(args);return ingress(args.signal,signal=>facade.recoverOperation({...args,signal}));},
  recoverDecision:args=>{args=snapshotArgs(args);return ingress(args.signal,async signal=>{const value=await facade.recoverDecision({...args,signal});const decisionId=value.receipt?.decision_id??null;if(decisionId!==null&&(typeof decisionId!=='string'||!uuidPattern.test(decisionId)))fail('CTF_RECOVERY_INVALID');return Object.freeze({state:value.state,admissionId:args.admissionId,decisionId,currentCompletion:false});});},
  read:args=>{args=snapshotArgs(args);return ingress(args.signal,async signal=>reads.read({...args,session:args.req?await canonical(args.req,signal):null},{signal}));},
  adminSolutions:args=>{args=snapshotArgs(args);return ingress(args.signal,async signal=>solutions(await canonical(args.req,signal),{signal}));},
  previewCapture:args=>{args=snapshotArgs(args);return ingress(args.signal,async signal=>preview.capture({stageId:args.stageId,session:await canonical(args.req,signal)},{signal}));},
  previewRevalidate:args=>{args=snapshotArgs(args);return ingress(args.signal,signal=>preview.revalidate(args.lease,{signal}));},
  practiceCapture:args=>{args=snapshotArgs(args);return ingress(args.signal,async signal=>practice.capture({session:await canonical(args.req,signal),stageId:args.stageId,signal}));},
  practiceRevalidate:args=>{args=snapshotArgs(args);return ingress(args.signal,async signal=>{await canonical(args.req,signal);return practice.revalidate({lease:args.lease,signal});});},
  heartbeat:args=>{args=snapshotArgs(args);return ingress(args.signal,async signal=>{
   const session=await canonical(args.req,signal),operationId=args.operationId??randomUUID();if(!uuidPattern.test(operationId))throw TypeError('Invalid heartbeat reference');
   const input={session,operationId,registrationToken:args.registrationToken};let value=await telemetry.admit(input,{signal});
   if(value.state==='pending'){await worker.pump({maxEvents:1,signal});value=await telemetry.admit(input,{signal});}
   return{status:value.state==='pending'?202:200,body:heartbeatPublicResponse(value)};
  });},
  deleteStudent:scope=>{scope={...scope};return ingress(scope.signal,signal=>deletion({...scope,signal}));},
  attempt:args=>{args=snapshotArgs(args);return ingress(args.signal,async signal=>{
   if(!attempts)fail('CTF_ATTEMPT_COMPOSITION_UNAVAILABLE');
   const session=await canonical(args.req,signal);
   const orchestration=createCtfPredefenseOrchestrator({repository:predefense,loadRequest:createCtfPredefenseRequestLoader({identityPool,ctfPool,request:args.request??null}),operations,worker,blocked,decision,defend:attempts.defend,languageModel:attempts.languageModel});
   const execution=createOwnedCtfExecution(args.execution,signal);
   const result=await orchestration.execute({runId:args.runId,session,execution,signal:execution.signal});
   if(result.status==='blocked_recorded')return blockedResponses.project({runId:args.runId,session},{signal});
   // Delivery/current-response composition remains explicit; internal accepted
   // receipts do not become success UI merely because inference completed.
   const operationId=result.operationId??null;if(operationId!==null&&(typeof operationId!=='string'||!uuidPattern.test(operationId)))fail('CTF_RECOVERY_INVALID');return{status:202,body:{success:false,pending:true,runId:args.runId,operationId,admissionId:result.admissionId??null,decisionId:result.receipt?.decision_id??null}};
  });},
  recoverPredefense:args=>predefenseResult(args,false),
  resumePredefense:args=>predefenseResult(args,true),
  publishBlocked:args=>{
   args=snapshotArgs(args);
   if(typeof args.runId!=='string'||!uuidPattern.test(args.runId))return Promise.reject(new TypeError('Invalid blocked run reference'));
   return ingress(args.signal,async signal=>{
    const session=await canonical(args.req,signal);
    // The existing reader authenticates the original claim session, both applied
    // receipts and current activation under its transaction-local publication locks.
    // No coordinator, provider, enqueue or worker pump belongs in this read path.
    return blockedResponses.project({runId:args.runId,session},{signal});
   });
  },
  publishDecision:args=>{args=snapshotArgs(args);return ingress(args.signal,signal=>publish(args,signal));},
  bootstrap(){fail('CTF_OPERATOR_ONLY');},activate(){fail('CTF_OPERATOR_ONLY');},
 });
}
module.exports={createCtfAuthorityRuntime,createTransactionLocalPublicationReadiness,createOwnedCtfExecution};
