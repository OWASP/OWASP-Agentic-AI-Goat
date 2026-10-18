'use strict';
// UNMOUNTED. Trusted dependencies load persisted request/stage facts. No HTTP
// body fields can nominate a verdict, failed count, adaptive hit, or authority.
const {classifyTechnique,hashPayload}=require('./promptInjectionCTF');
const {runDefenseLayers}=require('./ctfDefenseLayers');
const {stageDigest,stageSnapshot}=require('../agent-runtime/ctfStageJudge');
const {inputDocument,outcomeDocument}=require('./ctfPredefenseContract');
const {canonicalCtfJson}=require('./ctfLifecycleCommands');
const {validateCtfProjectionResult}=require('./ctfProjectionResults');
const freeze=x=>{if(x&&typeof x==='object'){Object.values(x).forEach(freeze);Object.freeze(x);}return x;};
const err=code=>Object.assign(Error(code),{code});
const uncertain=e=>e?.code==='CTF_TRANSACTION_UNCERTAIN'||/^08[A-Z0-9]{3}$/.test(e?.code||'')||['ECONNRESET','EPIPE','ETIMEDOUT','57P01','57P02','57P03'].includes(e?.code);
function createCtfPredefenseOrchestrator({repository,loadRequest,operations,worker,blocked,decision,defend=runDefenseLayers,languageModel},{waitMs=2000,maxPolls=3}={}){
 for(const fn of [repository?.claim,repository?.storeOutcome,repository?.consume,loadRequest,operations?.readAuthorized,worker?.pump,blocked?.enqueueFromClaim,decision?.evaluate,defend])if(typeof fn!=='function')throw TypeError('Canonical CTF pre-defense dependencies required');
 if(!Number.isInteger(waitMs)||waitMs<1||waitMs>5000||!Number.isInteger(maxPolls)||maxPolls<1||maxPolls>8)throw TypeError('Invalid CTF admission wait bounds');
 const pending=(runId,operationId=null)=>Object.freeze({status:'pending_recovery',runId,operationId,currentCompletion:false,publication:'requires_current_validation'});
 async function check(execution,signal){if(signal?.aborted)throw err('CTF_REQUEST_CANCELLED');await execution.check();if(signal?.aborted)throw err('CTF_REQUEST_CANCELLED');}
 async function applied(operationId,kind,session,execution,outerSignal){
  const deadline=AbortSignal.timeout(waitMs),signal=outerSignal?AbortSignal.any([outerSignal,deadline]):deadline;
  let listener;const aborted=new Promise((_,reject)=>{listener=()=>reject(err(deadline.aborted?'CTF_ADMISSION_WAIT_EXPIRED':'CTF_REQUEST_CANCELLED'));if(signal.aborted)listener();else signal.addEventListener('abort',listener,{once:true});});
  const work=async()=>{for(let n=0;n<maxPolls;n++){
   await check(execution,signal);const row=await operations.readAuthorized({operationId,session},{signal});
   if(!row)throw err('CTF_OPERATION_NOT_FOUND');
   if(row.actorId!==session.actorId||row.sessionId!==session.sessionId||row.command?.operationId!==operationId||row.command.kind!==kind)throw err('CTF_OPERATION_BINDING_MISMATCH');
   if(row.state==='blocked')throw err('CTF_PROJECTION_RECOVERY_REQUIRED');
   if(row.state==='applied'){const receipt=validateCtfProjectionResult(row.command,String(row.sequence),row.canonicalResult,row.resultHash);if(receipt.value.outcome!=='applied')throw err('CTF_PROJECTION_RECOVERY_REQUIRED');await check(execution,signal);return receipt.value;}
   if(row.state!=='pending')throw err('CTF_OPERATION_STATE_INVALID');
   if(n+1<maxPolls)await worker.pump({maxEvents:1,signal});
  }return null;};
  try{return await Promise.race([work(),aborted]);}catch(e){if(e.code==='CTF_ADMISSION_WAIT_EXPIRED'||uncertain(e))return null;throw e;}finally{signal.removeEventListener('abort',listener);}
 }
 return Object.freeze({async execute({runId,session,execution,signal}){
  if(!execution||typeof execution.check!=='function')throw TypeError('Owned execution required');
  const original=freeze(structuredClone(session));await check(execution,signal);
  const facts=freeze(structuredClone(await loadRequest({runId,session:original},{signal})));
  const {binding,stage,payload}=facts;
  if(binding.runId!==runId||binding.ownerId!==String(original.actorId)||binding.sessionId!==String(original.sessionId)||binding.stageDigest!==stageDigest(stage))throw err('CTF_PREDEFENSE_BINDING_MISMATCH');
  const technique=classifyTechnique(payload),normalized=hashPayload(payload),capturedStageSnapshot=stageSnapshot(stage);
  const input={version:1,binding,payload,normalizedPayload:normalized.normalized,payloadHash:normalized.hash,techniqueTag:technique.tag,techniqueConfidence:technique.confidence};
  const encoded=inputDocument(input,capturedStageSnapshot);
  let captured;
  try{captured=await repository.claim({session:original,input:encoded.document,stageSnapshot:capturedStageSnapshot,registrationToken:facts.registrationToken??null},{signal});}catch(e){if(uncertain(e))return pending(runId);throw e;}
  if(captured?.runId!==runId||typeof captured.claimed!=='boolean'||!captured.admissionOperationId||!captured.blockedOperationId)throw err('CTF_PREDEFENSE_CLAIM_INVALID');
  if(!captured.claimed&&!captured.outcome)return pending(runId,captured.admissionOperationId);
  if(captured.claimed){
   await check(execution,signal);
   const adaptive=captured.initialAdaptive?.disposition;
   if(!['category','payload','continue'].includes(adaptive))throw err('CTF_PREDEFENSE_ADAPTIVE_INVALID');
   let outcome;
   if(adaptive!=='continue')outcome={version:1,inputHash:encoded.documentHash,inputDecision:'skipped',reason:'',languageStatus:null,providerReceipt:null};
   else{
    // This is the same input-defense callback used by ctfAdmissionGraph. Its
    // existing language graph/execution budget remains the provider boundary.
    const result=await defend(stage,payload,{execution,languageModel,signal});await check(execution,signal);
    if(typeof result?.blocked!=='boolean')throw err('CTF_DEFENSE_RESULT_INVALID');
    outcome={version:1,inputHash:encoded.documentHash,inputDecision:result.blocked?'block':'allow',reason:result.reason||'',languageStatus:result.languageDecision?.status??null,providerReceipt:result.languageDecision?canonicalCtfJson(result.languageDecision):null};
   }
   outcome=outcomeDocument(outcome).document;
   try{await repository.storeOutcome({session:original,runId,outcome},{signal});}catch(e){if(uncertain(e))return pending(runId,captured.admissionOperationId);throw e;}
  }
  await check(execution,signal);
  let consumed;try{consumed=await repository.consume({session:original,runId},{signal});}catch(e){if(uncertain(e))return pending(runId,captured.admissionOperationId);throw e;}
  if(consumed?.consumed!==true)return pending(runId,captured.admissionOperationId);
  if(consumed.operationId!==captured.admissionOperationId||consumed.blockedOperationId!==captured.blockedOperationId||!['category','payload','input','continue'].includes(consumed.disposition))throw err('CTF_PREDEFENSE_CONSUMPTION_INVALID');
  const admission=await applied(consumed.operationId,'admit_attempt',original,execution,signal);
  if(!admission)return pending(runId,consumed.operationId);
  await check(execution,signal);
  if(consumed.disposition==='continue')return decision.evaluate({admissionId:consumed.operationId,session:original,execution,signal});
  // Required forward database guard derives the body from durable facts; there
  // is deliberately no fallback accepting a caller supplied lifecycle body.
  let recorded;try{recorded=await blocked.enqueueFromClaim({runId,session:original},{signal});}catch(e){if(uncertain(e))return pending(runId,consumed.blockedOperationId);throw e;}
  if(recorded?.operationId!==consumed.blockedOperationId)throw err('CTF_BLOCKED_OPERATION_MISMATCH');
  const receipt=await applied(consumed.blockedOperationId,'record_blocked_attempt',original,execution,signal);
  if(!receipt)return pending(runId,consumed.blockedOperationId);
  return Object.freeze({status:'blocked_recorded',runId,admissionId:consumed.operationId,operationId:consumed.blockedOperationId,receipt,currentCompletion:false,publication:'requires_current_validation'});
 }});
}
module.exports={createCtfPredefenseOrchestrator};
