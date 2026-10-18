'use strict';
const {createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {readQualifiedUploadSource,readQualifiedFixedUploadSource}=require('./secureshopV06UploadEvidence');
const {normalizeUploadPreviewRequest,requestDigest,validateUploadPreviewReceipt}=require('../../sidecars/sandbox-runner/owned-system/upload-preview-contract');
const PURPOSE='secureshop_avatar_upload';
const TOOL='uploads.preview_legacy_image';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hash=x=>createHash('sha256').update(x).digest('hex');
const fail=()=>Object.assign(Error('Original polyglot preview unavailable'),{code:'UPLOAD_PREVIEW_SOURCE_UNAVAILABLE',executionBoundary:true});
function previewIdentity(uploadOperationId){
 if(!UUID.test(uploadOperationId||''))throw fail();
 const uuid=label=>{const h=hash(JSON.stringify([label,uploadOperationId]));return `${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-a${h.slice(17,20)}-${h.slice(20,32)}`;};
 return Object.freeze({requestId:uuid('upload-preview-request-v1'),operationId:uuid('upload-preview-operation-v1')});
}
async function readGraphEffect(pool,receipt){
 const rows=(await pool.query(`SELECT e.run_id,e.owner_key,e.generation::text AS generation,e.effect_key,e.status,
 r.status AS run_status,o.generation::text AS live_generation FROM graph_runtime.effects e
 JOIN graph_runtime.runs r ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
 JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
 WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=$4 LIMIT 2`,
 [receipt?.runId,receipt?.ownerKey,receipt?.generation,receipt?.effectKey])).rows;
 if(rows.length!==1)throw fail();return rows[0];
}
function createV07UploadSourceReader({identityPool,agentsPool,assets,assertCurrent,read,journal,conversationRepository,qualifyModel}={}){
 for(const fn of [identityPool?.query,agentsPool?.query,assets?.lookup,assertCurrent,read,journal?.readUploadRequest,conversationRepository?.getTraceEvents,qualifyModel])if(typeof fn!=='function')throw TypeError('Polyglot source dependencies required');
 const privateBytes=new WeakMap();
 const current=async(check,signal)=>{signal?.throwIfAborted();if(check)await check();signal?.throwIfAborted();};
 async function stored(input){
  const {scope,persona,personaSession,target,mode,signal}=input;
  if(!target?.scene||mode?.featureId!=='uploads'||!['vuln','fixed'].includes(mode.mode))throw fail();
  const found=await assets.lookup({effectId:input.effectId,operationId:input.operationId,targetId:target.targetId,generation:scope.generation,
   sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration,mode:mode.mode,modeGeneration:mode.generation,modeStamp:mode.modeStamp});
  if(!found?.canonicalServe)throw fail();
  const {admission,effect,canonicalServe:serve}=found,b=admission.scope;
  if(!equal(createLaunchScope(b),createLaunchScope(scope))||persona?.role!=='customer'||b.shopUserId!==persona.id
   ||b.personaSessionId!==personaSession?.sessionId||b.personaAuthorityVersion!==personaSession.authorityVersion
   ||b.targetId!==target.targetId||b.sceneId!==target.scene.sceneId||b.sceneGeneration!==target.scene.sceneGeneration||b.grantId!==target.scene.grantId
   ||b.mode!==mode.mode||b.modeGeneration!==mode.generation||b.modeStamp!==mode.modeStamp||effect.outcome!=='completed'||effect.file?.isTraversal!==false
   ||admission.operationId!==input.operationId||effect.effectId!==input.effectId||!admission.request.public
   ||!/^.+\.gif$/i.test(effect.file.originalFilename)||effect.file.declaredMime!=='image/gif'||effect.file.byteCount>256*1024
   ||serve.status!==200||serve.responseSha256!==effect.file.bodySha256||serve.responseByteCount!==effect.file.byteCount||serve.contentType!=='image/gif')throw fail();
  await assertCurrent(admission);await current(input.check,signal);
  const bytes=await read({storedVirtualPath:effect.file.storedVirtualPath,responseByteCount:effect.file.byteCount,responseSha256:effect.file.bodySha256});
  if(!Buffer.isBuffer(bytes)||bytes.length!==effect.file.byteCount||hash(bytes)!==effect.file.bodySha256)throw fail();
  await assertCurrent(admission);await current(input.check,signal);
  const result=Object.freeze({admission,effect,serve});privateBytes.set(result,Buffer.from(bytes));return result;
 }
 async function load(input){
  const {binding,personaSession,target,mode,sessionId,requestId,check,signal}=input;
  if(!UUID.test(sessionId||'')||!UUID.test(requestId||'')||typeof check!=='function')throw fail();
  await current(check,signal);
  const row=await journal.readUploadRequest({sessionId,requestId,binding,purpose:PURPOSE});
  const meta=row?.result_json?.taskMetadata?.boundUpload;
  if(row?.status!=='completed'||!UUID.test(meta?.operationId||'')||!UUID.test(meta?.effectId||''))throw fail();
  const retained=await stored({scope:binding,persona:{id:binding.shopUserId,role:'customer'},personaSession,target,mode,operationId:meta.operationId,effectId:meta.effectId,check,signal});
  const traces=await conversationRepository.getTraceEvents(sessionId,binding,meta.traceEventIds,PURPOSE);
  const graphEffect=await readGraphEffect(identityPool,meta.graphEffect);await current(check,signal);
  const proof=(mode.mode==='fixed'?readQualifiedFixedUploadSource:readQualifiedUploadSource)({binding,personaSession,row,traces,retained,graphEffect,qualifyModel});
  if(!proof)throw fail();
  const value=Object.freeze({sessionId,requestId,row,traces,graphEffect,retained,proof,qualifyModel});privateBytes.set(value,privateBytes.get(retained));return value;
 }
 function workerRequest(source){
  const bytes=privateBytes.get(source),{admission,effect}=source?.retained||{};
  if(!bytes||!admission||!effect)throw fail();
  return normalizeUploadPreviewRequest({version:1,...{operationId:previewIdentity(admission.operationId).operationId},uploadOperationId:admission.operationId,
   uploadEffectId:effect.effectId,storageKey:admission.storageKey,bindingSha256:admission.bindingSha256,uploadRequestSha256:admission.requestSha256,
   bodySha256:effect.file.bodySha256,byteCount:bytes.length,bytesBase64:bytes.toString('base64'),mode:admission.scope.mode});
 }
 async function readPreview(input,retained){
  const id=previewIdentity(retained.admission.operationId),b=input.scope;
  const rows=(await agentsPool.query(`SELECT t.* FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
   WHERE t.request_id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active' AND s.conversation_purpose=$2
   AND s.platform_launch_id=$3 AND s.platform_scenario_id=$4 AND s.platform_launch_generation=$5
   AND s.original_platform_owner_id=$6 AND s.original_platform_session_id=$7 AND s.user_id=$8 AND s.role='customer' LIMIT 2`,
  [id.requestId,PURPOSE,b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,input.persona.id])).rows;
  if(rows.length!==1||rows[0].status!=='completed')return null;
  const row=rows[0],meta=row.result_json?.taskMetadata?.polyglotPreview;
  if(!meta||meta.uploadOperationId!==retained.admission.operationId||meta.operationId!==id.operationId||meta.previewRequestId!==id.requestId)throw fail();
  const bytes=privateBytes.get(retained);const request=normalizeUploadPreviewRequest({version:1,operationId:id.operationId,uploadOperationId:retained.admission.operationId,
   uploadEffectId:retained.effect.effectId,storageKey:retained.admission.storageKey,bindingSha256:retained.admission.bindingSha256,
   uploadRequestSha256:retained.admission.requestSha256,bodySha256:retained.effect.file.bodySha256,byteCount:bytes.length,bytesBase64:bytes.toString('base64'),mode:retained.admission.scope.mode});
  const receipt=validateUploadPreviewReceipt(meta.receipt,request);
  if(meta.workerRequestSha256!==requestDigest(request))throw fail();
  const traces=await conversationRepository.getTraceEvents(row.session_id,b,meta.traceEventIds,PURPOSE);
  const graphEffect=await readGraphEffect(identityPool,meta.graphEffect);
  await assertCurrent(retained.admission);
  return Object.freeze({row,traces,graphEffect,receipt,request});
 }
 return Object.freeze({load,workerRequest,readPreview,async read(input){const retained=await stored(input);if(input.mode.mode!=='vuln')return null;
  const preview=await readPreview(input,retained);return preview?Object.freeze({...retained,preview}):null;}});
}
module.exports={createV07UploadSourceReader,previewIdentity,readGraphEffect,PURPOSE,TOOL};
