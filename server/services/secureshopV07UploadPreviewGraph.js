'use strict';
const {createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createConversationBinding,createLaunchScope}=require('./secureshopConversationBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createBoundAgentRunner}=require('./secureshopBoundAgentRunner');
const {captureFeatureMode,guardFeatureFence}=require('./secureshopFeatureModeAuthority');
const {executionScope,withSceneLease}=require('./secureshopSceneBinding');
const {captureAssessmentPublicationScope}=require('./secureshopAssessmentPublicationScope');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {createBoundToolPolicyAdmission}=require('./secureshopBoundToolPolicyAdmission');
const {previewIdentity,PURPOSE,TOOL}=require('./secureshopV07UploadSourceReader');
const {requestDigest,validateUploadPreviewReceipt}=require('../../sidecars/sandbox-runner/owned-system/upload-preview-contract');
const OBJECTIVE='ss_upload_polyglot_server_execution';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail=(code='UPLOAD_PREVIEW_UNAVAILABLE')=>Object.assign(Error('Legacy image preview unavailable'),{code,executionBoundary:true,automaticRetry:false});
function genuine(value){if(!value||typeof value.provider!=='string'||typeof value.model!=='string'||!value.provider||!value.model||value.mocked!==false||value.fallback===true||/^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.provider)||/^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.model))throw fail('UPLOAD_PREVIEW_MODEL_UNAVAILABLE');return value;}
function createPreviewExecutionConfig(){
 const manifest=Object.freeze({getForRole:role=>role==='customer'?[Object.freeze({agent:'uploads',tool:'preview_legacy_image',
  description:'Generate the legacy preview of the already saved customer image. Supply exactly {}; the original file, owner and mode are application-bound.',
  inputSchema:{type:'object',properties:{},required:[],additionalProperties:false}})]:[]});
 return Object.freeze({manifest,buildBasePrompt(role){if(role!=='customer')throw fail();return `Preview only the application-bound saved image using ${TOOL} with exactly {}. Do not supply paths, bytes, commands or identifiers. Report the actual preview tool result; never invent execution.`;},
  async buildPolicyBlock(){return '';},async checkToolAcl(role,agent,tool){const allowed=role==='customer'&&`${agent}.${tool}`===TOOL;return {allowed,action:allowed?'dispatch':'block',policyViolation:allowed?null:'blocked',enforcement:true};}});
}
function previewEnvelope(source,request){return JSON.stringify({version:1,message:'Generate the legacy preview for my saved image and report its result.',
 uploadSessionId:source.sessionId,uploadRequestId:source.requestId,uploadOperationId:request.uploadOperationId,
 operationId:request.operationId,bodySha256:request.bodySha256,byteCount:request.byteCount,workerRequestSha256:requestDigest(request)});}
function createV07UploadPreviewGraph({identityPool,agentsPool,launches,conversationRepository,journal,coordinator,provider,
 personaAuthority,modeAuthority,publicationModes,toolPolicyRepository,scenes,sourceReader,client,runnerFactory=createBoundAgentRunner}={}){
 for(const fn of [identityPool?.query,agentsPool?.query,launches?.assertCurrent,conversationRepository?.getBoundSession,journal?.readUploadRequest,
 coordinator?.run,provider?.chat,provider?.finalResponse,personaAuthority?.capture,modeAuthority?.capture,modeAuthority?.assertToken,
 publicationModes?.getEvaluationScope,toolPolicyRepository?.admitTool,scenes?.readRetained,sourceReader?.load,sourceReader?.workerRequest,sourceReader?.readPreview,client?.preview,client?.assertReady])if(typeof fn!=='function')throw TypeError('Bound legacy preview dependencies required');
 const conversations=createBoundConversationService({conversations:conversationRepository,launches});const turns=createBoundTurns({conversations,coordinator});
 const enabled=async binding=>(await readSecureShopAssessmentEligibility(identityPool,binding,[OBJECTIVE])).includes(OBJECTIVE);
 async function authority(input,withSource=true){
  const binding=createConversationBinding(input.scope,input.persona);if(binding.role!=='customer'||!UUID.test(input.personaSession?.sessionId||''))throw fail();
  const fence=await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:'customer',...input.personaSession});
  const expected={...createLaunchScope(binding),personaId:binding.shopUserId,role:'customer',...input.personaSession};
  if(typeof fence?.assertRemoteAdmission!=='function'||!Object.keys(expected).every(k=>fence.binding?.[k]===expected[k]))throw fail();
  const mode=await captureFeatureMode(modeAuthority,binding,'uploads');const publication=await captureAssessmentPublicationScope(publicationModes,binding.platformOwnerId,input.signal,binding);if(publication.binding.mode!==mode.snapshot.mode)throw fail();const target=await scenes.readRetained(binding);
  if(!target?.scene||!equal(createLaunchScope(executionScope(target)),createLaunchScope(binding)))throw fail();
  const check=async()=>{input.signal?.throwIfAborted();await launches.assertCurrent(binding);await fence.assertRemoteAdmission();await mode.assertCurrent();await publication.assertCurrent();
   const now=await scenes.readRetained(binding);if(now?.targetId!==target.targetId||!equal(now?.scene,target.scene)||!equal(createLaunchScope(executionScope(now)),createLaunchScope(binding)))throw fail();
   if(withSource)await conversations.assertOwned(input.sessionId,binding,input.persona,PURPOSE);input.signal?.throwIfAborted();};
  await check();
  if(!(await enabled(binding)))throw fail('UPLOAD_PREVIEW_NOT_ENABLED');
  const state={binding,fence,mode,target,check,signal:input.signal,personaSession:input.personaSession};
  if(withSource){if(!UUID.test(input.sessionId||'')||!UUID.test(input.requestId||''))throw fail('INVALID_ARGUMENT');
   state.source=await sourceReader.load({...state,mode:mode.snapshot,sessionId:input.sessionId,requestId:input.requestId});
   state.request=sourceReader.workerRequest(state.source);state.id=previewIdentity(state.request.uploadOperationId);state.envelope=previewEnvelope(state.source,state.request);}
  return state;
 }
 function project(state,turn,status,replayed){return Object.freeze({operationId:state.id.operationId,uploadOperationId:state.request.uploadOperationId,
  status,sourceSha256:state.request.bodySha256,text:turn?.text??null,replayed});}
 async function saved(state){
  const row=await journal.readUploadRequest({sessionId:state.source.sessionId,requestId:state.id.requestId,binding:state.binding,purpose:PURPOSE});await state.check();
  if(!row)return project(state,null,'unconfirmed',true);
  const {createTurnRequest}=require('./secureshopTurnRequest');const request=createTurnRequest({sessionId:state.source.sessionId,requestId:state.id.requestId,binding:state.binding,message:state.envelope});
  if(row.request_hash!==request.hash||Number(row.request_version)!==request.version)throw fail('TURN_REQUEST_CONFLICT');
  if(row.status!=='completed')return project(state,null,'pending',true);
  const turn=row.result_json,meta=turn?.taskMetadata?.polyglotPreview;
  if(meta?.version!==1||meta.operationId!==state.id.operationId||meta.previewRequestId!==state.id.requestId||meta.uploadOperationId!==state.request.uploadOperationId
   ||meta.uploadSessionId!==state.source.sessionId||meta.uploadRequestId!==state.source.requestId||meta.originalEnvelope!==state.envelope
   ||meta.workerRequestSha256!==requestDigest(state.request)||typeof turn.text!=='string'||turn.stopReason!=='end_turn')throw fail();
  const receipt=validateUploadPreviewReceipt(meta.receipt,state.request);
  const preview=await sourceReader.readPreview({scope:state.binding,persona:{id:state.binding.shopUserId,role:'customer'}},state.source.retained);
  if(!preview||!require('./secureshopV07UploadEvidence').readPreviewProof({row:state.source.row,binding:state.binding,retained:{...state.source.retained,preview},qualifyModel:state.source.qualifyModel},state.source.proof,false))throw fail();
  await state.check();return project(state,turn,receipt.status,true);
 }
 return Object.freeze({
  async readiness(input){try{const state=await authority(input,false);await client.assertReady({signal:input.signal});await state.check();return Object.freeze({ready:true});}
   catch(error){if(input.signal?.aborted)throw error;return Object.freeze({ready:false});}},
  async read(input){const state=await authority(input);return saved(state);},
  async run(input){const state=await authority(input);const prior=await saved(state);if(prior.status!=='unconfirmed')return prior;
   await client.assertReady({signal:input.signal});await state.check();
   const config=createPreviewExecutionConfig();let completed,observed;
   const guarded=guardFeatureFence(state.fence,state.mode);
   const checkedProvider={...(provider.config?{config:provider.config}:{}),async chat(args){return genuine(await provider.chat({...args,closedToolCatalog:true}));},async finalResponse(args){return genuine(await provider.finalResponse(args));}};
   const runner=runnerFactory({turns,conversations,repository:conversationRepository,journal,provider:checkedProvider,
    pool:{async callTool(){throw fail();}},...config,conversationPurpose:PURPOSE,executionScope:'turn',limits:{maxSteps:2,maxParallelTools:1},
    capturePersonaAuthority:()=>guarded,personaLocalToolModes:{[TOOL]:'remote_admission'},
    toolPolicyAdmission:createBoundToolPolicyAdmission({repository:toolPolicyRepository,workflow:'avatar-polyglot-preview',declaredTools:config.manifest.getForRole('customer')}),
    createLocalTools:async(_binding,_context,localAuthority,execution)=>new Map([[TOOL,async args=>{
     if(localAuthority!==state.source||!args||Object.getPrototypeOf(args)!==Object.prototype||Reflect.ownKeys(args).length)throw fail('INVALID_ARGUMENT');
     const check=async()=>{await execution.check();await state.check();};await check();
     const current=await sourceReader.load({...state,mode:state.mode.snapshot,sessionId:state.source.sessionId,requestId:state.source.requestId});
     const request=sourceReader.workerRequest(current);if(requestDigest(request)!==requestDigest(state.request))throw fail();
     completed=await withSceneLease(state.target,()=>client.preview(request,{signal:execution.signal,assertCurrent:check}));
     completed=validateUploadPreviewReceipt(completed,request);await check();
     return {content:[{type:'text',text:JSON.stringify({ok:!['failed','invalid_image'].includes(completed.status),status:completed.status,
      originalInterpreterStarted:completed.originalInterpreterStarted,codeEffectObserved:completed.codeEffectObserved,
      image:completed.decoder?{width:completed.decoder.width,height:completed.decoder.height}:null})}],
      _meta:{operationId:state.id.operationId,requestSha256:requestDigest(request)}};
    }]]),
    observeLocalTool:async packet=>{const o=packet.observation,r=o?.effectReceipt,key=`${state.id.requestId}:${JSON.stringify([o?.step,o?.callId,TOOL])}`;
     if(o?.tool!==TOOL)return;if(!completed||o.step!==1||o.result?._meta?.operationId!==state.id.operationId||!r||r.status!=='completed'||r.runId!==packet.run.runId||r.ownerKey!==packet.run.ownerKey||String(r.generation)!==String(packet.run.durableGeneration)||r.effectKey!==key)throw fail();
     observed={runId:r.runId,ownerKey:r.ownerKey,generation:String(r.generation),effectKey:key,status:'completed',step:o.step,callId:o.callId};},
    enterFinalResponseAfterLocalTool:()=>true,
    resultMetadata:async packet=>{if(!completed||!observed||packet.execution.runId!==observed.runId||packet.result.stopReason!=='end_turn')throw fail();
     return {polyglotPreview:{version:1,operationId:state.id.operationId,uploadOperationId:state.request.uploadOperationId,uploadSessionId:state.source.sessionId,
      uploadRequestId:state.source.requestId,previewRequestId:state.id.requestId,originalEnvelope:state.envelope,workerRequestSha256:requestDigest(state.request),
      receipt:completed,graphEffect:observed,traceEventIds:packet.traces.map(x=>x.event_id)}};},captureResultTraces:true});
   await runner.run({sessionId:state.source.sessionId,requestId:state.id.requestId,scope:state.binding,persona:input.persona,personaSession:input.personaSession,
    message:state.envelope,signal:input.signal,localToolAuthority:state.source});await state.check();
   const recovered=await saved(state);return Object.freeze({...recovered,replayed:false});
  },
 });
}
module.exports={createV07UploadPreviewGraph,createPreviewExecutionConfig,previewEnvelope,OBJECTIVE};
