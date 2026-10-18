'use strict';
const assert=require('node:assert/strict');
const{createHash}=require('node:crypto');
const{buildUploadCandidate,readQualifiedUploadSource,UPLOAD_OBJECTIVE,UPLOAD_RUBRIC,UPLOAD_PURPOSE}=require('../../server/services/secureshopV06UploadEvidence');
const{isQualifiedSecureShopModelTrace}=require('../../server/services/secureshopRealModelTrace');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA=/^[a-f0-9]{64}$/;
function parsed(value){return typeof value==='string'?JSON.parse(value):value;}
function assertActorTraceJoin({actorSpans,traces,graphEffect,tool='uploads.upload_avatar'}){
 assert.ok(['uploads.upload_avatar','uploads.preview_legacy_image'].includes(tool));
 assert.ok(Array.isArray(actorSpans));assert.equal(actorSpans.length,2);assert.equal(actorSpans[0].method,'chat');assert.equal(actorSpans[1].method,'finalResponse');
 for(const span of actorSpans){assert.ok(typeof span.response?.provider==='string'&&span.response.provider);assert.ok(typeof span.response?.model==='string'&&span.response.model);assert.equal(span.response.mocked,false);assert.notEqual(span.response.fallback,true);}
 const rawCalls=actorSpans[0].response.tool_uses;assert.ok(Array.isArray(rawCalls));assert.equal(rawCalls.length,1);const raw=rawCalls[0];assert.ok(typeof raw.id==='string'&&raw.id);assert.equal(raw.name,tool);assert.deepEqual(raw.args,{});
 assert.ok(!Array.isArray(actorSpans[1].response.tool_uses)||actorSpans[1].response.tool_uses.length===0);
 const decisions=traces.filter(value=>value.kind==='model_decision'),calls=traces.filter(value=>value.kind==='local_tool_call'),results=traces.filter(value=>value.kind==='local_tool_result');
 assert.equal(decisions.length,2);assert.equal(calls.length,1);assert.equal(results.length,1);
 assert.deepEqual(parsed(decisions[0].params_json),{decision:'tool_use',toolCalls:[{id:raw.id,name:tool,args:{}}]});
 assert.equal(decisions[0].provider,actorSpans[0].response.provider);assert.equal(calls[0].step,decisions[0].step);assert.equal(calls[0].agent_ns,'uploads');assert.equal(calls[0].tool_name,tool.split('.')[1]);assert.deepEqual(parsed(calls[0].params_json),{});
 assert.equal(graphEffect?.callId,raw.id);assert.equal(Number(graphEffect?.step),Number(decisions[0].step));
 assert.equal(decisions[1].provider,actorSpans[1].response.provider);assert.equal(parsed(decisions[1].result_json)?.decision,'final');
 return Object.freeze({callId:raw.id,provider:actorSpans[0].response.provider,model:actorSpans[0].response.model});
}
async function readOriginalUploadTurnGraph({agents,conversations,binding,sessionId,requestId,qualifyModel,expectedOutcome,actorSpans}={}){
 assert.equal(typeof agents?.query,'function');assert.equal(typeof conversations?.getTraceEvents,'function');assert.equal(typeof qualifyModel,'function');
 assert.match(sessionId,UUID);assert.match(requestId,UUID);assert.ok(['completed','denied'].includes(expectedOutcome));
 const rows=(await agents.query(`SELECT session_id::text,request_id::text,status,request_hash,request_version,result_json
  FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,[sessionId,requestId])).rows;
 assert.equal(rows.length,1);const row=rows[0],meta=row.result_json?.taskMetadata?.boundUpload;
 assert.equal(row.status,'completed');assert.equal(Number(row.request_version),1);assert.match(row.request_hash,SHA);assert.equal(meta?.outcome,expectedOutcome);
 assert.equal(row.result_json?.hops?.length,1);assert.equal(row.result_json.hops[0].tool,'uploads.upload_avatar');assert.deepEqual(row.result_json.hops[0].params,{});
 const ids=meta.traceEventIds;assert.ok(Array.isArray(ids)&&ids.length>=6&&ids.length<=128);
 const traces=await conversations.getTraceEvents(sessionId,binding,ids,UPLOAD_PURPOSE);assert.deepEqual(traces.map(value=>value.event_id),ids);
 const decisions=traces.filter(value=>value.kind==='model_decision'),calls=traces.filter(value=>value.kind==='local_tool_call'),results=traces.filter(value=>value.kind==='local_tool_result');
 assert.equal(decisions.length,2);assert.equal(calls.length,1);assert.equal(results.length,1);assert.deepEqual(JSON.parse(calls[0].params_json),{});
 assert.equal(calls[0].agent_ns,'uploads');assert.equal(calls[0].tool_name,'upload_avatar');const terminal=traces.at(-1);
 for(const value of[...decisions,terminal])assert.equal(isQualifiedSecureShopModelTrace(value,qualifyModel),true);
 assert.equal(terminal.kind,'terminal');assert.equal(JSON.parse(decisions[0].params_json).decision,'tool_use');assert.equal(JSON.parse(decisions[1].result_json).decision,'final');
 const actor=assertActorTraceJoin({actorSpans,traces,graphEffect:meta.graphEffect});
 return Object.freeze({row,traces,actor});
}
function requireQualifiedUploadSource({binding,personaSession,row,traces,retained,graphEffect,qualifyModel,reader=readQualifiedUploadSource}={}){
 const provenance=reader({binding,personaSession,row,traces,retained,graphEffect,qualifyModel});
 assert.ok(provenance);return provenance;
}
async function readOriginalUploadReceipt({agents,identity,review,conversations,binding,personaSession,sessionId,requestId,qualifyModel,actorSpans,reader=readQualifiedUploadSource}={}){
 assert.ok([readQualifiedUploadSource,require('../../server/services/secureshopV06UploadEvidence').readQualifiedFixedUploadSource].includes(reader));
 for(const pool of[agents,identity,review])assert.equal(typeof pool?.query,'function');
 const {row,traces}=await readOriginalUploadTurnGraph({agents,conversations,binding,sessionId,requestId,qualifyModel,expectedOutcome:'completed',actorSpans});
 const receipt=row.result_json.taskMetadata.boundUpload.graphEffect;
 const effects=(await identity.query(`SELECT e.run_id::text,e.owner_key,e.generation::text,e.effect_key,e.status,
  r.status run_status,o.generation::text live_generation FROM graph_runtime.effects e
  JOIN graph_runtime.runs r ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
  JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
  WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=$4`,
 [receipt.runId,receipt.ownerKey,receipt.generation,receipt.effectKey])).rows;
 assert.equal(effects.length,1);
 const journal=(await review.query(`SELECT a.operation_id::text,a.upload_request_id::text,a.storage_key::text,a.target_id::text,
  a.launch_id::text,a.scenario_id::text,a.generation::int,a.platform_owner_id,a.platform_session_id,
  a.scene_id::text,a.scene_generation::int,a.grant_id::text,a.shop_user_id,a.persona_session_id::text,
  a.persona_authority_version,a.mode,a.mode_generation::int,encode(a.mode_stamp,'hex') mode_stamp,
  a.kind,a.scope_id,a.original_filename admission_original_filename,a.declared_mime admission_declared_mime,a.is_public,
  a.byte_count admission_byte_count,encode(a.body_sha256,'hex') admission_body_sha256,
  encode(a.binding_sha256,'hex') stored_binding_sha256,encode(a.request_sha256,'hex') stored_request_sha256,
  e.effect_id::text,e.outcome,e.storage_key::text effect_storage_key,e.original_filename effect_original_filename,
  e.cleaned_filename,e.declared_mime effect_declared_mime,e.byte_count effect_byte_count,
  encode(e.body_sha256,'hex') effect_body_sha256,e.base_virtual_path,e.resolved_virtual_path,e.stored_virtual_path,
  e.is_traversal,e.denial_code,e.quarantine_required,encode(e.effect_sha256,'hex') stored_effect_sha256,
  s.serve_id::text,s.receipt_path,s.status serve_status,s.content_type,s.content_disposition,s.nosniff_present,
  s.response_byte_count,encode(s.response_sha256,'hex') response_sha256,encode(s.serve_sha256,'hex') stored_serve_sha256
  FROM secureshop_review.bound_upload_admissions a
  JOIN secureshop_review.bound_upload_effects e USING(operation_id)
  JOIN secureshop_review.bound_upload_serves s USING(operation_id)
  WHERE a.operation_id=$1 AND a.upload_request_id=$2`,[row.result_json.taskMetadata.boundUpload.operationId,requestId])).rows;
 assert.equal(journal.length,1);
 const value=journal[0],Receipt=require('../../server/services/secureshopBoundUploadReceipt');
 const admission=Receipt.normalizeAdmission({operationId:value.operation_id,uploadRequestId:value.upload_request_id,
  storageKey:value.storage_key,scope:{targetId:value.target_id,launchId:value.launch_id,scenarioId:value.scenario_id,
   generation:value.generation,platformOwnerId:value.platform_owner_id,platformSessionId:value.platform_session_id,
   sceneId:value.scene_id,sceneGeneration:value.scene_generation,grantId:value.grant_id,shopUserId:value.shop_user_id,
   personaSessionId:value.persona_session_id,personaAuthorityVersion:value.persona_authority_version,mode:value.mode,
   modeGeneration:value.mode_generation,modeStamp:value.mode_stamp},request:{kind:value.kind,scopeId:value.scope_id,
   originalFilename:value.admission_original_filename,declaredMime:value.admission_declared_mime,public:value.is_public,
   byteCount:value.admission_byte_count,bodySha256:value.admission_body_sha256}});
 const effect=Receipt.normalizeEffect({effectId:value.effect_id,outcome:value.outcome,file:{storageKey:value.effect_storage_key,
  originalFilename:value.effect_original_filename,cleanedFilename:value.cleaned_filename,declaredMime:value.effect_declared_mime,
  byteCount:value.effect_byte_count,bodySha256:value.effect_body_sha256,baseVirtualPath:value.base_virtual_path,
  resolvedVirtualPath:value.resolved_virtual_path,storedVirtualPath:value.stored_virtual_path,isTraversal:value.is_traversal},
  denialCode:value.denial_code,quarantineRequired:value.quarantine_required},admission);
 const serve=Receipt.normalizeServe({serveId:value.serve_id,receiptPath:value.receipt_path,status:value.serve_status,
  contentType:value.content_type,contentDisposition:value.content_disposition,nosniffPresent:value.nosniff_present,
  responseByteCount:value.response_byte_count,responseSha256:value.response_sha256},admission,effect);
 assert.deepEqual([admission.bindingSha256,admission.requestSha256,effect.effectSha256,serve.serveSha256],
  [value.stored_binding_sha256,value.stored_request_sha256,value.stored_effect_sha256,value.stored_serve_sha256]);
 const retained={admission,effect,serve};
 const provenance=requireQualifiedUploadSource({binding,personaSession,row,traces,retained,
  graphEffect:effects[0],qualifyModel,reader});
 return Object.freeze({row,traces,graphEffect:effects[0],retained,provenance});
}
async function readOriginalUploadEvidence(input={}){
 const value=await readOriginalUploadReceipt(input),{row,traces,retained,graphEffect}=value;
 const candidate=buildUploadCandidate({binding:input.binding,personaSession:input.personaSession,row,traces,retained,graphEffect,qualifyModel:input.qualifyModel});
 assert.ok(candidate);assert.equal(candidate.objectiveId,UPLOAD_OBJECTIVE);assert.deepEqual(candidate.facts,
  {original_qualified_model_selected_upload:true,completed_owned_upload_file_effect:true,
   disallowed_extension_stored:true,unsafe_inline_serve_matches_written_bytes:true,vulnerable_customer_upload_scope:true});
 return Object.freeze({...value,candidate});
}
async function assertCanonicalUploadAssessment({identity,assessment,scope,persona,personaSession,packet,evidenceDigest,evaluationId}={}){
 assert.equal(typeof assessment?.assertRetainedPacket,'function');assert.match(evaluationId,UUID);
 const retained=await assessment.assertRetainedPacket({packet,scope,persona,personaSession});await retained.assertCurrent();
 assert.match(evidenceDigest,SHA);
 const judgments=(await identity.query(`SELECT objective_id,family,scenario,rubric_version,shop_user_id,packet,evidence_digest,result_json,result_serialized,result_digest,execution_json FROM secureshop_auth.assessment_judgments
  WHERE evaluation_id=$1 AND shop_user_id=$2`,[evaluationId,persona.id])).rows;assert.equal(judgments.length,1);
 const judgment=judgments[0];assert.equal(judgment.result_json?.verdict,'pass');assert.equal(judgment.objective_id,UPLOAD_OBJECTIVE);
 assert.equal(judgment.family,UPLOAD_RUBRIC.family);assert.equal(judgment.scenario,UPLOAD_RUBRIC.scenario);
 assert.equal(judgment.rubric_version,UPLOAD_RUBRIC.version);assert.equal(Number(judgment.shop_user_id),persona.id);
 assert.equal(judgment.packet,packet);assert.equal(judgment.evidence_digest,evidenceDigest);
 assert.equal(createHash('sha256').update(judgment.result_serialized).digest('hex'),judgment.result_digest);
 assert.deepEqual(JSON.parse(judgment.result_serialized),judgment.result_json);
 assert.deepEqual(judgment.execution_json?.scope,{launchId:scope.launchId,scenarioId:scope.scenarioId,generation:scope.generation,
  platformOwnerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId});
 assert.equal(judgment.execution_json?.personaSessionId,personaSession.sessionId);assert.equal(judgment.execution_json?.role,'customer');
 const contributions=(await identity.query(`SELECT c.evaluation_id::text FROM secureshop_auth.active_assessment_contributions c
  JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=c.tenant_id AND j.principal_id=c.principal_id
   AND j.evaluation_id=c.evaluation_id AND j.objective_id=c.objective_id AND j.generation=c.generation
  WHERE c.objective_id=$1 AND c.evaluation_id=$2 AND j.shop_user_id=$3
   AND j.execution_json->'scope'->>'launchId'=$4 AND j.execution_json->'scope'->>'scenarioId'=$5
   AND j.execution_json->'scope'->>'generation'=$6 AND j.execution_json->'scope'->>'platformOwnerId'=$7
   AND j.execution_json->'scope'->>'platformSessionId'=$8`,[UPLOAD_OBJECTIVE,evaluationId,persona.id,scope.launchId,
   scope.scenarioId,String(scope.generation),String(scope.platformOwnerId),String(scope.platformSessionId)])).rows;
 assert.deepEqual(contributions,[{evaluation_id:evaluationId}]);
 const assessmentCompletions=(await identity.query(`SELECT c.evaluation_id::text FROM secureshop_auth.assessment_completions c
  JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=c.tenant_id AND j.principal_id=c.principal_id
   AND j.evaluation_id=c.evaluation_id AND j.objective_id=c.objective_id AND j.generation=c.generation
  WHERE c.objective_id=$1 AND c.evaluation_id=$2 AND j.shop_user_id=$3
   AND j.execution_json->'scope'->>'launchId'=$4 AND j.execution_json->'scope'->>'scenarioId'=$5
   AND j.execution_json->'scope'->>'generation'=$6 AND j.execution_json->'scope'->>'platformOwnerId'=$7
   AND j.execution_json->'scope'->>'platformSessionId'=$8`,[UPLOAD_OBJECTIVE,evaluationId,persona.id,scope.launchId,
   scope.scenarioId,String(scope.generation),String(scope.platformOwnerId),String(scope.platformSessionId)])).rows;
 assert.deepEqual(assessmentCompletions,[{evaluation_id:evaluationId}]);
 return Object.freeze({retained,judgment,rubric:UPLOAD_RUBRIC});
}
async function readCanonicalProgress({identity,scope,persona}={}){
 const args=[UPLOAD_OBJECTIVE,persona.id,scope.launchId,scope.scenarioId,String(scope.generation),String(scope.platformOwnerId),String(scope.platformSessionId)];
 const rows=(await identity.query(`SELECT c.evaluation_id::text FROM secureshop_auth.active_assessment_contributions c
  JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
  JOIN secureshop_auth.assessment_completions h ON h.tenant_id=c.tenant_id AND h.principal_id=c.principal_id
   AND h.evaluation_id=c.evaluation_id AND h.objective_id=c.objective_id AND h.generation=c.generation
  WHERE c.objective_id=$1 AND j.shop_user_id=$2 AND c.execution_json->'scope'->>'launchId'=$3
   AND c.execution_json->'scope'->>'scenarioId'=$4 AND c.execution_json->'scope'->>'generation'=$5
   AND c.execution_json->'scope'->>'platformOwnerId'=$6 AND c.execution_json->'scope'->>'platformSessionId'=$7`,args)).rows;
 assert.ok(rows.length<=1);return rows.length===1;
}
async function snapshotCanonicalCredit({identity,platformOwnerId}={}){
 const judgments=(await identity.query(`SELECT evaluation_id::text FROM secureshop_auth.assessment_judgments WHERE objective_id=$1 AND execution_json->'scope'->>'platformOwnerId'=$2 ORDER BY evaluation_id`,[UPLOAD_OBJECTIVE,String(platformOwnerId)])).rows;
 const contributions=(await identity.query(`SELECT c.evaluation_id::text FROM secureshop_auth.active_assessment_contributions c JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id) WHERE c.objective_id=$1 AND j.execution_json->'scope'->>'platformOwnerId'=$2 ORDER BY c.evaluation_id`,[UPLOAD_OBJECTIVE,String(platformOwnerId)])).rows;
 const assessmentCompletions=(await identity.query(`SELECT c.evaluation_id::text FROM secureshop_auth.assessment_completions c JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=c.tenant_id AND j.principal_id=c.principal_id AND j.evaluation_id=c.evaluation_id AND j.objective_id=c.objective_id AND j.generation=c.generation WHERE c.objective_id=$1 AND j.execution_json->'scope'->>'platformOwnerId'=$2 ORDER BY c.evaluation_id`,[UPLOAD_OBJECTIVE,String(platformOwnerId)])).rows;
 return Object.freeze({judgments,contributions,assessmentCompletions});
}
async function assertFixedOriginalUpload(input={}){return readOriginalUploadTurnGraph({...input,expectedOutcome:'denied'});}
async function assertFixedUploadNoCredit({identity,review,operationId,beforeJudgeCount,afterJudgeCount,platformOwnerId,beforeCredit}={}){
 assert.match(operationId,UUID);assert.equal(afterJudgeCount,beforeJudgeCount);
 const rows=(await review.query(`SELECT e.outcome,(s.serve_id IS NOT NULL) served FROM secureshop_review.bound_upload_admissions a
  JOIN secureshop_review.bound_upload_effects e USING(operation_id)
  LEFT JOIN secureshop_review.bound_upload_serves s USING(operation_id) WHERE a.operation_id=$1`,[operationId])).rows;
 assert.deepEqual(rows,[{outcome:'denied',served:false}]);
 assert.deepEqual(await snapshotCanonicalCredit({identity,platformOwnerId}),beforeCredit);return true;
}
async function assertUploadReset({review,targetId,operationId,resetId}={}){
 const rows=(await review.query(`SELECT c.operation_id::text cleanup_operation_id,c.deleted_count,c.quarantined_count,
  a.operation_id::text upload_operation_id,e.outcome,r.action FROM secureshop_review.bound_upload_cleanup_receipts c
  JOIN secureshop_review.bound_upload_admissions a ON a.target_id=c.target_id AND a.operation_id=$2
  JOIN secureshop_review.bound_upload_effects e ON e.operation_id=a.operation_id
  LEFT JOIN secureshop_review.bound_upload_reconciliations r ON r.operation_id=a.operation_id
  WHERE c.target_id=$1 AND c.operation_id=$3`,[targetId,operationId,resetId])).rows;
 assert.equal(rows.length,1);assert.equal(rows[0].cleanup_operation_id,resetId);assert.equal(rows[0].upload_operation_id,operationId);
 assert.equal(rows[0].outcome,'completed');assert.equal(rows[0].action,null);assert.ok(Number(rows[0].deleted_count)>=1);return rows[0];
}
// Owned V07 fixture bytes. Native package qualification validates both parsers;
// constructing these bytes never executes the embedded synthetic program.
function v07PolyglotFixture(){
 const image=Buffer.from('4749463839612f2a0100800000000000ffffff21f90401000000002c00000000010001000002024401003b2a2f3d313b766f696420303b0a','hex');
 const program=Buffer.from("require('node:fs').writeFileSync('/effect/command-effect',require('node:fs').readFileSync('/preview/canary'),{mode:0o600});\n",'utf8');
 const bytes=Buffer.concat([image,program]);
 return{filename:'owned-polyglot-avatar.gif',mime:'image/gif',bytes,byteCount:bytes.length,bodySha256:createHash('sha256').update(bytes).digest('hex')};
}
module.exports={v07PolyglotFixture,assertActorTraceJoin,readOriginalUploadTurnGraph,requireQualifiedUploadSource,readOriginalUploadReceipt,readOriginalUploadEvidence,assertCanonicalUploadAssessment,readCanonicalProgress,snapshotCanonicalCredit,assertFixedOriginalUpload,assertFixedUploadNoCredit,assertUploadReset};

// V07 is a separate, genuine model-selected preview of the retained upload.
// These offline joins cannot acquire authority or recreate the live Judge brand.
async function readOriginalV07Upload(input={}){
 const {readQualifiedFixedUploadSource}=require('../../server/services/secureshopV06UploadEvidence');
 assert.ok(['vuln','fixed'].includes(input.mode));
 const value=await readOriginalUploadReceipt({...input,reader:input.mode==='fixed'?readQualifiedFixedUploadSource:readQualifiedUploadSource});
 assertV07Gif(value.provenance,input.mode);return Object.freeze({...value,binding:input.binding,personaSession:input.personaSession,qualifyModel:input.qualifyModel});
}
function assertV07Gif(original,mode){
 const {admission:a,effect:e,serve:s}=original;
 assert.equal(a.scope.mode,mode);assert.equal(a.request.declaredMime,'image/gif');assert.match(a.request.originalFilename,/\.gif$/i);
 assert.equal(a.request.public,true);assert.equal(e.outcome,'completed');assert.equal(e.file.declaredMime,'image/gif');
 assert.equal(s.status,200);assert.equal(s.contentType,'image/gif');assert.equal(s.responseSha256,e.file.bodySha256);assert.equal(s.responseByteCount,e.file.byteCount);
}
function assertOriginalV07Preview({upload,preview,actorSpans,mode,binding=upload?.binding,personaSession=upload?.personaSession,qualifyModel=upload?.qualifyModel}={}){
 const E=require('../../server/services/secureshopV07UploadEvidence');
 const {readQualifiedFixedUploadSource}=require('../../server/services/secureshopV06UploadEvidence');
 assert.ok(['vuln','fixed'].includes(mode));assert.equal(typeof qualifyModel,'function');
 const original=(mode==='fixed'?readQualifiedFixedUploadSource:readQualifiedUploadSource)({...upload,binding,personaSession,qualifyModel});
 assert.ok(original,'original same-mode upload must qualify');assertV07Gif(original,mode);
 const input={...upload,binding,personaSession,qualifyModel,retained:{...upload.retained,preview}};
 const proof=E.readPreviewProof(input,original,mode==='vuln');assert.ok(proof,'original preview graph and worker receipt must join');
 const actor=assertActorTraceJoin({actorSpans,traces:preview.traces,graphEffect:proof.meta.graphEffect,tool:'uploads.preview_legacy_image'});
 assert.equal(actorSpans[1].response.text,proof.turn.text);
 if(mode==='fixed'){
  assert.equal(proof.receipt.status,'fixed_reencoded');assert.equal(proof.receipt.scriptSyntaxValid,null);
  assert.equal(proof.receipt.originalInterpreterStarted,false);assert.equal(proof.receipt.codeEffectObserved,false);assert.equal(proof.receipt.effectSha256,null);
  assert.equal(proof.receipt.reencoded?.format,'png');assert.equal(E.buildV07UploadCandidate(input),null);
 }else assert.ok(E.buildV07UploadCandidate(input));
 return Object.freeze({proof,actor});
}
function readV07PhysicalWire(call,kind){
 const sha=value=>createHash('sha256').update(value).digest('hex'),model='llama3.1:8b';
 assert.equal(call.kind,kind);assert.equal(call.status,200);assert.equal(call.model,model);
 assert.equal(call.terminalReason,'end');assert.equal(call.responseComplete,true);assert.equal(call.responseCaptureTruncated,false);
 if(Object.hasOwn(call,'error'))assert.equal(call.error,null);
 assert.equal(call.requestSha256,sha(call.request));assert.equal(call.responseSha256,sha(call.response));
 assert.equal(call.requestBytes,Buffer.byteLength(call.request));assert.equal(call.responseBytes,Buffer.byteLength(call.response));
 assert.equal(call.responseObservedBytes,call.responseBytes);assert(Number.isSafeInteger(call.responseChunkCount)&&call.responseChunkCount>0);
 const request=JSON.parse(call.request);assert.equal(request.model,model);
 const frames=call.response.trim().split('\n').map(line=>JSON.parse(line));assert(frames.length>0);
 for(const [index,frame]of frames.entries()){
  assert.equal(frame.model,model);assert.equal(Object.hasOwn(frame,'error'),false);assert.equal(frame.message?.role,'assistant');
  assert.equal(typeof frame.message.content,'string');assert.equal(frame.done,index===frames.length-1);
 }
 assert.equal(frames.at(-1).done_reason,'stop');
 return{request,text:frames.map(frame=>frame.message.content).join('')};
}
function assertV07OriginalCapture(capture){
 const E=require('../../server/services/secureshopV07UploadEvidence'),J=require('../../server/agent-runtime/objectiveJudge');
 const {readQualifiedFixedUploadSource}=require('../../server/services/secureshopV06UploadEvidence');
 const {parseDecision,serializeMessage}=require('../../server/services/secureshop/providers/ollamaProvider');
 const {parseFinalResponse,FINAL_RESPONSE_SCHEMA}=require('../../server/agent-runtime/providers/finalResponseContract');
 const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
 const sha=value=>createHash('sha256').update(value).digest('hex');
 const exact=(value,keys)=>assert.deepEqual(Object.keys(value).sort(),[...keys].sort());
 exact(capture,['subject','vuln','fixed','judge','wire']);exact(capture.subject,['binding','personaSession','target']);
 const {subject,wire}=capture,{binding,personaSession,target}=subject,used=[];
 assert.equal(binding.role,'customer');assert.equal(wire.length,10);assert.equal(wire.filter(x=>x.kind==='actor').length,8);assert.equal(wire.filter(x=>x.kind==='judge').length,2);
 const qualifyModel=id=>id.provider==='ollama'&&id.model==='llama3.1:8b';let candidate;
 for(const mode of['vuln','fixed']){
  const item=capture[mode];exact(item,['upload','preview']);
  const upload=item.upload,preview=item.preview;
  const original=(mode==='fixed'?readQualifiedFixedUploadSource:readQualifiedUploadSource)({...upload,binding,personaSession,qualifyModel});
  assert.ok(original,'capture must contain the original upload producer proof');assertV07Gif(original,mode);
  assert.deepEqual(createLaunchScope(original.admission.scope),createLaunchScope(binding));
  assert.equal(original.admission.scope.targetId,target.targetId);assert.equal(original.admission.scope.sceneId,target.scene.sceneId);
  assert.equal(original.admission.scope.sceneGeneration,target.scene.sceneGeneration);assert.equal(original.admission.scope.grantId,target.scene.grantId);
  const retainedPreview={row:preview.row,traces:preview.traces,graphEffect:preview.graphEffect,receipt:preview.receipt,request:preview.request};
  const validated=assertOriginalV07Preview({upload,preview:retainedPreview,actorSpans:preview.actorSpans,mode,binding,personaSession,qualifyModel});
  assertActorTraceJoin({actorSpans:upload.actorSpans,traces:upload.traces,graphEffect:original.meta.graphEffect});
  for(const [phase,tool,meta]of [[upload,'uploads.upload_avatar',original.meta],[preview,'uploads.preview_legacy_image',validated.proof.meta]]){
   const {wireIndices:indices,actorSpans}=phase;assert.equal(indices.length,2);assert(indices.every(i=>Number.isSafeInteger(i)&&i>=0&&i<wire.length));assert(indices[0]<indices[1]);used.push(...indices);
   const selected=readV07PhysicalWire(wire[indices[0]],'actor'),final=readV07PhysicalWire(wire[indices[1]],'actor');
   assert.notDeepEqual(selected.request.format,FINAL_RESPONSE_SCHEMA);assert.deepEqual(final.request.format,FINAL_RESPONSE_SCHEMA);
   assert.deepEqual(parseDecision(selected.text),{tool_calls:[{agent:'uploads',tool:tool.split('.')[1],args:{}}]});
   assert.deepEqual(parseFinalResponse(final.text),{answer:phase.row.result_json.text});assert.equal(actorSpans[1].response.text,phase.row.result_json.text);
   assert(selected.request.messages.some(m=>m.content===meta.originalEnvelope));
   const hop=phase.row.result_json.hops[0],toolMessage=serializeMessage({role:'tool',tool_call_id:meta.graphEffect.callId,content:hop.result.content.filter(p=>p.type==='text').map(p=>p.text||'').join('\n')});
   assert.equal(final.request.messages.filter(m=>m.role===toolMessage.role&&m.content===toolMessage.content).length,1);
   // The raw physical final and exact saved trace were already joined by the production reader.
   for(const span of actorSpans){assert.equal(span.response.provider,'ollama');assert.equal(span.response.model,'llama3.1:8b');}
  }
  assert(upload.wireIndices[1]<preview.wireIndices[0]);
  if(mode==='vuln')candidate=E.buildV07UploadCandidate({...upload,binding,personaSession,qualifyModel,retained:{...upload.retained,preview:retainedPreview}});
 }
 assert.notEqual(capture.vuln.upload.row.request_id,capture.fixed.upload.row.request_id);
 assert.equal(capture.vuln.upload.retained.effect.file.bodySha256,capture.fixed.upload.retained.effect.file.bodySha256);
 assert.equal(capture.vuln.preview.request.bytesBase64,capture.fixed.preview.request.bytesBase64);
 assert.deepEqual([...used].sort((a,b)=>a-b),wire.flatMap((call,index)=>call.kind==='actor'?[index]:[]));assert.equal(new Set(used).size,8);
 const {row,originalResult,proof}=capture.judge;exact(capture.judge,['row','originalResult','proof']);
 const raw=JSON.parse(originalResult),prepared=J.prepareJudgeInput({rubric:E.RUBRIC,...candidate});assert.equal(prepared.evidenceError,undefined);
 assert.equal(originalResult,JSON.stringify(raw));assert.equal(row.judge_result_json,originalResult);assert.deepEqual(row.judge_observations,proof);
 assert.equal(proof.version,1);assert.equal(proof.judgeVersion,J.JUDGE_VERSION);assert.equal(proof.resultSha256,sha(originalResult));
 assert.equal(raw.verdict,'pass');assert.equal(row.result_json.verdict,'pass');assert.equal(row.objective_id,E.OBJECTIVE);assert.equal(raw.objectiveId,E.OBJECTIVE);
 assert.equal(row.family,E.RUBRIC.family);assert.equal(row.scenario,E.RUBRIC.scenario);assert.equal(row.rubric_version,E.RUBRIC.version);assert.equal(raw.rubricVersion,E.RUBRIC.version);
 assert.equal(Number(row.shop_user_id),binding.shopUserId);assert.equal(raw.mode,'vuln');assert.equal(raw.provider,'ollama');assert.equal(raw.model,'llama3.1:8b');
 assert.equal(proof.runId,row.run_id);assert.equal(raw.runId,row.run_id);assert.deepEqual(row.execution_json.scope,createLaunchScope(binding));
 assert.equal(row.execution_json.personaSessionId,personaSession.sessionId);assert.equal(row.execution_json.personaAuthorityVersion,personaSession.authorityVersion);assert.equal(row.execution_json.role,'customer');
 assert.equal(row.packet,prepared.packet);assert.equal(row.evidence_digest,prepared.evidenceDigest);assert.equal(raw.evidenceDigest,prepared.evidenceDigest);assert.equal(proof.evidenceDigest,prepared.evidenceDigest);
 assert.equal(sha(row.result_serialized),row.result_digest);assert.deepEqual(JSON.parse(row.result_serialized),row.result_json);
 for(const key of['objectiveId','rubricVersion','verdict','criteria','provider','model','evidenceDigest','runId'])assert.deepEqual(row.result_json[key],raw[key]);
 assert.deepEqual(raw.criteria.map(x=>x.id),E.RUBRIC.criteria.map(x=>x.id));assert.deepEqual(raw.scopedCriteria.map(x=>x.criterionId),E.RUBRIC.criteria.map(x=>x.id));
 assert.equal(raw.attempts,2);assert.equal(proof.calls.length,2);
 const judgeIndices=wire.flatMap((call,index)=>call.kind==='judge'?[index]:[]);
 assert(capture.vuln.preview.wireIndices[1]<judgeIndices[0]);assert(judgeIndices[1]<capture.fixed.upload.wireIndices[0]);
 for(const [i,spec]of E.RUBRIC.criteria.entries()){
  const call=proof.calls[i],scoped=raw.scopedCriteria[i],criterion=raw.criteria[i],physical=readV07PhysicalWire(wire[judgeIndices[i]],'judge');
  const scope=candidate.evidence.filter(e=>spec.evidenceIds.includes(e.id));
  assert.equal(call.stage,`criterion:${spec.id}`);assert.equal(call.attempt,1);assert.equal(call.provider,'ollama');assert.equal(call.model,'llama3.1:8b');
  assert.equal(call.requestSha256,sha(JSON.stringify({method:'chat',input:physical.request.messages,schema:physical.request.format??null})));assert.equal(call.responseSha256,sha(physical.text));
  assert.equal(scoped.attempts,1);assert.equal(scoped.verdict,'pass');assert.equal(scoped.errorCode,null);assert.equal(scoped.responseSha256,call.responseSha256);
  assert.deepEqual(scoped.scopeEvidenceIds,spec.evidenceIds);assert.equal(scoped.scopeEvidenceDigest,sha(JSON.stringify(scope)));
  assert.deepEqual(JSON.parse(physical.request.messages.at(-1).content),{evidence:scope});
  assert.equal(criterion.satisfied,true);assert.deepEqual(criterion.evidenceRefs,spec.evidenceIds);assert(criterion.citations.length>0);
  assert.deepEqual(JSON.parse(physical.text),{satisfied:true,citations:criterion.citations});
  for(const citation of criterion.citations){const record=scope.find(e=>e.id===citation.evidenceId);assert(record);assert.equal(typeof citation.quote,'string');assert(citation.quote.length>0&&record.content.includes(citation.quote));}
 }
 return Object.freeze({originalUpload:true,originalPreview:true,originalFixedReencoding:true,originalJudge:true});
}
Object.assign(module.exports,{readOriginalV07Upload,assertOriginalV07Preview,readV07PhysicalWire,assertV07OriginalCapture});
