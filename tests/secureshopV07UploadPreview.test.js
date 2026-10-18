'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {fixture:uploadFixture}=require('./secureshopV06UploadCanonicalAssessment.test');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createV07UploadSourceReader,previewIdentity,TOOL}=require('../server/services/secureshopV07UploadSourceReader');
const {createV07UploadPreviewGraph,OBJECTIVE}=require('../server/services/secureshopV07UploadPreviewGraph');
const {buildV07UploadCandidate,RUBRIC}=require('../server/services/secureshopV07UploadEvidence');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {REGISTRY_SHA256}=require('../server/services/secureshopBoundAclRegistry');
const {ISOLATION,requestDigest}=require('../sidecars/sandbox-runner/owned-system/upload-preview-contract');
const hash=x=>createHash('sha256').update(x).digest('hex');
// This is controlled producer compatibility, never actual model or Node execution proof.
async function fixture(mode='vuln'){
 const bytes=Buffer.from('4749463839612f2a0100800000000000ffffff21f90401000000002c00000000010001000002024401003b2a2f3d313b766f696420303b0a','hex');
 const f=await uploadFixture({initialMode:mode,attachment:{bytes,filename:'avatar.gif',mime:'image/gif',public:true}}),d=f.dependencies;
 const rows=new Map(),effects=new Map(),previewId=previewIdentity(f.retained().admission.operationId);let calls=0,actors=0,checks=0;
 const journal={...d.journal,async readUploadRequest(input){return input.requestId===f.requestId?f.sourceRow():rows.get(input.requestId)||null;},
  async claim(input){const prior=rows.get(input.requestId);if(prior)return {status:prior.status,result:prior.result_json};const r=createTurnRequest(input);rows.set(input.requestId,{session_id:input.sessionId,request_id:input.requestId,request_hash:r.hash,request_version:r.version,status:'started',result_json:null});return {status:'claimed',claimId:randomUUID()};},
  async complete(input){Object.assign(rows.get(input.requestId),{status:'completed',result_json:structuredClone(input.result)});},async markUncertain(input){const row=rows.get(input.requestId);if(row&&row.status!=='completed')row.status='uncertain';}};
 const identityPool={async query(sql,args){if(sql.includes('workshop_platform.objectives'))return{rows:[{objective_id:OBJECTIVE}]};if(sql.includes('FROM graph_runtime.effects')&&effects.has(args[0]))return{rows:[effects.get(args[0])]};return d.identityPool.query(sql,args);}};
 const agentsPool={async query(){return{rows:[...rows.values()]};}};
 const sourceReader=createV07UploadSourceReader({identityPool,agentsPool,journal,conversationRepository:d.conversationRepository,qualifyModel:()=>true,
  assets:{async lookup(){const r=f.retained();return{...r,canonicalServe:r.serve};}},assertCurrent:async()=>{checks++;await d.check();},read:async()=>Buffer.from(bytes)});
 const coordinator={async run(sessionId,options,work){const runId=randomUUID(),ownerKey=JSON.stringify(['SecureShopBoundConversation',sessionId]);return work({runId,ownerKey,generation:'0',durableGeneration:'0',check:d.check,
  async effectWithReceipt(key,fn){const effectKey=`${options.idempotencyKey}:${key}`,value=await fn();effects.set(runId,{run_id:runId,owner_key:ownerKey,generation:'0',effect_key:effectKey,status:'completed',run_status:'completed',live_generation:'0'});return {value,receipt:{version:1,runId,ownerKey,generation:'0',effectKey,status:'completed'}};}});}};
 const client={async assertReady(){},async preview(r,{assertCurrent}){calls++;await assertCurrent();return receipt(r);}};
 const graph=createV07UploadPreviewGraph({identityPool,agentsPool,journal,launches:{assertCurrent:d.check},conversationRepository:d.conversationRepository,
  coordinator,provider:{async chat(){actors++;return{provider:'controlled-original',model:'controlled-original',mocked:false,stop_reason:'tool_use',tool_uses:[{id:'preview-call',name:TOOL,args:{}}]};},async finalResponse(){actors++;return{provider:'controlled-original',model:'controlled-original',mocked:false,stop_reason:'end_turn',text:'The legacy preview completed.',responseMode:'structured_final'};}},
  personaAuthority:d.personaAuthority,modeAuthority:d.modeAuthority,publicationModes:{getEvaluationScope:async()=>({mode,generation:2,modeStamp:'a'.repeat(64)})},scenes:{readRetained:async()=>d.target},sourceReader,client,
  toolPolicyRepository:{async admitTool(input){return{admissionId:randomUUID(),runId:input.runId,invocationId:input.invocationId,toolKey:TOOL,policyVersion:'1',registrySha256:REGISTRY_SHA256,enforcement:true,allowed:true,action:'dispatch',policyViolation:null};}}});
 const input={scope:f.scope,persona:f.persona,personaSession:f.personaSession,sessionId:f.sessionId,requestId:f.requestId};
 return {f,d,graph,input,rows,effects,sourceReader,previewId,identityPool,counts:()=>({calls,actors,checks}),async evidence(){const retained=await sourceReader.read({scope:d.binding,persona:f.persona,personaSession:f.personaSession,target:d.target,mode:(await d.modeAuthority.capture()).snapshot,operationId:f.retained().admission.operationId,effectId:f.retained().effect.effectId});return{binding:d.binding,personaSession:f.personaSession,row:f.sourceRow(),traces:f.sourceRow().result_json.taskMetadata.boundUpload.traceEventIds.map(id=>f.trace.find(t=>t.event_id===id)),graphEffect:f.graphEffect,retained,qualifyModel:()=>true};}};
}
function receipt(r){const fixed=r.mode==='fixed';return {version:1,operationId:r.operationId,uploadOperationId:r.uploadOperationId,uploadEffectId:r.uploadEffectId,storageKey:r.storageKey,requestSha256:requestDigest(r),bindingSha256:r.bindingSha256,bodySha256:r.bodySha256,mode:r.mode,isolation:ISOLATION,runtime:{nodeVersion:'v26.10.0',platform:'linux',arch:'arm64'},decoder:{sharpVersion:'0.35.4',vipsVersion:'8.18.0',logicalWidth:10799,logicalHeight:1,width:1,height:1,pages:1,rawSha256:hash(Buffer.alloc(4)),rawByteCount:4},status:fixed?'fixed_reencoded':'executed',scriptSyntaxValid:fixed?null:true,originalInterpreterStarted:!fixed,reencoded:fixed?{format:'png',bodySha256:hash('controlled png'),byteCount:91}:null,exitCode:fixed?null:0,timedOut:false,truncated:false,drained:true,workerAttested:true,codeEffectObserved:!fixed,effectSha256:fixed?null:hash('controlled canary')};}
test('V07 actual upload and preview graph producers join exact source, model selections, receipt, packet and GET without replay',async()=>{
 const f=await fixture();assert.deepEqual(await f.graph.read(f.input),{operationId:f.previewId.operationId,uploadOperationId:f.f.retained().admission.operationId,status:'unconfirmed',sourceSha256:f.f.retained().effect.file.bodySha256,text:null,replayed:true});
 const out=await f.graph.run(f.input);assert.equal(out.status,'executed');assert.equal(out.replayed,false);assert.deepEqual(f.counts().actors,2);assert.equal(f.counts().calls,1);
 const saved=await f.graph.read(f.input);assert.deepEqual(saved,{...out,replayed:true});assert.deepEqual(await f.graph.run(f.input),saved);assert.equal(f.counts().calls,1);assert.equal(f.counts().actors,2);
 const input=await f.evidence(),candidate=buildV07UploadCandidate(input);assert.ok(candidate);const prepared=prepareJudgeInput({rubric:RUBRIC,...candidate});assert.equal(prepared.evidenceError,undefined);assert.ok(Buffer.byteLength(prepared.packet)<24000);
 for(const mutate of [x=>x.retained.preview.receipt.effectSha256='f'.repeat(64),x=>x.retained.preview.row.result_json.text='substituted',x=>x.retained.preview.row.result_json.hops[0].params={path:'/unowned'},x=>x.retained.preview.traces.find(t=>t.kind==='model_decision').provider='mock',x=>x.retained.preview.graphEffect.status='pending',x=>x.retained.preview.request.bytesBase64=Buffer.from('other').toString('base64')]){const copy=structuredClone({...input,qualifyModel:undefined});copy.qualifyModel=()=>true;mutate(copy);assert.equal(buildV07UploadCandidate(copy),null);}
 const before=f.counts();f.f.revoke();await assert.rejects(f.graph.read(f.input));assert.equal(f.counts().calls,before.calls);assert.equal(f.counts().actors,before.actors);
});
test('V07 pending/uncertain preview is GET-only and changed saved receipt cannot replay effects',async()=>{
 const f=await fixture();await f.graph.run(f.input);const row=f.rows.get(f.previewId.requestId);row.status='uncertain';assert.equal((await f.graph.run(f.input)).status,'pending');assert.equal(f.counts().calls,1);row.status='completed';row.result_json.taskMetadata.polyglotPreview.receipt.bodySha256='0'.repeat(64);await assert.rejects(f.graph.read(f.input));assert.equal(f.counts().calls,1);
});
module.exports={fixture,receipt};

test('V07 fixed graph retains same-byte decode/reencode receipt without original interpretation or eligible evidence',async()=>{
 const f=await fixture('fixed');const out=await f.graph.run(f.input);assert.equal(out.status,'fixed_reencoded');assert.equal(f.counts().actors,2);assert.equal(f.counts().calls,1);
 const r=f.rows.get(f.previewId.requestId).result_json.taskMetadata.polyglotPreview.receipt;assert.equal(r.originalInterpreterStarted,false);assert.equal(r.scriptSyntaxValid,null);assert.equal(r.effectSha256,null);
 assert.deepEqual(await f.graph.read(f.input),{...out,replayed:true});assert.equal(buildV07UploadCandidate(await f.evidence()),null);
});
test('V07 same original producers enter canonical independent Judge and saved failure without source replay',async()=>{
 const f=await fixture();await f.graph.run(f.input);const before=f.counts();
 const {createV06UploadAssessment}=require('../server/services/secureshopV06UploadAssessment');
 const {evidenceContract}=require('../server/services/secureshopV07UploadEvidence');
 const service=createV06UploadAssessment({...f.f.assessmentDependencies,identityPool:f.identityPool,sourceReader:f.sourceReader,evidenceContract});
 const result=await service.runAttempt(f.input);assert.equal(result.completed,false);assert.equal(result.judgment.verdict,'fail');assert.equal(f.f.counts().judgeCalls,1);
 const saved=await service.readOutcome(f.input);assert.equal(saved.judgment.verdict,'fail');assert.equal(saved.replayed,true);assert.equal(f.f.counts().judgeCalls,1);assert.equal(f.counts().calls,before.calls);assert.equal(f.counts().actors,before.actors);
 f.f.assessmentRow().status='uncertain';assert.deepEqual(await service.readOutcome(f.input),{completed:false,status:'pending',modelEvaluated:false});assert.equal(f.f.counts().judgeCalls,1);
 f.f.setMode('fixed');assert.deepEqual(await service.readOutcome(f.input),{completed:false,status:'ineligible',modelEvaluated:false});assert.equal(f.f.counts().judgeCalls,1);
});
test('V07 uses existing citation-only scoped semantics: both independent criteria required, false preserved and foreign/source-only citations rejected',async()=>{
 const f=await fixture();await f.graph.run(f.input);const candidate=buildV07UploadCandidate(await f.evidence());
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 for(const [falseId,badQuote,expected] of [[null,false,'pass'],['saved_polyglot_preview_selected',false,'fail'],['polyglot_server_code_executed',false,'fail'],[null,true,'unavailable']]){
  const calls=[];const judge=createObjectiveJudge({model:{async chat(messages){const instruction=messages[0].content,record=JSON.parse(messages[1].content).evidence[0];calls.push({instruction,record});
   assert.doesNotMatch(instruction,/authorized task,? (?:the )?source instruction/);assert.match(instruction,/Return ONLY JSON with satisfied and citations/);
   const criterion=record.id==='preview_decision'?'saved_polyglot_preview_selected':'polyglot_server_code_executed',satisfied=criterion!==falseId;
   return{provider:'controlled',model:'v07-protocol-control',mocked:false,response:JSON.stringify({satisfied,citations:satisfied?[{evidenceId:badQuote?'upload_request':record.id,quote:record.content}]:[]})};
  }}});const result=await judge({rubric:RUBRIC,...candidate});assert.equal(result.verdict,expected);if(expected==='pass')assert.equal(calls.length,2);
 }
});
