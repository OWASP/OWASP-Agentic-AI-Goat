'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const evidence=require('../server/services/secureshopMailAgentReadEvidence');
function fixture(){
 const f=require('./secureshopMailAgentReadOriginalReader.test').fixture();
 f.traces.forEach(row=>row.ts=new Date('2026-10-15T12:00:00.000Z'));
 const binding=createConversationBinding(f.input.scope,f.input.persona);
 const mailExecution={version:1,featureId:'mail',policyVersion:'owned-mail-recipient-header-and-html-v1',mode:'vuln',generation:0,modeStamp:'a'.repeat(64),scope:f.input.scope};
 const assistantExecution={...mailExecution,featureId:'merchant_assistant',policyVersion:'owned-merchant-read-and-confirmation-v1'};
 const raw={sessionId:f.input.sessionId,requestId:f.input.requestId,envelope:f.envelope,
  mail:f.packet,origin:f.turn.result_json.taskMetadata.roleChat.mailOrigin,text:f.turn.result_json.text,
  turn:f.turn,traces:f.traces,run:f.run,effect:f.effect};
 const options={binding,personaSession:f.input.personaSession,mailExecution,assistantExecution};
 raw.turn.result_json.taskMetadata.roleChat.mailReadExecution=structuredClone({assistant:assistantExecution,mail:mailExecution});
 const source=evidence.projectMailAgentReadSource(raw,options);
 return {raw,source,options,reader:f,input:{...options,sessionId:f.input.sessionId,requestId:f.input.requestId,qualifyModel:()=>true}};
}
module.exports={fixture};
if(require.main===module){
 test('V11 native Date rows project explicitly and bounded observation is source-derived',()=>{
  const f=fixture(),candidate=evidence.buildMailAgentReadCandidate({source:f.source,qualifyModel:()=>true});
  assert.ok(candidate);assert.equal(f.source.traces[0].ts,'2026-10-15T12:00:00.000Z');
  assert.ok(f.raw.traces[0].ts instanceof Date);assert.equal(candidate.evidence.length,1);
  assert.equal(f.source.traces[2].result_json,undefined);
  assert.equal(f.source.traces[2].result_sha256.length,64);
  assert.deepEqual(candidate.evidence[0].content.observation,{
   version:1,selectedTool:'merchant.mail_detail',callerShopUserId:f.source.binding.shopUserId,
   recipientShopUserId:f.source.mail.recipient.id,readOperationId:f.source.mail.readOperationId,
   messageId:f.source.mail.messageId,receiptSha256:f.source.mail.receiptSha256,
   observedBodyExcerpt:f.source.mail.message.bodyMarkdown});
  assert.equal(candidate.evidence[0].content.version,3);
  assert.equal(evidence.RUBRIC.mailAgentReadCitationContract,'body-excerpt-v1');
 });
 for(const [label,change] of [
  ['same mailbox',s=>s.mail.recipient.id=s.binding.shopUserId],
  ['empty body',s=>{s.mail.message.bodyMarkdown='';s.mail.message.bodyHtml='';}],
  ['manual-only provenance',s=>s.traces=[]],['fixed mail',s=>s.mailExecution.mode='fixed'],
  ['fixed assistant',s=>s.assistantExecution.mode='fixed'],['changed body',s=>s.mail.message.bodyMarkdown='changed'],
  ['unqualified model',s=>s.traces[0].provider='mock'],['stale effect',s=>s.effect.generation='77'],
  ['invalid timestamp',s=>s.traces[0].ts='invalid'],['wrong original hash',s=>s.turn.requestHash='0'.repeat(64)]])
 test('V11 evidence rejects '+label,()=>{const f=fixture();change(f.source);assert.equal(evidence.buildMailAgentReadCandidate({source:f.source,qualifyModel:()=>true}),null);});
 test('V11 bounded observation is an exact source substring with HTML fallback and intact Unicode',()=>{
  const f=fixture(),prefix='🙂'.repeat(500);f.source.mail.message.bodyMarkdown='';
  f.source.mail.message.bodyHtml=`  ${prefix}<p>tail</p>  `;
  const observation=evidence.projectMailAgentReadObservation(f.source);
  assert.ok(Buffer.byteLength(observation.observedBodyExcerpt)<=800);
  assert.ok(observation.observedBodyExcerpt.length<=800);
  assert.ok(f.source.mail.message.bodyHtml.includes(observation.observedBodyExcerpt));
  assert.equal(observation.observedBodyExcerpt.isWellFormed(),true);
 });
 test('V11 invalid native Date is rejected before canonical JSON rather than serialized to null',()=>{
  const f=fixture();f.raw.traces[0].ts=new Date(NaN);assert.throws(()=>evidence.projectMailAgentReadSource(f.raw,f.options));
 });
 test('V11 independent Judge false is preserved, positive must cite actual body, no structural pass',async()=>{
  const f=fixture(),execution={runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
  const candidate=evidence.buildMailAgentReadCandidate({source:f.source,qualifyModel:()=>true,execution});assert.ok(candidate);
  let calls=0,result={verdict:'fail',criteria:[]};
  const guard=evidence.createMailAgentReadJudgeGuard(async()=>{calls++;return result;},()=>true);
  const input={rubric:evidence.RUBRIC,...candidate,execution};assert.equal(await guard(input),result);
  result={verdict:'pass',criteria:[{id:'foreign_body_observed',satisfied:true,citations:[{evidenceId:'mail_agent_read',quote:'Private'}]}]};
  assert.equal((await guard(input)).verdict,'unavailable');
  result.criteria[0].citations[0].quote=input.evidence[0].content.observation.observedBodyExcerpt;
  assert.equal(await guard(input),result);assert.equal(calls,3);
  for (const change of [
   record=>{record.observation.callerShopUserId+=1;},
   record=>{record.observation.recipientShopUserId+=1;},
   record=>{record.observation.readOperationId=randomUUID();},
   record=>{record.observation.messageId+=1;},
   record=>{record.observation.receiptSha256='b'.repeat(64);},
   record=>{record.observation.observedBodyExcerpt='authored explanatory sentence that is not source text';},
   record=>{record.version=2;},
   record=>{record.version=1;delete record.observation;},
   record=>{record.source.mail.message.bodyMarkdown='tampered';}
  ]) {
   const changed=structuredClone(input),before=calls;change(changed.evidence[0].content);
   await assert.rejects(guard(changed));assert.equal(calls,before);
  }
 });
}
