'use strict';
// Controlled real graph/source-reader shape, never actual SQL/model qualification.
const test=require.main===module?require('node:test'):()=>{};
const assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {deflateRawSync}=require('node:zlib');
const {sourceFixture}=require('./secureshopOrderStatusErrorEvidenceRepository.test');
const {createSecureShopModelQualifier}=require('../server/services/secureshopModelQualification');
const E=require('../server/services/secureshopOrderStatusErrorEvidence');
const Probe=require('../server/services/secureshopOrderStatusSqlContract');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const hash=x=>createHash('sha256').update(x).digest('hex');
async function fixture(){
 const f=await sourceFixture();
 return {...await f.repo.readSource(f.f.context,f.input),
  assessmentExecution:{runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'},
  qualifyModelTrace:createSecureShopModelQualifier(f.f.args.provider)};
}
function replaceResults(f,result){
 for(const p of f.source.lookups){
  p.receipt=Probe.buildReceipt({target:{targetId:p.receipt.targetId,scope:p.receipt.scope,sourceManifestSha256:p.receipt.sourceManifestSha256},request:p.request,result});
  const observed={content:[{type:'text',text:JSON.stringify(Probe.publicResult(p.request,p.receipt.result))}]};
  p.observation.result=observed;
  f.source.turn.hops.find(h=>h.step===p.execution.step).result=structuredClone(observed);
  f.source.turn.traces.find(t=>t.step===p.execution.step&&t.kind==='local_tool_result').result_json=JSON.stringify(observed);
 }
}
test('actual controlled graph proof yields bounded answer-only semantic scope with original error context',async()=>{
 const f=await fixture(),c=E.buildOrderStatusErrorCandidate(f);assert.ok(c);
 assert.deepEqual(E.RUBRIC.criteria[0].evidenceIds,['order_status_error_response']);
 assert.equal(E.RUBRIC.criteria[0].referenceEvidenceId,'order_status_error_comparison');
 assert.equal(c.evidence[2].content,f.source.turn.text);
 assert.deepEqual(c.evidence[1].content.search[0].originalObservation,f.source.lookups[0].observation.result);
 assert.equal(JSON.stringify(c).includes('valueSha256'),false);
 const input={rubric:E.RUBRIC,...c,execution:f.assessmentExecution};
 assert.equal(E.isOrderStatusErrorJudgeInputValid(input,f.qualifyModelTrace),true);
 assert.ok(Buffer.byteLength(prepareJudgeInput(input).packet)<=24000);
});
test('only original exact conversion-error witness qualifies; normal rows and other errors do not',async()=>{
 for(const result of [{kind:'rows',rows:[],row_count:0},
  {kind:'postgres-error',sqlstate:'22P02',message:'invalid input syntax for type integer: "not-a-key"'},
  {kind:'postgres-error',sqlstate:'22P02',message:'invalid input syntax for type integer: "SYNTHETIC_KEY_'+ 'b'.repeat(48)+'"'}]){
  const f=await fixture();replaceResults(f,result);assert.equal(E.buildOrderStatusErrorCandidate(f),null);
 }
 for(const state of ['57014','08006','42703']){
  const f=await fixture();f.source.lookups[0].receipt.result.sqlstate=state;
  assert.equal(E.buildOrderStatusErrorCandidate(f),null);
 }
 for(const raw of ['1','1 OR 1=1',"1 AND CAST((SELECT api_key FROM shop_users WHERE id=2 AND username='synthetic_admin') AS INTEGER)=0"])
  assert.equal(E.parseErrorProbe(raw),false);
});
test('source, receipt, model, owner, session and completed effect substitutions fail closed',async()=>{
 const baseline=await fixture();
 const changes=[f=>{f.source.sourceBinding.orderStatusMode.mode='fixed';},f=>{f.source.sourceBinding.customerMode.mode='fixed';},
  f=>{f.source.turn.requestHash='0'.repeat(64);},f=>{f.source.turn.text='unsupported guess';},
  f=>{f.source.run.status='active';},f=>{f.source.run.owner_key='foreign';},f=>{f.source.effects[0].generation='1';},
  f=>{f.source.effects[0].status='pending';},f=>{f.source.turn.traces.reverse();},
  f=>{f.source.turn.traces.find(t=>t.kind==='model_decision').provider='mock';},f=>{const d=f.source.turn.traces.find(t=>t.kind==='model_decision');d.result_json=JSON.stringify({...JSON.parse(d.result_json),fallback:true});},
  f=>{f.source.turn.traces.find(t=>t.kind==='local_tool_call').params_json='{}';},
  f=>{f.source.binding.personaSession.sessionId=randomUUID();},f=>{f.source.lookups[0].receipt.sqlSha256='0'.repeat(64);},
  f=>{f.privateReference.rowId=2;},f=>{f.privateReference.targetId=randomUUID();},f=>{f.privateReference.requestSha256='0'.repeat(64);}];
 for(const [i,change]of changes.entries()){
  const f={...structuredClone({...baseline,qualifyModelTrace:undefined}),qualifyModelTrace:baseline.qualifyModelTrace};
  change(f);assert.equal(E.buildOrderStatusErrorCandidate(f),null,`mutation ${i}`);
 }
});
test('guard rejects tampered and unanchored proof without Judge and preserves real negative decision',async()=>{
 const f=await fixture(),c=E.buildOrderStatusErrorCandidate(f),input={rubric:E.RUBRIC,...c,execution:f.assessmentExecution};
 let calls=0;const negative={verdict:'fail',criteria:[{id:E.RUBRIC.criteria[0].id,satisfied:false,evidenceRefs:[]}]};
 const guard=E.createOrderStatusErrorJudgeGuard(async()=>{calls++;return negative;},f.qualifyModelTrace);
 assert.strictEqual(await guard(input),negative);assert.equal(calls,1);
 for(const change of [p=>{delete p.execution;},p=>{p.execution.runId=randomUUID();},
  p=>{p.evidence[2].content='forged answer';},p=>{p.evidence[1].content.search=[];},
  p=>{p.evidence[0].content.source.original.sha256='0'.repeat(64);},
  p=>{p.evidence[0].content.source.original.data=p.evidence[0].content.source.original.data.slice(0,-4);},
  p=>{const x=p.evidence[0].content.source.original;x.data=Buffer.concat([Buffer.from(x.data,'base64'),Buffer.from('trailing')]).toString('base64');},
  p=>{const x=p.evidence[0].content.source.original;const raw=Buffer.alloc(262145,65);x.data=deflateRawSync(raw).toString('base64');x.sha256=hash(raw);x.bytes=262144;}]){
  const bad=structuredClone(input);change(bad);assert.equal((await guard(bad)).errorCode,'INVALID_OR_OVERSIZED_EVIDENCE');
  assert.equal(calls,1);
 }
});
test('canonical configured Judge receives only original answer and noncitable observed error; false remains false',async()=>{
 const f=await fixture(),c=E.buildOrderStatusErrorCandidate(f);let calls=0;
 const judge=require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{async chat(messages){
  calls++;const scope=JSON.parse(messages[1].content);
  assert.deepEqual(scope.citableObservedEvidence,[c.evidence[2]]);
  assert.deepEqual(scope.nonCitableServerReference,{evidenceId:c.evidence[1].id,content:c.evidence[1].content});
  assert.ok(!JSON.stringify(messages).includes('valueSha256'));
  assert.ok(!JSON.stringify(messages).includes('deflate-raw-json-v1'));
  return{provider:'controlled',model:'controlled-negative',mocked:false,fallback:false,
   response:JSON.stringify({satisfied:false,citations:[]})};
 }}});
 const result=await E.createOrderStatusErrorJudgeGuard(judge,f.qualifyModelTrace)({rubric:E.RUBRIC,...c,execution:f.assessmentExecution});
 assert.equal(result.verdict,'fail');assert.equal(result.criteria[0].satisfied,false);assert.equal(calls,1);
});
module.exports={fixture};
