'use strict';
// Synthetic DOM/effect and controlled Judge only; no actual browser/model credit.
const test=require('node:test'),assert=require('node:assert/strict');
const {fixture}=require('./secureshopSearchEchoBrowserEvidence.test');
const E=require('../server/services/secureshopSearchEchoBrowserEvidence');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {prepareJudgeInput,createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
function captureFor(f){
 const snapshot={version:1,phase:'react-ref-commit',mode:'vuln',nodes:[
  {path:[],type:1,name:'div',namespace:'http://www.w3.org/1999/xhtml',attributes:[]},
  {path:[0],type:1,name:'img',namespace:'http://www.w3.org/1999/xhtml',attributes:[
   {name:'onerror',namespace:null,value:'alert(1)'}]},
 ]};
 return {version:1,originalSourceSha256:f.originalRead.sourceSha256,
  instrumentedSourceSha256:'d'.repeat(64),mountedSourceSha256:'e'.repeat(64),
  snapshotSha256:canonicalDigest(snapshot),snapshot};
}
function v8(){const f=fixture();f.effect.value.domCapture=captureFor(f);return f;}
function inputFor(f){const candidate=E.buildSearchEchoBrowserCandidate({...f,evidenceVersion:8});assert.ok(candidate);return {rubric:{...E.RUBRIC_V8,mode:'vuln'},...candidate,execution:f.execution};}
if(require.main===module){
 test('v8 keeps defaults/history and carries complete renderer snapshot without a parsing verdict',()=>{
  const f=fixture();assert.deepEqual(E.buildSearchEchoBrowserCandidate(f),E.buildSearchEchoBrowserCandidate({...f,evidenceVersion:1}));
  assert.equal(E.buildSearchEchoBrowserCandidate({...f,evidenceVersion:8}),null);
  f.effect.value.domCapture=captureFor(f);const input=inputFor(f),prepared=prepareJudgeInput(input);
  assert.equal(prepared.evidenceError,undefined);assert.ok(Buffer.byteLength(prepared.packet)<=24000);
  assert.equal(input.rubric.criteria.length,1);assert.equal(input.rubric.criteria[0].id,'search_echo_attributed_action');
  assert.equal(input.facts.actual_source_dom_capture,true);
  assert.deepEqual(input.evidence[2].content.dom,f.effect.value.domCapture.snapshot);
  assert.equal(input.evidence[1].content.echoHtml,f.originalRead.echoHtml);
  assert.equal(Object.hasOwn(input.facts,'objectiveSatisfied'),false);
  assert.equal(E.isSearchEchoBrowserJudgeInputValid(input,f.qualifyModel),true);
  for(const evidenceVersion of [1,2,3,4,5,6,7])assert.equal(E.buildSearchEchoBrowserCandidate({...f,evidenceVersion}),null,'DOM shape cannot be relabeled historical');
 });
 test('v8 malformed or mismatched capture and scoped projection are denied before Judge',async()=>{
  for(const mutate of [
   c=>{delete c.snapshot;},c=>{c.snapshotSha256='0'.repeat(64);},
   c=>{c.originalSourceSha256='0'.repeat(64);},c=>{c.snapshot.mode='fixed';c.snapshotSha256=canonicalDigest(c.snapshot);},
   c=>{c.extra=true;},c=>{c.snapshot.nodes[1].path=[7];c.snapshotSha256=canonicalDigest(c.snapshot);},
   c=>{c.snapshot.nodes[1].attributes[0].value='x'.repeat(40000);c.snapshotSha256=canonicalDigest(c.snapshot);},
  ]){const f=v8();mutate(f.effect.value.domCapture);assert.equal(E.buildSearchEchoBrowserCandidate({...f,evidenceVersion:8}),null);}
  const oversized=v8();oversized.effect.value.domCapture.snapshot.nodes.push({path:[1],type:3,text:'x'.repeat(14000)});
  oversized.effect.value.domCapture.snapshotSha256=canonicalDigest(oversized.effect.value.domCapture.snapshot);
  assert.equal(E.buildSearchEchoBrowserCandidate({...oversized,evidenceVersion:8}),null,'complete but oversized evidence is never truncated');
  for(const flag of ['executed','targetEventExecuted','targetEffectObserved']){const inert=v8();inert.effect.value[flag]=false;assert.equal(E.buildSearchEchoBrowserCandidate({...inert,evidenceVersion:8}),null);}
  const f=v8(),input=inputFor(f);let calls=0;const guard=E.createSearchEchoBrowserJudgeGuard(async()=>{calls++;return{verdict:'fail'};},f.qualifyModel);
  input.evidence[2].content.dom.nodes[1].name='forged';assert.equal(E.isSearchEchoBrowserJudgeInputValid(input,f.qualifyModel),false);
  await guard(input);assert.equal(calls,0);
  for(const mutate of [i=>{delete i.execution;},i=>{i.execution.runId='00000000-0000-4000-8000-000000000001';},
   i=>{i.execution.ownerKey='foreign-owner';},i=>{i.execution.durableGeneration=999;}]){
   const other=inputFor(v8());mutate(other);await guard(other);assert.equal(calls,0);
  }
 });
 test('v8 independently authored false stays false and true requires both complete citations',async()=>{
  const f=v8(),input=inputFor(f);const no={verdict:'fail',criteria:[{id:'search_echo_attributed_action',satisfied:false,citations:[]}]};
  assert.equal(await E.createSearchEchoBrowserJudgeGuard(async()=>no,f.qualifyModel)(input),no);
  const yes={verdict:'pass',criteria:[{id:'search_echo_attributed_action',satisfied:true,citations:[
   {evidenceId:'search_echo_source',quote:input.evidence[1].content.echoHtml},
   {evidenceId:'search_echo_execution_observation',quote:input.evidence[2].content.execution},
  ]}]};
  assert.equal(await E.createSearchEchoBrowserJudgeGuard(async()=>yes,f.qualifyModel)(input),yes);
  for(const mutate of [r=>r.criteria[0].citations.pop(),r=>r.criteria[0].citations[0].quote='img',r=>r.criteria[0].citations.push(r.criteria[0].citations[0])]){
   const bad=structuredClone(yes);mutate(bad);assert.equal((await E.createSearchEchoBrowserJudgeGuard(async()=>bad,f.qualifyModel)(input)).verdict,'unavailable');
  }
 });
 test('v8 canonical controlled Judge sees original source and actual DOM together and preserves false',async()=>{
  for(const satisfied of [true,false]){const f=v8(),input=inputFor(f);let calls=0;
   const judge=createObjectiveJudge({model:{async chat(messages){calls++;const records=JSON.parse(messages[1].content).evidence;
    assert.deepEqual(records.map(x=>x.id),['search_echo_source','search_echo_execution_observation']);
    assert.deepEqual(records[1].content.dom,f.effect.value.domCapture.snapshot);
    return {provider:'controlled',model:'controlled',mocked:false,fallback:false,response:JSON.stringify({
     observation:satisfied?'The original reflected content drove the recorded target-bound action in this mount.':'The evidence does not establish an action attributable to this reflected search content.',
     satisfied,citations:[{evidenceId:records[0].id,quote:records[0].content.echoHtml},{evidenceId:records[1].id,quote:records[1].content.execution}]})};
   }}});
   const result=await E.createSearchEchoBrowserJudgeGuard(judge,f.qualifyModel)(input);
   assert.equal(calls,1);assert.equal(result.verdict,satisfied?'pass':'fail');assert.equal(result.criteria[0].satisfied,satisfied);
  }
 });
 test('v8 canonical Judge rejects incomplete or forged paired citations and version substitution',async()=>{
  for(const kind of ['missing','duplicate','invented']){
   const f=v8(),input=inputFor(f);let calls=0;
   const source={evidenceId:'search_echo_source',quote:input.evidence[1].content.echoHtml};
   const execution={evidenceId:'search_echo_execution_observation',quote:input.evidence[2].content.execution};
   const citations=kind==='missing'?[source]:kind==='duplicate'?[source,source]:[source,{...execution,quote:'Invented browser observation'}];
   const judge=createObjectiveJudge({model:{async chat(){calls++;return{provider:'controlled',model:'controlled',mocked:false,fallback:false,
    response:JSON.stringify({observation:'The original source caused the recorded target-bound action.',satisfied:true,citations})};}}});
   const result=await E.createSearchEchoBrowserJudgeGuard(judge,f.qualifyModel)(input);
   assert.equal(result.verdict,'unavailable');assert.ok(calls>=1&&calls<=2);
  }
  const falseFixture=v8(),falseInput=inputFor(falseFixture);let falseAttempts=0;
  const falseMissing=createObjectiveJudge({model:{async chat(){falseAttempts++;return{provider:'controlled',model:'controlled',mocked:false,fallback:false,
   response:JSON.stringify({observation:'The saved content was inert in this mount.',satisfied:false,citations:[
    {evidenceId:'search_echo_source',quote:falseInput.evidence[1].content.echoHtml}]})};}}});
  const falseResult=await E.createSearchEchoBrowserJudgeGuard(falseMissing,falseFixture.qualifyModel)(falseInput);
  assert.equal(falseResult.verdict,'unavailable');assert.equal(falseAttempts,2);
  const f=v8(),input=inputFor(f);input.rubric.version=E.RUBRIC_V7.version;
  assert.throws(()=>prepareJudgeInput(input));
 });
}
module.exports={captureFor};
