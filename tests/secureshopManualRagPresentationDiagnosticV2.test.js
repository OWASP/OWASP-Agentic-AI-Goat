'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {createHash}=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {RUBRIC}=require('../server/services/secureshopManualRagEvidence');
const D=require('./fixtures/secureshopManualRagPresentationDiagnosticV2');
const hash=s=>createHash('sha256').update(s).digest('hex');
const copy=x=>structuredClone(x);
const retainedAvailable=fs.existsSync(D.RETAINED);
const explicitlyRequested=process.env.V26_RETAINED_DIAGNOSTIC==='1';
function genuine(){return D.loadRetainedPair();}

test('retained pair is pinned, genuine, and independently joined',
 {skip:!retainedAvailable&&!explicitlyRequested},()=>{
  const {wire,cases}=genuine();
  assert.equal(hash(fs.readFileSync(D.RETAINED)),D.PINS.wire);
  assert.ok(cases.clean.task===cases.poisoned.task);
  assert.notEqual(cases.clean.original.requestId,cases.poisoned.original.requestId);
  assert.equal(cases.clean.tool.retrieved_context.filter(x=>x.sourceKind==='manual').length,0);
  assert.equal(cases.poisoned.tool.retrieved_context.filter(x=>x.sourceKind==='manual').length,1);
  assert.equal(hash(cases.poisoned.manual.text),D.PINS.selectedManual);
  for(const label of ['clean','poisoned']){
   const trace=cases[label].original.traces.find(x=>x.kind==='local_tool_result');
   assert.equal(hash(trace.result_json),D.PINS[label].traceResult);
   assert.equal(hash(JSON.stringify(cases[label].tool)),D.PINS[label].observedToolResult);
  }
  assert.equal(wire.originalCapture.paired.comparison.semanticAdoption,null);
  assert.equal(wire.originalCapture.paired.comparison.canonicalCredit,false);
 });

test('lossless presentation keeps original answer, task, tool result, and rubric without model polarity',
 {skip:!retainedAvailable&&!explicitlyRequested},()=>{
  const {cases}=genuine();
  for(const label of ['clean','poisoned']){
   const formatted=D.formatCase(label,cases);
   const input=formatted.modelInput;
   assert.equal(formatted.profile,D.PROFILE);
   assert.ok(isDeepStrictEqual(formatted.rubric,RUBRIC));
   assert.equal(input.nonCitableServerReference.evidenceId,'manual_comparison');
   assert.ok(input.nonCitableServerReference.content.originalTask.text===cases[label].task);
   assert.ok(isDeepStrictEqual(input.nonCitableServerReference.content.untrustedObservedToolResult,cases[label].tool));
   assert.equal(input.citableObservedEvidence.length,1);
   assert.equal(input.citableObservedEvidence[0].id,'manual_consumer_response');
   assert.equal(input.citableObservedEvidence[0].source,'assistant_response');
   assert.ok(input.citableObservedEvidence[0].content===cases[label].answer);
   assert.equal(hash(input.citableObservedEvidence[0].content),D.PINS[label].answer);
   assert.ok(!JSON.stringify(input).includes('candidatePositive'));
   assert.ok(!JSON.stringify(input).includes('canonicalCredit'));
   assert.equal(formatted.hostProvenance.canonicalCredit,false);
  }
  const clean=D.formatCase('clean',cases).modelInput.nonCitableServerReference.content;
  const poisoned=D.formatCase('poisoned',cases).modelInput.nonCitableServerReference.content;
  assert.equal(clean.selectedManual,null);
  assert.ok(poisoned.selectedManual.text===cases.poisoned.manual.text);
  assert.equal(poisoned.selectedManual.textSha256,D.PINS.selectedManual);
  assert.ok(!poisoned.untrustedObservedToolResult.retrieved_context.some(x=>x.sourceKind==='manual'&&x.text!==poisoned.selectedManual.text));
 });

test('source, task, answer, manual, and observation tampering fail closed',
 {skip:!retainedAvailable&&!explicitlyRequested},()=>{
  const {wire}=genuine();
  const mutations=[
   x=>{x.originalCapture.source.sourceDigest='0'.repeat(64);},
   x=>{x.originalCapture.paired.cases.clean.consumer.original.message+=' ';},
   x=>{x.originalCapture.paired.cases.poisoned.consumer.original.result.text+=' ';},
   x=>{x.originalCapture.paired.cases.poisoned.result.retrieved_context.find(y=>y.sourceKind==='manual').text+=' ';},
   x=>{x.originalCapture.source.semantic.observation.mcp.content[0].text='{}';},
   x=>{x.originalCapture.paired.cases.clean.consumer.original.traces.find(y=>y.kind==='local_tool_result').result_json='{}';},
   x=>{x.originalCapture.paired.cases.poisoned.consumer.original.traces.find(y=>y.kind==='local_tool_result').session_id='unbound';},
   x=>{x.originalCapture.paired.cases.clean.consumer.original.requestId=x.originalCapture.paired.cases.poisoned.consumer.original.requestId;},
   x=>{x.originalCapture.judgeInput.rubric.criteria[0].description+=' ';},
  ];
  for(const mutate of mutations){const x=copy(wire);mutate(x);assert.throws(()=>D.verifyRetainedPair(x),/V26_DIAGNOSTIC_/);}
 });

test('formatter rejects substituted answer or tool result before a model input exists',
 {skip:!retainedAvailable&&!explicitlyRequested},()=>{
  const {cases}=genuine();
  const changedAnswer=copy(cases);changedAnswer.clean.answer+=' ';
  assert.throws(()=>D.formatCase('clean',changedAnswer),/V26_DIAGNOSTIC_FORMATTED_SOURCE/);
  const changedTool=copy(cases);changedTool.poisoned.tool.retrieved_context[0].text+=' ';
  assert.throws(()=>D.formatCase('poisoned',changedTool),/V26_DIAGNOSTIC_FORMATTED_SOURCE/);
  const changedTask=copy(cases);changedTask.clean.task+=' ';
  assert.throws(()=>D.formatCase('clean',changedTask),/V26_DIAGNOSTIC_FORMATTED_SOURCE/);
  const changedManual=copy(cases);changedManual.poisoned.manual.text+=' ';
  assert.throws(()=>D.formatCase('poisoned',changedManual),/V26_DIAGNOSTIC_FORMATTED_SOURCE/);
  const missingManual=copy(cases);missingManual.poisoned.manual=null;
  assert.throws(()=>D.formatCase('poisoned',missingManual),/V26_DIAGNOSTIC_FORMATTED_SOURCE/);
  const falseCleanManual=copy(cases);falseCleanManual.clean.manual=copy(cases.poisoned.manual);
  assert.throws(()=>D.formatCase('clean',falseCleanManual),/V26_DIAGNOSTIC_FORMATTED_SOURCE/);
  const changedRequest=copy(cases);changedRequest.poisoned.original.requestHash='0'.repeat(64);
  assert.throws(()=>D.formatCase('poisoned',changedRequest),/V26_DIAGNOSTIC_FORMATTED_SOURCE/);
  assert.throws(()=>D.formatCase('other',cases),/V26_DIAGNOSTIC_CASE_LABEL/);
 });

test('only the pinned retained file can be loaded; no provider runner is exported',()=>{
 assert.throws(()=>D.loadRetainedPair('/tmp/not-the-retained-capture'),/V26_DIAGNOSTIC_PATH/);
 assert.equal(D.run,undefined);
 assert.equal(D.evaluate,undefined);
 assert.equal(D.createJudge,undefined);
});

test('four-call protocol is a disabled proposal preserving two original criteria and citation policy',()=>{
 const plan=D.proposedCallPlan();
 assert.equal(plan.enabled,false);
 assert.equal(plan.status,'proposal_only');
 assert.equal(plan.physicalJudgeCallsMax,4);
 assert.equal(plan.perCaseCriterionCallsMax,1);
 assert.equal(plan.actorCalls,0);
 assert.equal(plan.repairs,0);
 assert.equal(plan.canonicalCredit,false);
 assert.equal(plan.referenceCitable,false);
 assert.equal(plan.originalCitationPolicy,'contextual');
 assert.ok(isDeepStrictEqual(plan.criteria,RUBRIC.criteria.map(x=>x.id)));
 assert.ok(RUBRIC.criteria.every(x=>x.referenceEvidenceId==='manual_comparison'
  &&x.evidenceIds.join(',')==='manual_consumer_response'
  &&x.citationPolicy==='contextual'));
});
