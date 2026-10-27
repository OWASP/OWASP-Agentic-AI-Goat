'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const V6=require('./fixtures/secureshopUserLookupResponseFormatV6');
const V4=require('./fixtures/secureshopUserLookupResponseFormatV4');
const E=require('../server/services/secureshopUserLookupEvidence');
test('only exact V4 non-citable index is added to unchanged original packets',()=>{
 const plan=V6.prepareExperiment();
 for(let i=0;i<2;i++){
  const input=V6.modelInput(plan,i),p=input.original;
  assert(E.isUserLookupJudgeInputValid(p));
  assert.deepEqual(Object.keys(input).sort(),['auxiliary','instructionAddition','original']);
  assert.deepEqual(Object.keys(input.auxiliary),['nonCitableVerbatimSpanIndex']);
  const expected=V4.syntheticResponseFormat(p.evidence[1].content,p.evidence[2].content);
  assert.deepEqual(input.auxiliary.nonCitableVerbatimSpanIndex,expected.nonCitableVerbatimSpanIndex);
  assert.equal(p.rubric.criteria.length,4);
  for(const criterion of p.rubric.criteria){assert.deepEqual(criterion.allowedSources,['assistant_response']);assert.deepEqual(criterion.evidenceIds,['user_lookup_response']);}
  for(const key of ['expectedVerdict','provenance','positive','negative'])assert(!Object.hasOwn(input,key));
  assert.throws(()=>{p.evidence[2].content='fabricated';},TypeError);
 }
 assert.equal(plan.executionAuthorized,false);
 assert.equal(plan.provenance.terminalCallCountAvailable,false);
});
test('copied plans, substituted cases and invalid selectors are not admitted',()=>{
 const p=V6.prepareExperiment();
 for(const copy of [{...p},structuredClone(p),JSON.parse(JSON.stringify(p))]){
  assert.throws(()=>V6.modelInput(copy,0));assert.throws(()=>V6.createAccounting(copy));
 }
 for(const i of [-1,2,'0',NaN])assert.throws(()=>V6.modelInput(p,i));
});
test('closed physical accounting includes repairs/failures without refund or hidden retry',()=>{
 const a=V6.createAccounting(V6.prepareExperiment());
 for(let c=0;c<2;c++)for(let k=0;k<4;k++){
  assert.equal(a.reserve(c,k).attempt,1);assert.equal(a.reserve(c,k).attempt,2);
  assert.throws(()=>a.reserve(c,k),/exhausted/);
 }
 assert.equal(a.snapshot().physicalReservations,16);
 assert.equal(a.snapshot().physicalDispatchVerified,false);
 assert.throws(()=>a.reserve(0,0));assert.throws(()=>a.reserve(2,0));
 assert.equal(V6.PROTOCOL.evaluationTimeoutMs,90000);
 assert.equal(V6.PROTOCOL.maximumOutputTokens,900);
 assert.equal(V6.PROTOCOL.contextTokens,32768);
 assert.equal(V6.PROTOCOL.transportRetries,0);
});
