'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {candidate,main,MODEL,DIGEST,VERSION}=require('./fixtures/pricingManualH4V7ActualJudgeCalibration');
const {declarations}=require('./fixtures/pricingManualH4V6ActualJudgeCalibration');

test('v7 actual candidate reuses the exact reviewed two-case H4 declarations without mounting',()=>{
 const declared=declarations(process.cwd());assert.deepEqual(declared.cases.map(item=>item.expectedVerdict),['fail','pass']);
 for(const item of declared.cases){const built=candidate(item,declared.learnerQuestion);assert.equal(built.spec.supportContract,VERSION);assert.equal(built.comparison.policy.version,VERSION);assert.deepEqual(built.evidence.map(entry=>entry.content),[item.source,item.response,declared.learnerQuestion]);}
 const current=require('../server/services/secureshopPricingAssessment').PRICING_RUBRICS.ss_pricing_manual_injection;assert.equal(current.sourceComparison.supportContract,'pricing-semantic-decomposition-v6');assert.notEqual(current.sourceComparison.supportContract,VERSION);
 assert.equal(MODEL,'llama3.1:8b');assert.equal(DIGEST,'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
});

test('v7 actual candidate rejects options and a missing gate before network',async()=>{
 const prior=global.fetch;let calls=0;global.fetch=async()=>{calls++;throw Error('network must not run');};
 try{await assert.rejects(main({unexpected:true}),/accepts no runtime options/);delete process.env.PRICING_MANUAL_H4_V7_ACTUAL_JUDGE;await assert.rejects(main());assert.equal(calls,0);}finally{global.fetch=prior;}
});

test('v7 candidate policy is exactly four one-call stages with full source effect audit',()=>{
 const declared=declarations(process.cwd()),built=candidate(declared.cases[0],declared.learnerQuestion),policy=built.comparison.policy;
 assert.equal(policy.maximumCalls,4);assert.deepEqual([policy.maximumSourceCalls,policy.maximumEffectCalls,policy.maximumRelationCalls,policy.maximumSupportCalls],[1,1,1,1]);
 const source=built.comparison.validateSource(JSON.stringify({coverage:'complete',groups:[],nonconditions:[]})),wire=JSON.parse(built.comparison.effectMessages(source).messages[1].content);
 assert.equal(wire.original_source,declared.cases[0].source);assert.equal(JSON.stringify(wire).includes(declared.cases[0].response),false);assert.equal(JSON.stringify(wire).includes(declared.learnerQuestion),false);
});
