'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {declarations,hardBound,main,MODEL,DIGEST}=require('./fixtures/pricingManualH4V6ActualJudgeCalibration');
const {packet}=require('./fixtures/pricingManualActualJudgeCalibration');
const {PRICING_RUBRICS}=require('../server/services/secureshopPricingAssessment');

test('H4 v9/v6 calibration pins exactly the retained negative and semantic counterfactual',()=>{
 const declared=declarations(process.cwd());assert.equal(declared.cases.length,2);assert.deepEqual(declared.cases.map(item=>item.expectedVerdict),['fail','pass']);
 assert.equal(MODEL,'llama3.1:8b');assert.equal(DIGEST,'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
 assert.equal(PRICING_RUBRICS.ss_pricing_manual_injection.version,'secureshop-pricing-manual-v9');assert.equal(PRICING_RUBRICS.ss_pricing_manual_injection.sourceComparison.supportContract,'pricing-semantic-decomposition-v6');
});

test('H4 packets expose only exact source, response and learner question without labels',()=>{
 const declared=declarations(process.cwd()),rubric={...PRICING_RUBRICS.ss_pricing_manual_injection,mode:'vuln'};
 for(const item of declared.cases){const value=packet(rubric,item,declared.learnerQuestion);assert.deepEqual(value.evidence.map(entry=>entry.content),[item.source,item.response,declared.learnerQuestion]);assert.equal(Object.hasOwn(value,'expectedVerdict'),false);assert(value.evidence.every(entry=>!Object.hasOwn(entry,'expectedVerdict')));}
});

test('independent H4 transport bound denies a tenth HTTP call before upstream',async()=>{
 let upstream=0;const bound=hardBound(async()=>{upstream++;return new Response('{}',{status:200});});
 for(let index=0;index<9;index++)assert.equal((await bound.fetch('http://127.0.0.1')).status,200);
 await assert.rejects(bound.fetch('http://127.0.0.1'),error=>error?.code==='HTTP_BUDGET_EXHAUSTED');assert.equal(upstream,9);assert.equal(bound.count,9);
});

test('invalid model request options are denied before the network or budget counter',async()=>{
 let upstream=0;const bound=hardBound(async()=>{upstream++;return new Response('{}',{status:200});});
 const valid={model:MODEL,stream:true,options:{temperature:0,num_ctx:32768,num_predict:4096},format:{type:'object'}};
 await assert.rejects(bound.fetch('http://127.0.0.1:11434/api/chat',{body:JSON.stringify({...valid,options:{...valid.options,num_ctx:4096}})}));
 assert.equal(upstream,0);assert.equal(bound.count,0);
 assert.equal((await bound.fetch('http://127.0.0.1:11434/api/chat',{body:JSON.stringify(valid)})).status,200);assert.equal(upstream,1);assert.equal(bound.count,1);
});

test('invalid options and missing execution gate reject before network',async()=>{
 const prior=global.fetch;let calls=0;global.fetch=async()=>{calls++;throw Error('network must not run');};
 try{await assert.rejects(main({unexpected:true}),/accepts no runtime options/);delete process.env.PRICING_MANUAL_H4_V6_ACTUAL_JUDGE;await assert.rejects(main());assert.equal(calls,0);}finally{global.fetch=prior;}
});
