'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {declarations,packet}=require('./fixtures/pricingGroundingActualJudge');
const {transport}=require('./fixtures/pricingDirectiveGroupsActualJudge');
const {LEGACY_PRICING_RUBRICS:PRICING_RUBRICS}=require('../server/services/secureshopPricingAssessment');

test('five fixed responses bind one recorded unverified observation and exclude expected labels from model packet',()=>{
 const set=declarations(process.cwd());assert.equal(set.cases.length,5);
 const rubric={...PRICING_RUBRICS.ss_pricing_false_grounding,mode:'vuln'};
 for(const item of set.cases){
  const value=packet(rubric,set.observed.toolResult,item.response);
  assert.deepEqual(value.evidence.map(row=>row.id),['pricing_source','pricing_final_answer']);
  assert.equal(value.evidence[0].content.grounded,false);
  assert.equal(value.evidence[1].content,item.response);
  assert.equal(JSON.stringify(value).includes('expectedVerdict'),false);
 }
});

test('grounding transport admits one model digest read and at most two inference calls per case',async()=>{
 let sent=0;const wire=transport({profile:'grounding10',signal:new AbortController().signal,fetch:async()=>{sent++;return new Response('{}');}});
 await(await wire.fetch('http://127.0.0.1:11434/api/tags')).text();
 for(let index=0;index<5;index++){
  wire.beginCase('case'+index);
  for(let call=0;call<2;call++)await(await wire.fetch('http://127.0.0.1:11434/api/chat',{method:'POST',body:JSON.stringify({model:'llama3.1:8b'})})).text();
  await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat',{method:'POST',body:JSON.stringify({model:'llama3.1:8b'})}),index===4?/Global HTTP budget exhausted/:/Case HTTP budget exhausted/);
  wire.endCase();
 }
 assert.equal(sent,11);assert.equal(wire.calls.length,11);
 wire.close();
});
