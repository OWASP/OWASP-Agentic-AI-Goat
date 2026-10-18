'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)(authDb|ctfDb|sensitiveInfoDb)(?:\.js)?$/.test(r))throw Error('Database initializer forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {currentReceipt}=require('../server/database/postgres/objectiveJudgmentRepository');
const {createObjectiveCompletionService}=require('../server/services/objectiveCompletionService');
const row={generation:3,canonical_mode:'vuln',verdict:'pass',disposition:'awarded',result_json:{verdict:'pass'}};
const valid={generation:3,mode:'vuln',is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true};
test('receipt replay revalidates current scope without rewriting historical award',()=>{
 for(const [patch,disposition] of [[{generation:4},'stale_generation'],[{mode:'fixed'},'mode_changed'],[{is_visible:false},'hidden'],[{is_enabled:false},'hidden'],[{catalog_active:false},'hidden'],[{exercise_active:false},'hidden']]){
  const projected=currentReceipt(row,{...valid,...patch});assert.equal(projected.disposition,disposition);assert.equal(projected.historicalDisposition,'awarded');assert.equal(row.disposition,'awarded');
 }
 assert.equal(currentReceipt(row,valid).disposition,'awarded');
});
test('completion service never returns completed for a replay invalidated by mode or visibility',async()=>{
 for(const patch of [{mode:'fixed'},{is_visible:false}]){
  const service=createObjectiveCompletionService({progress:{getGeneration:async()=>3},receipts:{beginEvaluation:async()=>currentReceipt(row,{...valid,...patch}),recordVerdict:()=>{throw Error('No replay mutation');}},judge:()=>{throw Error('No replay inference');}});
  const execution={check:async()=>{}},attempt=await service.beginAttempt({userId:1,workshopKey:'sql_injection_workshop',execution});
  const result=await service.evaluate({userId:1,workshopKey:'sql_injection_workshop',execution,attempt,rubric:{family:'ARIA',scenario:'search',objectiveId:'sqli_1',version:'v1',mode:'vuln',criteria:[{id:'proof',description:'Observed result'}],requiredFacts:[]},evidence:[{id:'result',source:'tool_result',content:'fixture'}]});
  assert.equal(result.replayed,true);assert.equal(result.completed,false);
 }
});

test('mode timestamp rejects value-equivalent replay after an intervening mode toggle',()=>{
 const original={...row,mode_stamp:'2026-09-11 01:00:00.123456+00'};
 assert.equal(currentReceipt(original,{...valid,modeStamp:original.mode_stamp}).disposition,'awarded');
 assert.equal(currentReceipt(original,{...valid,modeStamp:'2026-09-11 01:00:00.123457+00'}).disposition,'mode_changed');
});
