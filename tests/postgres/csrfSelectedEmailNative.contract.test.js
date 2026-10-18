'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
test('selected native composition rejects non-disposable execution before creating pools',async()=>{
 const old=process.env.PG_TEST_DISPOSABLE;delete process.env.PG_TEST_DISPOSABLE;
 try{await assert.rejects(require('./csrfSelectedEmailNativeSupport').createSelectedEmailApp(),/Expected values/);}finally{if(old===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=old;}
});
test('historical effective vuln rubric remains valid without inventing null Judge mode',()=>{
 const {prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');const packet={rubric:{family:'CSRF',scenario:'xss',objectiveId:'csrf_x1',version:'csrf-observed-v8',mode:'vuln',criteria:[{id:'observed_outcome',description:'Synthetic inbox observation for historical null recovery.',allowedSources:['server_observation']}],requiredFacts:['required_observation']},evidence:[{id:'receipt',source:'server_observation',content:{synthetic:true}}],facts:{required_observation:false}};
 const prepared=prepareJudgeInput(packet);assert.equal(prepared.evidenceError,undefined);assert.equal(prepared.rubric.mode,'vuln');assert.equal(JSON.parse(prepared.packet).facts.required_observation,false);
 assert.equal(require('../../server/agent-runtime/judgeErrors').canRetryJudgeError('JUDGE_UNAVAILABLE'),true);
});
test('selected-read fixture key matches actual coordinator default namespace and exact dispatch node',async()=>{
 const {createRunCoordinator}=require('../../server/agent-runtime/runCoordinator'),{randomUUID}=require('node:crypto'),{selectedReadEffectKey}=require('./csrfSelectedEmailNativeSupport');let stored;
 const runs=createRunCoordinator({family:'CSRF',ledger:{effect:async(context,key,callback)=>{stored={context,key};return callback();}}});const dispatchId=randomUUID();
 await runs.run('7',{},async execution=>{await execution.effect(`email_selected_read_${execution.runId}_${dispatchId}`,async()=>true);assert.equal(stored.key,selectedReadEffectKey(execution.runId,dispatchId));assert.equal(stored.context.runId,execution.runId);assert.notEqual(stored.key,`email_selected_read_${execution.runId}_${dispatchId}`);});
 assert.throws(()=>selectedReadEffectKey('foreign',dispatchId));
});
