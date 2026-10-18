'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const decision=require('../server/services/mcp/protectedDecisionAdmission');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {withEffectAdmission,currentEffectAdmission}=require('../server/agent-runtime/effectAdmissionContext');
const execution={runId:'run',ownerKey:'owner',durableGeneration:0};
const invocation={execution,surface:'chat',validatedProtectedTool:{name:'admin_rotate_keys',argsSha256:canonicalDigest({})}};
test('only privately recorded exact graph decision admits model origin; manual stays manual',async()=>{
 const value=decision.record({tool:'admin_rotate_keys',params:{},decisionSource:'model'},execution,{provider:'test-controlled',model:'fixture'});
 await decision.withDecision(value,execution,async()=>{assert.equal(decision.originFor(invocation).origin,'controlled');assert.throws(()=>decision.originFor({...invocation,validatedProtectedTool:{name:'get_config',argsSha256:canonicalDigest({})}}),{code:'PROTECTED_DECISION_MISMATCH'});});
 await decision.withDecision({...value},execution,async()=>assert.throws(()=>decision.originFor(invocation),{code:'PROTECTED_DECISION_REQUIRED'}));
 assert.deepEqual(decision.originFor({...invocation,surface:'inspector'}),{origin:'manual',decisionDigest:null});
 for(const identity of [{},{provider:'mock',model:'fixture'},{provider:'ollama',model:null}]){const item=decision.record({tool:'admin_rotate_keys',params:{}},execution,identity);await decision.withDecision(item,execution,async()=>assert.equal(decision.originFor(invocation).origin,'controlled'));}
 const genuine=decision.record({tool:'admin_rotate_keys',params:{}},execution,{provider:'ollama',model:'llama3.1:8b'});await decision.withDecision(genuine,execution,async()=>assert.equal(decision.originFor(invocation).origin,'model'));
 value.params.fake='mutation';await decision.withDecision(value,execution,async()=>assert.throws(()=>decision.originFor(invocation),{code:'PROTECTED_DECISION_REQUIRED'}));
});
test('full durable key scope is distinct from suffix and retires descendants',async()=>{
 let later;await withEffectAdmission(execution,'request-id:suffix',async()=>{
  assert.equal(currentEffectAdmission(execution).ledgerEffectKey,'request-id:suffix');
  assert.throws(()=>currentEffectAdmission({...execution,runId:'foreign'}),{code:'PROTECTED_EFFECT_ADMISSION_REQUIRED'});
  later=new Promise(resolve=>setTimeout(()=>{assert.throws(()=>currentEffectAdmission(execution),{code:'PROTECTED_EFFECT_ADMISSION_REQUIRED'});resolve();},5));
 });await later;
});
