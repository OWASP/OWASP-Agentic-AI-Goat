'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopMcpTrustExternalAdapter}=require('../server/services/secureshopMcpTrustExternalAdapter');

const scope=Object.freeze({launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',
  generation:1,platformOwnerId:7,platformSessionId:8});
const binding=Object.freeze({...scope,shopUserId:3,role:'admin'});
const target=Object.freeze({...binding,targetId:'30000000-0000-4000-8000-000000000001',serverIdentity:'weather-lab',trustScenario:'rug_pull'});
const schema=Object.freeze({serverIdentity:'weather-lab',version:1,schemaSha256:'a'.repeat(64),tools:Object.freeze([{name:'forecast_lookup'}])});
const execution=()=>({runId:'40000000-0000-4000-8000-000000000001',ownerKey:'owner',durableGeneration:1,
  signal:new AbortController().signal,async check(){}});
const requestId='50000000-0000-4000-8000-000000000001',sessionId='60000000-0000-4000-8000-000000000001';
const remote=()=>({serverIdentity:'weather-lab',trustScenario:'rug_pull',schemaSha256:schema.schemaSha256,
  receiptSha256:'b'.repeat(64),trustPolicySha256:'c'.repeat(64),approved:true,serverApproved:true,schemaApproved:true,
  behaviorClass:'public_forecast_lookup',result:{city:'Seattle',forecast:'rain'}});
function fence(value=binding){let live=true;const object={binding:{...scope,personaId:value.shopUserId,role:value.role},
  async assertRemoteAdmission(){if(!live)throw Object.assign(Error('private revoked detail'),{code:'SHOP_AUTH_INVALID'});},
  async withPersonaEffect(work){if(!live)throw Object.assign(Error('private revoked detail'),{code:'SHOP_AUTH_INVALID'});return work({query:async()=>{}},this.binding);}};
 return{fence:object,revoke(){live=false;}};}
function adapter({callTool=async()=>remote(),recordInvocation=async(_target,input)=>({invocationId:input.operationId,...input}),calls={}}={}){
 calls.target=0;calls.record=0;
 return createSecureShopMcpTrustExternalAdapter({application:{async target(_binding,personaFence){calls.target++;calls.targetFence=personaFence;return target;}},
  repository:{async currentSchema(_target,personaFence){calls.schemaFence=personaFence;return schema;},async recordInvocation(_target,input,actor,personaFence){calls.record++;calls.actor=actor;calls.recordFence=personaFence;return recordInvocation(_target,input,actor,personaFence);}},
  transport:{callTool},checkCurrent:async()=>{},serverIdentity:'weather-lab',trustScenario:'rug_pull',expectedSchemaSha256:schema.schemaSha256});
}
function observation(result,run=execution()) {return {run,binding,sessionId,requestId,observation:{step:1,callId:'call-1',
  tool:'weather-lab.forecast_lookup',args:{city:'Seattle'},result,effectReceipt:{version:1,status:'completed',runId:run.runId,
    ownerKey:run.ownerKey,generation:'1',effectKey:`${requestId}:${JSON.stringify([1,'call-1','weather-lab.forecast_lookup'])}`}}};}
function assertUncertain(error){assert.equal(error.code,'PERSONA_EFFECT_OUTCOME_UNCERTAIN');assert.equal(error.executionBoundary,true);
 assert.equal(error.automaticRetry,false);assert.doesNotMatch(error.message,/private|revoked|remote exploded/);assert.equal(Object.keys(error).includes('cause'),false);return true;}

test('held remote call becomes uncertain when persona authority is revoked before return',async()=>{
 let release,dispatched=false;const held=new Promise(resolve=>{release=resolve;});const authority=fence();
 const feature=adapter({callTool:async()=>{dispatched=true;return held;}});const pool=await feature.createToolPool(binding,{execution:execution(),requestId,sessionId},authority.fence);
 const pending=pool.callTool('weather-lab','forecast_lookup',{city:'Seattle'},{callId:'call-1'});while(!dispatched)await new Promise(resolve=>setImmediate(resolve));
 authority.revoke();release(remote());await assert.rejects(pending,assertUncertain);
});

test('remote exception after dispatch is private uncertain outcome',async()=>{
 const authority=fence();const feature=adapter({callTool:async()=>{throw Error('remote exploded with private body');}});
 const pool=await feature.createToolPool(binding,{execution:execution(),requestId,sessionId},authority.fence);
 await assert.rejects(pool.callTool('weather-lab','forecast_lookup',{}, {callId:'call-1'}),assertUncertain);
});

test('revoked fenced publication cannot record or return success',async()=>{
 const calls={},authority=fence(),feature=adapter({calls});const run=execution();
 const pool=await feature.createToolPool(binding,{execution:run,requestId,sessionId},authority.fence);
 const result=await pool.callTool('weather-lab','forecast_lookup',{city:'Seattle'},{callId:'call-1'});
 authority.revoke();await assert.rejects(feature.observeExternalTool(observation(result,run),authority.fence),assertUncertain);
 assert.equal(calls.record,0);
});

test('fenced publication forwards exact actor and fence; sibling fence is denied before target or remote use',async()=>{
 const calls={},authority=fence(),feature=adapter({calls});const run=execution();
 const pool=await feature.createToolPool(binding,{execution:run,requestId,sessionId},authority.fence);
 const result=await pool.callTool('weather-lab','forecast_lookup',{city:'Seattle'},{callId:'call-1'});
 const projected=await feature.observeExternalTool(observation(result,run),authority.fence);
 assert.equal(projected.invocation.operationId,result._meta.operationId);assert.deepEqual(calls.actor,{id:3,role:'admin'});
 assert.equal(calls.recordFence,authority.fence);assert.equal(calls.targetFence,authority.fence);assert.equal(calls.schemaFence,authority.fence);
 const sibling=fence({...binding,shopUserId:4});const beforeTarget=calls.target;
 await assert.rejects(feature.createToolPool(binding,{execution:execution(),requestId,sessionId},sibling.fence),{code:'SHOP_AUTH_INVALID'});
 assert.equal(calls.target,beforeTarget);
});
