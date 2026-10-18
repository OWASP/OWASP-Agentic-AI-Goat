'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createRegisteredInvocationObserver}=require('../server/services/secureshopRegisteredInvocationObservation');
function fixture(meta){
 const binding={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:11,shopUserId:3,role:'admin'},run={runId:'30000000-0000-4000-8000-000000000001',ownerKey:'owner7',durableGeneration:1,check:async()=>{checks.push('run');}},checks=[];
 const request={operationId:'40000000-0000-4000-8000-000000000001',args:{query:'owned'}};
 const sdk={content:[{type:'text',text:'actual bounded result'}],...(meta?{_meta:meta}:{})};
 const stored={envelope:{snapshot:{tools:[{name:'search_catalog'}]},request:{entryId:'50000000-0000-4000-8000-000000000001',toolName:'search_catalog',runId:run.runId,requestId:'request-1',callId:'call-1',binding,args:request.args},effectKey:'effect-1',executorMapping:{request}},receipt:{result:structuredClone(sdk)}};
 const observation={callId:'call-1',tool:'owned_50000000000040008000000000000001.tool_0',args:request.args,effectReceipt:{version:1,status:'completed',runId:run.runId,ownerKey:run.ownerKey,generation:'1',effectKey:'effect-1'},result:{...structuredClone(sdk),_meta:{...sdk._meta,ownedRegistryInvocation:{request,receipt:structuredClone(stored.receipt),runId:run.runId,effectKey:'effect-1'}}}};
 const journal={readCompleted:async input=>{checks.push('journal');assert.deepEqual(input,{scope:binding,invocationId:request.operationId});return stored;}},fence={assertRemoteAdmission:async()=>checks.push('fence')};
 return{input:{run,binding,requestId:'request-1',observation},stored,checks,fence,journal};
}
test('exact durable journal and graph receipt join preserves SDK metadata and grants no award',async()=>{
 for(const meta of [undefined,{}, {prior_meta:{nested:['retained',2]}}]){
  const f=fixture(meta),before=structuredClone(f.input.observation),result=await createRegisteredInvocationObserver({journal:f.journal})(f.input,f.fence);
  assert.deepEqual(result,{invocationId:f.input.observation.result._meta.ownedRegistryInvocation.request.operationId,runId:f.input.run.runId,effectKey:'effect-1',state:'completed',drained:true});assert.equal(Object.hasOwn(result,'awarded'),false);assert.equal(Object.hasOwn(result,'genuineCredit'),false);assert.deepEqual(f.input.observation,before);assert.deepEqual(f.checks,['run','fence','journal','fence','run']);
 }
});
test('owner session run effect tool arguments result and retained metadata substitutions deny',async()=>{
 const mutations=[
 f=>f.input.observation.effectReceipt.ownerKey='foreign',f=>f.input.binding={...f.input.binding,platformSessionId:12},f=>f.input.binding={...f.input.binding,platformOwnerId:8},
 f=>f.input.observation.effectReceipt.runId='foreign',f=>f.input.observation.effectReceipt.generation='2',f=>f.input.observation.effectReceipt.effectKey='foreign',
 f=>f.stored.envelope.request.runId='foreign',f=>f.stored.envelope.request.requestId='foreign',f=>f.input.observation.callId='foreign',f=>f.input.observation.tool+='x',
 f=>f.input.observation.args={query:'changed'},f=>f.input.observation.result.content[0].text='changed',f=>f.input.observation.result._meta.prior_meta='changed',
 f=>f.stored.envelope.executorMapping={request:{...f.stored.envelope.executorMapping.request,operationId:'foreign'}},
 f=>f.input.observation.result._meta.ownedRegistryInvocation.receipt={result:{content:[]}},f=>f.input.observation.effectReceipt.status='pending'];
 for(const mutate of mutations){const f=fixture({prior_meta:'retained'});mutate(f);await assert.rejects(createRegisteredInvocationObserver({journal:f.journal})(f.input,f.fence));}
});
test('revocation and absent durable journal fail closed; attacker reserved metadata cannot manufacture evidence',async()=>{
 for(const phase of ['before','after','journal','reserved']){const f=fixture(phase==='reserved'?{ownedRegistryInvocation:{attacker:true}}:undefined);let n=0;
 if(phase==='before'||phase==='after')f.input.run.check=async()=>{if(++n===(phase==='before'?1:2))throw Error('revoked');};
 if(phase==='journal')f.journal.readCompleted=async()=>{throw Error('missing');};
 await assert.rejects(createRegisteredInvocationObserver({journal:f.journal})(f.input,f.fence));}
});
