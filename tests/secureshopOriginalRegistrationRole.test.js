'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {fixture,launch,session,requestId}=require('./secureshopBoundRoleChat.test');
const {withEffectAdmission,currentEffectAdmission}=require('../server/agent-runtime/effectAdmissionContext');
function coordinatorFactory(){return{async run(owner,options,work){
 const admission=await options.admit();if(admission.skip)return admission.value;
 const execution={runId:'80000000-0000-4000-8000-000000000001',ownerKey:owner,durableGeneration:'1',signal:options.signal,async check(){}};
 const effect=(key,fn)=>withEffectAdmission(execution,key,fn);
 return work({...execution,effect,async effectWithReceipt(key,fn){return{value:await effect(key,fn),receipt:{version:1,ownerKey:owner,generation:'1',runId:execution.runId,effectKey:key,status:'completed'}}},async trace(){}});
}}}
test('bound model selection dispatches original register once with trusted effect and exact command, then replays immutable turn',async()=>{
 const calls=[];let closes=0;
 const application={ready:true,mode:'vuln',create(context){assert.deepEqual(context.personaSession,session);assert.equal(context.scope.platformOwnerId,launch.platformOwnerId);
  return{async invoke(args,selection){await context.assertRunCurrent();assert.equal(await context.readRegistryVersion(),'0');
   const admission=currentEffectAdmission(context.execution);assert.ok(admission.ledgerEffectKey);
   calls.push({args:structuredClone(args),selection});return{ok:true,name:args.name,transport:'stdio',operationId:requestId,state:'completed'};
  },async close(){closes++}};}};
 const mcpRegistryChat={async snapshot(){return{registryReady:true,registryVersion:'0',scopeKey:'a'.repeat(64),servers:[]}}};
 const f=fixture('admin',{mcpRegistryChat,mcpRegistrationApplication:()=>application,coordinatorFactory,jsonbResults:true});
 const created=await f.runtime.createSession(launch,f.actor,session);
 const args={name:'owned-package',transport:'stdio',stdio_cmd:'printf "exact ; unchanged" > /owned-mcp-files/stdio-effect'};
 f.decide('mcp-registry.register',args);
 const input={scope:launch,persona:f.actor,personaSession:session,sessionId:created.id,requestId,message:'Register this stdio package using its supplied command.'};
 await f.runtime.run(input);
 assert.equal(calls.length,1);assert.equal(closes,1);assert.deepEqual(calls[0].args,args);assert.equal(calls[0].selection.tool,'mcp-registry.register');
 assert.ok(f.offers.some(list=>list.some(t=>t.agent==='mcp-registry'&&t.tool==='register')));
 const provenance=f.savedTurn(requestId).taskMetadata.roleChat.originalMcpRegistration;
 assert.equal(provenance.runId,'80000000-0000-4000-8000-000000000001');assert.deepEqual(provenance.observation.args,args);
 assert.equal(provenance.observation.effectReceipt.status,'completed');assert.ok(provenance.traceEventIds.length);
 await f.runtime.run(input);assert.equal(calls.length,1);assert.equal(closes,1);
});
test('unavailable registration transport does not advertise original command',async()=>{
 const f=fixture('admin',{mcpRegistrationApplication:()=>null,coordinatorFactory});
 const created=await f.runtime.createSession(launch,f.actor,session);f.decide('admin.users_search',{search:'student'});
 await f.runtime.run({scope:launch,persona:f.actor,personaSession:session,sessionId:created.id,requestId,message:'Find student'});
 assert.ok(f.offers.every(list=>list.every(t=>t.agent!=='mcp-registry')));
});
