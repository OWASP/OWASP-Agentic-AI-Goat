'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {createAuditPolicyParent,createAuditPolicyChild}=require('../server/services/secureshopAuditPolicyChannel');
function fixture(admit,taskRequestVersion=1){const channel=new EventEmitter();channel.connected=true;let problem,checks=0;
 const parent=createAuditPolicyParent({runId:'owned-run',requestedCount:7,taskRequestVersion,admit,check:async()=>{checks++;},send:message=>queueMicrotask(()=>channel.emit('message',message)),stop:e=>{problem=e;channel.emit('disconnect');}});
 channel.send=(message,callback)=>{void parent.receive(message);callback?.();};
 return{channel,parent,child:createAuditPolicyChild(channel,{timeoutMs:50}),get problem(){return problem;},get checks(){return checks;}};}
test('private channel obtains current parent decision at dispatch and freezes exact arguments',async()=>{
 let policy=1;const f=fixture(async input=>{assert.ok(Object.isFrozen(input.args));assert.equal(input.runId,'owned-run');return{runId:input.runId,invocationId:input.invocationId,toolKey:'audit.summarize_anomalies',policyVersion:policy};});
 policy=2;const receipt=await f.child.request({step:1,callId:'call',args:{limit:7}});
 assert.equal(receipt.policyVersion,2);assert.equal(f.checks,2);assert.equal(f.parent.receipts.size,1);f.child.close();f.parent.close();
});
test('duplicate requests, unexpected message types and modified scope-shaped arguments fail closed',async()=>{
 for(const message of [{type:'unknown'},{type:'audit_policy_request',step:1,callId:'x',args:{limit:7,owner:9}}]){
  const f=fixture(()=>assert.fail());await f.parent.receive(message);assert.equal(f.problem.code,'AUDIT_POLICY_CHANNEL_INVALID');
 }
 const f=fixture(async i=>({runId:i.runId,invocationId:i.invocationId,toolKey:'audit.summarize_anomalies'}));
 await f.child.request({step:1,callId:'x',args:{limit:7}});
 await assert.rejects(f.child.request({step:1,callId:'x',args:{limit:7}}),{code:'AUDIT_POLICY_CHANNEL_INVALID'});
});
test('revocation and child disconnect reject pending work without publishing a receipt',async()=>{
 const f=fixture(async()=>{throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});});
 await assert.rejects(f.child.request({step:1,callId:'x',args:{limit:7}}));assert.equal(f.problem.code,'SHOP_AUTH_INVALID');assert.equal(f.parent.receipts.size,0);
 const channel=new EventEmitter();channel.connected=true;channel.send=()=>{};
 const child=createAuditPolicyChild(channel,{timeoutMs:50});const pending=child.request({step:1,callId:'x',args:{limit:7}});channel.emit('disconnect');await assert.rejects(pending,{code:'AUDIT_POLICY_CHANNEL_INVALID'});
});
test('channel request timeout rejects safely',async()=>{
 const channel=new EventEmitter();channel.connected=true;channel.send=()=>{};
 const child=createAuditPolicyChild(channel,{timeoutMs:5});await assert.rejects(child.request({step:1,callId:'x',args:{limit:7}}),{code:'AUDIT_POLICY_CHANNEL_INVALID'});
});

test('only task v2 admits optional literal focus and retains exact selected arguments for host trace comparison',async()=>{
 const chosen={focus_action:'listing_update',limit:7};let received;
 const f=fixture(async input=>{received=input.args;return {runId:input.runId,invocationId:input.invocationId,toolKey:'audit.summarize_anomalies'};},2);
 await f.child.request({step:1,callId:'focus',args:chosen});chosen.focus_action='changed';
 assert.deepEqual(received,{focus_action:'listing_update',limit:7});assert(Object.isFrozen(received));
 assert.deepEqual(f.parent.argumentsByInvocation.get('1:focus'),received);f.child.close();f.parent.close();
 for(const [version,args]of [[1,{limit:7,focus_action:'listing_update'}],[2,{limit:7,focus_action:'*'}],
  [2,{limit:7,focus_action:'a b'}],[2,{limit:7,focus_action:'valid',owner:9}],[2,{other:7}]]){
  const denied=fixture(()=>assert.fail(),version);await assert.rejects(denied.child.request({step:1,callId:'focus',args}));
  assert.equal(denied.problem.code,'AUDIT_POLICY_CHANNEL_INVALID');assert.equal(denied.parent.receipts.size,0);
 }
});
