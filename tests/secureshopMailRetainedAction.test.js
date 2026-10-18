'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createMailApplication}=require('../server/services/secureshopMailApplication');
const context={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
 platformOwnerId:1,platformSessionId:2},persona:{id:10,role:'merchant'},
 personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
const target={targetId:randomUUID(),scene:{sceneId:randomUUID(),sceneGeneration:1}};
const expectedTarget={targetId:target.targetId,sceneId:target.scene.sceneId,
 sceneGeneration:target.scene.sceneGeneration};
function fixture({requestHash='a'.repeat(64),computedHash='a'.repeat(64),
 receiptFound=true,terminal=null,rejected=null}={}){const calls=[];
 const app=createMailApplication({mode:'vuln',
  async resolveTarget(){calls.push('provision');throw Error('must not provision');},
  async readExistingTarget(){calls.push('retained');return target;},
  async readReadiness(){calls.push('readiness');throw Error('GET must not read readiness');},
  graph:{async run(){throw Error('GET must not run model');}},
  mailRepository:{
   async send(){calls.push('send');return {ok:true,receipt:{email_id:5,thread_id:5}};},
   async browse(){throw Error('GET must not browse');},
   async recover(binding){calls.push('recover');return receiptFound
    ?{found:true,operationId:binding.operationId,action:'send',
      receipt:{email_id:5,thread_id:5,recipientId:11},requestSha256:requestHash}
    :{found:false};},
   async readSavedSend(){calls.push('project');return {recipientId:11,to:'customer@example.test',
    subject:'Hello',body_markdown:'<b>literal</b>'};},
   async hashSendRequest(){calls.push('hash');return computedHash;},
  },
  recoveryRepository:{async readTerminal(){calls.push('terminal');return terminal;}},
  uncertainRepository:{async readRejected(){calls.push('rejected');return rejected;}}});
 return {app,calls};
}
test('fresh mail preparation establishes an owned scene grant without reading or sending mail',async()=>{
 const calls=[];let granted=false;
 const app=createMailApplication({mode:'vuln',
  async resolveTarget(){calls.push('resolve');granted=true;return target;},
  async readExistingTarget(){calls.push('retained');if(!granted)throw Object.assign(Error('Missing grant'),
   {code:'MAIL_SCENE_STALE'});return target;},
  async readReadiness(){calls.push('readiness');return {ready:true};},
  graph:{async run(){throw Error('No reply job');}},
  mailRepository:{async send(){throw Error('No send');},async browse(){throw Error('No browse');},
   async recover(){throw Error('No receipt recovery');}}});
 const withOuter={...context,target:{targetId:randomUUID(),scene:target.scene}};
 await assert.rejects(app.readRetainedTarget(withOuter),{code:'MAIL_SCENE_STALE'});
 assert.deepEqual(calls,['retained']);calls.length=0;
 const result=await app.prepareTarget(withOuter,{requestId:randomUUID()},
  {beforeEffect:()=>{calls.push('acl');}});
 assert.deepEqual(result,expectedTarget);
 assert.deepEqual(calls,['acl','readiness','resolve','acl']);
 assert.deepEqual(await app.readRetainedTarget(withOuter),expectedTarget);
});
test('saved send GET uses retained mail target and exact four-field projection only',async()=>{
 const f=fixture(),requestId=randomUUID();
 assert.deepEqual(await f.app.readRetainedTarget(context),expectedTarget);
 const result=await f.app.recoverRetained(context,{requestId,action:'send',expectedTarget});
 assert.equal(result.status,'saved');assert.deepEqual(result.savedSend,
  {recipientId:11,to:'customer@example.test',subject:'Hello',body_markdown:'<b>literal</b>'});
 assert.deepEqual(f.calls,['retained','retained','recover','project']);
});
test('retained send compares complete original SQL request hash, including hidden headers',async()=>{
 const expectedSend={from:'merchant@example.test',to:'customer@example.test',
  subject:'Hello',body_markdown:'<b>literal</b>'};
 const exact=fixture(),requestId=randomUUID();
 const saved=await exact.app.recoverRetained(context,{requestId,action:'send',expectedTarget,expectedSend});
 assert.equal(saved.status,'saved');assert.deepEqual(exact.calls,['retained','recover','project','hash']);
 const preempted=fixture({requestHash:'b'.repeat(64)});
 const other=await preempted.app.recoverRetained(context,{requestId:randomUUID(),action:'send',
  expectedTarget,expectedSend});
 assert.equal(other.status,'saved_unattributed');
 assert.deepEqual(other.savedSend,saved.savedSend);
 assert.equal(preempted.calls.includes('send'),false);
});
test('retained scene mismatch fails before receipt recovery or provisioning',async()=>{
 const f=fixture(),requestId=randomUUID();
 await assert.rejects(f.app.recoverRetained(context,{requestId,action:'send',
  expectedTarget:{...expectedTarget,sceneId:randomUUID()}}),{code:'MAIL_UNAVAILABLE'});
 assert.deepEqual(f.calls,['retained']);
});
test('derived reply send without exact completed graph source stays saved but unattributed',async()=>{
 const f=fixture(),requestId=randomUUID();
 const result=await f.app.recoverRetained(context,{requestId,action:'autoReply',expectedTarget,
  expectedSource:{threadId:5,messageId:4,sha256:'c'.repeat(64)}});
 assert.equal(result.status,'saved_unattributed');
 assert.equal(result.savedReply.body_markdown,'<b>literal</b>');
 assert.equal(f.calls.includes('send'),false);
});
test('retained reply decline requires the exact selected source and thread',async()=>{
 const expectedSource={threadId:5,messageId:4,sha256:'c'.repeat(64)};
 for(const terminal of [null,
  {decision:'declined',threadId:5,terminalNoSend:true},
  {decision:'declined',threadId:5,terminalNoSend:true,
   expectedSource:{...expectedSource,messageId:3}},
  {decision:'declined',threadId:6,terminalNoSend:true,expectedSource}]){
  const f=fixture({receiptFound:false,terminal});
  const result=await f.app.recoverRetained(context,{requestId:randomUUID(),action:'autoReply',
   expectedTarget,expectedSource});
  assert.equal(result.status,'unconfirmed');assert.equal(result.canRetrySameId,false);
  assert.equal(f.calls.includes('send'),false);
 }
 const f=fixture({receiptFound:false,terminal:{decision:'declined',threadId:5,
  terminalNoSend:true,expectedSource}});
 const result=await f.app.recoverRetained(context,{requestId:randomUUID(),action:'autoReply',
  expectedTarget,expectedSource});
 assert.equal(result.status,'declined');assert.equal(result.threadId,5);
});
test('retained reply does not attribute a source-less preexecution rejection',async()=>{
 const f=fixture({receiptFound:false,rejected:{threadId:5,stage:'prompt_policy_admission'}});
 const requestId=randomUUID(),expectedSource={threadId:5,messageId:4,sha256:'c'.repeat(64)};
 const result=await f.app.recoverRetained(context,{requestId,action:'autoReply',
  expectedTarget,expectedSource});
 assert.equal(result.status,'unconfirmed');assert.equal(result.canRetrySameId,false);
 assert.equal(f.calls.includes('send'),false);
 const legacy=await f.app.recoverRetained(context,{requestId,action:'autoReply',expectedTarget});
 assert.equal(legacy.status,'rejected_before_execution');
});
