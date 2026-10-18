'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {createBoundMailActions,createMailActionProposal,validateMailActionProposal,
 projectMailActionProposal,validateMailActionOperation}=require('../server/services/secureshopRoleMailActions');

const mailModeCapability={version:1,featureId:'mail',policyVersion:'owned-mail-recipient-header-and-html-v1',
 effectiveMode:'vuln',scope:{kind:'launch_feature',id:'mail'}};
const outerModeCapability={version:1,featureId:'merchant_assistant',policyVersion:'owned-merchant-read-and-confirmation-v1',
 effectiveMode:'vuln',scope:{kind:'launch_feature',id:'merchant_assistant'}};
const sender={id:10,username:'merchant',email:'merchant@example.test',role:'merchant'};
const recipient={id:11,username:'customer',email:'customer@example.test',role:'customer'};
const mailScene={targetId:randomUUID(),sceneId:randomUUID(),sceneGeneration:1};
const context={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
 platformOwnerId:1,platformSessionId:2},persona:{id:10,role:'merchant'},
 personaSession:{sessionId:randomUUID(),authorityVersion:'1'},
 target:{targetId:randomUUID(),scene:{sceneId:randomUUID(),sceneGeneration:1}}};
const source={sessionId:randomUUID(),requestId:randomUUID()},origin={step:2,callId:'call-2'};
function choice(action){const snapshot=action==='send'
 ?{version:1,kind:'recipients',recipients:[recipient],hasMore:false,mailModeCapability}
 :{version:1,kind:'list',readOperationId:randomUUID(),mailModeCapability,
   receiptSha256:'a'.repeat(64),recipient:sender,offset:0,total:1,hasMore:false,
   headers:[{id:15,threadId:14,from:recipient.email,to:sender.email,
    subject:'Question',createdAt:'2026-10-11T00:00:00Z',sha256:'b'.repeat(64)}]};
 return {version:1,kind:action==='send'?'merchant_mail_recipient':'merchant_mail_message',
  choiceId:randomUUID(),sourceId:action==='send'?recipient.id:15,
  snapshotSha256:canonicalDigest(snapshot),snapshot,card:{version:1,kind:'card',choiceId:randomUUID(),title:'x',detail:'y'}};
}
function fixture(){const calls=[];let actors=[sender,recipient],granted=false;
 const mailApplication={
  async readiness(){calls.push('readiness');return {ready:true,modeCapability:mailModeCapability};},
  async prepareTarget(_context,{requestId},options){calls.push('prepareTarget');
   assert.equal(requestId,source.requestId);await options?.beforeEffect?.();granted=true;return mailScene;},
  async readRetainedTarget(){calls.push('retained');if(!granted)throw Object.assign(Error('Missing grant'),
   {code:'MAIL_SCENE_STALE'});return mailScene;},
  async send(_context,input,options){calls.push('send');assert.deepEqual(options.expectedTarget,mailScene);
   assert.equal(input.from,sender.email);return {ok:true,receipt:{email_id:30,thread_id:30}};},
  async reply(_context,input,options){calls.push('reply');assert.deepEqual(options.expectedSource,
   {threadId:14,messageId:15,sha256:'b'.repeat(64)});
   assert.equal(input.threadId,14);return {ok:true,status:'declined'};},
  async recoverRetained(_context,input){calls.push('recover');assert.deepEqual(input.expectedTarget,mailScene);
   if(input.action==='autoReply')return {ok:true,status:'declined'};
   return {ok:true,status:'saved',email_id:30,thread_id:30,
    savedSend:{recipientId:recipient.id,to:recipient.email,subject:'Hello',body_markdown:'<b>literal</b>'}};},
 };
 const adapter=createBoundMailActions({mailApplication,listMailActors:async()=>actors,mode:'vuln'});
 return {adapter,calls,setActors:value=>{actors=value;}};
}
test('mail preparation freezes literal bytes and source without a send or reply effect',async()=>{
 const f=fixture(),selected=choice('send');
 await assert.rejects(f.adapter.reconstruct({context,source,origin,selected,action:'send',
  input:{subject:'Hello',body_markdown:'<b>literal</b>'},modeCapability:outerModeCapability,
  mailModeCapability,savedProposal:createMailActionProposal({context,source,origin,selected,
   action:'send',input:{subject:'Hello',body_markdown:'<b>literal</b>'},
   modeCapability:outerModeCapability,mailModeCapability,sender,mailScene})}),
 {code:'MAIL_SCENE_STALE'},'saved GET never establishes a missing grant');
 assert.deepEqual(f.calls,['retained']);f.calls.length=0;
 const proposal=await f.adapter.prepare({context,source,origin,selected,action:'send',
  input:{subject:'Hello',body_markdown:'<b>literal</b>'},modeCapability:outerModeCapability});
 assert.deepEqual(f.calls,['readiness','prepareTarget']);
 assert.equal(proposal.send.body_markdown,'<b>literal</b>');
 assert.deepEqual(projectMailActionProposal(proposal),{version:1,kind:'merchant_mail_proposal',
  action:'send',proposalId:proposal.proposalId,recipient:{username:'customer',email:recipient.email},
  subject:'Hello',body_markdown:'<b>literal</b>',source:null});
 const rebuilt=createMailActionProposal({context,source,origin,selected,action:'send',
  input:{subject:'Hello',body_markdown:'<b>literal</b>'},modeCapability:outerModeCapability,
  mailModeCapability,sender,mailScene});
 assert.deepEqual(rebuilt,proposal);
 assert.throws(()=>validateMailActionProposal({...proposal,send:{...proposal.send,to:'other@example.test'}}),
  {code:'ROLE_MAIL_ACTION_INVALID'});
 const saved=await f.adapter.confirm({context,proposal,beforeEffect:()=>f.calls.push('acl')});
 assert.equal(saved.status,'saved');assert.equal(saved.sendOperationId,proposal.proposalId);
 assert.deepEqual(saved.savedSend,{recipientId:recipient.id,to:recipient.email,subject:'Hello',body_markdown:'<b>literal</b>'});
 assert(f.calls.indexOf('acl')<f.calls.indexOf('send'));
 assert.equal(f.calls.filter(name=>name==='send').length,1);
});
test('reply proposal authorizes only a source-bound future agent job; retained read is effect-free',async()=>{
 const f=fixture(),selected=choice('reply');
 const proposal=await f.adapter.prepare({context,source,origin,selected,action:'reply',
  input:{},modeCapability:outerModeCapability});
 assert.deepEqual(proposal.expectedSource,{threadId:14,messageId:15,sha256:'b'.repeat(64)});
 assert.deepEqual(projectMailActionProposal(proposal).source,
  {from:recipient.email,subject:'Question',createdAt:'2026-10-11T00:00:00Z'});
 assert.equal((await f.adapter.confirm({context,proposal})).status,'declined');
 assert.equal(f.calls.filter(name=>name==='reply').length,1);
 const savedSender={...sender,username:'changed display'};
 f.setActors([savedSender,recipient]);
 const rebuilt=await f.adapter.reconstruct({context,source,origin,selected,action:'reply',input:{},
  modeCapability:outerModeCapability,mailModeCapability,savedProposal:proposal});
 assert.deepEqual(rebuilt,proposal,'saved GET reconstructs from original frozen sender');
 const reads=f.calls.length;
 await f.adapter.recover({context,proposal});
 assert.equal(f.calls.filter(name=>name==='send').length,0);
 assert.equal(f.calls.filter(name=>name==='reply').length,1);
 assert.equal(f.calls.length,reads+2,'retained target plus receipt read only');
});
test('foreign same-target mailbox remains inspectable but cannot prepare a caller reply job',async()=>{
 const f=fixture(),selected=choice('reply');
 selected.snapshot.recipient=recipient;
 selected.snapshotSha256=canonicalDigest(selected.snapshot);
 await assert.rejects(f.adapter.prepare({context,source,origin,selected,action:'reply',
  input:{},modeCapability:outerModeCapability}),{code:'ROLE_MAIL_SOURCE_UNAVAILABLE'});
 assert.equal(f.calls.filter(name=>name==='reply'||name==='send').length,0);
});
test('operation validator pins saved send ID and keeps unknown outcomes unknown',()=>{
 const proposalId=randomUUID(),base={version:1,kind:'merchant_mail_operation',action:'send',proposalId,
  status:'unconfirmed',sendOperationId:null,emailId:null,threadId:null,savedSend:null,canRetrySameId:true};
 assert.deepEqual(validateMailActionOperation(base),base);
 assert.throws(()=>validateMailActionOperation({...base,status:'saved',sendOperationId:randomUUID(),
  emailId:1,threadId:1,savedSend:{recipientId:1,to:'x',subject:'y',body_markdown:''},canRetrySameId:false}),
  {code:'ROLE_MAIL_OPERATION_INVALID'});
 const preempted={...base,status:'saved_unattributed',sendOperationId:proposalId,
  emailId:1,threadId:1,savedSend:{recipientId:1,to:'x',subject:'y',body_markdown:''},
  canRetrySameId:false};
 assert.deepEqual(validateMailActionOperation(preempted),preempted);
});
