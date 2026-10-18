'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const {createBoundMailChat,validateMailChatResult}=require('../server/services/secureshopRoleMailRead');

const requestId='11111111-1111-4111-8111-111111111111';
const capability={version:1,featureId:'mail',policyVersion:'owned-mail-recipient-header-and-html-v1',
 effectiveMode:'vuln',scope:{kind:'launch_feature',id:'mail'}};
const self={id:10,username:'merchant',email:'merchant@example.test',role:'merchant'};
const other={id:11,username:'colleague',email:'colleague@example.test',role:'merchant'};
const context={scope:{launchId:'22222222-2222-4222-8222-222222222222',
 scenarioId:'33333333-3333-4333-8333-333333333333',generation:1,platformOwnerId:1,
 platformSessionId:1},persona:{id:10,role:'merchant'},personaSession:{sessionId:'44444444-4444-4444-8444-444444444444',authorityVersion:'1'}};
const sha='a'.repeat(64),receiptSha256='b'.repeat(64);
const header={id:7,threadId:7,from:'sender@example.test',to:other.email,
 subject:'Saved message',createdAt:'2026-10-11T00:00:00Z',sha256:sha};
const headerFor=id=>({...header,id,threadId:id,subject:`Saved message ${id}`});
const message={...headerFor(7),bodyMarkdown:'hello',bodyHtml:'<p>hello</p>',headersRaw:'From: sender',
 sourceBytes:Buffer.byteLength('hello<p>hello</p>From: sender'),oversized:false};
function fixture(){
 const calls={disclose:0,project:[],before:0};
 const application={
  async readiness(){return{ready:true,modeCapability:capability};},
  async disclose(_context,{requestId:operation,userId}){calls.disclose++;
   assert.equal(operation,requestId);assert.equal(userId,other.id);
   return{receipt:{userId,messages:[2,3,4,5,6,7].map(id=>({id,sha256:sha}))},
    emails:[{body_markdown:'raw source'}],mailModeCapability:capability};},
  async projectDisclosure(_context,{requestId:operation,messageId=null,offset=0}){
   calls.project.push({operation,messageId,offset});
   const base={readOperationId:operation,recipientId:other.id,receiptSha256,total:6};
   return messageId===null?{...base,kind:'page',offset,
    headers:(offset===0?[7,6,5,4,3]:[2]).map(headerFor),nextOffset:offset===0?5:null,
    mailModeCapability:capability}:{...base,kind:'detail',message,mailModeCapability:capability};
  },
 };
 const adapter=createBoundMailChat({mailApplication:application,
  listMailActors:async()=>[self,other],mode:'vuln'});
 return{adapter,calls};
}
test('merchant mail read uses one durable disclosure and receipt-bound saved detail',async()=>{
 const {adapter,calls}=fixture();
 const recipients=await adapter.recipients({context,search:'colleague'});
 assert.equal(recipients.kind,'recipients');assert.deepEqual(recipients.recipients,[other]);
 const list=await adapter.list({context,recipient:recipients.recipients[0],requestId,
  beforeEffect:()=>{calls.before++;}});
 assert.equal(list.kind,'list');assert.deepEqual(list.headers,[7,6,5,4,3].map(headerFor));
 assert.equal(list.hasMore,true);
 assert.equal(JSON.stringify(list).includes('raw source'),false);
 const older=await adapter.page({context,packet:list,offset:5});
 assert.deepEqual(older.headers,[headerFor(2)]);assert.equal(older.hasMore,false);
 const detail=await adapter.detail({context,packet:list,messageId:7});
 assert.equal(detail.status,'complete');assert.equal(detail.message.bodyMarkdown,'hello');
 assert.deepEqual(await adapter.verify({context,packet:list}),list);
 assert.deepEqual(await adapter.verify({context,packet:detail}),detail);
 assert.equal(calls.disclose,1);assert.equal(calls.before,1);
 assert.deepEqual(calls.project.map(row=>row.messageId),[null,null,7,null,7]);
});
test('recipient snapshot and receipt changes fail closed; oversized saved detail has no source',async()=>{
 const {adapter}=fixture();
 await assert.rejects(adapter.list({context,recipient:{...other,email:'wrong@example.test'},requestId}),
  {code:'ROLE_MAIL_RECIPIENT_STALE'});
 const list=await adapter.list({context,recipient:other,requestId});
 await assert.rejects(adapter.verify({context,packet:{...list,receiptSha256:'c'.repeat(64)}}),
  {code:'ROLE_MAIL_RECEIPT_MISMATCH'});
 const oversized={version:1,kind:'detail',readOperationId:requestId,
  mailModeCapability:capability,receiptSha256,recipient:other,messageId:7,
  messageSha256:sha,status:'oversized',message:null};
 assert.deepEqual(validateMailChatResult(oversized),oversized);
 assert.deepEqual(await adapter.verify({context,packet:oversized}),oversized);
});
test('selected recipient cannot carry an old mail mode into disclosure',async()=>{
 let reads=0;
 const fixedAuthority={capture:async()=>({snapshot:{version:1,featureId:'mail',
  policyVersion:'owned-mail-recipient-header-and-html-v1',mode:'fixed'},assertCurrent:async()=>{}}),
  assertToken:token=>token};
 const adapter=createBoundMailChat({mailApplication:{readiness:async()=>({ready:true}),
  disclose:async()=>{reads++;throw Error('must not disclose');},projectDisclosure:async()=>{}},
  listMailActors:async()=>[self,other],modeAuthority:fixedAuthority,mode:'vuln'});
 await assert.rejects(adapter.list({context,recipient:other,mailModeCapability:capability,requestId}),
  {code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(reads,0);
});
