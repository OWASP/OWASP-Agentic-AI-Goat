'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const mailScene=require('../server/services/secureshopMailSceneBinding');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const {createSecureShopMailInlineBindingRepository}=require('../server/database/postgres/secureshopMailInlineBindingRepository');
const hex=seed=>seed.repeat(64).slice(0,64);
function httpRecord(binding,summaryRequestId){
 const source={readOperationId:randomUUID(),receiptSha256:hex('d'),bodyHtmlSha256:hex('e')};
 const targetReceipt={version:1,issuanceId:binding.issuanceId,sendOperationId:binding.sendOperationId,targetId:binding.targetId,
  listenerTargetId:binding.listenerTargetId,nonceSha256:binding.nonceSha256,path:binding.path,resourceKind:binding.resourceKind,
  urlSha256:binding.urlSha256,method:'GET',status:200,responseSha256:hex('f'),receiptSha256:hex('1')};
 return {version:1,binding,source,targetReceipt,runId:randomUUID(),ownerKey:'merchant:11',generation:'0',sessionId:randomUUID(),
  summaryRequestId,callId:'summary:1',effectKey:`${summaryRequestId}:[1,\"summary:1\",\"email.summarize_thread\"]`,
  parsedResultSha256:hex('2'),observationSha256:hex('3')};
}
function fixture(){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:9};
 const targetId=randomUUID(),sessionId=randomUUID(),grantId=randomUUID(),sceneId=randomUUID();
 const sceneBinding=createSceneBinding({...scope,targetId},{sceneId,sceneGeneration:1,grantId,execution:scope,withLease:work=>work()});
 const target=mailScene.attach({...scope,targetId},sceneBinding);
 const events=[];let revoked=false;let next=null;
 const client={query:async(sql,args=[])=>{events.push({sql,args});
  if(sql.includes('SET LOCAL'))return{rows:[]};
  if(sql.includes('assert_mail_scene_execution_grant'))return{rows:[{allowed:true}]};
  if(sql.includes('save_bound_mail_inline'))return{rows:[{result:next}]};
  if(sql.includes('read_bound_mail_inline_binding'))return{rows:[{result:next}]};
  if(sql.includes('record_bound_mail_inline_http_invocation'))return{rows:[{result:next}]};
  if(sql.includes('read_bound_mail_inline_http_invocation'))return{rows:[{result:next}]};
  throw Error('unexpected query');
 }};
 const personaAuthority={capture(binding){return{binding:{...binding.scope,personaId:binding.personaId,role:binding.role,sessionId:binding.sessionId,authorityVersion:binding.authorityVersion},
  async withPersonaEffect(work){events.push({effect:true});return work(client);},
  async assertRemoteAdmission(){events.push({admission:true});if(revoked)throw Object.assign(Error('revoked'),{code:'REVOKED'});}
 };}};
 const repo=createSecureShopMailInlineBindingRepository({pool:{connect:async()=>client},personaAuthority,
  verifyPendingReservation:async(raw,value)=>{events.push({pending:{raw,value}});return pending;}});
 const operationId=randomUUID(),issuanceId=randomUUID(),listenerTargetId=randomUUID();
 const raw={scope,targetId,target,persona:{id:11,role:'merchant'},personaSession:{sessionId,authorityVersion:'1'},mode:'vuln',operationId};
 const reservation={issuanceId,listenerTargetId,nonceSha256:hex('a'),path:'/inline/a',resourceKind:'mail_inline_image_v1',urlSha256:hex('b')};
 let pending=reservation;
 const binding={...reservation,sendOperationId:operationId,targetId,messageId:22,messageSha256:hex('c'),threadId:22,recipientId:12};
 const payload={from:'merchant@example.test',to:'customer@example.test',subject:'Teaching',body_markdown:'<img>',body_html:'<img>',headers_raw:'From: merchant@example.test\r\nTo: customer@example.test\r\nSubject: Teaching'};
 return{repo,raw,reservation,binding,payload,events,set(v){next=v;},setPending(v){pending=v;},revoke(){revoked=true;}};
}
test('saveTeachingMessage uses only the private wrapper and returns the exact immutable binding',async()=>{
 const f=fixture();f.set({send:{operationId:f.raw.operationId,replayed:false,receipt:{email_id:22,thread_id:22,recipientId:12,contentSha256:hex('c')}},binding:f.binding});
 const got=await f.repo.saveTeachingMessage(f.raw,{reservation:f.reservation,payload:f.payload});
 assert.equal(got.binding.issuanceId,f.reservation.issuanceId);assert.equal(got.binding.sendOperationId,f.raw.operationId);
 const call=f.events.find(e=>e.sql?.includes('save_bound_mail_inline'));assert.ok(call);assert.equal(call.args[11],f.raw.operationId);assert.equal(call.args[14],f.reservation.issuanceId);
 assert.equal(f.events.filter(e=>e.pending).length,1);assert.equal(f.events.find(e=>e.pending).pending.raw.operationId,f.raw.operationId);
 assert.equal(f.events.some(e=>e.sql?.includes('bound_lab_mail(')),false);assert.equal(f.events.at(-1).admission,true);
});
test('generic receipt or descriptor substitution is rejected before a caller can treat it as bound',async()=>{
 const f=fixture();f.set({send:{operationId:f.raw.operationId,replayed:true,receipt:{email_id:22,thread_id:22,recipientId:12,contentSha256:hex('c')}},binding:{...f.binding,path:'/other'}});
 await assert.rejects(f.repo.saveTeachingMessage(f.raw,{reservation:f.reservation,payload:f.payload}),{code:'MAIL_INLINE_BINDING_INVALID'});
 await assert.rejects(f.repo.saveTeachingMessage(f.raw,{reservation:{...f.reservation,path:'https://x'},payload:f.payload}),{code:'INVALID_ARGUMENT'});
});
test('a structurally valid but non-pending reservation is rejected before the private save call',async()=>{
 const f=fixture();f.setPending({...f.reservation,path:'/other'});
 await assert.rejects(f.repo.saveTeachingMessage(f.raw,{reservation:f.reservation,payload:f.payload}),{code:'MAIL_INLINE_BINDING_INVALID'});
 assert.equal(f.events.some(event=>event.sql?.includes('save_bound_mail_inline')),false);
});
test('invocation accepts canonical durable generation zero and rejects noncanonical or negative forms',async()=>{
 const f=fixture(),summaryRaw={...f.raw,operationId:randomUUID()},record=httpRecord(f.binding,summaryRaw.operationId);
 f.set(record);const saved=await f.repo.recordInvocation(summaryRaw,record);assert.equal(saved.generation,'0');
 for(const generation of ['-1','00','01','1.0','']){
  const g=fixture(),current={...g.raw,operationId:randomUUID()};
  await assert.rejects(g.repo.recordInvocation(current,{...httpRecord(g.binding,current.operationId),generation}),{code:'MAIL_INLINE_INVOCATION_INVALID'});
 }
});
test('readBound is SELECT-only and fences the selected immutable source',async()=>{
 const f=fixture();f.set(f.binding);const got=await f.repo.readBound(f.raw,{messageId:22,messageSha256:hex('c'),recipientId:12});
 assert.equal(got.path,'/inline/a');const call=f.events.find(e=>e.sql?.includes('read_bound_mail_inline_binding'));assert.ok(call);assert.equal(call.args[11],22);assert.equal(call.args[13],12);
 assert.equal(f.events.some(e=>e.sql?.includes('save_bound_mail_inline')),false);
});
test('revocation is surfaced after the private read rather than returning stale evidence',async()=>{
 const f=fixture();f.set(f.binding);f.revoke();await assert.rejects(f.repo.readBound(f.raw,{messageId:22,messageSha256:hex('c'),recipientId:12}),{code:'REVOKED'});
});
test('only the merchant Inbox authority can invoke private save or retained binding reads',async()=>{
 const f=fixture();f.set(f.binding);const customer={...f.raw,persona:{...f.raw.persona,role:'customer'}};
 await assert.rejects(f.repo.saveTeachingMessage(customer,{reservation:f.reservation,payload:f.payload}),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(f.repo.readBound(customer,{messageId:22,messageSha256:hex('c'),recipientId:12}),{code:'SHOP_AUTH_INVALID'});
 assert.equal(f.events.some(event=>event.sql?.includes('bound_mail_inline')),false);
});
test('the exact HTTP observation is append-only under the later summary identity',async()=>{
 const f=fixture(),summaryRaw={...f.raw,operationId:randomUUID()},record=httpRecord(f.binding,summaryRaw.operationId);f.set(record);
 const saved=await f.repo.recordInvocation(summaryRaw,record);
 assert.deepEqual(saved,record);
 const call=f.events.find(event=>event.sql?.includes('record_bound_mail_inline_http_invocation'));
 assert.ok(call);assert.equal(call.args[11],summaryRaw.operationId);assert.equal(call.args[21],f.binding.issuanceId);
});
test('saved invocation reads are select-only, current-bound, and reject altered receipt domains',async()=>{
 const f=fixture(),summaryRaw={...f.raw,operationId:randomUUID()},record=httpRecord(f.binding,summaryRaw.operationId);f.set(record);
 const saved=await f.repo.readInvocation(summaryRaw,{summaryRequestId:summaryRaw.operationId});
 assert.deepEqual(saved,record);assert.equal(f.events.some(event=>event.sql?.includes('record_bound_mail_inline_http_invocation')),false);
 await assert.rejects(f.repo.recordInvocation(summaryRaw,{...record,targetReceipt:{...record.targetReceipt,responseSha256:hex('4')}}),{code:'MAIL_INLINE_RECORD_UNCERTAIN'});
});
