'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto'),{MessageChannel}=require('node:worker_threads');
test('mail opaque refs cross the actual acknowledged frame channel and preserve other workflows',async()=>{
 const {createScopedShopStateStore}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');const {createHostShopStateChannel,connectFrameShopState}=await import('../client/src/pages/secureshop/bridge/stateChannel.mjs');const {SHOP_MAIL_KEY,createShopStorage}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');const {decodeMailReferences,updateMailReference}=await import('../client/src/pages/secureshop/bridge/mailReferences.mjs');
 const values=new Map(),storage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)},scenarioId=randomUUID();
 const store=createScopedShopStateStore({storage,scenarioId,generation:1,isCurrent:()=>true}),ports=new MessageChannel(),host=createHostShopStateChannel({port:ports.port1,store}),frame=await connectFrameShopState({port:ports.port2,timeoutMs:1000});
 try{assert.equal(frame.getItem(SHOP_MAIL_KEY),null);frame.setItem('ss_guest_cart','[{"id":7}]');const scope='a'.repeat(64),ref={action:'autoReply',requestId:randomUUID(),digest:'b'.repeat(64)},encoded=updateMailReference(null,scope,'pending',ref);frame.setItem(SHOP_MAIL_KEY,encoded);await frame.flush();const actual=JSON.parse(values.get(`dvaia:secureshop:${scenarioId}:1`));assert.deepEqual(decodeMailReferences(actual[SHOP_MAIL_KEY]).scopes[scope].pending,ref);assert.equal(actual.ss_guest_cart,'[{"id":7}]');
 const next=updateMailReference(frame.getItem(SHOP_MAIL_KEY),scope,'assessment',{requestId:randomUUID(),replyOperationId:ref.requestId,threadId:4});frame.setItem(SHOP_MAIL_KEY,next);await frame.flush();assert.equal(decodeMailReferences(frame.getItem(SHOP_MAIL_KEY)).scopes[scope].assessment.threadId,4);
 const header={requestId:randomUUID(),sendOperationId:randomUUID()};frame.setItem(SHOP_MAIL_KEY,updateMailReference(frame.getItem(SHOP_MAIL_KEY),scope,'headerAssessment',header));await frame.flush();assert.deepEqual(decodeMailReferences(JSON.parse(values.get(`dvaia:secureshop:${scenarioId}:1`))[SHOP_MAIL_KEY]).scopes[scope].headerAssessment,header);
 assert.throws(()=>frame.setItem(SHOP_MAIL_KEY,JSON.stringify({...JSON.parse(next),body:'private source'})));
 const strict=createShopStorage({getStorage:()=>({getItem(){throw Error('opaque');},setItem(){throw Error('quota');},removeItem(){throw Error('quota');}})});assert.throws(()=>strict.getItem(SHOP_MAIL_KEY));assert.throws(()=>strict.setItem(SHOP_MAIL_KEY,next));
 }finally{frame.close();host.close();}
});
test('mail codec rejects authority/raw content and bounds unknown refs without active eviction',async()=>{
 const {decodeMailReferences,updateMailReference}=await import('../client/src/pages/secureshop/bridge/mailReferences.mjs');const reference={action:'send',requestId:randomUUID(),digest:'a'.repeat(64)};let value=null;
 for(let i=1;i<=8;i++)value=updateMailReference(value,i.toString(16).repeat(64),'pending',reference);
 assert.throws(()=>updateMailReference(value,'9'.repeat(64),'pending',reference));assert.equal(Object.keys(decodeMailReferences(value).scopes).length,8);
 for(const field of ['token','body_html','ownerId','completed'])assert.throws(()=>updateMailReference(null,'a'.repeat(64),'pending',{...reference,[field]:'forged'}));assert.throws(()=>decodeMailReferences(' '.repeat(8193)));assert.deepEqual(decodeMailReferences(null),{version:3,scopes:{}});
});
test('version2 header references migrate legacy opaque reply state and reject content or forged identity fields',async()=>{
 const {decodeMailReferences,updateMailReference}=await import('../client/src/pages/secureshop/bridge/mailReferences.mjs');const scope='a'.repeat(64),reply={requestId:randomUUID(),replyOperationId:randomUUID(),threadId:4},header={requestId:randomUUID(),sendOperationId:randomUUID()};
 const legacy=JSON.stringify({version:1,scopes:{[scope]:{pending:null,assessment:reply}}});assert.deepEqual(decodeMailReferences(legacy).scopes[scope].assessment,reply);
 const next=decodeMailReferences(updateMailReference(legacy,scope,'headerAssessment',header));assert.equal(next.version,3);assert.deepEqual(next.scopes[scope].assessment,reply);assert.deepEqual(next.scopes[scope].headerAssessment,header);
 for(const key of ['subject','headers_raw','ownerId','token','completed','replyOperationId'])assert.throws(()=>updateMailReference(legacy,scope,'headerAssessment',{...header,[key]:'forged'}));
 assert.throws(()=>updateMailReference(legacy,scope,'headerAssessment',{...header,requestId:header.sendOperationId}));assert.throws(()=>updateMailReference(legacy,scope,'headerAssessment',{...header,evaluationId:'invalid'}));
});

test('disclosure recovery stores closed distinct IDs and confirmation without message content',async()=>{
 const {decodeMailReferences,updateMailReference}=await import('../client/src/pages/secureshop/bridge/mailReferences.mjs');
 const scope='b'.repeat(64),reference={requestId:randomUUID(),readOperationId:randomUUID(),userId:99,confirmed:false};
 const raw=updateMailReference(null,scope,'disclosureAssessment',reference);assert.deepEqual(decodeMailReferences(raw).scopes[scope].disclosureAssessment,reference);
 for(const bad of [{...reference,requestId:reference.readOperationId},{...reference,confirmed:'yes'},{...reference,emails:[]}])assert.throws(()=>updateMailReference(null,scope,'disclosureAssessment',bad));
});
