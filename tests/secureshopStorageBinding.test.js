'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
async function binding(){const {createShopStorageBinding}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');const local=new Map();return createShopStorageBinding({local:{getItem:k=>local.get(k)??null,setItem:(k,v)=>local.set(k,v),removeItem:k=>local.delete(k)}});}
test('storage binding retains local behavior and delegates frame writes and flush explicitly',async()=>{
 const b=await binding();b.storage.setItem('secureshop_v2_token','local');assert.equal(b.storage.getItem('secureshop_v2_token'),'local');await b.flush();
 const values=new Map();let flushed=false;
 const release=b.attach({getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k),async flush(){flushed=true;}});
 assert.equal(b.storage.getItem('secureshop_v2_token'),null);b.storage.setItem('secureshop_v2_token','frame');await b.flush();assert.equal(flushed,true);assert.equal(values.get('secureshop_v2_token'),'frame');
 release();assert.throws(()=>b.storage.getItem('secureshop_v2_token'),{name:'AbortError'});await assert.rejects(b.flush(),{name:'AbortError'});
});
test('strict frame failures never resurrect local state; stale release cannot detach a new binding',async()=>{
 const b=await binding();b.storage.setItem('secureshop_v2_token','stale');
 const adapter={getItem(){throw Error('revoked');},setItem(){throw Error('quota');},removeItem(){throw Error('revoked');},flush(){throw Error('not saved');}};
 const first=b.attach(adapter);assert.throws(()=>b.attach(adapter));assert.throws(()=>b.storage.getItem('secureshop_v2_token'),/revoked/);assert.throws(()=>b.storage.setItem('secureshop_v2_token','new'),/quota/);await assert.rejects(b.flush(),/not saved/);
 assert.throws(()=>b.storage.getItem('platform_token'),/Unsupported/);first();const second=b.attach({...adapter,getItem:()=> 'fresh'});first();assert.equal(b.storage.getItem('secureshop_v2_token'),'fresh');second();
});

test('disconnect disables the credential source and closes attached state before reattachment',async()=>{
 const b=await binding();let closed=false;
 const release=b.attach({getItem:()=> 'unacknowledged-jwt',setItem(){},removeItem(){},flush(){},close(){closed=true;}});
 b.disconnect();assert.equal(closed,true);assert.throws(()=>b.storage.getItem('secureshop_v2_token'),{name:'AbortError'});
 const next=b.attach({getItem:()=> 'new-launch',setItem(){},removeItem(){},flush(){}});release();assert.equal(b.storage.getItem('secureshop_v2_token'),'new-launch');next();
});
