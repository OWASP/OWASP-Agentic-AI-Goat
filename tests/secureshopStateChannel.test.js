'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
async function setup(storage) {
 const {createScopedShopStateStore}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const {createHostShopStateChannel,connectFrameShopState}=await import('../client/src/pages/secureshop/bridge/stateChannel.mjs');
 const values=new Map();storage ||= {getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v)};
 let current=true;
 const store=createScopedShopStateStore({storage,scenarioId:'11111111-1111-4111-8111-111111111111',generation:1,isCurrent:()=>current});
 const ports=new MessageChannel();const host=createHostShopStateChannel({port:ports.port1,store});
 const frame=await connectFrameShopState({port:ports.port2,timeoutMs:1000});
 return {host,frame,storage,revoke(){current=false;}};
}

test('acknowledged state writes preserve synchronous shop reads and persist into a new frame',async()=>{
 const first=await setup();let second;
 try {
  first.frame.setItem('secureshop_v2_token','forged-shop-jwt');
  first.frame.setItem('ss_guest_cart','[{"id":7}]');
  assert.equal(first.frame.getItem('secureshop_v2_token'),'forged-shop-jwt');
  await first.frame.flush();
  second=await setup(first.storage);
  assert.equal(second.frame.getItem('secureshop_v2_token'),'forged-shop-jwt');
  assert.equal(second.frame.getItem('ss_guest_cart'),'[{"id":7}]');
  assert.throws(()=>second.frame.setItem('platform_token','secret'));
  second.frame.removeItem('secureshop_v2_token');await second.frame.flush();
 }finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}
});

test('storage failure and revoked authority reject flush instead of reporting durable success',async()=>{
 for(const quota of [false,true]){
  const f=await setup(quota?{getItem:()=>null,setItem(){throw Error('private filesystem details');}}:undefined);
  try{
   if(!quota)f.revoke();f.frame.setItem('ss_guest_cart','[]');
   await assert.rejects(f.frame.flush(),/not saved/);
   assert.throws(()=>f.frame.setItem('ss_guest_cart','[]'),/not saved/);
  }finally{f.frame.close();f.host.close();}
 }
});

test('host shutdown cancels pending state and disables subsequent reads',async()=>{
 const f=await setup();
 f.frame.setItem('ss_guest_cart','[]');const pending=f.frame.flush();
 f.host.close();
 await assert.rejects(pending,{name:'AbortError'});
 assert.throws(()=>f.frame.getItem('ss_guest_cart'),{name:'AbortError'});
 await assert.rejects(f.frame.flush(),{name:'AbortError'});f.frame.close();
});

test('bounded optional user operation persists through acknowledged parent channel without exposing platform keys', async () => {
 const {createScopedShopStateStore}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const {createHostShopStateChannel,connectFrameShopState}=await import('../client/src/pages/secureshop/bridge/stateChannel.mjs');
 const {MessageChannel}=require('node:worker_threads');const values=new Map();
 const storage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v)};
 const make=async()=>{const c=new MessageChannel(),host=createHostShopStateChannel({port:c.port1,store:createScopedShopStateStore({storage,scenarioId:'10000000-0000-4000-8000-000000000001',generation:1,isCurrent:()=>true})});return{host,frame:await connectFrameShopState({port:c.port2})};};
 const one=await make();assert.equal(one.frame.getItem('ss_user_admin_pending'),null);
 one.frame.setItem('ss_user_admin_pending','{"operationId":"owned-role-change"}');await one.frame.flush();one.frame.close();one.host.close();
 const two=await make();assert.equal(two.frame.getItem('ss_user_admin_pending'),'{"operationId":"owned-role-change"}');
 assert.throws(()=>two.frame.setItem('ss_user_admin_pending','x'.repeat(8193)),/limit/);
 assert.throws(()=>two.frame.setItem('platform_token','secret'));
 two.frame.removeItem('ss_user_admin_pending');await two.frame.flush();two.frame.close();two.host.close();
});

test('last completed customer chat pointer survives parent ACK without storing transcript authority',async()=>{
 const {SHOP_CUSTOMER_CHAT_COMPLETED_KEY}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const row={shopUserId:7,sessionId:'11111111-1111-4111-8111-111111111111',
  requestId:'22222222-2222-4222-8222-222222222222',startedAt:1};
 const raw=JSON.stringify({version:1,references:[row]});
 const first=await setup();let second;
 try{
  first.frame.setItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY,raw);await first.frame.flush();
  second=await setup(first.storage);
  assert.equal(second.frame.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY),raw);
  assert.throws(()=>second.frame.setItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY,
   JSON.stringify({version:1,references:[{...row,reply:'untrusted transcript'}]})));
  second.frame.removeItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY);await second.frame.flush();
  assert.equal(second.frame.getItem(SHOP_CUSTOMER_CHAT_COMPLETED_KEY),null);
 }finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}
});

test('last completed role assistant pointer survives parent ACK with no transcript or model payload',async()=>{
 const {SHOP_ROLE_ASSISTANT_COMPLETED_KEY}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const row={role:'merchant',shopUserId:7,
  sessionId:'11111111-1111-4111-8111-111111111111',
  requestId:'22222222-2222-4222-8222-222222222222',startedAt:1};
 const raw=JSON.stringify({version:1,references:[row]});
 const first=await setup();let second;
 try{
  first.frame.setItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY,raw);await first.frame.flush();
  second=await setup(first.storage);
  assert.equal(second.frame.getItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY),raw);
  assert.throws(()=>second.frame.setItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY,
   JSON.stringify({version:1,references:[{...row,cards:['untrusted']}]})));
  second.frame.removeItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY);await second.frame.flush();
  assert.equal(second.frame.getItem(SHOP_ROLE_ASSISTANT_COMPLETED_KEY),null);
 }finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}
});

test('rebuild opaque reference survives acknowledged frame reload independently of diagnostics',async()=>{
 const {SHOP_SYSTEM_REBUILD_KEY,SHOP_SYSTEM_DIAGNOSTIC_KEY}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const reference=JSON.stringify({version:1,references:[{scopeKey:'a'.repeat(64),operationId:'11111111-1111-4111-8111-111111111111',state:'pending'}]});
 const first=await setup();let second;
 try{
  assert.equal(first.frame.getItem(SHOP_SYSTEM_REBUILD_KEY),null);
  first.frame.setItem(SHOP_SYSTEM_REBUILD_KEY,reference);first.frame.setItem(SHOP_SYSTEM_DIAGNOSTIC_KEY,reference);await first.frame.flush();
  first.frame.close();first.host.close();second=await setup(first.storage);
  assert.equal(second.frame.getItem(SHOP_SYSTEM_REBUILD_KEY),reference);
  second.frame.removeItem(SHOP_SYSTEM_REBUILD_KEY);await second.frame.flush();
  assert.equal(second.frame.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY),reference);
 }finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}
});

test('restart opaque reference survives acknowledged frame reload independently of diagnostics',async()=>{
 const {SHOP_SYSTEM_RESTART_KEY,SHOP_SYSTEM_DIAGNOSTIC_KEY}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const reference=JSON.stringify({version:1,references:[{scopeKey:'a'.repeat(64),operationId:'11111111-1111-4111-8111-111111111111',state:'pending'}]});
 const first=await setup();let second;
 try{
  assert.equal(first.frame.getItem(SHOP_SYSTEM_RESTART_KEY),null);
  first.frame.setItem(SHOP_SYSTEM_RESTART_KEY,reference);first.frame.setItem(SHOP_SYSTEM_DIAGNOSTIC_KEY,reference);await first.frame.flush();
  first.frame.close();first.host.close();second=await setup(first.storage);
  assert.equal(second.frame.getItem(SHOP_SYSTEM_RESTART_KEY),reference);
  second.frame.removeItem(SHOP_SYSTEM_RESTART_KEY);await second.frame.flush();
  assert.equal(second.frame.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY),reference);
 }finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}
});

test('Listings opaque references survive acknowledged frame reload and reject extra authority fields',async()=>{
 const first=await setup();let second;const key='secureshop.listings.operations.v1';const raw=JSON.stringify({import:{scopeKey:'a'.repeat(64),digest:'b'.repeat(64),operationId:'11111111-1111-4111-8111-111111111111'}});
 try{assert.equal(first.frame.getItem(key),null);first.frame.setItem(key,raw);await first.frame.flush();second=await setup(first.storage);assert.equal(second.frame.getItem(key),raw);assert.throws(()=>second.frame.setItem(key,JSON.stringify({import:{...JSON.parse(raw).import,platformToken:'untrusted'}})));second.revoke();second.frame.removeItem(key);await assert.rejects(second.frame.flush(),/not saved/);}finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}
});

test('inventory recovery reference crosses acknowledged state channel and rejects raw prompt fields',async()=>{const first=await setup();let second;const key='secureshop.inventory.operation.v1',row={scopeKey:'a'.repeat(64),digest:'b'.repeat(64),requestId:'11111111-1111-4111-8111-111111111111'};try{assert.equal(first.frame.getItem(key),null);first.frame.setItem(key,JSON.stringify(row));await first.frame.flush();second=await setup(first.storage);assert.deepEqual(JSON.parse(second.frame.getItem(key)),row);assert.throws(()=>second.frame.setItem(key,JSON.stringify({...row,message:'raw'})));}finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}});

test('coupon reference crosses acknowledged parent channel and reload without storing coupon input',async()=>{
 const first=await setup();let second;const key='secureshop.coupon.operation.v1',row={scopeKey:'a'.repeat(64),digest:'b'.repeat(64),operationId:'11111111-1111-4111-8111-111111111111'};
 try{assert.equal(first.frame.getItem(key),null);first.frame.setItem(key,JSON.stringify(row));await first.frame.flush();second=await setup(first.storage);assert.deepEqual(JSON.parse(second.frame.getItem(key)),row);assert.throws(()=>second.frame.setItem(key,JSON.stringify({...row,code:'raw coupon'})));second.revoke();second.frame.removeItem(key);await assert.rejects(second.frame.flush(),/not saved/);}finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}
});

test('checkout reference crosses acknowledged parent channel and rejects payment or address fields',async()=>{
 const first=await setup();let second;const key='secureshop.checkout.operation.v1';
 const row={scopeKey:'a'.repeat(64),intentDigest:'b'.repeat(64),operationId:'11111111-1111-4111-8111-111111111111'};
 try{
  assert.equal(first.frame.getItem(key),null);
  first.frame.setItem(key,JSON.stringify(row));await first.frame.flush();
  second=await setup(first.storage);assert.deepEqual(JSON.parse(second.frame.getItem(key)),row);
  assert.throws(()=>second.frame.setItem(key,JSON.stringify({...row,shippingAddress:'raw address'})));
  assert.throws(()=>second.frame.setItem(key,JSON.stringify({...row,paymentMethod:'raw payment'})));
  second.revoke();second.frame.removeItem(key);await assert.rejects(second.frame.flush(),/not saved/);
 }finally{first.frame.close();first.host.close();second?.frame.close();second?.host.close();}
});


test('file-summary IDs are acknowledged and retired through real message ports',async()=>{
 const {SHOP_CUSTOMER_FILE_SUMMARY_KEY:runKey,SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY:gradeKey}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const saved=JSON.stringify({version:1,shopUserId:7,sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',startedAt:100});
 const channel=await setup();
 try {
  channel.frame.setItem(runKey,saved);channel.frame.setItem(gradeKey,saved);await channel.frame.flush();
  assert.equal(channel.frame.getItem(runKey),saved);assert.equal(channel.frame.getItem(gradeKey),saved);
  channel.frame.removeItem(gradeKey);channel.frame.removeItem(runKey);await channel.frame.flush();
  assert.equal(channel.frame.getItem(runKey),null);assert.equal(channel.frame.getItem(gradeKey),null);
 } finally {channel.frame.close();channel.host.close();}
});
