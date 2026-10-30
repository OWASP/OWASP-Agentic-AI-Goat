'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const scenarioId='11111111-1111-4111-8111-111111111111';
const state={secureshop_v2_token:'learner-forged',ss_guest_cart:'[{"id":7,"quantity":2}]'};
async function setup() {
  const {createScopedShopStateStore}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
  const values=new Map([['platform_token','synthetic-platform']]);
  const storage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value)};
  return {createScopedShopStateStore,values,storage};
}

test('shop state survives recreation within its trusted scenario/generation and exposes no platform keys', async()=>{
  const {createScopedShopStateStore,storage,values}=await setup();
  const options={storage,scenarioId,generation:1,isCurrent:()=>true};
  const first=createScopedShopStateStore(options);first.replace(state);first.close();
  const next=createScopedShopStateStore(options);assert.deepEqual({...next.read()},state);
  assert.equal(values.get('platform_token'),'synthetic-platform');
  for(const override of [{generation:2},{scenarioId:'22222222-2222-4222-8222-222222222222'}]) {
    const other=createScopedShopStateStore({...options,...override});assert.deepEqual({...other.read()},{secureshop_v2_token:null,ss_guest_cart:null});
  }
});

test('state writes fail visibly on quota, revoked generation, expanded keys and oversized data',async()=>{
  const {createScopedShopStateStore,storage}=await setup();let current=true;
  const store=createScopedShopStateStore({storage,scenarioId,generation:1,isCurrent:()=>current});
  assert.throws(()=>store.replace({...state,platform_token:'private'}));
  assert.throws(()=>store.replace({...state,ss_guest_cart:'界'.repeat(50000)}));
  store.replace(state);current=false;assert.throws(()=>store.read(),{name:'AbortError'});assert.throws(()=>store.replace(state),{name:'AbortError'});
  const quota=createScopedShopStateStore({storage:{...storage,setItem(){throw new DOMException('quota','QuotaExceededError');}},scenarioId,generation:1,isCurrent:()=>true});
  assert.throws(()=>quota.replace(state),{name:'QuotaExceededError'});
});

test('corrupted persisted state is rejected without erasing it; revocation during write prevents acknowledgement',async()=>{
  const {createScopedShopStateStore,storage,values}=await setup();
  const key=`owasp-ai-goat:secureshop:${scenarioId}:1`;values.set(key,'{"platform_token":"bad"}');
  const store=createScopedShopStateStore({storage,scenarioId,generation:1,isCurrent:()=>true});
  assert.throws(()=>store.read());assert.equal(values.get(key),'{"platform_token":"bad"}');
  let current=true;const revoked=createScopedShopStateStore({storage:{...storage,setItem(k,v){values.set(k,v);current=false;}},scenarioId,generation:1,isCurrent:()=>current});
  assert.throws(()=>revoked.replace(state),{name:'AbortError'});
});

test('trusted retirement removes only the confirmed old generation and is unavailable before cleanup',async()=>{
 const {createScopedShopStateStore,storage,values}=await setup();let confirmed=false;
 const oldKey=`owasp-ai-goat:secureshop:${scenarioId}:1`;const newKey=`owasp-ai-goat:secureshop:${scenarioId}:2`;
 values.set(oldKey,JSON.stringify(state));values.set(newKey,JSON.stringify(state));
 const store=createScopedShopStateStore({storage:{...storage,removeItem:key=>values.delete(key)},scenarioId,generation:1,isCurrent:()=>false,canRetire:()=>confirmed});
 assert.throws(()=>store.retire(),/not confirmed/);assert.ok(values.has(oldKey));
 confirmed=true;store.retire();assert.equal(values.has(oldKey),false);assert.ok(values.has(newKey));assert.equal(values.get('platform_token'),'synthetic-platform');
});
