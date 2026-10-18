'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
test('policy bridge preserves exact versioned source and recovery identity without accepting authority', async () => {
 const {compileOperation} = await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const mutation = {operationId:'11111111-1111-4111-8111-111111111111',expectedVersion:'2'};
 const content = {markdown:'{{ literal }} %2F é',injected_into:['admin'],...mutation};
 for (const operation of ['admin.policies.saveMarkdown','admin.policies.render']) {
  assert.deepEqual(compileOperation(operation,{params:{name:'50% off'},body:content}).body,content);
  assert.throws(()=>compileOperation(operation,{params:{name:'50% off'},body:{...content,scope:{launchId:'forged'}}}));
 }
 assert.deepEqual(compileOperation('admin.policies.upsert',{body:{name:'owned',...content}}).body,{name:'owned',...content});
 assert.deepEqual(compileOperation('admin.policies.delete',{params:{name:'owned'},body:mutation}).body,mutation);
 assert.equal(compileOperation('admin.policies.operation',{params:{operationId:mutation.operationId}}).path,`/api/secureshop/admin/policies/operations/${mutation.operationId}`);
 assert.throws(()=>compileOperation('admin.policies.operation',{params:{operationId:mutation.operationId},query:{persona:'admin'}}));
 assert.equal(compileOperation('admin.policies.readiness',{}).path,'/api/secureshop/admin/policies/readiness');
 assert.throws(()=>compileOperation('admin.policies.readiness',{query:{persona:'admin'}}));
});

test('policy pending metadata is bounded optional durable shop state and does not hide write failures', async () => {
 const {validateShopSnapshot} = await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const {createShopStorage,SHOP_TOKEN_KEY,SHOP_CART_KEY,SHOP_PROMPT_POLICY_KEY} = await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const base = {[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null};
 const pending = JSON.stringify({operationId:'11111111-1111-4111-8111-111111111111',action:'preview',expectedVersion:'1'});
 assert.equal(validateShopSnapshot({...base,[SHOP_PROMPT_POLICY_KEY]:pending})[SHOP_PROMPT_POLICY_KEY],pending);
 assert.throws(()=>validateShopSnapshot({...base,[SHOP_PROMPT_POLICY_KEY]:'é'.repeat(4097)}));
 const unavailable=createShopStorage({getStorage:()=>({getItem(){throw Error('unavailable');},setItem(){throw Error('unavailable');},removeItem(){throw Error('unavailable');}})});
 assert.throws(()=>unavailable.setItem(SHOP_PROMPT_POLICY_KEY,pending),/unavailable/);
 assert.throws(()=>unavailable.getItem(SHOP_PROMPT_POLICY_KEY),/unavailable/);
 assert.throws(()=>unavailable.removeItem(SHOP_PROMPT_POLICY_KEY),/unavailable/);
});
