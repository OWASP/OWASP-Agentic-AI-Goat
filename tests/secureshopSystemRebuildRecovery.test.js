'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
test('rebuild recovery holds only bounded opaque references and preserves other operation stores',async()=>{
 const {validateShopSnapshot}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const {SHOP_TOKEN_KEY,SHOP_CART_KEY,SHOP_SYSTEM_REBUILD_KEY,SHOP_SYSTEM_DIAGNOSTIC_KEY,SHOP_SYSTEM_CONFIG_KEY,createShopStorage}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const ref={scopeKey:'a'.repeat(64),operationId:'11111111-1111-4111-8111-111111111111',state:'pending'};
 const encoded=JSON.stringify({version:1,references:[ref]});
 const snapshot={[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,[SHOP_SYSTEM_REBUILD_KEY]:encoded,[SHOP_SYSTEM_CONFIG_KEY]:encoded,[SHOP_SYSTEM_DIAGNOSTIC_KEY]:encoded};
 assert.deepEqual({...validateShopSnapshot(snapshot)},snapshot);
 for(const state of ['pending','unknown','completed']){
  const value=JSON.stringify({version:1,references:[{...ref,state}]});
  assert.equal(validateShopSnapshot({...snapshot,[SHOP_SYSTEM_REBUILD_KEY]:value})[SHOP_SYSTEM_REBUILD_KEY],value);
 }
 for(const extra of [{sql:'SELECT secret'},{vectors:[1]},{corpus:'products'},{state:'awarded'}])assert.throws(()=>validateShopSnapshot({...snapshot,[SHOP_SYSTEM_REBUILD_KEY]:JSON.stringify({version:1,references:[{...ref,...extra}]})}));
 const memory=new Map(Object.entries(snapshot));const storage=createShopStorage({getStorage:()=>({getItem:k=>memory.get(k)??null,setItem:(k,v)=>memory.set(k,v),removeItem:k=>memory.delete(k)})});
 storage.removeItem(SHOP_SYSTEM_REBUILD_KEY);
 assert.equal(storage.getItem(SHOP_SYSTEM_CONFIG_KEY),encoded);assert.equal(storage.getItem(SHOP_SYSTEM_DIAGNOSTIC_KEY),encoded);assert.equal(storage.getItem(SHOP_SYSTEM_REBUILD_KEY),null);
});
test('rebuild reference durability failures propagate to caller',async()=>{
 const {SHOP_SYSTEM_REBUILD_KEY,createShopStorage}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const storage=createShopStorage({getStorage:()=>({setItem(){throw Error('storage unavailable');}})});
 assert.throws(()=>storage.setItem(SHOP_SYSTEM_REBUILD_KEY,'{}'),/storage unavailable/);
});
