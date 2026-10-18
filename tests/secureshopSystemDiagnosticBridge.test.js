'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

test('diagnostic bridge preserves shell teaching input and operation ID but rejects authority fields', async () => {
  const {compileOperation} = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const operationId = '11111111-1111-4111-8111-111111111111';
  const body = {operationId,cmd_template:'printf',args:'owned; uname -n'};
  assert.deepEqual(compileOperation('admin.system.diagnostic',{body}).body,body);
  for (const extra of [{targetId:operationId},{scope:{owner:1}},{personaSession:{}}]) {
    assert.throws(() => compileOperation('admin.system.diagnostic',{body:{...body,...extra}}));
  }
  const legacy={cmd_template:'echo',args:'hello'};
  assert.deepEqual(compileOperation('admin.system.diagnostic',{body:legacy}).body,legacy);
  assert.equal(compileOperation('admin.system.diagnosticAdministration',{}).method,'GET');
  assert.equal(compileOperation('admin.system.diagnosticOperation',{params:{operationId}}).path,
    `/api/secureshop/admin/system/diagnostic-operations/${operationId}`);
});

test('parent diagnostic recovery state accepts opaque references and rejects commands and malformed metadata', async () => {
  const {validateShopSnapshot} = await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
  const {SHOP_TOKEN_KEY,SHOP_CART_KEY,SHOP_SYSTEM_DIAGNOSTIC_KEY,createShopStorage} = await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
  const base = {[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null};
  const reference={scopeKey:'a'.repeat(64),operationId:'11111111-1111-4111-8111-111111111111',state:'pending'};
  const encoded=JSON.stringify({version:1,references:[reference]});
  assert.equal(validateShopSnapshot({...base,[SHOP_SYSTEM_DIAGNOSTIC_KEY]:encoded})[SHOP_SYSTEM_DIAGNOSTIC_KEY],encoded);
  const completed=JSON.stringify({version:1,references:[{...reference,state:'completed'}]});
  assert.equal(validateShopSnapshot({...base,[SHOP_SYSTEM_DIAGNOSTIC_KEY]:completed})[SHOP_SYSTEM_DIAGNOSTIC_KEY],completed);
  for(const bad of [{...reference,cmd_template:'id'},{...reference,state:'retired'},{...reference,scopeKey:'wrong'}]){
    assert.throws(()=>validateShopSnapshot({...base,[SHOP_SYSTEM_DIAGNOSTIC_KEY]:JSON.stringify({version:1,references:[bad]})}));
  }
  const storage=createShopStorage({getStorage:()=>({setItem(){throw new Error('durability unavailable');}})});
  assert.throws(()=>storage.setItem(SHOP_SYSTEM_DIAGNOSTIC_KEY,encoded),/durability unavailable/);
});
