'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
test('ACL bridge preserves versioned operation fields and denies authority injection', async () => {
  const { compileOperation } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const body = { enabled: true, operationId: '11111111-1111-4111-8111-111111111111', expectedVersion: '2' };
  assert.deepEqual(compileOperation('admin.accessControl.setEnforcement', { body }).body, body);
  assert.throws(() => compileOperation('admin.accessControl.setEnforcement', { body: { ...body, personaSession: {} } }));
  assert.equal(compileOperation('admin.accessControl.operation', { params: { operationId: body.operationId } }).path,
    `/api/secureshop/admin/access-control/operations/${body.operationId}`);
});
test('ACL pending key is bounded within the existing closed shop state schema', async () => {
  const { validateShopSnapshot } = await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
  const { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_ACL_KEY } = await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
  const base = { [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null };
  assert.equal(validateShopSnapshot({ ...base, [SHOP_ACL_KEY]: '{"operationId":"pending"}' })[SHOP_ACL_KEY], '{"operationId":"pending"}');
  assert.throws(() => validateShopSnapshot({ ...base, [SHOP_ACL_KEY]: 'x'.repeat(8193) }));
  assert.throws(() => validateShopSnapshot({ ...base, arbitrary_authority: '{}' }));
});
test('password reset bridge accepts only operation/version metadata and bounded nonsecret state key',async()=>{
 const {compileOperation}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const {validateShopSnapshot}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const body={operationId:'11111111-1111-4111-8111-111111111111',expectedCredentialVersion:'1',expectedAuthorityVersion:'2'};
 assert.deepEqual(compileOperation('admin.users.resetPassword',{params:{id:'2'},body}).body,body);
 assert.throws(()=>compileOperation('admin.users.resetPassword',{params:{id:'2'},body:{...body,password:'never'}}));
 assert.equal(compileOperation('admin.users.resetReveal',{params:{id:'2',operationId:body.operationId},body:{}}).method,'POST');
 const base={secureshop_v2_token:null,ss_guest_cart:null};
 // Use canonical required names rather than infer schema from UI labels.
 const {SHOP_TOKEN_KEY,SHOP_CART_KEY,SHOP_PASSWORD_RESET_KEY}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 assert.equal(validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,[SHOP_PASSWORD_RESET_KEY]:'{}'})[SHOP_PASSWORD_RESET_KEY],'{}');
 assert.throws(()=>validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,[SHOP_PASSWORD_RESET_KEY]:'x'.repeat(8193)}));
});
