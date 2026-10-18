const {test}=require('node:test'),assert=require('node:assert/strict');
test('Listings host state accepts only bounded opaque references',async()=>{
 const {decodeListingsReferences:decode}=await import('../client/src/pages/secureshop/pages/merchant/listingsReferences.mjs');
 const base={scopeKey:'a'.repeat(64),digest:'b'.repeat(64),operationId:'11111111-1111-4111-8111-111111111111'};
 assert.deepEqual(decode(JSON.stringify({import:base})),{import:base});
 const template={...base,productId:7};
 assert.deepEqual(decode(JSON.stringify({template})),{template});
 for(const invalid of [{...template,productId:0},{...template,productId:'7'},{...template,productId:2147483648},{...template,templateSource:'{{ source }}'}])
  assert.throws(()=>decode(JSON.stringify({template:invalid})));
 for(const x of [{import:{...base,url:'http://supplier'}},{unknown:base},{import:{...base,scopeKey:'authority'}},{assessment:Array(9).fill({})},{assessment:[{scopeKey:base.scopeKey,digest:base.digest,requestId:base.operationId,rewriteOperationId:base.operationId,saveOperationId:base.operationId,retryRequestId:base.operationId}]}])assert.throws(()=>decode(JSON.stringify(x)));
 assert.throws(()=>decode(' '.repeat(8193)));assert.deepEqual(decode(null),{});
});
