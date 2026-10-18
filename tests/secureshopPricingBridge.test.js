'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
test('pricing recovery state is closed, bounded and preserves original identity without storing request content',async()=>{
 const {encodePricingReferences,decodePricingReferences,pricingRequestDigest,pricingResult}=await import('../client/src/pages/secureshop/pages/merchant/pricingOperation.mjs');
 const body={operationId:randomUUID(),productId:7,message:'Recommend price'};
 const hash=await pricingRequestDigest(body);
 assert.equal(hash,require('../server/services/secureshopPricingContract').requestDigest({...body,task:'pricing-strategy'}));
 const row={scopeKey:'a'.repeat(64),operationId:body.operationId,productId:7,action:'suggest',requestSha256:hash};
 assert.deepEqual(decodePricingReferences(encodePricingReferences([row])),[row]);
 assert.throws(()=>encodePricingReferences([{...row,message:body.message}]));
 assert.throws(()=>encodePricingReferences([row,row]));
 assert.throws(()=>encodePricingReferences(Array.from({length:25},()=>({...row,operationId:randomUUID()}))));
 assert.throws(()=>pricingResult({ok:true,operationId:randomUUID(),state:'completed'},row));
 assert.deepEqual(pricingResult({ok:false,operationId:row.operationId,state:'not_found'},row),{state:'not_found'});
});
test('host shop-state accepts validated pricing reference and rejects raw injected content',async()=>{
 const {validateShopSnapshot}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const {SHOP_TOKEN_KEY,SHOP_CART_KEY,SHOP_PRICING_KEY}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const base={[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null};
 assert.equal(validateShopSnapshot({...base,[SHOP_PRICING_KEY]:null})[SHOP_PRICING_KEY],null);
 assert.throws(()=>validateShopSnapshot({...base,[SHOP_PRICING_KEY]:JSON.stringify({token:'private'})}));
});
test('structured experiment digest binds strategy and duration without changing legacy v1',async()=>{
 const {pricingRequestDigest}=await import('../client/src/pages/secureshop/pages/merchant/pricingOperation.mjs');
 const {requestDigest}=require('../server/services/secureshopPricingContract');
 const body={operationId:randomUUID(),productId:7,message:'Evaluate seven days',
  experiment:{strategy:'premium',durationDays:7}};
 assert.equal(await pricingRequestDigest(body),requestDigest({...body,task:'pricing-strategy'}));
 assert.notEqual(await pricingRequestDigest(body),await pricingRequestDigest({...body,experiment:{...body.experiment,durationDays:8}}));
 assert.notEqual(await pricingRequestDigest(body),await pricingRequestDigest({...body,experiment:{...body.experiment,strategy:'bundle'}}));
 await assert.rejects(pricingRequestDigest({...body,experiment:{strategy:'premium',durationDays:91}}));
});
test('closed Pricing bridge carries the exact optional experiment without authority fields',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const base={operationId:randomUUID(),productId:7,message:'Evaluate a pricing experiment'};
 const legacy=compileOperation('merchant.pricing.run',{body:base});
 assert.deepEqual(legacy.body,base);
 assert.equal(matchOperationRequest({pathname:legacy.path,method:legacy.method,body:base}).name,'merchant.pricing.run');
 const experiment={...base,experiment:{strategy:'premium',durationDays:14}};
 const request=compileOperation('merchant.pricing.run',{body:experiment});
 assert.deepEqual(request.body,experiment);
 assert.equal(matchOperationRequest({pathname:request.path,method:request.method,body:experiment}).name,'merchant.pricing.run');
 for(const key of ['scope','persona','token','ownerId'])
  assert.throws(()=>compileOperation('merchant.pricing.run',{body:{...experiment,[key]:'injected'}}));
 for(const key of ['productId','ownerId','sourceCallId'])
  assert.throws(()=>compileOperation('merchant.pricing.run',{body:{...experiment,experiment:{...experiment.experiment,[key]:7}}}));
});
test('client rejects a forged typed model recommendation even when an untrusted tool quote exists',async()=>{
 const {pricingRequestDigest,pricingResult}=await import('../client/src/pages/secureshop/pages/merchant/pricingOperation.mjs');
 const body={operationId:randomUUID(),productId:7,message:'Suggest price'};
 const requestSha256=await pricingRequestDigest(body);
 const reference={scopeKey:'a'.repeat(64),operationId:body.operationId,productId:7,action:'suggest',requestSha256};
 const recommendation={kind:'recommend',productId:7,price:42,rationale:'Typed final decision',sourceCallId:'call-1'};
 const receipt={version:'secureshop-pricing-execution.v1',operationId:body.operationId,requestSha256,
  runId:randomUUID(),targetId:randomUUID(),response:JSON.stringify(recommendation),modelRecommendation:recommendation,
  observations:[{tool:'pricing-strategy.suggest_price',callId:'call-1',args:{product_id:7},result:{suggested_price:0.01}}]};
 const result={ok:true,state:'completed',operationId:body.operationId,requestSha256,receipt};
 assert.deepEqual(pricingResult(result,reference).modelRecommendation,recommendation);
 assert.throws(()=>pricingResult({...result,receipt:{...receipt,modelRecommendation:{...recommendation,price:0.01}}},reference));
 assert.throws(()=>pricingResult({...result,receipt:{...receipt,observations:[{...receipt.observations[0],callId:'other'}]}},reference));
 const {modelRecommendation:unused,...unqualified}=receipt;
 assert.equal(pricingResult({...result,receipt:unqualified},reference).modelRecommendation,null);
});
