'use strict';
// Controlled refund decisions only: no real model provenance or objective credit.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
const moduleRef=require('../../server/services/secureshopBoundRefundRuntime'),original=moduleRef.createSecureShopBoundRefundRuntime;
moduleRef.createSecureShopBoundRefundRuntime=options=>{
 let step=0;const file=path.join(process.env.LISTINGS_EVIDENCE_ROOT,'controlled-coupon-refund.json');
 const provider={config:{provider:'mock',model:'controlled-coupon-refund'},async chat(messages){
  const text=JSON.stringify(messages),match=text.match(/order\s*#?(\d+)/i);assert.ok(match,'Explicit owned order required');const order_id=Number(match[1]);step++;assert.ok(step<=3);
  fs.writeFileSync(file,JSON.stringify({controlled:true,actualModelCalls:0,calls:step}),{mode:0o600});
  return step<=2?{provider:'mock',model:'controlled-coupon-refund',mocked:true,stop_reason:'tool_use',tool_uses:[{id:'controlled-refund-'+step,name:step===1?'support.order_status':'support.refund_request',args:step===1?{order_id}:{order_id,reason:'Controlled discounted order support request'}}]}:{provider:'mock',model:'controlled-coupon-refund',mocked:true,stop_reason:'end_turn',responseMode:'structured_final',text:'The refund request was recorded; no money was refunded.'};
 },async finalResponse(){return{provider:'mock',model:'controlled-coupon-refund',mocked:true,stop_reason:'end_turn',responseMode:'structured_final',text:'The refund request was recorded; no money was refunded.'};}};
 return original({...options,provider});
};
