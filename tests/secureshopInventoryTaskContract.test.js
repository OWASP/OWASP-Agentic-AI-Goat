'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {captureStockIntent,assertStockIntent,inventoryTaskEnvelope}=require('../server/services/secureshopInventoryTaskContract');

test('task intent admits exact integer bounds without retailer restriction and freezes a copy',()=>{
 const input={access:'write',stockChange:{productId:2147483647,quantity:0}},intent=captureStockIntent(input);
 input.stockChange.productId=1;input.stockChange.quantity=99;
 assert.deepEqual(intent,{access:'write',stockChange:{productId:2147483647,quantity:0}});
 assert.equal(Object.isFrozen(intent),true);assert.equal(Object.isFrozen(intent.stockChange),true);
 assert.deepEqual(captureStockIntent({access:'read',stockChange:null}),{access:'read',stockChange:null});
 assert.doesNotThrow(()=>assertStockIntent(intent,'set_stock',{productId:2147483647,quantity:0}));
});
test('task intent rejects missing/coerced/extra/out-of-range authority and off-intent selected arguments',()=>{
 for(const stockChange of [null,undefined,[],{productId:0,quantity:1},{productId:1,quantity:-1},
  {productId:2147483648,quantity:1},{productId:1,quantity:2147483648},{productId:1.5,quantity:1},
  {productId:1,quantity:'1'},{productId:1,quantity:1,retailerId:1}]){
  assert.throws(()=>captureStockIntent({access:'write',stockChange}),{code:'INVENTORY_INVALID'});
 }
 for(const stockChange of [undefined,[],{productId:1,quantity:1}])assert.throws(()=>captureStockIntent({access:'read',stockChange}),{code:'INVENTORY_INVALID'});
 const intent=captureStockIntent({access:'write',stockChange:{productId:1,quantity:1}});
 for(const args of [{productId:2,quantity:1},{productId:1,quantity:2},{productId:1,quantity:1,extra:true}])assert.throws(()=>assertStockIntent(intent,'set_stock',args),{code:'INVENTORY_TASK_MISMATCH'});
 assert.throws(()=>assertStockIntent({access:'read',stockChange:null},'set_stock',{productId:1,quantity:1}),{code:'INVENTORY_WRITE_NOT_AUTHORIZED'});
});
test('retained request envelope versions keep original literal JSON key order',()=>{
 const personaSession={sessionId:'original',authorityVersion:'1'},base={message:'Task',mode:'vuln',personaSession};
 assert.equal(inventoryTaskEnvelope({...base,version:1}),'\u007b"version":1,"message":"Task","mode":"vuln","personaSession":{"sessionId":"original","authorityVersion":"1"}}');
 assert.equal(inventoryTaskEnvelope({...base,version:2,access:'write'}),'\u007b"version":2,"message":"Task","access":"write","mode":"vuln","personaSession":{"sessionId":"original","authorityVersion":"1"}}');
 assert.equal(inventoryTaskEnvelope({...base,version:3,access:'write',stockChange:{quantity:0,productId:7}}),'\u007b"version":3,"message":"Task","access":"write","stockChange":{"productId":7,"quantity":0},"mode":"vuln","personaSession":{"sessionId":"original","authorityVersion":"1"}}');
});
