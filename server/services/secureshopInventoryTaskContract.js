'use strict';
const {exact}=require('./secureshopCouponContract');
const {fail}=require('./secureshopInventoryContract');

function captureStockIntent({access,stockChange}) {
  if(!['read','write'].includes(access))throw fail('INVENTORY_INVALID');
  if(access==='read'){
    if(stockChange!==null)throw fail('INVENTORY_INVALID');
    return Object.freeze({access,stockChange:null});
  }
  try{exact(stockChange,['productId','quantity']);}catch{throw fail('INVENTORY_INVALID');}
  if(!Number.isInteger(stockChange.productId)||stockChange.productId<1||stockChange.productId>2147483647
    ||!Number.isInteger(stockChange.quantity)||stockChange.quantity<0||stockChange.quantity>2147483647)throw fail('INVENTORY_INVALID');
  return Object.freeze({access,stockChange:Object.freeze({productId:stockChange.productId,quantity:stockChange.quantity})});
}
function assertStockIntent(intent,action,args){
  if(action!=='set_stock')return;
  if(intent.access!=='write')throw fail('INVENTORY_WRITE_NOT_AUTHORIZED');
  try{exact(args,['productId','quantity']);}catch{throw fail('INVENTORY_TASK_MISMATCH');}
  if(args.productId!==intent.stockChange.productId||args.quantity!==intent.stockChange.quantity)throw fail('INVENTORY_TASK_MISMATCH');
}
// Reconstruct retained versions in their original key order. Old requests never
// acquire new stock authority from an inferred tuple or a current UI choice.
function inventoryTaskEnvelope(meta,mode=meta.mode,personaSession=meta.personaSession){
  if(meta.version===1)return JSON.stringify({version:1,message:meta.message,mode,personaSession});
  if(meta.version===2)return JSON.stringify({version:2,message:meta.message,access:meta.access,mode,personaSession});
  const intent=captureStockIntent(meta);
  return JSON.stringify({version:3,message:meta.message,access:intent.access,stockChange:intent.stockChange,mode,personaSession});
}
function assertInventoryMetadata(meta){
  if(![1,2,3].includes(meta?.version))throw fail('INVENTORY_RECEIPT_MISMATCH');
  if(meta.version===1){
    if(Object.hasOwn(meta,'access')||Object.hasOwn(meta,'stockChange'))throw fail('INVENTORY_RECEIPT_MISMATCH');
    return;
  }
  if(!['read','write'].includes(meta.access)||!Array.isArray(meta.receipts))throw fail('INVENTORY_RECEIPT_MISMATCH');
  if(meta.version===2&&Object.hasOwn(meta,'stockChange'))throw fail('INVENTORY_RECEIPT_MISMATCH');
  const intent=meta.version===3?captureStockIntent(meta):{access:meta.access};
  for(const entry of meta.receipts){
    const binding=entry?.receipt?.binding;
    if(binding?.action==='set_stock'){
      if(meta.version===3)assertStockIntent(intent,binding.action,binding.args);
      else if(meta.access==='read')throw fail('INVENTORY_RECEIPT_MISMATCH');
    }
  }
}
module.exports={captureStockIntent,assertStockIntent,inventoryTaskEnvelope,assertInventoryMetadata};
