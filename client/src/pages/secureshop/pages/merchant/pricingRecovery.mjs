import {shopStorage,flushShopStorage,SHOP_PRICING_KEY} from '../../utils/shopStorage.mjs';
import {decodePricingReferences,encodePricingReferences,validatePricingReference} from './pricingOperation.mjs';
export const readPricingReferences=()=>decodePricingReferences(shopStorage.getItem(SHOP_PRICING_KEY));
const same=(a,b)=>!!a&&Object.keys(b).every(key=>a[key]===b[key]);
export async function savePricingReference(raw){
 const row=validatePricingReference(raw),rows=readPricingReferences();
 if(rows.some(x=>x.scopeKey===row.scopeKey))throw Error('Recover the pending Pricing operation first');
 const next=[...rows,row];shopStorage.setItem(SHOP_PRICING_KEY,encodePricingReferences(next));
 await flushShopStorage();
 if(!same(readPricingReferences().find(x=>x.scopeKey===row.scopeKey),row))throw Error('Pricing reference changed');
 return next;
}
export async function clearPricingReference(raw,current=()=>true){
 const row=validatePricingReference(raw),rows=readPricingReferences();
 if(!same(rows.find(x=>x.scopeKey===row.scopeKey),row))throw Error('Pricing reference changed');
 const next=rows.filter(x=>x.scopeKey!==row.scopeKey);
 try{
  if(next.length)shopStorage.setItem(SHOP_PRICING_KEY,encodePricingReferences(next));
  else shopStorage.removeItem(SHOP_PRICING_KEY);
  await flushShopStorage();
  if(current()&&readPricingReferences().some(x=>x.scopeKey===row.scopeKey))throw Error('Pricing reference changed');
  return next;
 }catch(error){
  // Failed parent removal ACK cannot prove that an admitted operation is retired.
  try{
   if(current()){
    const latest=readPricingReferences();
    if(current()&&!latest.some(x=>x.scopeKey===row.scopeKey)){
     shopStorage.setItem(SHOP_PRICING_KEY,encodePricingReferences([...latest,row]));
     await flushShopStorage();
    }
   }
  }catch{/* The caller still retains its unresolved reference. */}
  throw error;
 }
}

// This edits only metadata in the current launch's scoped browser storage.
export async function forgetForeignPricingReference(raw,currentScopeKey){
 if(typeof currentScopeKey!=='string'||!/^[a-f0-9]{64}$/.test(currentScopeKey))throw Error('Current Pricing scope is unavailable');
 const row=validatePricingReference(raw);
 if(row.scopeKey===currentScopeKey)throw Error('The current pending Pricing operation must remain available for readback');
 return clearPricingReference(row);
}
