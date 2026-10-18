import { decodeMailReferences, updateMailReference } from '../bridge/mailReferences.mjs';
import { SHOP_MAIL_KEY, shopStorage, flushShopStorage } from './shopStorage.mjs';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const KEYS=['stage','requestId','sourceSessionId','sourceRequestId','sendOperationId','messageId','startedAt'];
const invalid=()=>{throw new Error('Saved mail HTML assessment changed');};
export const sameMerchantMailHtmlAssessment=(a,b)=>!!a&&!!b&&KEYS.every(key=>a[key]===b[key]);
export function decodeMerchantMailHtmlAssessmentReference(value){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!==[...KEYS].sort().join(',')
  ||!['ready','submitted'].includes(value.stage)||![value.requestId,value.sourceSessionId,value.sourceRequestId,value.sendOperationId].every(id=>typeof id==='string'&&UUID.test(id))
  ||new Set([value.requestId,value.sourceSessionId,value.sourceRequestId,value.sendOperationId]).size!==4
  ||!Number.isSafeInteger(value.messageId)||value.messageId<1||value.messageId>2147483647
  ||!Number.isSafeInteger(value.startedAt)||value.startedAt<1)invalid();
 return Object.freeze({...value});
}
export function createMerchantMailHtmlAssessmentStore({storage=shopStorage,flush=flushShopStorage}={}){
 if(typeof storage?.getItem!=='function'||typeof storage?.setItem!=='function'||typeof storage?.removeItem!=='function'||typeof flush!=='function')throw new TypeError('Acknowledged mail assessment storage required');
 const raw=scope=>{if(typeof scope!=='string'||!SHA.test(scope))invalid();const value=decodeMailReferences(storage.getItem(SHOP_MAIL_KEY)).scopes[scope]?.htmlAssessment??null;return value===null?null:decodeMerchantMailHtmlAssessmentReference(value);};
 const write=(scope,value)=>{const encoded=updateMailReference(storage.getItem(SHOP_MAIL_KEY),scope,'htmlAssessment',value);if(encoded===null)storage.removeItem(SHOP_MAIL_KEY);else storage.setItem(SHOP_MAIL_KEY,encoded);};
 const exact=(scope,expected)=>{const current=raw(scope);if(!sameMerchantMailHtmlAssessment(current,expected))invalid();return current;};
 return Object.freeze({
  read:raw,
  async prepare(scope,identity,current=()=>true){const value=decodeMerchantMailHtmlAssessmentReference({stage:'ready',...identity});const prior=raw(scope);if(prior){if(!['sourceSessionId','sourceRequestId','sendOperationId','messageId'].every(key=>prior[key]===value[key]))invalid();await flush();if(current()!==true)invalid();return exact(scope,prior);}if(current()!==true)invalid();write(scope,value);let acknowledged=false;try{await flush();acknowledged=true;if(current()!==true)invalid();return exact(scope,value);}catch(error){if(!acknowledged&&sameMerchantMailHtmlAssessment(raw(scope),value)){write(scope,null);try{await flush();}catch{}}throw error;}},
  async submit(scope,reference,current=()=>true,written=()=>{}){const ready=decodeMerchantMailHtmlAssessmentReference(reference);if(ready.stage!=='ready'||current()!==true)invalid();exact(scope,ready);const value=decodeMerchantMailHtmlAssessmentReference({...ready,stage:'submitted'});write(scope,value);written(value);await flush();if(current()!==true)invalid();return exact(scope,value);},
  async rollback(scope,reference,current=()=>true){const submitted=decodeMerchantMailHtmlAssessmentReference(reference);if(submitted.stage!=='submitted'||current()!==true)invalid();exact(scope,submitted);const ready=decodeMerchantMailHtmlAssessmentReference({...submitted,stage:'ready'});write(scope,ready);try{await flush();if(current()!==true){if(sameMerchantMailHtmlAssessment(raw(scope),ready)){write(scope,null);try{await flush();}catch{}}invalid();}return exact(scope,ready);}catch(error){if(sameMerchantMailHtmlAssessment(raw(scope),ready)){write(scope,current()===true?submitted:null);try{await flush();}catch{}}throw error;}},
  async clear(scope,reference,current=()=>true){const value=decodeMerchantMailHtmlAssessmentReference(reference);if(current()!==true)invalid();exact(scope,value);write(scope,null);try{await flush();if(current()!==true||raw(scope)!==null)invalid();}catch(error){if(current()===true&&raw(scope)===null){write(scope,value);try{await flush();}catch{}}throw error;}return true;}
 });
}
export const merchantMailHtmlAssessmentStore=createMerchantMailHtmlAssessmentStore();
