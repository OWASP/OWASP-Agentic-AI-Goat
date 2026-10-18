import { decodeMailReferences, updateMailReference } from '../bridge/mailReferences.mjs';
import { SHOP_MAIL_KEY } from './shopStorage.mjs';
const HASH=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const KEYS=['version','shopUserId','sessionId','requestId','startedAt'];
const invalid=()=>{throw Error('Invalid saved agent mail-read assessment');};
const same=(a,b)=>!!a&&!!b&&KEYS.every(key=>a[key]===b[key]);
export function decodeMerchantMailReadAssessmentReference(value){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!==[...KEYS].sort().join(',')
  ||value.version!==1||!Number.isSafeInteger(value.shopUserId)||value.shopUserId<1
  ||![value.sessionId,value.requestId].every(id=>typeof id==='string'&&UUID.test(id))
  ||!Number.isSafeInteger(value.startedAt)||value.startedAt<1)invalid();
 return Object.freeze({...value});
}
export function createMerchantMailReadAssessmentStore({storage,flush}={}){
 if(!storage||!['getItem','setItem','removeItem'].every(key=>typeof storage[key]==='function')||typeof flush!=='function')
  throw TypeError('Acknowledged agent mail-read assessment storage required');
 const read=scope=>{if(!HASH.test(scope||''))invalid();const value=decodeMailReferences(storage.getItem(SHOP_MAIL_KEY)).scopes[scope]?.agentReadAssessment??null;return value===null?null:decodeMerchantMailReadAssessmentReference(value);};
 return Object.freeze({
  read,
  async submit(scope,reference,current=()=>true,written=()=>{}){
   const value=decodeMerchantMailReadAssessmentReference({version:1,...reference});
   if(current()!==true||read(scope)!==null)throw Error('Check the saved agent mail-read assessment');
   storage.setItem(SHOP_MAIL_KEY,updateMailReference(storage.getItem(SHOP_MAIL_KEY),scope,'agentReadAssessment',value));written(value);await flush();
   if(current()!==true||!same(read(scope),value))throw Error('Saved agent mail-read assessment changed');return value;
  },
  async clear(scope,reference,current=()=>true){
   const value=decodeMerchantMailReadAssessmentReference(reference),before=storage.getItem(SHOP_MAIL_KEY);
   if(current()!==true||!same(read(scope),value))throw Error('Saved agent mail-read assessment changed');
   const after=updateMailReference(before,scope,'agentReadAssessment',null);if(after===null)storage.removeItem(SHOP_MAIL_KEY);else storage.setItem(SHOP_MAIL_KEY,after);
   try{await flush();if(current()!==true||read(scope)!==null)throw Error('Saved agent mail-read assessment changed');}
   catch(error){if(current()===true&&storage.getItem(SHOP_MAIL_KEY)===after){if(before===null)storage.removeItem(SHOP_MAIL_KEY);else storage.setItem(SHOP_MAIL_KEY,before);try{await flush();}catch{}}throw error;}return true;
  }
 });
}
