const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const KEYS=['version','shopUserId','sessionId','requestId','operationId','startedAt'];
const MAX_BYTES=640;
export const CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY='secureshop.customer-avatar-upload.lesson.v1';
const invalid=()=>{throw new Error('Invalid saved avatar-upload request');};
const same=(left,right)=>!!left&&!!right&&KEYS.every(key=>left[key]===right[key]);
export function decodeCustomerAvatarUploadReference(raw){
 if(raw===null)return null;
 if(typeof raw!=='string'||new TextEncoder().encode(raw).byteLength>MAX_BYTES)invalid();
 let value;try{value=JSON.parse(raw);}catch{invalid();}
 if(!value||Object.getPrototypeOf(value)!==Object.prototype
  ||Object.keys(value).sort().join(',')!==[...KEYS].sort().join(',')||value.version!==1
  ||!Number.isSafeInteger(value.shopUserId)||value.shopUserId<1
  ||![value.sessionId,value.requestId].every(item=>typeof item==='string'&&UUID.test(item))
  ||!(value.operationId===null||typeof value.operationId==='string'&&UUID.test(value.operationId))
  ||!Number.isSafeInteger(value.startedAt)||value.startedAt<1)invalid();
 return Object.freeze(value);
}
export function createCustomerAvatarUploadReferenceStore({storage,flush,
 key=CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY}={}){
 if(typeof storage?.getItem!=='function'||typeof storage?.setItem!=='function'
  ||typeof storage?.removeItem!=='function'||typeof flush!=='function'
  ||key!==CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY)
  throw new TypeError('Acknowledged avatar-upload storage required');
 const readRaw=()=>decodeCustomerAvatarUploadReference(storage.getItem(key));
 return Object.freeze({
  read(shopUserId){
   if(!Number.isSafeInteger(shopUserId)||shopUserId<1)invalid();
   const value=readRaw();return value?.shopUserId===shopUserId?value:null;
  },
  async saveIntent(reference,current=()=>true,written=()=>{}){
   const value=decodeCustomerAvatarUploadReference(JSON.stringify({version:1,...reference,operationId:null}));
   if(current()!==true||readRaw()!==null)throw Error('Check the saved avatar-upload request first');
   storage.setItem(key,JSON.stringify(value));written(value);await flush();
   if(current()!==true||!same(readRaw(),value))throw Error('Saved avatar-upload request changed');
   return value;
  },
  async acknowledgeOperation(reference,operationId,current=()=>true){
   const prior=decodeCustomerAvatarUploadReference(JSON.stringify({version:1,...reference}));
   const value=decodeCustomerAvatarUploadReference(JSON.stringify({...prior,operationId}));
   if(current()!==true||!same(readRaw(),prior))throw Error('Saved avatar-upload request changed');
   storage.setItem(key,JSON.stringify(value));await flush();
   if(current()!==true||!same(readRaw(),value))throw Error('Saved avatar-upload operation changed');
   return value;
  },
  async clear(reference,current=()=>true){
   const prior=decodeCustomerAvatarUploadReference(JSON.stringify({version:1,...reference}));
   if(current()!==true||!same(readRaw(),prior))throw Error('Saved avatar-upload request changed');
   storage.removeItem(key);
   try{await flush();if(current()!==true||readRaw()!==null)throw Error('Saved avatar-upload request changed');}
   catch(error){storage.setItem(key,JSON.stringify(prior));try{await flush();}catch{}throw error;}
   return true;
  }
 });
}
