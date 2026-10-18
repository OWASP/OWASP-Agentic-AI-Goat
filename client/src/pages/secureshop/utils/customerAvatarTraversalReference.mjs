const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const OPERATION_KEYS=['version','shopUserId','sessionId','requestId','operationId','startedAt'];
const ASSESSMENT_KEYS=['version','shopUserId','sessionId','requestId','startedAt'];
const MAX_BYTES=640;
export const CUSTOMER_AVATAR_TRAVERSAL_REFERENCE_KEY='secureshop.customer-avatar-traversal.lesson.v1';
export const CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY='secureshop.customer-avatar-traversal.assessment.v1';
const invalid=()=>{throw new Error('Invalid saved avatar-traversal request');};
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const same=(left,right,keys)=>!!left&&!!right&&keys.every(key=>left[key]===right[key]);
function parse(raw,keys){
 if(raw===null)return null;
 if(typeof raw!=='string'||new TextEncoder().encode(raw).byteLength>MAX_BYTES)invalid();
 let value;try{value=JSON.parse(raw);}catch{invalid();}
 if(!exact(value,keys)||value.version!==1||!Number.isSafeInteger(value.shopUserId)||value.shopUserId<1
  ||![value.sessionId,value.requestId].every(item=>typeof item==='string'&&UUID.test(item))
  ||keys.includes('operationId')&&!(value.operationId===null||typeof value.operationId==='string'&&UUID.test(value.operationId))
  ||!Number.isSafeInteger(value.startedAt)||value.startedAt<1)invalid();
 return Object.freeze(value);
}
export const decodeCustomerAvatarTraversalReference=raw=>parse(raw,OPERATION_KEYS);
export const decodeCustomerAvatarTraversalAssessmentReference=raw=>parse(raw,ASSESSMENT_KEYS);

export function createCustomerAvatarTraversalReferenceStore({storage,flush,
 key=CUSTOMER_AVATAR_TRAVERSAL_REFERENCE_KEY}={}){
 if(typeof storage?.getItem!=='function'||typeof storage?.setItem!=='function'||typeof storage?.removeItem!=='function'
  ||typeof flush!=='function'||key!==CUSTOMER_AVATAR_TRAVERSAL_REFERENCE_KEY)throw new TypeError('Acknowledged avatar-traversal storage required');
 const raw=()=>decodeCustomerAvatarTraversalReference(storage.getItem(key));
 return Object.freeze({
  read(shopUserId){if(!Number.isSafeInteger(shopUserId)||shopUserId<1)invalid();const value=raw();return value?.shopUserId===shopUserId?value:null;},
  async saveIntent(reference,current=()=>true,written=()=>{}){
   const value=decodeCustomerAvatarTraversalReference(JSON.stringify({version:1,...reference,operationId:null}));
   if(current()!==true||raw()!==null)throw Error('Check the saved avatar-traversal request first');
   storage.setItem(key,JSON.stringify(value));written(value);await flush();
   if(current()!==true||!same(raw(),value,OPERATION_KEYS))throw Error('Saved avatar-traversal request changed');return value;
  },
  async acknowledgeOperation(reference,operationId,current=()=>true){
   const prior=decodeCustomerAvatarTraversalReference(JSON.stringify(reference));
   const value=decodeCustomerAvatarTraversalReference(JSON.stringify({...prior,operationId}));
   if(current()!==true||!same(raw(),prior,OPERATION_KEYS))throw Error('Saved avatar-traversal request changed');
   storage.setItem(key,JSON.stringify(value));await flush();
   if(current()!==true||!same(raw(),value,OPERATION_KEYS))throw Error('Saved avatar-traversal operation changed');return value;
  },
  async clear(reference,current=()=>true){
   const prior=decodeCustomerAvatarTraversalReference(JSON.stringify(reference));
   if(current()!==true||!same(raw(),prior,OPERATION_KEYS))throw Error('Saved avatar-traversal request changed');
   storage.removeItem(key);try{await flush();if(current()!==true||raw()!==null)throw Error('Saved avatar-traversal request changed');}
   catch(error){storage.setItem(key,JSON.stringify(prior));try{await flush();}catch{}throw error;}return true;
  }
 });
}

export function createCustomerAvatarTraversalAssessmentStore({storage,flush,
 key=CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY}={}){
 if(typeof storage?.getItem!=='function'||typeof storage?.setItem!=='function'||typeof storage?.removeItem!=='function'
  ||typeof flush!=='function'||key!==CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY)throw new TypeError('Acknowledged avatar-traversal assessment storage required');
 const raw=()=>decodeCustomerAvatarTraversalAssessmentReference(storage.getItem(key));
 return Object.freeze({
  read(reference){const value=raw();return value&&reference&&value.shopUserId===reference.shopUserId
    &&value.sessionId===reference.sessionId&&value.requestId===reference.requestId?value:null;},
  async submit(reference,current=()=>true,written=()=>{}){
   const value=decodeCustomerAvatarTraversalAssessmentReference(JSON.stringify({version:1,...reference}));
   if(current()!==true||raw()!==null)throw Error('Check the saved avatar-traversal assessment first');
   storage.setItem(key,JSON.stringify(value));written(value);await flush();
   if(current()!==true||!same(raw(),value,ASSESSMENT_KEYS))throw Error('Saved avatar-traversal assessment changed');return value;
  },
  async clear(reference,current=()=>true){
   const prior=decodeCustomerAvatarTraversalAssessmentReference(JSON.stringify(reference));
   if(current()!==true||!same(raw(),prior,ASSESSMENT_KEYS))throw Error('Saved avatar-traversal assessment changed');
   storage.removeItem(key);try{await flush();if(current()!==true||raw()!==null)throw Error('Saved avatar-traversal assessment changed');}
   catch(error){storage.setItem(key,JSON.stringify(prior));try{await flush();}catch{}throw error;}return true;
  }
 });
}
