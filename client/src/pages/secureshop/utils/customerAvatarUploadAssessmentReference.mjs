const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const KEYS=['version','shopUserId','sessionId','requestId','startedAt'];
export const CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY='secureshop.customer-avatar-upload.assessment.v1';
export const CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY='secureshop.customer-avatar-upload.svg-assessment.v1';
const invalid=()=>{throw new Error('Invalid saved avatar-upload assessment');};
const same=(a,b)=>!!a&&!!b&&KEYS.every(key=>a[key]===b[key]);
export function decodeCustomerAvatarUploadAssessmentReference(raw){
 if(raw===null)return null;if(typeof raw!=='string'||new TextEncoder().encode(raw).byteLength>512)invalid();
 let value;try{value=JSON.parse(raw);}catch{invalid();}
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!==[...KEYS].sort().join(',')
  ||value.version!==1||!Number.isSafeInteger(value.shopUserId)||value.shopUserId<1
  ||![value.sessionId,value.requestId].every(id=>typeof id==='string'&&UUID.test(id))
  ||!Number.isSafeInteger(value.startedAt)||value.startedAt<1)invalid();
 return Object.freeze(value);
}
function createAssessmentStore({storage,flush,key}={},expectedKey){
 if(typeof storage?.getItem!=='function'||typeof storage?.setItem!=='function'||typeof storage?.removeItem!=='function'
  ||typeof flush!=='function'||key!==expectedKey)
  throw new TypeError('Acknowledged avatar-upload assessment storage required');
 const raw=()=>decodeCustomerAvatarUploadAssessmentReference(storage.getItem(key));
 return Object.freeze({
  read(reference){const identity={shopUserId:reference?.shopUserId,sessionId:reference?.sessionId,requestId:reference?.requestId};
   if(!Number.isSafeInteger(identity.shopUserId)||identity.shopUserId<1
    ||![identity.sessionId,identity.requestId].every(id=>typeof id==='string'&&UUID.test(id)))invalid();
   const value=raw();if(value!==null&&(!same(value,{version:1,...identity,startedAt:value.startedAt})))
    throw Error('Saved avatar-upload assessment changed');return value;},
  async submit(reference,current=()=>true,written=()=>{}){const value=decodeCustomerAvatarUploadAssessmentReference(JSON.stringify({version:1,...reference}));
   if(current()!==true||raw()!==null)throw Error('Check the saved avatar-upload assessment');
   storage.setItem(key,JSON.stringify(value));written(value);await flush();
   if(current()!==true||!same(raw(),value))throw Error('Saved avatar-upload assessment changed');return value;},
  async clear(reference,current=()=>true){const value=decodeCustomerAvatarUploadAssessmentReference(JSON.stringify({version:1,...reference}));
   if(current()!==true||!same(raw(),value))throw Error('Saved avatar-upload assessment changed');storage.removeItem(key);
   try{await flush();if(current()!==true||raw()!==null)throw Error('Saved avatar-upload assessment changed');}
   catch(error){storage.setItem(key,JSON.stringify(value));try{await flush();}catch{}throw error;}return true;}
 });
}

export function createCustomerAvatarUploadAssessmentStore(options={}){
 return createAssessmentStore({...options,key:Object.hasOwn(options,'key')?options.key:CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY},CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY);
}
export const decodeCustomerAvatarSvgAssessmentReference=decodeCustomerAvatarUploadAssessmentReference;
export function createCustomerAvatarSvgAssessmentStore(options={}){
 return createAssessmentStore({...options,key:Object.hasOwn(options,'key')?options.key:CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY},CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY);
}

export const CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY='secureshop.customer-avatar-upload.polyglot-preview.v1';
export const CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY='secureshop.customer-avatar-upload.polyglot-assessment.v1';
export function createCustomerAvatarPolyglotPreviewStore(options={}){
 return createAssessmentStore({...options,key:Object.hasOwn(options,'key')?options.key:CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY},CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY);
}
export function createCustomerAvatarPolyglotAssessmentStore(options={}){
 return createAssessmentStore({...options,key:Object.hasOwn(options,'key')?options.key:CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY},CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY);
}
