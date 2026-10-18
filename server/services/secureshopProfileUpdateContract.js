'use strict';
const C=require('./secureshopConversationalCommerceContract');
const FIELD_KEYS=Object.freeze(['fullName','email','phone']);
const LIMITS=Object.freeze({fullName:512,email:320,phone:128});
const SHA=/^[a-f0-9]{64}$/;
const PROFILE_PATCH_SCHEMA=Object.freeze({type:'object',minProperties:1,additionalProperties:false,properties:{
 fullName:{type:['string','null'],maxLength:512},email:{type:'string',minLength:3,maxLength:320},phone:{type:['string','null'],maxLength:128}}});
function hash(value){if(typeof value!=='string'||!SHA.test(value))throw C.fail();return value;}
function field(key,value){
 if(value===null&&key!=='email')return null;
 if(typeof value!=='string'||!value.isWellFormed()||value.includes('\0')||Buffer.byteLength(value)>LIMITS[key])throw C.fail();
 if(key==='email'){if(!/^[^\s@]+@[^\s@]+$/.test(value))throw C.fail();return value;}
 return value.trim()?value:null;
}
function normalizeProfilePatch(value){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||!Object.keys(value).length||Object.keys(value).some(k=>!FIELD_KEYS.includes(k)))throw C.fail();
 return Object.freeze(Object.fromEntries(FIELD_KEYS.filter(k=>Object.hasOwn(value,k)).map(k=>[k,field(k,value[k])])));
}
function normalizeProfileFields(value){if(!C.exact(value,FIELD_KEYS))throw C.fail();return Object.freeze(Object.fromEntries(FIELD_KEYS.map(k=>[k,field(k,value[k])])));}
// A retained database row may predate strict email validation. Preserve its
// presentation bytes; only a changed email may invoke the strict patch rule.
function normalizeProfileView(value){
 if(!C.exact(value,FIELD_KEYS))throw C.fail();
 return Object.freeze(Object.fromEntries(FIELD_KEYS.map(key=>{
  const v=value[key];if(v===null&&key!=='email')return[key,null];
  if(typeof v!=='string'||!v.isWellFormed()||v.includes('\0')||Buffer.byteLength(v)>LIMITS[key]||key==='email'&&Buffer.byteLength(v)<3)throw C.fail();
  return[key,v];
 })));
}
function profileFieldsDigest(value){return C.digest(normalizeProfileView(value));}
function profileSaveRequest(value){
 if(!C.exact(value,['operationId','expectedSnapshotSha256','fields']))throw C.fail();
 return Object.freeze({operationId:C.uuid(value.operationId),expectedSnapshotSha256:hash(value.expectedSnapshotSha256),fields:normalizeProfileView(value.fields)});
}
function profileIntent(value){const {fields,...identity}=profileSaveRequest(value);return Object.freeze({...identity,fieldsSha256:profileFieldsDigest(fields)});}
function profileRequestDigest(value){return C.digest(profileIntent(value));}
function profileReceipt(value){
 if(!C.exact(value,['version','operationId','kind','status','result','replayed'])||value.version!==1||value.kind!=='profile.update'||!['completed','stale'].includes(value.status)||typeof value.replayed!=='boolean')throw C.fail('COMMERCE_STATE_INVALID');
 C.uuid(value.operationId);
 if(!C.exact(value.result,value.status==='stale'?['fieldsSha256']:['fieldsSha256','profileSnapshotSha256']))throw C.fail('COMMERCE_STATE_INVALID');
 hash(value.result.fieldsSha256);if(value.status==='completed')hash(value.result.profileSnapshotSha256);return value;
}
module.exports={FIELD_KEYS,PROFILE_PATCH_SCHEMA,normalizeProfilePatch,normalizeProfileFields,normalizeProfileView,profileFieldsDigest,profileSaveRequest,profileIntent,profileRequestDigest,profileReceipt};
