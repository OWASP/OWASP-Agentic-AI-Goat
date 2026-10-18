'use strict';
const C=require('./secureshopConversationalCommerceContract');
const LIMITS=Object.freeze({label:128,line1:1024,line2:1024,city:256,state:128,zip:64,phone:128});
const FIELD_KEYS=Object.freeze([...Object.keys(LIMITS),'isDefault']);
const SHA=/^[a-f0-9]{64}$/;
function hash(value){if(typeof value!=='string'||!SHA.test(value))throw C.fail();return value;}
function field(key,value,{draft=false}={}){
 if(value===null&&!draft)return null;
 if(typeof value!=='string'||!value.isWellFormed()||value.includes('\0')||Buffer.byteLength(value)>LIMITS[key])throw C.fail();
 return draft?value:value.trim()?value:null;
}
const ADDRESS_DRAFT_SCHEMA=Object.freeze({type:'object',additionalProperties:false,properties:Object.fromEntries(Object.entries(LIMITS).map(([key,maxLength])=>[key,{type:'string',maxLength}]))});
function normalizeAddressDraft(value){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).some(key=>!Object.hasOwn(LIMITS,key)))throw C.fail();
 return Object.freeze(Object.fromEntries(Object.keys(LIMITS).filter(key=>Object.hasOwn(value,key)).map(key=>[key,field(key,value[key],{draft:true})])));
}
function normalizeAddressFields(value){
 if(!C.exact(value,FIELD_KEYS)||typeof value.isDefault!=='boolean')throw C.fail();
 const fields=Object.fromEntries(Object.keys(LIMITS).map(key=>[key,field(key,value[key])]));
 if(fields.line1===null)throw C.fail();return Object.freeze({...fields,isDefault:value.isDefault});
}
function addressFieldsDigest(value){return C.digest(normalizeAddressFields(value));}
function addressFormRequest(value){
 if(!C.exact(value,['action','choiceId'])||!['create','update'].includes(value.action)||(value.action==='create'&&value.choiceId!==null))throw C.fail();
 return Object.freeze({action:value.action,choiceId:value.action==='create'?null:C.uuid(value.choiceId)});
}
function addressSaveRequest(value){
 if(!C.exact(value,['operationId','action','choiceId','expectedSnapshotSha256','defaultSetSha256','fields']))throw C.fail();
 const base=addressFormRequest({action:value.action,choiceId:value.choiceId});
 if(base.action==='create'&&value.expectedSnapshotSha256!==null)throw C.fail();
 return Object.freeze({operationId:C.uuid(value.operationId),...base,expectedSnapshotSha256:base.action==='create'?null:hash(value.expectedSnapshotSha256),defaultSetSha256:hash(value.defaultSetSha256),fields:normalizeAddressFields(value.fields)});
}
function addressIntent(value){const {fields,...identity}=addressSaveRequest(value);return Object.freeze({...identity,fieldsSha256:addressFieldsDigest(fields)});}
function addressSetup(value){
 if(!C.exact(value,['version','kind','action','choiceId','draft'])||value.version!==1||value.kind!=='address_setup')throw C.fail();
 return Object.freeze({version:1,kind:'address_setup',...addressFormRequest({action:value.action,choiceId:value.choiceId}),draft:normalizeAddressDraft(value.draft)});
}
function addressReceipt(value){
 if(!C.exact(value,['version','operationId','kind','status','result','replayed'])||value.version!==1||!['completed','stale'].includes(value.status)||!['address.create','address.update'].includes(value.kind)||typeof value.replayed!=='boolean')throw C.fail('COMMERCE_STATE_INVALID');
 C.uuid(value.operationId);
 if(value.status==='stale'){if(!C.exact(value.result,['fieldsSha256']))throw C.fail('COMMERCE_STATE_INVALID');hash(value.result.fieldsSha256);return value;}
 if(!C.exact(value.result,['addressId','fieldsSha256','addressSnapshotSha256','defaultSetSha256']))throw C.fail('COMMERCE_STATE_INVALID');
 C.integer(value.result.addressId,1,Number.MAX_SAFE_INTEGER);for(const key of ['fieldsSha256','addressSnapshotSha256','defaultSetSha256'])hash(value.result[key]);return value;
}
module.exports={FIELD_KEYS,ADDRESS_DRAFT_SCHEMA,normalizeAddressDraft,normalizeAddressFields,addressFieldsDigest,addressFormRequest,addressSaveRequest,addressIntent,addressSetup,addressReceipt};
