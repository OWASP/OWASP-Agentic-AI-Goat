'use strict';
const {createHash}=require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const fail=()=>Object.assign(new Error('Inventory proposal unavailable'),{code:'ROLE_INVENTORY_PROPOSAL_INVALID'});
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===keys.slice().sort().join(',');
function proposalId(sessionId,requestId,step,callId){
 if(!UUID.test(sessionId)||!UUID.test(requestId)||!Number.isSafeInteger(step)||step<1||step>4
  ||typeof callId!=='string'||!callId||Buffer.byteLength(callId,'utf8')>128)throw fail();
 const h=createHash('sha256').update(JSON.stringify(['merchant-inventory-proposal-v1',sessionId,requestId,step,callId])).digest('hex');
 return `${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-8${h.slice(17,20)}-${h.slice(20,32)}`;
}
function validate(value,{sessionId,requestId}={}){
 if(!exact(value,['version','proposalId','product','stockChange','message','scopeKey','modeCapability','origin','sourceSnapshotSha256'])
  ||value.version!==1||!exact(value.product,['choiceId','name'])||!UUID.test(value.product.choiceId)
  ||typeof value.product.name!=='string'||!value.product.name.trim()||!value.product.name.isWellFormed()
  ||Buffer.byteLength(value.product.name,'utf8')>256
  ||!exact(value.stockChange,['productId','quantity'])||!Number.isSafeInteger(value.stockChange.productId)
  ||value.stockChange.productId<1||value.stockChange.productId>2147483647
  ||!Number.isSafeInteger(value.stockChange.quantity)||value.stockChange.quantity<0||value.stockChange.quantity>2147483647
  ||typeof value.message!=='string'||!value.message.trim()||!value.message.isWellFormed()
  ||value.message.includes('\0')||Buffer.byteLength(value.message,'utf8')>8192
  ||!SHA.test(value.scopeKey||'')||!SHA.test(value.sourceSnapshotSha256||'')
  ||!exact(value.modeCapability,['version','featureId','policyVersion','effectiveMode','scope'])
  ||value.modeCapability.version!==1||value.modeCapability.featureId!=='inventory'
  ||typeof value.modeCapability.policyVersion!=='string'||!value.modeCapability.policyVersion
  ||!['vuln','fixed'].includes(value.modeCapability.effectiveMode)
  ||!exact(value.modeCapability.scope,['kind','id'])||value.modeCapability.scope.kind!=='launch_feature'
  ||value.modeCapability.scope.id!=='inventory'
  ||!exact(value.origin,['step','callId'])||!UUID.test(value.proposalId||'')
  ||value.proposalId!==proposalId(sessionId,requestId,value.origin.step,value.origin.callId))throw fail();
 return value;
}
function create({sessionId,requestId,step,callId,selected,quantity,message,readiness}){
 if(!selected||!Number.isSafeInteger(selected.sourceId)||!UUID.test(selected.choiceId||'')
  ||!SHA.test(selected.snapshotSha256||'')||!readiness||readiness.ready!==true)throw fail();
 return Object.freeze(validate({version:1,proposalId:proposalId(sessionId,requestId,step,callId),
  product:{choiceId:selected.choiceId,name:selected.card?.title},
  stockChange:{productId:selected.sourceId,quantity},message,scopeKey:readiness.scopeKey,
  modeCapability:readiness.modeCapability,origin:{step,callId},
  sourceSnapshotSha256:selected.snapshotSha256},{sessionId,requestId}));
}
function project(value,source){const p=validate(value,source);return Object.freeze({version:1,proposalId:p.proposalId,
 product:Object.freeze({...p.product}),stockChange:Object.freeze({...p.stockChange}),message:p.message,
 scopeKey:p.scopeKey,modeCapability:structuredClone(p.modeCapability)});}
module.exports={createRoleInventoryProposal:create,validateRoleInventoryProposal:validate,
 projectRoleInventoryProposal:project};
