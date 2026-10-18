'use strict';
const {createHash}=require('node:crypto');
const {validateListingEditPreview}=require('./secureshopListingEditContract');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===keys.slice().sort().join(',');
const fail=()=>Object.assign(new Error('Listing proposal unavailable'),{code:'ROLE_LISTING_PROPOSAL_INVALID'});
function proposalId(sessionId,requestId,step,callId){
 if(!UUID.test(sessionId||'')||!UUID.test(requestId||'')||!Number.isSafeInteger(step)||step<1||step>4
  ||typeof callId!=='string'||!callId||Buffer.byteLength(callId)>128)throw fail();
 const h=createHash('sha256').update(JSON.stringify(['merchant-listing-proposal-v1',sessionId,requestId,step,callId])).digest('hex');
 return `${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-8${h.slice(17,20)}-${h.slice(20,32)}`;
}
function validate(value,{sessionId,requestId}={}){
 if(!exact(value,['version','proposalId','product','preview','origin','sourceSnapshotSha256'])||value.version!==1
  ||!exact(value.product,['choiceId','name'])||!UUID.test(value.product.choiceId||'')
  ||typeof value.product.name!=='string'||!value.product.name.trim()||!value.product.name.isWellFormed()
  ||value.product.name.includes('\0')||Buffer.byteLength(value.product.name)>256
  ||!SHA.test(value.sourceSnapshotSha256||'')||!exact(value.origin,['step','callId'])
  ||value.proposalId!==proposalId(sessionId,requestId,value.origin.step,value.origin.callId))throw fail();
 try{validateListingEditPreview(value.preview)}catch{throw fail()}
 return value;
}
function create({sessionId,requestId,step,callId,selected,preview}){
 if(!selected||selected.sourceId!==preview?.productId)throw fail();
 return Object.freeze(validate({version:1,proposalId:proposalId(sessionId,requestId,step,callId),
  product:{choiceId:selected.choiceId,name:selected.card?.title},preview:structuredClone(preview),
  origin:{step,callId},sourceSnapshotSha256:selected.snapshotSha256},{sessionId,requestId}));
}
function project(value,source){const p=validate(value,source);return Object.freeze({version:1,proposalId:p.proposalId,
 product:Object.freeze({...p.product}),preview:structuredClone(p.preview)});}
module.exports={createRoleListingProposal:create,validateRoleListingProposal:validate,projectRoleListingProposal:project};
