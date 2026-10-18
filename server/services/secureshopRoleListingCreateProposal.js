'use strict';
const {createHash}=require('node:crypto');
const {validateListingCreatePreview}=require('./secureshopListingCreateContract');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).sort().join(',')===keys.slice().sort().join(',');
const fail=()=>Object.assign(new Error('Listing proposal unavailable'),{code:'ROLE_LISTING_CREATE_PROPOSAL_INVALID'});
function proposalId(sessionId,requestId,step,callId){
 if(!UUID.test(sessionId||'')||!UUID.test(requestId||'')||!Number.isSafeInteger(step)||step<1||step>4
  ||typeof callId!=='string'||!callId||Buffer.byteLength(callId)>128)throw fail();
 const h=createHash('sha256').update(JSON.stringify(['merchant-listing-create-proposal-v1',sessionId,requestId,step,callId])).digest('hex');
 return `${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-8${h.slice(17,20)}-${h.slice(20,32)}`;
}
function validate(value,{sessionId,requestId}={}){
 if(!exact(value,['version','proposalId','preview','origin'])||value.version!==1
  ||!exact(value.origin,['step','callId'])
  ||value.proposalId!==proposalId(sessionId,requestId,value.origin.step,value.origin.callId))throw fail();
 try{
  const preview=validateListingCreatePreview(value.preview);
  if(preview.version===2){
   const source=preview.source.preparation;
   if(source.sessionId!==sessionId||source.requestId!==requestId
    ||source.step!==value.origin.step||source.callId!==value.origin.callId)throw fail();
  }
 }catch{throw fail()}
 return value;
}
function create({sessionId,requestId,step,callId,preview}){
 return Object.freeze(validate({version:1,proposalId:proposalId(sessionId,requestId,step,callId),
  preview:structuredClone(preview),origin:{step,callId}},{sessionId,requestId}));
}
function project(value,source){const p=validate(value,source);return Object.freeze({version:1,proposalId:p.proposalId,
 preview:structuredClone(p.preview)});}
module.exports={createRoleListingCreateProposal:create,validateRoleListingCreateProposal:validate,projectRoleListingCreateProposal:project};
