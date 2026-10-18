'use strict';
const {createHash}=require('node:crypto');
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail=()=>Object.assign(Error('Review proposal unavailable'),{code:'ROLE_REVIEW_PROPOSAL_INVALID'});
function id(sessionId,requestId,origin){
 if(!UUID.test(sessionId||'')||!UUID.test(requestId||'')||!exact(origin,['step','callId'])||!Number.isSafeInteger(origin.step)||origin.step<1||origin.step>4||typeof origin.callId!=='string'||!origin.callId||Buffer.byteLength(origin.callId)>128)throw fail();
 const h=hash(['merchant-review-proposal-v1',sessionId,requestId,origin.step,origin.callId]);return`${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-8${h.slice(17,20)}-${h.slice(20,32)}`;
}
function modeValid(m){return exact(m,['version','featureId','policyVersion','effectiveMode','scope'])&&m.version===1&&m.featureId==='review'&&m.policyVersion==='product-feedback-enforced-decision-v1'&&['vuln','fixed'].includes(m.effectiveMode)&&exact(m.scope,['kind','id'])&&m.scope.kind==='launch_feature'&&m.scope.id==='review';}
function publicValue(p){
 // Preserve the original creation byte order after PostgreSQL jsonb reorders
 // nested objects. Validation still checks the complete original key sets.
 const r=p.review,m=p.modeCapability;
 return{version:1,proposalId:p.proposalId,
  review:{choiceId:r.choiceId,reviewId:r.reviewId,productId:r.productId,rating:r.rating,body:r.body,status:r.status},
  decision:p.decision,reason:p.reason,expectedSnapshotSha256:p.expectedSnapshotSha256,scopeKey:p.scopeKey,
  modeCapability:{version:m.version,featureId:m.featureId,policyVersion:m.policyVersion,effectiveMode:m.effectiveMode,
   scope:{kind:m.scope.kind,id:m.scope.id}}};
}
function validate(p,source){
 if(!exact(p,['version','proposalId','review','decision','reason','expectedSnapshotSha256','scopeKey','modeCapability','requestSha256','origin','sourceSnapshotSha256'])||p.version!==1||p.proposalId!==id(source.sessionId,source.requestId,p.origin)
  ||!exact(p.review,['choiceId','reviewId','productId','rating','body','status'])||!UUID.test(p.review.choiceId||'')||!Number.isSafeInteger(p.review.reviewId)||p.review.reviewId<1||!Number.isSafeInteger(p.review.productId)||p.review.productId<1||!Number.isInteger(p.review.rating)||p.review.rating<1||p.review.rating>5||p.review.status!=='pending'||typeof p.review.body!=='string'||Buffer.byteLength(p.review.body)>65536
  ||!['approve','reject'].includes(p.decision)||p.decision==='approve'&&p.reason!==null||p.decision==='reject'&&(typeof p.reason!=='string'||!p.reason.trim()||Buffer.byteLength(p.reason)>1024)
  ||!SHA.test(p.expectedSnapshotSha256||'')||!SHA.test(p.sourceSnapshotSha256||'')||typeof p.scopeKey!=='string'||!p.scopeKey||Buffer.byteLength(p.scopeKey)>1024||!modeValid(p.modeCapability)||p.requestSha256!==hash(publicValue(p)))throw fail();return{...p,...publicValue(p)};
}
function create({sessionId,requestId,step,callId,selected,detail,decision,reason}){
 const p={version:1,proposalId:id(sessionId,requestId,{step,callId}),review:{choiceId:selected.choiceId,reviewId:detail.row.id,productId:detail.row.productId,rating:detail.row.rating,body:detail.row.body,status:detail.row.status},decision,reason:decision==='approve'?null:reason,expectedSnapshotSha256:detail.snapshotSha256,scopeKey:detail.scopeKey,modeCapability:detail.modeCapability,origin:{step,callId},sourceSnapshotSha256:selected.snapshotSha256};
 p.requestSha256=hash(publicValue(p));return validate(p,{sessionId,requestId});
}
function project(value,source){const p=validate(value,source);return{...publicValue(p),requestSha256:p.requestSha256};}
module.exports={createRoleReviewProposal:create,validateRoleReviewProposal:validate,projectRoleReviewProposal:project,reviewModeValid:modeValid};
