'use strict';
const {isDeepStrictEqual}=require('node:util');
const {captureFeatureMode,guardFeatureFence,projectFeatureMode}=require('./secureshopFeatureModeAuthority');
const moderation=require('./secureshopReviewModerationBinding');
const reviewScene=require('./secureshopReviewSceneBinding');
const {createManualReviewDecision}=require('./secureshopManualReviewDecision');
const {reviewSnapshotSha256}=require('./secureshopReviewSnapshot');
const {projectReviewForMode}=require('./secureshopBoundReviewTools');
const fail=()=>Object.assign(new Error('Review assistant unavailable'),{code:'ROLE_REVIEW_UNAVAILABLE'});
function createRoleReviewService({repository,application,authority,modeAuthority,scenes}){
 async function context(input){
  if(input.persona?.role!=='merchant')throw fail();
  const mode=await captureFeatureMode(modeAuthority,input.scope,'review');
  const fence=guardFeatureFence(await authority.capture({scope:input.scope,personaId:input.persona.id,role:'merchant',...input.personaSession}),mode);
  await fence.assertRemoteAdmission();
  const product=await scenes.readExisting(input.scope),target=product&&await repository.readSceneTarget(product);
  if(!target||reviewScene.productScene(target)?.targetId!==product.targetId)throw fail();
  const cap=moderation.capture(target,input.persona,fence);
  const manual=createManualReviewDecision({authority:{capture:()=>fence},repository,resolveTarget:async()=>target});
  const capability=await manual.capability(input);
  return{mode,fence,target,cap,manual,scopeKey:capability.scopeKey};
 }
 async function read(input){const c=await context(input),row=await repository.getReview(c.target,input.reviewId,{moderation:c.cap});
  if(!row)throw Object.assign(Error('Review unavailable'),{code:'ROLE_CHOICE_STALE'});
  await c.fence.assertRemoteAdmission();return{...c,row,snapshotSha256:reviewSnapshotSha256(row)};}
 return Object.freeze({
  async prepare(input){return application.prepareScene(input);},
  async list(input){
   const c=await context(input),result=await repository.listReviews(c.target,{status:input.status==='all'?undefined:input.status,productId:input.productId,limit:5,offset:(input.page-1)*5},{moderation:c.cap});
   const rows=result.rows.map(item=>{const row={id:item.id,productId:item.product_id,authorId:item.author_id,body:item.body,rating:item.rating,status:item.status,moderatorKind:item.moderator_kind,moderatorNotes:item.moderator_notes,createdAt:item.created_at,moderatedAt:item.moderated_at,...(typeof item.product_name==='string'?{productName:item.product_name}: {})};return{row,snapshotSha256:reviewSnapshotSha256(row)}});
   await c.fence.assertRemoteAdmission();return{rows,total:result.total,modeCapability:projectFeatureMode(c.mode)};
  },
  async detail(input){const c=await read(input);return{row:c.row,snapshotSha256:c.snapshotSha256,scopeKey:c.scopeKey,modeCapability:projectFeatureMode(c.mode),observation:projectReviewForMode({reviewId:c.row.id,productId:c.row.productId,rating:c.row.rating,status:c.row.status,body:c.row.body},c.mode.snapshot.mode)};},
  async confirm(input){const c=await context(input);
   if(c.scopeKey!==input.scopeKey||!isDeepStrictEqual(projectFeatureMode(c.mode),input.modeCapability))throw Object.assign(Error('Review mode changed'),{code:'ROLE_PROPOSAL_STALE'});
   const value=await c.manual.decide(input);await c.fence.assertRemoteAdmission();return{ok:true,applied:value.applied,review_id:input.reviewId,receipt:value.receipt,replayed:value.replayed,executionScopeKey:value.executionScopeKey};
  },
  async capability(input){const c=await context(input);return{scopeKey:c.scopeKey,modeCapability:projectFeatureMode(c.mode)};}
 });
}
module.exports={createRoleReviewService};
