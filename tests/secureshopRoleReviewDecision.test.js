'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopBoundReviewRepository}=require('../server/database/postgres/secureshopBoundReviewRepository');
const {reviewSnapshotSha256}=require('../server/services/secureshopReviewSnapshot');
const receipts=require('../server/database/postgres/secureshopReviewDecisionReceipt');
const id=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const scope={targetId:id(1),launchId:id(2),scenarioId:id(3),generation:1,platformOwnerId:4,platformSessionId:5};
const actor={id:6,role:'merchant'},operation={operationId:id(7),kind:'manual',personaSessionId:id(8),authorityVersion:'1'};
function fixture(){
 const row={id:9,product_id:10,author_id:11,body:'This product works.',rating:5,status:'pending',moderator_kind:null,moderator_notes:null,created_at:'2026-10-10T00:00:00Z',moderated_at:null};
 const events=[],queries=[];let failCommit=false,failAudit=false;
 const client={release(){},async query(sql,args=[]){queries.push(sql);
  if(sql==='COMMIT'&&failCommit)throw Error('commit unavailable');
  if(/^(BEGIN|COMMIT|ROLLBACK|SET TRANSACTION)|pg_advisory/.test(sql))return{rows:[]};
  if(sql.includes('AS scene_bound'))return{rows:[{scene_bound:false}]};
  if(sql.includes('review_targets'))return{rows:[{lifecycle:'active'}]};
  if(sql.includes('bound_audit_events')){const event=events.find(e=>e.eventId===args[0]);return{rows:event?[{source_kind:'review_decision_operation',launch_id:scope.launchId,scenario_id:scope.scenarioId,generation:scope.generation,original_platform_owner_id:scope.platformOwnerId,original_platform_session_id:scope.platformSessionId,shop_user_id:actor.id,shop_role:actor.role,params_json:event.paramsJson}]:[]}}
  if(sql.startsWith('UPDATE secureshop_review.reviews')){row.status=args[2];row.moderator_kind=args[3];row.moderator_notes=args[4];row.moderated_at='2026-10-10T01:00:00Z';return{rows:[row]}}
  if(sql.includes('FROM secureshop_review.reviews'))return{rows:args[1]===row.id?[row]:[]};
  throw Error('Unexpected query');
 }};
 const repository=createSecureShopBoundReviewRepository({query:client.query,connect:async()=>client},{checkCurrent:async()=>{},checkRetirement:async()=>{},checkCleanup:async()=>{},auditStore:{async append(_c,event){if(failAudit)throw Error('audit unavailable');events.push(event)}}});
 const view=()=>({id:row.id,productId:row.product_id,authorId:row.author_id,body:row.body,rating:row.rating,status:row.status,moderatorKind:row.moderator_kind,moderatorNotes:row.moderator_notes,createdAt:row.created_at,moderatedAt:row.moderated_at});
 return{repository,row,events,queries,view,setCommitFailure(){failCommit=true},setAuditFailure(){failAudit=true}};
}
const input={reviewId:9,decision:'approve',notes:null,moderatorKind:'manual',auditPersona:actor,operation};
test('optional review snapshot leaves historical request bytes unchanged and binds new intent',()=>{
 const legacy=receipts.request(scope,input,operation),before=structuredClone(legacy.exact);
 assert.equal(Object.hasOwn(legacy.exact,'expectedSnapshotSha256'),false);
 const current=receipts.request(scope,{...input,expectedSnapshotSha256:'a'.repeat(64)},operation);
 assert.deepEqual(Object.fromEntries(Object.entries(current.exact).filter(([k])=>k!=='expectedSnapshotSha256')),before);
 assert.notEqual(current.sha256,legacy.sha256);assert.equal(receipts.request(scope,input,operation).sha256,legacy.sha256);
 assert.throws(()=>receipts.request(scope,{...input,expectedSnapshotSha256:'bad'},operation),{code:'REVIEW_OPERATION_CONFLICT'});
});
test('locked snapshot mismatch durably records no-effect stale receipt and exact replay remains stale',async()=>{
 const f=fixture(),expectedSnapshotSha256=reviewSnapshotSha256(f.view());f.row.body='Concurrent edit';
 const value=await f.repository.decide(scope,{...input,expectedSnapshotSha256});
 assert.equal(value.applied,false);assert.equal(value.code,'REVIEW_STALE');assert.equal(value.receipt.resultCode,'REVIEW_STALE');
 assert.equal(f.row.status,'pending');assert.equal(f.events.length,1);assert.equal(f.events[0].action,'review_decide_operation');
 assert.equal(f.queries.some(q=>q.startsWith('UPDATE')),false);assert.equal(f.queries.includes('COMMIT'),true);
 f.row.body='Restored';const replay=await f.repository.decide(scope,{...input,expectedSnapshotSha256});assert.equal(replay.replayed,true);assert.deepEqual(replay.receipt,value.receipt);assert.equal(f.events.length,1);
 assert.deepEqual(await f.repository.readDecisionReceipt(scope,{operationId:operation.operationId,auditPersona:actor}),value.receipt);
 await assert.rejects(f.repository.decide(scope,{...input,expectedSnapshotSha256:'b'.repeat(64)}),{code:'REVIEW_OPERATION_CONFLICT'});
});
test('matching snapshot applies once and exact replay precedes changed status CAS',async()=>{
 const f=fixture(),expectedSnapshotSha256=reviewSnapshotSha256(f.view()),value=await f.repository.decide(scope,{...input,expectedSnapshotSha256});
 assert.equal(value.applied,true);assert.equal(value.receipt.resultCode,null);assert.equal(value.receipt.expectedSnapshotSha256,expectedSnapshotSha256);
 assert.equal(f.events.filter(e=>e.action==='review_decide').length,1);
 assert.equal((await f.repository.decide(scope,{...input,expectedSnapshotSha256})).replayed,true);
 assert.equal(f.events.length,2);
});
test('commit and audit failure never become a successful stale or applied receipt',async()=>{
 for(const method of ['setCommitFailure','setAuditFailure']){const f=fixture();f[method]();await assert.rejects(f.repository.decide(scope,{...input,expectedSnapshotSha256:'a'.repeat(64)}),/unavailable/);assert.ok(f.queries.includes('ROLLBACK'));}
});

test('review service uses existing scene for reads, exact fixed policy and current mode before manual effect',async()=>{
 const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
 const reviewScene=require('../server/services/secureshopReviewSceneBinding');
 const product=createSceneBinding({...scope,targetId:id(20)},{sceneId:id(21),sceneGeneration:1,grantId:id(22),execution:scope,withLease:work=>work()});
 const target=reviewScene.attach(scope,product),f=fixture();let modeName='fixed',effects=0,prepared=0;
 const authority={capture(input){return{binding:{...input.scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work()}}}};
 const modeAuthority={async capture(_scope,featureId){const mode=modeName;return{snapshot:{featureId,mode,policyVersion:'product-feedback-enforced-decision-v1'},async assertCurrent(){if(mode!==modeName)throw Object.assign(Error('mode changed'),{code:'SECURESHOP_FEATURE_MODE_STALE'})}}},assertToken:t=>t};
 const service=require('../server/services/secureshopRoleReviewService').createRoleReviewService({scenes:{async readExisting(){return product}},authority,modeAuthority,application:{async prepareScene(){prepared++}},repository:{async readSceneTarget(){return target},async getReview(){return f.view()},async readDecisionReceipt(){return null},async decide(_t,args){effects++;const requested=receipts.request(scope,{...args,decision:args.decision==='approve'?'approved':'rejected'},args.operation);return{applied:true,receipt:receipts.packet(requested,{applied:true,review:{...f.view(),status:'approved'}}).receipt,replayed:false}},async listReviews(){return{rows:[{...f.row}],total:1}}}});
 const request={scope,persona:actor,personaSession:{sessionId:operation.personaSessionId,authorityVersion:'1'}};
 await service.prepare(request);assert.equal(prepared,1);
 const listed=await service.list({...request,page:1,status:'pending'});assert.equal(listed.rows[0].row.body,f.row.body);assert.equal(listed.rows[0].snapshotSha256,reviewSnapshotSha256(f.view()));
 const detail=await service.detail({...request,reviewId:9});assert.equal(detail.observation.body,'[Review text withheld from the agent in fixed mode]');assert.equal(detail.observation.policy_decision,'approve');assert.equal(detail.row.body,f.row.body);
 assert.equal(effects,0);assert.equal(prepared,1);
 modeName='vuln';await assert.rejects(service.confirm({...request,reviewId:9,operationId:operation.operationId,decision:'approve',scopeKey:detail.scopeKey,modeCapability:detail.modeCapability,expectedSnapshotSha256:detail.snapshotSha256}),{code:'ROLE_PROPOSAL_STALE'});assert.equal(effects,0);
 const raw=await service.detail({...request,reviewId:9});assert.equal(raw.observation.body,f.row.body);
 await service.confirm({...request,reviewId:9,operationId:operation.operationId,decision:'approve',scopeKey:raw.scopeKey,modeCapability:raw.modeCapability,expectedSnapshotSha256:raw.snapshotSha256});assert.equal(effects,1);assert.equal(prepared,1);
});
