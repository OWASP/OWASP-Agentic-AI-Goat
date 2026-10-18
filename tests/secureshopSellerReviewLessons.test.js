'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const reviewScene = require('../server/services/secureshopReviewSceneBinding');
const { PROFILE_DIGESTS } = require('../server/services/secureshopBoundReviewFixtureProfiles');
const { createSecureShopBoundReviewRepository } = require('../server/database/postgres/secureshopBoundReviewRepository');
const id = n => `00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const birth = {launchId:id(1),scenarioId:id(2),generation:1,platformOwnerId:11,platformSessionId:12};
const product = createSceneBinding({...birth,targetId:id(3)}, {sceneId:id(4),sceneGeneration:1,grantId:id(5),execution:birth,withLease:work=>work()});
const target = reviewScene.attach({...birth,targetId:id(6)},product);
const hash = value => crypto.createHash('sha256').update(value).digest();
function fixture({status='adopted',corrupt=false,custom=false,cleanupCount=4}={}) {
  const seed=Buffer.from(custom?'a'.repeat(64):PROFILE_DIGESTS.preferred,'hex');
  const rows = status==='adopted'||status==='replayed' ? [1,2].map(n=>({id:100+n,product_id:n,body:`raw lesson ${n}`})) : [];
  const markers=rows.map((r,i)=>{
    const body=hash(r.body);
    return {profile_version:1,ordinal:i+1,product_target_id:product.targetId,retailer_id:1000000001,
      product_id:r.product_id,review_id:r.id,body_sha256:body,seed_sha256:seed,
      provenance_sha256:hash([target.targetId,1,i+1,product.targetId,1000000001,r.product_id,r.id,body.toString('hex'),seed.toString('hex')].join(':'))};
  });
  if(corrupt) markers[0].provenance_sha256=Buffer.alloc(32);
  const calls=[];
  const client={release(){},async query(sql,params=[]){calls.push({sql,params});
    if(/^(BEGIN|COMMIT|ROLLBACK)/.test(sql))return{rows:[]};
    if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:true}]};
    if(sql.includes('scene_review_targets'))return{rows:[{exists:1}]};
    if(sql.includes('review_cleanup_receipts'))return{rows:[]};
    if(sql.includes('count(*)'))return{rows:[{count:cleanupCount}]};
    if(sql.includes('review_targets'))return{rows:[{seed_count:2,seed_sha256:seed,lifecycle:'active'}]};
    if(sql.includes('adopt_seller_review_lessons'))return{rows:[{status}]};
    if(sql.includes('seller_review_lessons'))return{rows:markers};
    if(sql.includes('reviews'))return{rows};
    throw Error('Unexpected query');
  }};
  const repository=createSecureShopBoundReviewRepository({query:client.query,connect:async()=>client},
    {checkCurrent:async()=>{},checkRetirement:async()=>{},checkCleanup:async()=>{}});
  return {repository,calls};
}
test('adoption pins exact target and current scene grant and verifies immutable supplement provenance',async()=>{
  for(const status of ['adopted','replayed']) {
    const f=fixture({status});assert.deepEqual(await f.repository.adoptSellerLessons(target),{status});
    const call=f.calls.find(row=>row.sql.includes('adopt_seller_review_lessons'));
    assert.deepEqual(call.params,[target.targetId,product.scene.grantId]);
    const targetLock=f.calls.findIndex(row=>row.sql.includes('review_targets')&&row.sql.includes('FOR UPDATE'));
    const grantLock=f.calls.findIndex(row=>row.sql.includes('assert_scene_execution_grant'));
    assert.ok(targetLock>=0&&targetLock<grantLock,'target UPDATE precedes grant SHARE');
    assert.equal(f.calls.filter(row=>row.sql.startsWith('UPDATE')).length,0);
  }
});
test('custom profiles and bounded adoption denials are explicit and do not fabricate source rows',async()=>{
  for(const status of ['custom_profile','capacity_unavailable','owned_products_unavailable']) {
    const f=fixture({status,custom:status==='custom_profile'});
    assert.deepEqual(await f.repository.adoptSellerLessons(target),{status});
    assert.equal(f.calls.some(row=>row.sql.startsWith('INSERT')),false);
  }
});
test('unrecognized or corrupt supplemental provenance rolls back instead of claiming adoption',async()=>{
  const f=fixture({corrupt:true});await assert.rejects(f.repository.adoptSellerLessons(target),{code:'REVIEW_TARGET_PARTIAL'});
  assert.equal(f.calls.at(-1).sql,'ROLLBACK');
  const unknown=fixture({status:'silently_skipped'});await assert.rejects(unknown.repository.adoptSellerLessons(target),{code:'REVIEW_TARGET_PARTIAL'});
});

test('cleanup refuses to delete when total rows cannot cover both original seed and supplement',async()=>{
  const f=fixture({cleanupCount:3});
  await assert.rejects(f.repository.cleanup(target,{operationId:id(9)}),{code:'REVIEW_TARGET_PARTIAL'});
  assert.equal(f.calls.some(row=>row.sql.startsWith('DELETE')),false);
  assert.equal(f.calls.at(-1).sql,'ROLLBACK');
});
