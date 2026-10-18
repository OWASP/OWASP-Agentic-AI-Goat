'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const {createSecureShopSceneRepository}=require('../server/database/postgres/secureshopSceneRepository');
const {createSecureShopScenes}=require('../server/services/secureshopScenes');

const scope={launchId:'11111111-1111-4111-8111-111111111111',
 scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,
 platformOwnerId:3,platformSessionId:4};
const sceneId='33333333-3333-4333-8333-333333333333';
const grantId='44444444-4444-4444-8444-444444444444';
const targetId='55555555-5555-4555-8555-555555555555';
const row={scene_id:sceneId,scene_generation:1,is_default:true,created_at:'2026-10-11T00:00:00Z',
 status:'active',product_target_id:targetId,birth_launch_id:scope.launchId,
 birth_scenario_id:scope.scenarioId,birth_generation:scope.generation,
 original_platform_owner_id:scope.platformOwnerId,birth_platform_session_id:scope.platformSessionId,
 grant_id:grantId};
test('retained scene grant is SELECT only and missing grant fails closed',async()=>{
 const queries=[];let found=true;
 const pool={connect:async()=>{throw Error('unexpected transaction');},
  query:async(sql)=>{queries.push(sql);return{rows:found?[row]:[]};}};
 const repository=createSecureShopSceneRepository({pool,launches:{assertCurrent:async()=>{}}});
 const grant=await repository.readRetainedGrant(scope,sceneId);
 assert.equal(grant.grantId,grantId);
 found=false;
 await assert.rejects(repository.readRetainedGrant(scope,sceneId),{code:'SHOP_SCENE_STALE'});
 assert.equal(queries.length,2);
 assert.ok(queries.every(sql=>/^SELECT\b/.test(sql.trim())));
});
test('retained scene binding performs only existing grant checks',async()=>{
 const queries=[];
 const grant={sceneId,sceneGeneration:1,grantId,execution:scope,
  storage:{...scope,targetId}};
 const repository={candidates:()=>{},adopt:()=>{},grant:()=>{throw Error('write grant called');},
  select:()=>{},withLease:async(_grant,work)=>work(),
  list:async()=>[{sceneId,isDefault:true}],
  readRetainedGrant:async()=>grant};
 const scenes=createSecureShopScenes({repository,
  reviewPool:{query:async sql=>{queries.push(sql);return{rowCount:1};}},
  launches:{assertCurrent:async()=>{}}});
 const retained=await scenes.readRetained(scope);
 assert.equal(retained.targetId,targetId);
 assert.equal(retained.scene.grantId,grantId);
 assert.equal(queries.length,1);
 assert.match(queries[0],/^SELECT\b/);
});
