'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const {createSecureShopStandaloneAuthRepository}=require('../server/database/postgres/secureshopStandaloneAuthRepository');
const {createSecureShopSceneRepository}=require('../server/database/postgres/secureshopSceneRepository');
const principalId='11111111-1111-4111-8111-111111111111', tenantId='22222222-2222-4222-8222-222222222222';
const sceneId='33333333-3333-4333-8333-333333333333', otherScene='44444444-4444-4444-8444-444444444444';
const expiresAt='2099-01-01T00:00:00.000Z';
function authFixture({selected=true,revoked=false}={}) {
  const calls=[];
  const source={principalId,principalOwnerId:9,ownerId:91,authSessionId:10,tenantId,membershipVersion:'1',
    shopUserId:1000000001,username:'customer',email:'a@example.test',role:'customer',credentialVersion:'1',authorityVersion:'1',expiresAt};
  async function query(sql,args=[]) {
    calls.push([sql,args]);
    if(sql.includes('SELECT p.principal_id::text AS "principalId"'))return{rows:[source]};
    if(sql.includes('FROM secureshop_auth.practice_selections x JOIN'))return{rows:selected?[{sessionId:21,expiresAt,revokedAt:revoked?'2026-01-01':null}]:[]};
    if(sql.includes('SELECT scene.scene_id'))return{rows:[{scene_id:sceneId}]};
    if(sql.startsWith('INSERT INTO secureshop_auth.execution_sessions'))return{rows:[{sessionId:22,expiresAt,revokedAt:null}]};
    return{rows:[],rowCount:1};
  }
  const repo=createSecureShopStandaloneAuthRepository({pool:{query,connect:async()=>({query,release(){}})}});
  return{calls,repo,input:{principalId,authSessionId:10,credentialVersion:'1',authorityVersion:'1'}};
}
test('bootstrap returns the selected execution instead of arbitrarily choosing an older execution',async()=>{
  const f=authFixture(); assert.equal((await f.repo.readOrCreateDefaultExecutionSession(f.input)).sessionId,21);
  assert.equal(f.calls.some(([sql])=>sql.startsWith('INSERT')),false);
});
test('renewal initializes a fresh execution while preserving only the retained scene choice',async()=>{
  const f=authFixture({selected:false});
  assert.equal((await f.repo.readOrCreateDefaultExecutionSession(f.input)).sessionId,22);
  const choice=f.calls.find(([sql])=>sql.includes('SELECT scene.scene_id'));
  assert.match(choice[0],/prior.auth_session_id=s.renewed_from_session_id/);
  const write=f.calls.find(([sql])=>sql.startsWith('INSERT INTO secureshop_auth.practice_selections'));
  assert.deepEqual(write[1],[10,tenantId,principalId,22,sceneId]);
  const preference=f.calls.find(([sql])=>sql.startsWith('INSERT INTO secureshop_auth.practice_preferences'));
  assert.deepEqual(preference[1],[tenantId,principalId,sceneId]);
});
test('revoked selected execution cannot be silently replaced under the same cookie',async()=>{
  const f=authFixture({revoked:true});
  await assert.rejects(f.repo.readOrCreateDefaultExecutionSession(f.input),{code:'SHOP_AUTH_INVALID'});
  assert.equal(f.calls.some(([sql])=>sql.startsWith('INSERT')),false);
});
const scope={launchId:'55555555-5555-4555-8555-555555555555',scenarioId:'66666666-6666-4666-8666-666666666666',
  generation:1,platformOwnerId:91,platformSessionId:21};
function sceneFixture({platform=false,stale=false}={}) {
  const calls=[];
  const rows=[sceneId,otherScene].map((id,index)=>({scene_id:id,scene_generation:'1',is_default:index===0,
    created_at:'2026-01-01',status:'active',product_target_id:id,birth_launch_id:scope.launchId,
    birth_scenario_id:scope.scenarioId,birth_generation:'1',original_platform_owner_id:91,birth_platform_session_id:21}));
  async function query(sql,args=[]) {
    calls.push([sql,args]);
    if(sql.includes('SELECT e.auth_session_id,e.tenant_id,e.principal_id'))return{rows:platform?[]:[{
      auth_session_id:10,tenant_id:tenantId,principal_id:principalId,execution_session_id:stale?20:21,scene_id:otherScene}]};
    if(sql.includes('SELECT auth_session_id,tenant_id,principal_id'))return{rows:platform?[]:[{auth_session_id:10,tenant_id:tenantId,principal_id:principalId}]};
    if(sql.startsWith('SELECT * FROM identity.secureshop_scenes'))return{rows:sql.includes('scene_id=$1')?rows.filter(row=>row.scene_id===args[0]):rows};
    return{rows:[],rowCount:1};
  }
  return{calls,repo:createSecureShopSceneRepository({pool:{query,connect:async()=>({query,release(){}})},launches:{assertCurrent:async()=>true}})};
}
test('standalone scene list projects caller choice while platform default is unchanged',async()=>{
  const shop=sceneFixture();const scenes=await shop.repo.list(scope);
  assert.equal(scenes.find(row=>row.isDefault).sceneId,otherScene);
  const platform=sceneFixture({platform:true});assert.equal((await platform.repo.list(scope)).find(row=>row.isDefault).sceneId,sceneId);
});
test('standalone scene selection updates only exact caller and its revisioned preference',async()=>{
  const f=sceneFixture();assert.equal((await f.repo.select(scope,otherScene)).isDefault,true);
  assert.equal(f.calls.some(([sql])=>sql.startsWith('UPDATE identity.secureshop_scenes')),false);
  const changed=f.calls.find(([sql])=>sql.startsWith('UPDATE secureshop_auth.practice_selections'));
  assert.deepEqual(changed[1],[otherScene,10,tenantId,principalId,21]);
});
test('superseded execution cannot resolve the replacement execution scene',async()=>{
  await assert.rejects(sceneFixture({stale:true}).repo.list(scope),{code:'SHOP_SCENE_STALE'});
});
