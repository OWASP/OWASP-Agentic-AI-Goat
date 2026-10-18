'use strict';
const {createLaunchScope}=require('./secureshopConversationBinding');
const {executionScope,withSceneLease}=require('./secureshopSceneBinding');
const binding=require('./secureshopMailSceneBinding');
const fail=code=>Object.assign(Error('Mail scene unavailable'),{code:code||'MAIL_SCENE_STALE',executionBoundary:true});
const KEYS=['launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
const sameOuterScene=(expected,actual)=>expected?.targetId===actual?.targetId
 &&expected?.scene?.sceneId===actual?.scene?.sceneId
 &&expected?.scene?.sceneGeneration===actual?.scene?.sceneGeneration;
function createMailScenes({repository,scenes,catalog,agentsPool,launches,inboxRepository,resolveFixtures,personaAuthority}){
 if(['read','candidates','adopt'].some(k=>typeof repository?.[k]!=='function')
  ||typeof scenes?.withProvisionLease!=='function'||typeof scenes?.readExisting!=='function'
  ||typeof catalog?.prepareTarget!=='function'||typeof agentsPool?.query!=='function'
  ||typeof launches?.reservePersonaInboxTarget!=='function'||typeof inboxRepository?.provision!=='function'
  ||typeof resolveFixtures!=='function'||typeof personaAuthority?.capture!=='function')throw TypeError('Mail scene dependencies required');
 async function verify(b){
  const row=(await agentsPool.query(`SELECT target_id,launch_id,scenario_id,generation,
    original_platform_owner_id,original_platform_session_id FROM secureshop_agents.persona_inbox_targets
    WHERE target_id=$1 AND lifecycle='active'`,[b.targetId])).rows[0];
  if(!row)return false;
  if(row.launch_id!==b.launchId||row.scenario_id!==b.scenarioId||Number(row.generation)!==b.generation
   ||Number(row.original_platform_owner_id)!==b.platformOwnerId||Number(row.original_platform_session_id)!==b.platformSessionId)throw fail();
  return true;
 }
 async function bind(scene,b){return withSceneLease(scene,async()=>{
  if(!await verify(b))throw fail();
  const e=executionScope(scene),s=scene.scene;
  await agentsPool.query(`INSERT INTO secureshop_agents.mail_scene_targets
    (scene_id,scene_generation,target_id,original_platform_owner_id,birth_launch_id,birth_scenario_id,birth_generation,birth_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(scene_id) DO NOTHING`,
  [s.sceneId,s.sceneGeneration,b.targetId,b.platformOwnerId,b.launchId,b.scenarioId,b.generation,b.platformSessionId]);
  await agentsPool.query(`INSERT INTO secureshop_agents.mail_scene_execution_grants
    (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(grant_id) DO NOTHING`,
  [s.grantId,s.sceneId,s.sceneGeneration,b.targetId,e.launchId,e.scenarioId,e.generation,e.platformOwnerId,e.platformSessionId]);
  const result=binding.attach(b,scene);await binding.assertGrant(agentsPool,result);return result;
 });}
 return Object.freeze({
  async readExisting(scope){const e=createLaunchScope(scope),scene=await scenes.readExisting(e);if(!scene)throw fail();
   const b=await repository.read(scene);if(!b)throw fail();return bind(scene,b);},
  // Saved mail projections must not adopt a target or recreate a scene grant.
  async readRetained(scope){
   if(typeof scenes.readRetained!=='function')throw fail();
   const e=createLaunchScope(scope),scene=await scenes.readRetained(e);if(!scene)throw fail();
   const b=await repository.read(scene);if(!b)throw fail();
   return withSceneLease(scene,async()=>{
    if(!await verify(b))throw fail();
    const result=binding.attach(b,scene);await binding.assertGrant(agentsPool,result);return result;
   });},
  async resolve(context){const e=createLaunchScope(context.scope);
   const fence=await personaAuthority.capture({scope:e,personaId:context.persona?.id,role:context.persona?.role,...context.personaSession});
   if(typeof fence?.assertRemoteAdmission!=='function'||KEYS.some(k=>fence.binding?.[k]!==e[k])
    ||fence.binding.personaId!==context.persona?.id||fence.binding.role!==context.persona?.role
    ||fence.binding.sessionId!==context.personaSession?.sessionId
    ||fence.binding.authorityVersion!==context.personaSession?.authorityVersion)throw fail('SHOP_AUTH_INVALID');
   await fence.assertRemoteAdmission();
   // Catalog preparation owns its provisioning lease. Finish it first, then
   // re-resolve the selected scene under the mail provisioning lease.
   await catalog.prepareTarget({...context,personaEffect:
    require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence)});
   const result=await scenes.withProvisionLease(e,async()=>{
    // Mail-first visits establish the same shop scene as catalog-first visits.
    const scene=await scenes.readExisting(e);if(!scene)throw fail();
    // A selected RoleChat scene cannot provision a grant on a different
    // practice if the owner's selection changes during fresh preparation.
    if(context.target!==undefined&&!sameOuterScene(context.target,scene))throw fail();
    let b=await repository.read(scene);
    if(!b){
     const candidates=await repository.candidates(scene),active=[];
     for(const candidate of candidates)if(await verify(candidate))active.push(candidate);
     const associated=active.filter(candidate=>candidate.associated);
     if(associated.length>1||(!associated.length&&active.length>1))throw fail('MAIL_SCENE_SELECTION_REQUIRED');
     b=associated[0]||active[0];
     if(!b){
      const reserved=await launches.reservePersonaInboxTarget({launchId:e.launchId,platformOwnerId:e.platformOwnerId,
       platformSessionId:e.platformSessionId,expectedGeneration:e.generation});
      b=Object.freeze({...e,targetId:reserved.targetId});
      await fence.assertRemoteAdmission();
      const fixtures=await resolveFixtures();
      await withSceneLease(scene,()=>fence.withCrossStoreEffect(
       ()=>inboxRepository.provision(b,{fixtures,mode:'advisory'})));
     }
     b=await repository.adopt(scene,b);
    }
    return bind(scene,b);
   });
   await fence.assertRemoteAdmission();await launches.assertCurrent(e);return result;
  },
 });
}
module.exports={createMailScenes};
