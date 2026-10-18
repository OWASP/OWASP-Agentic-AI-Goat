'use strict';
const { createLaunchScope } = require('./secureshopConversationBinding');
const { createSceneBinding, executionScope, authorizeSceneMerchant } = require('./secureshopSceneBinding');
function unavailable(code = 'SHOP_SCENE_STALE') {
  return Object.assign(new Error(code === 'SHOP_SCENE_SELECTION_REQUIRED'
    ? 'Choose an existing shop practice to continue' : 'Shop practice is unavailable'), { code });
}
function createSecureShopScenes({ repository, reviewPool, launches } = {}) {
  if (['candidates','adopt','list','grant','select','withLease'].some(key => typeof repository?.[key] !== 'function')
      || typeof reviewPool?.query !== 'function' || typeof launches?.assertCurrent !== 'function') throw TypeError('Scene dependencies required');
  async function discover(scope) {
    const e = createLaunchScope(scope);
    const candidates = await repository.candidates(e);
    // Read only already provisioned, active targets with an exact birth binding.
    // A reservation alone is not evidence that a populated shop exists.
    const active = [];
    if (candidates.length) {
      const rows = (await reviewPool.query(`SELECT target_id,launch_id,scenario_id,generation,
        original_platform_owner_id,original_platform_session_id FROM secureshop_review.product_targets
        WHERE target_id=ANY($1::uuid[]) AND original_platform_owner_id=$2 AND lifecycle='active'`,
      [candidates.map(value => value.targetId), e.platformOwnerId])).rows;
      for (const b of candidates) {
        const row = rows.find(value => value.target_id === b.targetId);
        if (!row) continue;
        if (row.launch_id !== b.launchId || row.scenario_id !== b.scenarioId || Number(row.generation) !== b.generation
            || Number(row.original_platform_session_id) !== b.platformSessionId) throw unavailable();
        active.push(b);
      }
    }
    return repository.adopt(e, active);
  }
  async function bind(scope, scene) {
    const grant = await repository.grant(scope, scene.sceneId);
    return repository.withLease(grant, async () => {
      const e = grant.execution;
      const values = [grant.grantId, grant.sceneId, grant.sceneGeneration, grant.storage.targetId,
        e.launchId, e.scenarioId, e.generation, e.platformOwnerId, e.platformSessionId];
      await reviewPool.query(`INSERT INTO secureshop_review.scene_execution_grants
        (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(grant_id) DO NOTHING`, values);
      const exact = await reviewPool.query(`SELECT 1 FROM secureshop_review.scene_execution_grants
        WHERE (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
          =($1,$2,$3,$4,$5,$6,$7,$8,$9)`, values);
      if (exact.rowCount !== 1) throw unavailable();
      return createSceneBinding(grant.storage, { ...grant, withLease: work => repository.withLease(grant, work) });
    });
  }
  async function bindRetained(scope, scene) {
    if(typeof repository.readRetainedGrant!=='function')throw unavailable();
    const grant=await repository.readRetainedGrant(scope,scene.sceneId);
    return repository.withLease(grant,async()=>{
      const e=grant.execution;
      const values=[grant.grantId,grant.sceneId,grant.sceneGeneration,grant.storage.targetId,
        e.launchId,e.scenarioId,e.generation,e.platformOwnerId,e.platformSessionId];
      const exact=await reviewPool.query(`SELECT 1 FROM secureshop_review.scene_execution_grants
        WHERE (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,
          original_platform_owner_id,original_platform_session_id)
          =($1,$2,$3,$4,$5,$6,$7,$8,$9)`,values);
      if(exact.rowCount!==1)throw unavailable();
      return createSceneBinding(grant.storage,{...grant,withLease:work=>repository.withLease(grant,work)});
    });
  }
  async function selected(scope) {
    const scenes = await discover(scope);
    const selected = scenes.find(scene => scene.isDefault);
    if (!selected && scenes.length > 1) throw unavailable('SHOP_SCENE_SELECTION_REQUIRED');
    return selected || scenes[0] || null;
  }
  return Object.freeze({
    withProvisionLease: (scope, work) => typeof repository.withProvisionLease === 'function'
      ? repository.withProvisionLease(scope, work) : work(),
    store: scope => typeof repository.store === 'function' ? repository.store(scope) : null,
    async merchant(binding, actorId) {
      if (typeof repository.merchant !== 'function') throw unavailable();
      await repository.merchant(executionScope(binding), actorId);
      return authorizeSceneMerchant(binding, actorId);
    },
    async list(scope) {
      const scenes = await discover(scope);
      await launches.assertCurrent(scope);
      return scenes.map((scene, index) => Object.freeze({ id: scene.sceneId, label: `Shop practice ${index + 1}`,
        createdAt: scene.createdAt, isDefault: scene.isDefault }));
    },
    async select(scope, sceneId) {
      const work = async () => {
        await discover(scope);
        const scene = await repository.select(scope, sceneId);
        return Object.freeze({ id: scene.sceneId, isDefault: true });
      };
      return typeof repository.withProvisionLease === 'function'
        ? repository.withProvisionLease(scope, work) : work();
    },
    async resolve(scope) {
      const scene = await selected(scope);
      // New practice provisioning continues through the existing captured
      // persona/launch path. finalize() adopts only its verified result.
      return scene ? bind(scope, scene) : null;
    },
    async readExisting(scope) {
      const scenes = await repository.list(scope);
      const selected = scenes.find(scene => scene.isDefault);
      if (!selected && scenes.length > 1) throw unavailable('SHOP_SCENE_SELECTION_REQUIRED');
      return selected || scenes[0] ? bind(scope, selected || scenes[0]) : null;
    },
    async readRetained(scope) {
      const scenes=await repository.list(scope);
      const selected=scenes.find(scene=>scene.isDefault);
      if(!selected&&scenes.length>1)throw unavailable('SHOP_SCENE_SELECTION_REQUIRED');
      return selected||scenes[0]?bindRetained(scope,selected||scenes[0]):null;
    },
    async finalize(scope, provisioned) {
      const e = createLaunchScope(scope);
      if (provisioned.scene !== undefined) return provisioned;
      if (['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key => provisioned[key] !== e[key])) throw unavailable();
      const scene = await selected(e);
      if (!scene) throw unavailable();
      return bind(e, scene);
    },
  });
}
module.exports = { createSecureShopScenes };
