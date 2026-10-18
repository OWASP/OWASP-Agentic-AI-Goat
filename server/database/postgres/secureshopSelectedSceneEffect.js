'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const { withTransaction } = require('./index');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const stale = () => Object.assign(new Error('Selected shop scene unavailable'),
  { code: 'SHOP_SCENE_STALE', executionBoundary: true });

// A standalone selection lease for short local cross-store effects only.
// Lock order: identity owner -> launch/selection/scene -> persona -> review.
// Never invoke scenes.readExisting/select (ownerTransaction), HTTP, or model
// work inside this callback. The original target's separate scene lease and
// mode/persona fences remain the caller's responsibility.
function createSelectedSceneEffect({ pool, launches } = {}) {
  if (typeof pool?.connect !== 'function' || typeof launches?.assertCurrent !== 'function')
    throw new TypeError('Selected scene effect dependencies required');
  const held = new AsyncLocalStorage();
  return async function withSelectedSceneEffect({ scope, expectedTarget } = {}, work) {
    const binding = createLaunchScope(scope);
    if (held.getStore() || typeof work !== 'function' || !expectedTarget
        || Object.getPrototypeOf(expectedTarget) !== Object.prototype
        || Reflect.ownKeys(expectedTarget).length !== 4
        || Object.keys(expectedTarget).sort().join(',') !== 'grantId,sceneGeneration,sceneId,targetId'
        || ['targetId', 'sceneId', 'grantId'].some(key => !UUID.test(expectedTarget[key] || ''))
        || !Number.isSafeInteger(expectedTarget.sceneGeneration)
        || expectedTarget.sceneGeneration < 1) throw stale();
    const target = Object.freeze({ targetId: expectedTarget.targetId.toLowerCase(),
      sceneId: expectedTarget.sceneId.toLowerCase(),
      sceneGeneration: expectedTarget.sceneGeneration,
      grantId: expectedTarget.grantId.toLowerCase() });
    await launches.assertCurrent(binding);
    let entered = false;
    try {
      return await withTransaction(pool, async client => {
        await client.query("SET LOCAL lock_timeout='3000ms'");
        await client.query("SET LOCAL statement_timeout='3000ms'");
        await client.query("SET LOCAL idle_in_transaction_session_timeout='5000ms'");
        // SceneRepository.select and practice publication acquire UPDATE on
        // this same owner before changing the current selection.
        const owner = await client.query(`SELECT id FROM identity.secureshop_authority_owners
          WHERE id=$1 AND realm='shop' AND is_active=1 AND NOT source_deleted
          AND (account_locked_until IS NULL OR account_locked_until<=clock_timestamp())
          FOR SHARE`, [binding.platformOwnerId]);
        if (owner.rowCount !== 1) throw stale();
        const check = async () => {
          const current = await client.query(`SELECT l.launch_id
            FROM identity.secureshop_launches l
            JOIN secureshop_auth.execution_authority_state a
              ON a.session_id=l.platform_session_id AND a.owner_id=l.original_platform_owner_id
            JOIN secureshop_auth.execution_sessions e ON e.session_id=a.session_id
            JOIN secureshop_auth.practice_selections x
              ON x.auth_session_id=e.auth_session_id AND x.tenant_id=e.tenant_id
              AND x.principal_id=e.principal_id AND x.execution_session_id=e.session_id
            JOIN identity.secureshop_scenes s ON s.scene_id=x.scene_id
            JOIN identity.secureshop_scene_execution_grants g ON g.scene_id=s.scene_id
              AND g.scene_generation=s.scene_generation
            WHERE l.launch_id=$1 AND l.scenario_id=$2 AND l.generation=$3
              AND l.original_platform_owner_id=$4 AND l.platform_session_id=$5
              AND l.status='active' AND l.expires_at>clock_timestamp()
              AND a.is_active=1 AND a.expires_at>clock_timestamp()
              AND s.scene_id=$6 AND s.product_target_id=$7 AND s.scene_generation=$8
              AND s.original_platform_owner_id=$4 AND s.status='active'
              AND g.grant_id=$9 AND g.launch_id=$1 AND g.scenario_id=$2
              AND g.generation=$3 AND g.original_platform_owner_id=$4
              AND g.original_platform_session_id=$5
            FOR SHARE OF l,x,s`, [binding.launchId, binding.scenarioId,
            binding.generation, binding.platformOwnerId, binding.platformSessionId,
            target.sceneId, target.targetId, target.sceneGeneration, target.grantId]);
          if (current.rowCount !== 1) throw stale();
        };
        await check();
        return held.run(true, async () => {
          entered = true;
          const result = await work();
          await check();
          return result;
        });
      });
    } catch (cause) {
      if (!entered) throw cause;
      // The separate review transaction may already have committed. An
      // identity lease/COMMIT failure must never claim its effect rolled back.
      throw Object.assign(new Error('Selected scene effect requires authoritative readback'),
        { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', executionBoundary: true, cause });
    }
  };
}

module.exports = { createSelectedSceneEffect };
