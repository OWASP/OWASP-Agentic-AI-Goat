'use strict';

const { createLaunchScope } = require('./secureshopConversationBinding');
const trusted = new WeakSet();
const leases = new WeakMap();
const merchants = new WeakMap();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function unavailable() {
  return Object.assign(new Error('Shop practice authority is unavailable'), { code: 'SHOP_SCENE_STALE', executionBoundary: true });
}

// Only the server resolver creates these capabilities. JSON, spread copies and
// client-supplied scene fields cannot authorize access to an older snapshot.
function createSceneBinding(storage, { sceneId, sceneGeneration, grantId, execution, withLease } = {}) {
  const birth = createLaunchScope(storage);
  const current = createLaunchScope(execution);
  if (![storage.targetId, sceneId, grantId].every(value => typeof value === 'string' && UUID.test(value))
      || !Number.isSafeInteger(sceneGeneration) || sceneGeneration < 1
      || current.platformOwnerId !== birth.platformOwnerId || typeof withLease !== 'function') throw unavailable();
  const scene = Object.freeze({ sceneId, sceneGeneration, grantId, execution: current });
  const result = Object.freeze({ ...birth, targetId: storage.targetId, scene });
  trusted.add(result);
  leases.set(result, withLease);
  return result;
}
function copySceneBinding(source, normalized) {
  if (source?.scene !== undefined && !trusted.has(source)) throw unavailable();
  if (!trusted.has(source)) return Object.freeze(normalized);
  if (['targetId', 'launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
    .some(key => source[key] !== normalized[key])) throw unavailable();
  const result = Object.freeze({ ...normalized, scene: source.scene });
  trusted.add(result);
  leases.set(result, leases.get(source));
  if (merchants.has(source)) merchants.set(result, merchants.get(source));
  return result;
}
function authorizeSceneMerchant(binding, actorId) {
  if (!trusted.has(binding) || !Number.isSafeInteger(actorId) || actorId < 1000000000) throw unavailable();
  const result = copySceneBinding(binding, { ...createLaunchScope(binding), targetId: binding.targetId });
  merchants.set(result, actorId);
  return result;
}
function isSceneMerchant(binding, actorId) {
  return trusted.has(binding) && merchants.get(binding) === actorId;
}
function withSceneLease(binding, work) {
  if (typeof work !== 'function') throw unavailable();
  executionScope(binding);
  return trusted.has(binding) ? leases.get(binding)(work) : work();
}
function executionScope(binding) {
  if (binding?.scene !== undefined && !trusted.has(binding)) throw unavailable();
  return trusted.has(binding) ? binding.scene.execution : binding;
}
async function assertSceneGrant(client, binding) {
  if (!trusted.has(binding)) {
    if (binding?.scene !== undefined) throw unavailable();
    return;
  }
  const { sceneId, sceneGeneration, grantId, execution: e } = binding.scene;
  const result = await client.query(`SELECT secureshop_review.assert_scene_execution_grant(
    $1::uuid,$2::uuid,$3::bigint,$4::uuid,$5::uuid,$6::uuid,$7::bigint,$8::integer,$9::integer) AS allowed`,
  [grantId, sceneId, sceneGeneration, binding.targetId, e.launchId, e.scenarioId,
    e.generation, e.platformOwnerId, e.platformSessionId]);
  if (result.rows[0]?.allowed !== true) throw unavailable();
}
module.exports = { createSceneBinding, copySceneBinding, executionScope, assertSceneGrant, withSceneLease,
  authorizeSceneMerchant, isSceneMerchant };
