'use strict';

const { executionScope, assertSceneGrant, withSceneLease } = require('./secureshopSceneBinding');
const trusted = new WeakMap();
const KEYS = ['targetId', 'launchId', 'scenarioId', 'generation',
  'platformOwnerId', 'platformSessionId'];
function unavailable() {
  throw Object.assign(new Error('Review scene authority is unavailable'),
    { code: 'SHOP_SCENE_STALE', executionBoundary: true });
}
function attach(reviewBirth, productScene) {
  if (!productScene?.scene || !productScene?.targetId) unavailable();
  executionScope(productScene); // Reject caller-supplied scene lookalikes.
  if (reviewBirth.platformOwnerId !== productScene.platformOwnerId) unavailable();
  const binding = Object.freeze(Object.fromEntries(KEYS.map(key => [key, reviewBirth[key]])));
  trusted.set(binding, productScene);
  return binding;
}
function copy(source, normalized) {
  const scene = trusted.get(source);
  if (!scene) return Object.freeze(normalized);
  if (KEYS.some(key => source[key] !== normalized[key])) unavailable();
  return attach(normalized, scene);
}
function productScene(binding) { return trusted.get(binding) || null; }
function current(binding) { const scene = productScene(binding); return scene ? executionScope(scene) : binding; }
function withLease(binding, work) {
  const scene = productScene(binding);
  return scene ? withSceneLease(scene, work) : work();
}
async function assertGrant(client, binding) {
  const scene = productScene(binding);
  if (!scene) return;
  await assertSceneGrant(client, scene);
  const row = (await client.query(`SELECT 1 FROM secureshop_review.scene_review_targets m
    JOIN secureshop_review.review_targets r ON r.target_id=m.review_target_id
    WHERE m.scene_id=$1 AND m.product_target_id=$2 AND m.review_target_id=$3
      AND m.original_platform_owner_id=$4 AND r.lifecycle='active'
      AND (r.launch_id,r.scenario_id,r.generation,r.original_platform_owner_id,
        r.original_platform_session_id)=($5,$6,$7,$8,$9)
    FOR SHARE OF r`, [scene.scene.sceneId, scene.targetId, binding.targetId,
      scene.platformOwnerId, binding.launchId, binding.scenarioId, binding.generation,
      binding.platformOwnerId, binding.platformSessionId])).rows[0];
  if (!row) unavailable();
}
module.exports = { attach, copy, productScene, current, withLease, assertGrant };
