'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopSceneResetPreflight } = require('../server/services/secureshopSceneResetPreflight');

const sceneId = '30000000-0000-4000-8000-000000000001';
const productId = '40000000-0000-4000-8000-000000000001';
const launchId = '10000000-0000-4000-8000-000000000001';
const resetId = '50000000-0000-4000-8000-000000000001';

function pools(identity, review) {
  return {
    identityPool: {
      query: identity,
      async connect() {
        return { query: async (sql, params) => {
          if (['BEGIN','COMMIT','ROLLBACK'].includes(sql)) return { rows:[] };
          return identity(sql,params);
        }, release() {} };
      },
    },
    reviewPool: { query: review },
  };
}

test('readiness excludes an unrelated local product or review reservation', async () => {
  const identity = async sql => {
    if (sql.includes('FROM identity.secureshop_scenes s')) return { rows:[{ scene_id:sceneId, product_target_id:productId }] };
    if (sql.includes('FROM identity.secureshop_scene_execution_grants g')) return { rows:[{ '?column?':1 }] };
    if (sql.includes('AND NOT (r.target_id=ANY')) return { rows:[{ '?column?':1 }] };
    throw new Error(`Unexpected identity SQL: ${sql}`);
  };
  const review = async sql => {
    if (sql.includes('FROM secureshop_review.product_targets')) return { rows:[{ '?column?':1 }] };
    if (sql.includes('FROM secureshop_review.scene_review_targets')) return { rows:[] };
    throw new Error(`Unexpected review SQL: ${sql}`);
  };
  const preflight = createSecureShopSceneResetPreflight(pools(identity, review));
  const result = await preflight.preview({ ownerId:7, launchId, generation:1, sceneId });
  assert.deepEqual(result, { available:false });
});

test('retired review mapping without an immutable canonical claimant stays unresolved', async () => {
  const identity = async sql => {
    if (sql.includes('pg_advisory_xact_lock')) return { rows:[{}] };
    if (sql.includes('FROM identity.secureshop_launch_resets o')) return { rows:[{
      scene_id:sceneId, product_target_id:productId, retiring_launch_id:null,
    }] };
    if (sql.includes('FROM identity.secureshop_scene_review_targets')) return { rows:[] };
    throw new Error(`Unexpected identity SQL: ${sql}`);
  };
  const review = async sql => {
    if (sql.includes('FROM secureshop_review.scene_review_targets')) return { rows:[{
      review_target_id:'60000000-0000-4000-8000-000000000001', lifecycle:'active',
    }] };
    throw new Error(`Unexpected review SQL: ${sql}`);
  };
  const preflight = createSecureShopSceneResetPreflight(pools(identity, review));
  await assert.rejects(preflight.withOwnerLease(7, lease => lease.reconcileRetired(resetId)),
    { code:'CLEANUP_REQUIRED' });
});

test('crash after mirror commit still creates the exact review retirement claim on recovery', async () => {
  const reviewId = '60000000-0000-4000-8000-000000000001';
  const claims = [];
  const identity = async (sql, params) => {
    if (sql.includes('pg_advisory_xact_lock')) return { rows:[{}] };
    if (sql.includes('FROM identity.secureshop_launch_resets o')) return { rows:[{
      scene_id:sceneId, product_target_id:productId, retiring_launch_id:launchId,
      from_generation:'1', to_generation:'2',
    }] };
    if (sql.includes('FROM identity.secureshop_scene_review_targets')) return { rows:[{ target_id:reviewId }] };
    if (sql.includes('identity.ensure_secureshop_scene_review_retirement')) {
      claims.push(params);
      return { rows:[{ admitted:true }] };
    }
    throw new Error(`Unexpected identity SQL: ${sql}`);
  };
  const review = async sql => {
    if (sql.includes('FROM secureshop_review.scene_review_targets')) return { rows:[{
      review_target_id:reviewId, lifecycle:'active',
    }] };
    throw new Error(`Unexpected review SQL: ${sql}`);
  };
  const preflight = createSecureShopSceneResetPreflight(pools(identity, review));
  await preflight.withOwnerLease(7, lease => lease.reconcileRetired(resetId));
  assert.deepEqual(claims, [[sceneId,reviewId]]);
});
