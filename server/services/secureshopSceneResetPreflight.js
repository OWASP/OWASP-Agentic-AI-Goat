'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const { createHash } = require('node:crypto');
const { withTransaction } = require('../database/postgres');
const reviewScene = require('./secureshopReviewSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function unavailable() { return Object.assign(new Error('Scene reset preflight unavailable'), { code: 'CLEANUP_REQUIRED' }); }
function ownerId(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw unavailable();
  return value;
}
function scope(value) {
  if (!value || !UUID.test(value.launchId) || !Number.isSafeInteger(value.generation)
      || value.generation < 1) throw unavailable();
  return Object.freeze({ launchId: value.launchId.toLowerCase(), generation: value.generation });
}

function createSecureShopSceneResetPreflight({ identityPool, reviewPool } = {}) {
  if (typeof identityPool?.connect !== 'function' || typeof reviewPool?.query !== 'function') throw unavailable();
  const held = new AsyncLocalStorage();

  async function mirror(sceneId, productTargetId, reviewTargetId, expectedOwner) {
    if (![sceneId, productTargetId, reviewTargetId].every(value => typeof value === 'string' && UUID.test(value))) throw unavailable();
    const row = (await reviewPool.query(`SELECT m.scene_id,m.product_target_id,m.review_target_id,
      m.original_platform_owner_id,r.launch_id,r.scenario_id,r.generation,
      r.original_platform_session_id,r.lifecycle
      FROM secureshop_review.scene_review_targets m
      JOIN secureshop_review.review_targets r ON r.target_id=m.review_target_id
      WHERE m.scene_id=$1 AND m.product_target_id=$2 AND m.review_target_id=$3`,
    [sceneId, productTargetId, reviewTargetId])).rows[0];
    if (!row || Number(row.original_platform_owner_id) !== expectedOwner || row.lifecycle !== 'active') throw unavailable();
    return withTransaction(identityPool, async client => {
      const selected = (await client.query(`SELECT g.grant_id FROM identity.secureshop_scenes s
        JOIN identity.secureshop_scene_execution_grants g ON g.scene_id=s.scene_id
        JOIN identity.secureshop_target_reservations r ON r.target_id=$3 AND r.target_kind='reviews'
        WHERE s.scene_id=$1 AND s.product_target_id=$2
          AND s.original_platform_owner_id=$4 AND r.original_platform_owner_id=$4
          AND r.launch_id=$5 AND r.generation=$6
          AND ((r.launch_id,r.generation)=(s.birth_launch_id,s.birth_generation)
            OR (r.launch_id,r.generation)=(g.launch_id,g.generation))
        ORDER BY g.created_at,g.grant_id LIMIT 1`,
      [sceneId,productTargetId,reviewTargetId,expectedOwner,row.launch_id,Number(row.generation)])).rows[0];
      if (!selected) throw unavailable();
      await client.query(`INSERT INTO identity.secureshop_scene_review_targets
        (scene_id,target_id,original_platform_owner_id,birth_launch_id,birth_scenario_id,
         birth_generation,birth_platform_session_id,adopted_by_grant_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
      [sceneId,reviewTargetId,expectedOwner,row.launch_id,row.scenario_id,Number(row.generation),
        Number(row.original_platform_session_id),selected.grant_id]);
      const exact = (await client.query(`SELECT 1 FROM identity.secureshop_scene_review_targets
        WHERE scene_id=$1 AND target_id=$2 AND original_platform_owner_id=$3
          AND (birth_launch_id,birth_scenario_id,birth_generation,birth_platform_session_id)=($4,$5,$6,$7)`,
      [sceneId,reviewTargetId,expectedOwner,row.launch_id,row.scenario_id,Number(row.generation),
        Number(row.original_platform_session_id)])).rows[0];
      if (!exact) throw unavailable();
      return true;
    });
  }

  async function preflightLaunches(value, { expectedSceneId } = {}) {
    const token = held.getStore();
    if (!token?.active) throw unavailable();
    if (!Array.isArray(value) || value.length > 256 || Object.keys(value).length !== value.length) throw unavailable();
    const launches = value.map(scope);
    if (new Set(launches.map(item => `${item.launchId}:${item.generation}`)).size !== launches.length) throw unavailable();
    const rows = (await identityPool.query(`SELECT DISTINCT s.scene_id,s.product_target_id,s.original_platform_owner_id
      FROM identity.secureshop_scenes s
      WHERE s.original_platform_owner_id=$1 AND s.status='active'
        AND (EXISTS (
          SELECT 1 FROM unnest($2::uuid[],$3::bigint[]) AS birth(launch_id,generation)
          WHERE (s.birth_launch_id,s.birth_generation)=(birth.launch_id,birth.generation)) OR EXISTS (
          SELECT 1 FROM identity.secureshop_scene_execution_grants g
          WHERE g.scene_id=s.scene_id AND (g.launch_id,g.generation) IN (
            SELECT x.launch_id,x.generation FROM unnest($2::uuid[],$3::bigint[]) AS x(launch_id,generation))))
      ORDER BY s.scene_id`, [token.ownerId, launches.map(x => x.launchId),
        launches.map(x => x.generation)])).rows;
    if (expectedSceneId !== undefined) {
      if (typeof expectedSceneId !== 'string' || !UUID.test(expectedSceneId)
          || rows.length !== 1 || rows[0].scene_id !== expectedSceneId.toLowerCase()) throw unavailable();
      const selected = (await identityPool.query(`SELECT scene_id FROM identity.secureshop_scenes
        WHERE original_platform_owner_id=$1 AND status='active'`, [token.ownerId])).rows;
      if (selected.length !== 1 || selected[0].scene_id !== expectedSceneId.toLowerCase()) throw unavailable();
    }
    const selectedTargets = new Set(rows.map(row => row.product_target_id));
    for (const row of rows) {
      const mappings = (await reviewPool.query(`SELECT m.review_target_id FROM secureshop_review.scene_review_targets m
        WHERE m.scene_id=$1 AND m.product_target_id=$2 AND m.original_platform_owner_id=$3`,
      [row.scene_id,row.product_target_id,token.ownerId])).rows;
      if (mappings.length > 1) throw unavailable();
      if (mappings.length) {
        selectedTargets.add(mappings[0].review_target_id);
        await mirror(row.scene_id,row.product_target_id,mappings[0].review_target_id,token.ownerId);
      }
    }
    if (expectedSceneId !== undefined) {
      const orphan = (await identityPool.query(`SELECT 1 FROM identity.secureshop_target_reservations r
        WHERE r.original_platform_owner_id=$1 AND r.target_kind IN ('products','reviews')
          AND (r.launch_id,r.generation) IN (
            SELECT x.launch_id,x.generation FROM unnest($2::uuid[],$3::bigint[]) AS x(launch_id,generation))
          AND NOT (r.target_id=ANY($4::uuid[])) LIMIT 1`,
      [token.ownerId,launches.map(x => x.launchId),launches.map(x => x.generation),
        [...selectedTargets]])).rows[0];
      if (orphan) throw unavailable();
    }
    return Object.freeze({ sceneCount: rows.length,
      reviewMirrorCount: rows.length ? Number((await identityPool.query(`SELECT count(*)::int n
        FROM identity.secureshop_scene_review_targets WHERE scene_id=ANY($1::uuid[])`,
      [rows.map(row => row.scene_id)])).rows[0].n) : 0 });
  }

  async function listOwnerLaunches() {
    const token = held.getStore();
    if (!token?.active) throw unavailable();
    const rows = (await identityPool.query(`SELECT launch_id,generation
      FROM identity.secureshop_launches
      WHERE original_platform_owner_id=$1 AND NOT identity.secureshop_launch_is_retired(launch_id)
      ORDER BY launch_id LIMIT 257`, [token.ownerId])).rows;
    if (rows.length > 256) throw unavailable();
    return Object.freeze(rows.map(row => scope({launchId:row.launch_id,generation:Number(row.generation)})));
  }
  async function readExactResetIntent({ launchId, generation, idempotencyKey, sceneId } = {}) {
    const token = held.getStore();
    if (!token?.active || typeof sceneId !== 'string' || !UUID.test(sceneId)
        || typeof idempotencyKey !== 'string' || !idempotencyKey.length
        || Buffer.byteLength(idempotencyKey) > 256) throw unavailable();
    const launch = scope({ launchId, generation });
    const hash = createHash('sha256').update(idempotencyKey).digest();
    const row = (await identityPool.query(`SELECT o.reset_id,o.status
      FROM identity.secureshop_launch_resets o
      JOIN identity.secureshop_launches l ON l.launch_id=o.launch_id
      JOIN identity.secureshop_scenes scene ON scene.scene_id=$5
      JOIN identity.secureshop_scene_target_retirements claim
        ON claim.scene_id=scene.scene_id AND claim.target_kind='products'
       AND claim.target_id=scene.product_target_id
       AND claim.retiring_launch_id=o.launch_id AND claim.from_generation=o.from_generation
       AND claim.to_generation=o.to_generation
      WHERE o.launch_id=$1 AND o.from_generation=$2 AND o.idempotency_hash=$3
        AND l.original_platform_owner_id=$4 AND scene.original_platform_owner_id=$4
        AND scene.status='retired' AND o.status IN ('fenced','committed')`,
    [launch.launchId,launch.generation,hash,token.ownerId,sceneId.toLowerCase()])).rows[0];
    return row ? Object.freeze({ exists:true, resetId:row.reset_id, status:row.status })
      : Object.freeze({ exists:false });
  }

  async function reconcileRetired(resetId) {
    const token = held.getStore();
    if (!token?.active || typeof resetId !== 'string' || !UUID.test(resetId)) throw unavailable();
    const scenes = (await identityPool.query(`SELECT scene.scene_id,scene.product_target_id,
      claim.retiring_launch_id,claim.from_generation,claim.to_generation
      FROM identity.secureshop_launch_resets o
      JOIN identity.secureshop_scenes scene ON scene.original_platform_owner_id=$2
        AND scene.status='retired'
      LEFT JOIN identity.secureshop_scene_target_retirements claim
        ON claim.scene_id=scene.scene_id AND claim.target_kind='products'
      WHERE o.reset_id=$1 AND o.launch_id IN (
        SELECT launch_id FROM identity.secureshop_launches
        WHERE original_platform_owner_id=$2)
        AND ((scene.birth_launch_id=o.launch_id AND scene.birth_generation=o.from_generation)
          OR EXISTS (SELECT 1 FROM identity.secureshop_scene_execution_grants grant_row
            WHERE grant_row.scene_id=scene.scene_id AND grant_row.launch_id=o.launch_id
              AND grant_row.generation=o.from_generation))
      ORDER BY scene.scene_id LIMIT 257`, [resetId,token.ownerId])).rows;
    if (scenes.length > 256) throw unavailable();
    for (const scene of scenes) {
      const mapping = (await reviewPool.query(`SELECT m.review_target_id,r.lifecycle
        FROM secureshop_review.scene_review_targets m
        JOIN secureshop_review.review_targets r ON r.target_id=m.review_target_id
        WHERE m.scene_id=$1 AND m.product_target_id=$2
          AND m.original_platform_owner_id=$3`,
      [scene.scene_id,scene.product_target_id,token.ownerId])).rows;
      if (mapping.length > 1) throw unavailable();
      if (!mapping.length) continue;
      const review = mapping[0];
      const known = (await identityPool.query(`SELECT target_id FROM identity.secureshop_scene_review_targets
        WHERE scene_id=$1`, [scene.scene_id])).rows[0];
      if (known && known.target_id !== review.review_target_id) throw unavailable();
      // Product cleanup history or a mail retirement can establish this claim
      // in 0147. A later review history alone cannot prove which transition
      // first retired the scene, so that legacy ambiguity stays explicit debt.
      if (!scene.retiring_launch_id) throw unavailable();
      const claimant = scene;
      if (!known && review.lifecycle === 'active') {
        await mirror(scene.scene_id,scene.product_target_id,review.review_target_id,token.ownerId);
      } else if (!known) {
        const history = (await identityPool.query(`SELECT 1 FROM identity.secureshop_target_cleanup_history h
          JOIN identity.secureshop_launch_resets o ON o.reset_id=h.operation_id
          WHERE h.target_id=$1 AND h.target_kind='reviews' AND
            (o.launch_id,o.from_generation,o.to_generation)=($2,$3,$4)`,
        [review.review_target_id,claimant.retiring_launch_id,claimant.from_generation,
          claimant.to_generation])).rows[0];
        if (!history) throw unavailable();
        continue;
      }
      const ensured = (await identityPool.query(`SELECT
        identity.ensure_secureshop_scene_review_retirement($1,$2) AS admitted`,
      [scene.scene_id,review.review_target_id])).rows[0];
      if (ensured?.admitted !== true) throw unavailable();
    }
    return true;
  }

  async function withOwnerLease(value, work) {
    const owner = ownerId(value);
    if (typeof work !== 'function') throw unavailable();
    const nested = held.getStore();
    if (nested) {
      if (!nested.active || nested.ownerId !== owner) throw unavailable();
      return work(Object.freeze({ preflightLaunches, listOwnerLaunches, readExactResetIntent,
        reconcileRetired }));
    }
    return withTransaction(identityPool, async client => {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-store-provision:'||$1::text,0))", [owner]);
      const token = { ownerId: owner, active: true };
      try { return await held.run(token, () => work(Object.freeze({ preflightLaunches, listOwnerLaunches,
        readExactResetIntent, reconcileRetired }))); }
      finally { token.active = false; }
    });
  }

  async function mirrorReviewScene(target) {
    const scene = reviewScene.productScene(target);
    if (!scene || !scene.scene) throw unavailable();
    return mirror(scene.scene.sceneId,scene.targetId,target.targetId,scene.platformOwnerId);
  }
  async function preview({ ownerId: requestedOwner, launchId, generation, sceneId } = {}) {
    const owner = ownerId(requestedOwner);
    const launch = scope({ launchId, generation });
    if (typeof sceneId !== 'string' || !UUID.test(sceneId)) throw unavailable();
    const scenes = (await identityPool.query(`SELECT s.scene_id,s.product_target_id
      FROM identity.secureshop_scenes s
      WHERE s.original_platform_owner_id=$1 AND s.status='active'`, [owner])).rows;
    if (scenes.length !== 1 || scenes[0].scene_id !== sceneId.toLowerCase()) return Object.freeze({ available:false });
    const grant = (await identityPool.query(`SELECT 1 FROM identity.secureshop_scene_execution_grants g
      WHERE g.scene_id=$1 AND g.launch_id=$2 AND g.generation=$3
        AND g.original_platform_owner_id=$4`,
    [sceneId,launch.launchId,launch.generation,owner])).rows[0];
    if (!grant) return Object.freeze({ available:false });
    const product = (await reviewPool.query(`SELECT 1 FROM secureshop_review.product_targets
      WHERE target_id=$1 AND original_platform_owner_id=$2 AND lifecycle='active'`,
    [scenes[0].product_target_id,owner])).rows[0];
    if (!product) return Object.freeze({ available:false });
    const mapping = (await reviewPool.query(`SELECT m.review_target_id,r.launch_id,r.generation
      FROM secureshop_review.scene_review_targets m
      JOIN secureshop_review.review_targets r ON r.target_id=m.review_target_id
      WHERE m.scene_id=$1 AND m.product_target_id=$2
        AND m.original_platform_owner_id=$3 AND r.lifecycle='active'`,
    [sceneId,scenes[0].product_target_id,owner])).rows;
    if (mapping.length > 1) throw unavailable();
    if (mapping.length) {
      const reserved = (await identityPool.query(`SELECT 1 FROM identity.secureshop_target_reservations
        WHERE target_id=$1 AND target_kind='reviews' AND launch_id=$2
          AND generation=$3 AND original_platform_owner_id=$4`,
      [mapping[0].review_target_id,mapping[0].launch_id,Number(mapping[0].generation),owner])).rows[0];
      if (!reserved) return Object.freeze({ available:false });
    }
    const targets = [scenes[0].product_target_id,...mapping.map(row => row.review_target_id)];
    const orphan = (await identityPool.query(`SELECT 1 FROM identity.secureshop_target_reservations r
      WHERE r.original_platform_owner_id=$1 AND r.launch_id=$2 AND r.generation=$3
        AND r.target_kind IN ('products','reviews')
        AND NOT (r.target_id=ANY($4::uuid[])) LIMIT 1`,
    [owner,launch.launchId,launch.generation,targets])).rows[0];
    if (orphan) return Object.freeze({ available:false });
    return Object.freeze({ available:true, sceneId:sceneId.toLowerCase() });
  }
  return Object.freeze({ withOwnerLease, mirrorReviewScene, preview });
}

module.exports = { createSecureShopSceneResetPreflight };
