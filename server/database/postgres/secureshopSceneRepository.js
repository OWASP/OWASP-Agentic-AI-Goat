'use strict';
const { randomUUID } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const { withTransaction } = require('./index');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function unavailable(code = 'SHOP_SCENE_STALE') {
  return Object.assign(new Error('Shop practice is unavailable'), { code, executionBoundary: true });
}
function sceneRow(row) {
  return Object.freeze({ sceneId: row.scene_id, sceneGeneration: Number(row.scene_generation),
    isDefault: row.is_default, createdAt: row.created_at, status: row.status,
    storage: Object.freeze({ targetId: row.product_target_id, launchId: row.birth_launch_id,
      scenarioId: row.birth_scenario_id, generation: Number(row.birth_generation),
      platformOwnerId: Number(row.original_platform_owner_id),
      platformSessionId: Number(row.birth_platform_session_id) }) });
}
function createSecureShopSceneRepository({ pool, provisionPool, launches } = {}) {
  if (provisionPool !== undefined && provisionPool === pool) throw TypeError('Distinct scene provision pool required');
  provisionPool ||= pool; // Retained direct fixture callers use the original single-pool seam.
  if (typeof pool?.connect !== 'function' || typeof provisionPool?.connect !== 'function'
      || typeof launches?.assertCurrent !== 'function') throw TypeError('Scene authority required');
  const held = new AsyncLocalStorage();
  const provisioning = new AsyncLocalStorage();
  async function current(client, scope, lock = false) {
    const result = await client.query(`SELECT l.launch_id FROM identity.secureshop_launches l
      JOIN identity.secureshop_authority_sessions s ON s.id=l.platform_session_id JOIN identity.secureshop_authority_owners u ON u.id=s.user_id
      WHERE l.launch_id=$1 AND l.scenario_id=$2 AND l.generation=$3 AND l.platform_session_id=$5
        AND l.original_platform_owner_id=$4 AND s.user_id=$4 AND l.status='active'
        AND l.expires_at>clock_timestamp() AND s.is_active=1 AND s.expires_at>clock_timestamp()
        AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
      ${lock ? 'FOR SHARE OF l' : ''}`,
    [scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId, scope.platformSessionId]);
    if (result.rowCount !== 1) throw unavailable();
  }
  async function ownerTransaction(scope, work) {
    return withTransaction(pool, async client => {
      await client.query('SELECT id FROM identity.secureshop_authority_owners WHERE id=$1 FOR UPDATE', [scope.platformOwnerId]);
      await current(client, scope, true);
      const result = await work(client);
      await current(client, scope);
      return result;
    });
  }
  async function callerRows(client, scope, rows, initialize = false) {
    const selected = (await client.query(`SELECT e.auth_session_id,e.tenant_id,e.principal_id,
      x.execution_session_id,x.scene_id FROM secureshop_auth.execution_sessions e
      LEFT JOIN secureshop_auth.practice_selections x ON x.auth_session_id=e.auth_session_id
        AND x.tenant_id=e.tenant_id AND x.principal_id=e.principal_id
      WHERE e.session_id=$1`, [scope.platformSessionId])).rows[0];
    if (!selected) return rows; // Retained platform launches keep their original default behavior.
    if (Number(selected.execution_session_id) !== scope.platformSessionId) throw unavailable();
    let sceneId = selected.scene_id;
    if (!sceneId && initialize) {
      sceneId = rows.find(row => row.is_default)?.scene_id || (rows.length === 1 ? rows[0].scene_id : null);
      if (sceneId) {
        await client.query(`UPDATE secureshop_auth.practice_selections SET scene_id=$1
          WHERE auth_session_id=$2 AND tenant_id=$3 AND execution_session_id=$4 AND scene_id IS NULL`,
        [sceneId,selected.auth_session_id,selected.tenant_id,scope.platformSessionId]);
        await client.query(`INSERT INTO secureshop_auth.practice_preferences(tenant_id,principal_id,scene_id)
          VALUES($1,$2,$3) ON CONFLICT(tenant_id,principal_id) DO NOTHING`,
        [selected.tenant_id,selected.principal_id,sceneId]);
      }
    }
    return rows.map(row => ({ ...row, is_default: row.scene_id === sceneId }));
  }
  async function list(scope) {
    const execution = createLaunchScope(scope); await launches.assertCurrent(execution);
    const rows = (await pool.query(`SELECT * FROM identity.secureshop_scenes
      WHERE original_platform_owner_id=$1 AND status='active' ORDER BY created_at,scene_id`,
    [execution.platformOwnerId])).rows;
    return (await callerRows(pool, execution, rows)).map(sceneRow);
  }
  return Object.freeze({
    list,
    async withProvisionLease(scope, work) {
      const e = createLaunchScope(scope);
      if (typeof work !== 'function') throw unavailable();
      const nested = provisioning.getStore();
      if (nested) {
        if (!nested.active || nested.ownerId !== e.platformOwnerId) throw unavailable();
        return work();
      }
      // This separate lock serializes discovery/provisioning across logins but
      // deliberately does not hold a launch row while its reservation API runs.
      return withTransaction(provisionPool, async client => {
        await client.query("SET LOCAL lock_timeout='10s'");
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-store-provision:'||$1::text,0))",
          [e.platformOwnerId]);
        await current(client, e);
        const token = { ownerId: e.platformOwnerId, active: true };
        try {
          return await provisioning.run(token, async () => {
            const result = await work(); await current(client, e); return result;
          });
        } finally { token.active = false; }
      });
    },
    async store(scope) {
      const e = createLaunchScope(scope); await launches.assertCurrent(e);
      const row = (await pool.query(`SELECT t.tenant_id,t.seed_merchant_id FROM secureshop_auth.tenants t
        JOIN secureshop_auth.execution_sessions s ON s.tenant_id=t.tenant_id
        WHERE t.owner_id=$1 AND s.session_id=$2 AND t.is_active`,
      [e.platformOwnerId,e.platformSessionId])).rows[0];
      return row ? Object.freeze({ tenantId: row.tenant_id, seedMerchantId: Number(row.seed_merchant_id) }) : null;
    },
    async merchant(scope, actorId) {
      const e = createLaunchScope(scope); await launches.assertCurrent(e);
      const row = (await pool.query(`SELECT m.shop_user_id FROM secureshop_auth.tenants t
        JOIN secureshop_auth.execution_sessions s ON s.tenant_id=t.tenant_id
        JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=t.tenant_id AND m.principal_id=s.principal_id
        WHERE t.owner_id=$1 AND s.session_id=$2 AND m.shop_user_id=$3
          AND t.is_active AND m.is_active AND m.membership_version=s.membership_version`,
      [e.platformOwnerId,e.platformSessionId,actorId])).rows[0];
      if (!row) throw unavailable('OWNER_MISMATCH');
      return true;
    },
    async candidates(scope) {
      const e = createLaunchScope(scope); await launches.assertCurrent(e);
      return (await pool.query(`SELECT r.target_id,l.launch_id,l.scenario_id,r.generation,
        r.original_platform_owner_id,l.original_platform_session_id
        FROM identity.secureshop_target_reservations r JOIN identity.secureshop_launches l USING(launch_id)
        WHERE r.original_platform_owner_id=$1 AND r.target_kind='products'
          AND NOT EXISTS(SELECT 1 FROM identity.secureshop_scenes scene WHERE scene.product_target_id=r.target_id)
          AND NOT EXISTS(SELECT 1 FROM secureshop_auth.practice_operations pending
            WHERE pending.target_id=r.target_id)
        ORDER BY r.created_at,r.target_id`, [e.platformOwnerId])).rows.map(row => Object.freeze({
        targetId: row.target_id, launchId: row.launch_id, scenarioId: row.scenario_id,
        generation: Number(row.generation), platformOwnerId: Number(row.original_platform_owner_id),
        platformSessionId: Number(row.original_platform_session_id),
      }));
    },
    // Candidate target IDs come from owned review-store readback, never the UI.
    async adopt(scope, candidates) {
      const e = createLaunchScope(scope);
      if (!Array.isArray(candidates) || candidates.length > 256) throw unavailable();
      return ownerTransaction(e, async client => {
        for (const candidate of candidates) {
          const b = createLaunchScope(candidate);
          if (b.platformOwnerId !== e.platformOwnerId || !UUID.test(candidate.targetId)) throw unavailable();
          const inserted = await client.query(`INSERT INTO identity.secureshop_scenes
            (scene_id,original_platform_owner_id,product_target_id,birth_launch_id,birth_scenario_id,
             birth_generation,birth_platform_session_id)
            VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(product_target_id) DO NOTHING RETURNING scene_id`,
          [randomUUID(), b.platformOwnerId, candidate.targetId, b.launchId, b.scenarioId, b.generation, b.platformSessionId]);
          if (inserted.rowCount) for (const [id, role] of [[11, 'customer'], [12, 'merchant'], [13, 'admin']]) {
            await client.query(`INSERT INTO identity.secureshop_scene_principals(principal_id,scene_id,shop_user_id,seed_role)
              VALUES($1,$2,$3,$4)`, [randomUUID(), inserted.rows[0].scene_id, id, role]);
          }
        }
        const rows = (await client.query(`SELECT * FROM identity.secureshop_scenes
          WHERE original_platform_owner_id=$1 AND status='active' ORDER BY created_at,scene_id`, [e.platformOwnerId])).rows;
        if (rows.length === 1 && !rows[0].is_default) {
          await client.query('UPDATE identity.secureshop_scenes SET is_default=true WHERE scene_id=$1', [rows[0].scene_id]);
          rows[0].is_default = true;
        }
        return (await callerRows(client, e, rows, true)).map(sceneRow);
      });
    },
    async select(scope, sceneId) {
      const e = createLaunchScope(scope); if (!UUID.test(sceneId)) throw unavailable();
      return ownerTransaction(e, async client => {
        const row = (await client.query(`SELECT * FROM identity.secureshop_scenes
          WHERE scene_id=$1 AND original_platform_owner_id=$2 AND status='active' FOR UPDATE`, [sceneId, e.platformOwnerId])).rows[0];
        if (!row) throw unavailable();
        const caller = (await client.query(`SELECT auth_session_id,tenant_id,principal_id
          FROM secureshop_auth.execution_sessions WHERE session_id=$1`, [e.platformSessionId])).rows[0];
        if (caller) {
          const changed = await client.query(`UPDATE secureshop_auth.practice_selections SET scene_id=$1
            WHERE auth_session_id=$2 AND tenant_id=$3 AND principal_id=$4 AND execution_session_id=$5`,
          [sceneId,caller.auth_session_id,caller.tenant_id,caller.principal_id,e.platformSessionId]);
          if (changed.rowCount !== 1) throw unavailable();
          await client.query(`INSERT INTO secureshop_auth.practice_preferences(tenant_id,principal_id,scene_id)
            VALUES($1,$2,$3) ON CONFLICT(tenant_id,principal_id) DO UPDATE SET scene_id=EXCLUDED.scene_id`,
          [caller.tenant_id,caller.principal_id,sceneId]);
          return sceneRow({ ...row, is_default: true });
        }
        await client.query(`UPDATE identity.secureshop_scenes SET is_default=false
          WHERE original_platform_owner_id=$1 AND status='active' AND is_default`, [e.platformOwnerId]);
        await client.query('UPDATE identity.secureshop_scenes SET is_default=true WHERE scene_id=$1', [sceneId]);
        return sceneRow({ ...row, is_default: true });
      });
    },
    async grant(scope, sceneId) {
      const e = createLaunchScope(scope); if (!UUID.test(sceneId)) throw unavailable();
      return ownerTransaction(e, async client => {
        const row = (await client.query(`SELECT * FROM identity.secureshop_scenes
          WHERE scene_id=$1 AND original_platform_owner_id=$2 AND status='active' FOR SHARE`, [sceneId, e.platformOwnerId])).rows[0];
        if (!row) throw unavailable();
        const values = [randomUUID(), sceneId, row.scene_generation, e.launchId, e.scenarioId, e.generation, e.platformOwnerId, e.platformSessionId];
        await client.query(`INSERT INTO identity.secureshop_scene_execution_grants
          (grant_id,scene_id,scene_generation,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(scene_id,launch_id,generation) DO NOTHING`, values);
        const grant = (await client.query(`SELECT * FROM identity.secureshop_scene_execution_grants
          WHERE scene_id=$1 AND launch_id=$2 AND generation=$3`, [sceneId, e.launchId, e.generation])).rows[0];
        if (grant.scenario_id !== e.scenarioId || Number(grant.original_platform_session_id) !== e.platformSessionId
            || Number(grant.original_platform_owner_id) !== e.platformOwnerId) throw unavailable();
        return Object.freeze({ ...sceneRow(row), grantId: grant.grant_id, execution: e });
      });
    },
    async readRetainedGrant(scope, sceneId) {
      const e = createLaunchScope(scope); if (!UUID.test(sceneId)) throw unavailable();
      await launches.assertCurrent(e);
      const rows = (await pool.query(`SELECT s.*,g.grant_id FROM identity.secureshop_scenes s
        JOIN identity.secureshop_scene_execution_grants g ON g.scene_id=s.scene_id
          AND g.scene_generation=s.scene_generation
          AND g.launch_id=$3 AND g.scenario_id=$4 AND g.generation=$5
          AND g.original_platform_owner_id=$2 AND g.original_platform_session_id=$6
        WHERE s.scene_id=$1 AND s.original_platform_owner_id=$2 AND s.status='active'`,
      [sceneId,e.platformOwnerId,e.launchId,e.scenarioId,e.generation,e.platformSessionId])).rows;
      if(rows.length!==1||!UUID.test(rows[0].grant_id||''))throw unavailable();
      await launches.assertCurrent(e);
      return Object.freeze({...sceneRow(rows[0]),grantId:rows[0].grant_id,execution:e});
    },
    async withLease(grant, work) {
      const e = createLaunchScope(grant.execution);
      const nested = held.getStore();
      if (nested) {
        if (nested.grantId !== grant.grantId || !nested.active) throw unavailable();
        return work();
      }
      return withTransaction(pool, async client => {
        await client.query("SET LOCAL statement_timeout='5s'");
        await current(client, e, true);
        const valid = await client.query(`SELECT 1 FROM identity.secureshop_scene_execution_grants g
          JOIN identity.secureshop_scenes s USING(scene_id)
          WHERE g.grant_id=$1 AND g.scene_id=$2 AND g.scene_generation=$3
            AND g.launch_id=$4 AND g.scenario_id=$5 AND g.generation=$6
            AND g.original_platform_owner_id=$7 AND g.original_platform_session_id=$8
            AND s.status='active' AND s.scene_generation=g.scene_generation
            AND s.original_platform_owner_id=g.original_platform_owner_id
          FOR SHARE OF s`, [grant.grantId, grant.sceneId, grant.sceneGeneration,
          e.launchId, e.scenarioId, e.generation, e.platformOwnerId, e.platformSessionId]);
        if (valid.rowCount !== 1) throw unavailable();
        const token = { grantId: grant.grantId, active: true };
        try { return await held.run(token, async () => { const result = await work(); await current(client, e); return result; }); }
        finally { token.active = false; }
      });
    },
  });
}
function createSecureShopProductionSceneRepository({pool,provisionPool,leasePool,launches}={}){
  if([pool,provisionPool,leasePool].some(value=>typeof value?.connect!=='function')
    ||new Set([pool,provisionPool,leasePool]).size!==3)
    throw TypeError('Distinct scene control, provision, and graph lease pools required');
  return createSecureShopSceneRepository({pool,provisionPool,launches});
}
module.exports = { createSecureShopSceneRepository, createSecureShopProductionSceneRepository };
