'use strict';
const { randomUUID, createHash, createHmac } = require('node:crypto');
const { withTransaction } = require('./index');
const { assertSecureShopStandaloneAuthPrincipal } = require('../../services/secureshopStandaloneAuth');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const admitted = new WeakSet();
function fail(code = 'SHOP_PRACTICE_CONFLICT') {
  return Object.assign(new Error('Shop practice admission unavailable'), { code });
}
function operationId(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw fail('INVALID_ARGUMENT');
  return value.toLowerCase();
}
function assertPracticeAdmission(value) {
  if (!admitted.has(value)) throw fail();
  return value;
}
function project(id, state, sceneId = null) {
  return Object.freeze({ operationId: id, status: state, sceneId, canResume: state === 'pending' });
}
function createSecureShopPracticeAdmissionRepository({ pool, tenantSlug = 'default' } = {}) {
  if (typeof pool?.connect !== 'function' || !/^[a-z][a-z0-9_-]{0,63}$/.test(tenantSlug)) {
    throw TypeError('Practice identity store required');
  }
  async function current(client, raw, lock = false) {
    const base = assertSecureShopStandaloneAuthPrincipal(raw);
    // Same principal-first order as password changes, rotation and membership administration.
    if (lock) await client.query('SELECT principal_id FROM secureshop_auth.principals WHERE principal_id=$1 FOR UPDATE', [base.principalId]);
    const row = (await client.query(`SELECT s.session_id,t.tenant_id,t.owner_id,t.seed_merchant_id,
      m.membership_version,p.principal_id,s.expires_at
      FROM secureshop_auth.sessions s JOIN secureshop_auth.principals p USING(principal_id)
      JOIN secureshop_auth.tenant_memberships m USING(principal_id)
      JOIN secureshop_auth.tenants t USING(tenant_id)
      JOIN secureshop_auth.session_membership_snapshots v ON v.session_id=s.session_id
        AND v.tenant_id=m.tenant_id AND v.membership_version=m.membership_version
      WHERE s.session_id=$1 AND p.principal_id=$2 AND t.slug=$3
        AND p.is_active AND m.is_active AND t.is_active
        AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
        AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND s.credential_version=p.credential_version AND s.authority_version=p.authority_version
        AND p.credential_version=$4 AND p.authority_version=$5
      ${lock ? 'FOR SHARE OF s,m,t' : ''}`,
    [base.sessionId, base.principalId, tenantSlug, base.credentialVersion, base.authorityVersion])).rows[0];
    if (!row) throw fail('SHOP_AUTH_INVALID');
    if (lock) await client.query('SELECT id FROM identity.secureshop_authority_owners WHERE id=$1 FOR UPDATE', [row.owner_id]);
    return row;
  }
  async function lookup(client, id, context) {
    const row = (await client.query(`SELECT o.*,p.scene_id AS published_scene_id
      FROM secureshop_auth.practice_operations o LEFT JOIN secureshop_auth.practice_publications p USING(operation_id)
      WHERE o.operation_id=$1`, [id])).rows[0];
    if (row && (row.principal_id !== context.principal_id || row.tenant_id !== context.tenant_id)) throw fail();
    return row;
  }
  async function resumable(client, row, context, lock = false) {
    if (Number(row.auth_session_id) !== Number(context.session_id)
      || String(row.membership_version) !== String(context.membership_version)) return false;
    const result = await client.query(`SELECT x.auth_session_id FROM secureshop_auth.practice_selections x
      JOIN secureshop_auth.practice_preferences pref ON pref.tenant_id=x.tenant_id AND pref.principal_id=x.principal_id
      JOIN identity.secureshop_launches source ON source.launch_id=$3
      JOIN identity.secureshop_launches target ON target.launch_id=$4
      JOIN identity.secureshop_authority_sessions ss ON ss.id=source.platform_session_id
      JOIN identity.secureshop_authority_sessions ts ON ts.id=target.platform_session_id
      JOIN identity.secureshop_scenes scene ON scene.scene_id=x.scene_id
      WHERE x.auth_session_id=$1 AND x.tenant_id=$2 AND x.principal_id=$5
        AND x.execution_session_id=$6 AND x.scene_id=$7 AND x.revision=$8 AND pref.revision=$14
        AND source.platform_session_id=$6 AND source.generation=$9 AND source.status='active'
        AND source.expires_at>clock_timestamp() AND target.status='active'
        AND target.platform_session_id=$10 AND target.generation=$11 AND target.scenario_id=$12
        AND source.original_platform_owner_id=$13 AND target.original_platform_owner_id=$13
        AND target.expires_at>clock_timestamp() AND ss.is_active=1 AND ts.is_active=1
        AND ss.expires_at>clock_timestamp() AND ts.expires_at>clock_timestamp()
        AND scene.status='active' AND scene.original_platform_owner_id=$13
      ${lock ? 'FOR UPDATE OF x,pref FOR SHARE OF source,target,scene' : ''}`,
    [row.auth_session_id,row.tenant_id,row.source_launch_id,row.launch_id,row.principal_id,
      row.source_execution_id,row.source_scene_id,row.source_selection_revision,row.source_generation,
      row.execution_session_id,row.generation,row.scenario_id,row.owner_id,row.source_preference_revision]);
    return result.rowCount === 1;
  }
  async function state(client, id, context, row) {
    if (!row) return project(id, 'unconfirmed');
    if (row.published_scene_id) return project(id, 'published', row.published_scene_id);
    return project(id, await resumable(client, row, context) ? 'pending' : 'retained_unfinished');
  }
  return Object.freeze({
    async read(base, rawId) {
      const id = operationId(rawId);
      return withTransaction(pool, async client => {
        const context = await current(client, base);
        return state(client, id, context, await lookup(client, id, context));
      });
    },
    async admit(base, rawId) {
      const id = operationId(rawId);
      return withTransaction(pool, async client => {
        const context = await current(client, base, true);
        const prior = await lookup(client, id, context);
        if (prior) return state(client, id, context, prior);
        const source = (await client.query(`SELECT x.*,l.launch_id,l.generation,pref.revision AS preference_revision
          FROM secureshop_auth.practice_selections x
          JOIN secureshop_auth.practice_preferences pref ON pref.tenant_id=x.tenant_id AND pref.principal_id=x.principal_id
          JOIN identity.secureshop_launches l ON l.platform_session_id=x.execution_session_id
          JOIN identity.secureshop_authority_sessions a ON a.id=x.execution_session_id
          JOIN identity.secureshop_scenes scene ON scene.scene_id=x.scene_id
          WHERE x.auth_session_id=$1 AND x.tenant_id=$2 AND x.principal_id=$3
            AND a.is_active=1 AND a.expires_at>clock_timestamp()
            AND l.status='active' AND l.expires_at>clock_timestamp()
            AND l.original_platform_owner_id=$4 AND scene.original_platform_owner_id=$4 AND scene.status='active'
          FOR UPDATE OF x,pref FOR SHARE OF l,scene`,
        [context.session_id,context.tenant_id,context.principal_id,context.owner_id])).rows[0];
        if (!source) throw fail();
        if ((await client.query('SELECT 1 FROM secureshop_auth.practice_operations WHERE source_execution_id=$1',
          [source.execution_session_id])).rowCount) throw fail();
        const counts = (await client.query(`SELECT
          (SELECT count(*) FROM identity.secureshop_launches WHERE original_platform_owner_id=$1
            AND identity.secureshop_launch_consumes_capacity(launch_id)) AS launches,
          (SELECT count(*) FROM identity.secureshop_target_reservations
            WHERE original_platform_owner_id=$1 AND target_kind='products') AS products`, [context.owner_id])).rows[0];
        if (Number(counts.launches) >= 256 || Number(counts.products) >= 256) throw fail('SHOP_PRACTICE_CAPACITY');
        const execution = (await client.query(`INSERT INTO secureshop_auth.execution_sessions
          (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
          VALUES($1,$2,$3,$4,$5) RETURNING session_id`,
        [context.session_id,context.tenant_id,context.principal_id,context.membership_version,context.expires_at])).rows[0];
        const bearer = createHmac('sha256', base.launchBearer)
          .update(JSON.stringify(['secureshop-tenant-launch-v1', context.tenant_id, Number(execution.session_id)]))
          .digest('base64url');
        const launchId = randomUUID(), scenarioId = randomUUID(), targetId = randomUUID(), sceneId = randomUUID();
        await client.query(`INSERT INTO identity.secureshop_launches
          (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,handle_hash,scenario_id,expires_at)
          VALUES($1,$2,$2,$3,$4,$5,LEAST($6::timestamptz,clock_timestamp()+interval '30 minutes'))`,
        [launchId,execution.session_id,context.owner_id,createHash('sha256').update(bearer).digest(),scenarioId,context.expires_at]);
        await client.query(`INSERT INTO identity.secureshop_target_reservations
          (target_id,launch_id,generation,target_kind,original_platform_owner_id) VALUES($1,$2,1,'products',$3)`,
        [targetId,launchId,context.owner_id]);
        await client.query(`INSERT INTO secureshop_auth.practice_operations
          (operation_id,tenant_id,principal_id,auth_session_id,membership_version,source_execution_id,
           source_launch_id,source_generation,source_scene_id,source_selection_revision,
           execution_session_id,launch_id,scenario_id,generation,owner_id,target_id,scene_id,source_preference_revision)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,$14,$15,$16,$17)`,
        [id,context.tenant_id,context.principal_id,context.session_id,context.membership_version,
          source.execution_session_id,source.launch_id,source.generation,source.scene_id,source.revision,
          execution.session_id,launchId,scenarioId,context.owner_id,targetId,sceneId,source.preference_revision]);
        await current(client, base);
        return project(id, 'pending');
      });
    },
    async publish(base, rawId, provision) {
      const id = operationId(rawId);
      if (typeof provision !== 'function') throw TypeError('Practice provisioner required');
      return withTransaction(pool, async client => {
        const context = await current(client, base, true);
        const row = await lookup(client, id, context);
        if (!row || row.published_scene_id) return state(client, id, context, row);
        if (!await resumable(client, row, context, true)) return project(id, 'retained_unfinished');
        // Identity locks span the real cross-store provision and final publication.
        // Failed COMMIT retains the immutable reservation for same-ID recovery.
        const binding = Object.freeze({ targetId: row.target_id, launchId: row.launch_id,
          scenarioId: row.scenario_id, generation: Number(row.generation),
          platformOwnerId: Number(row.owner_id), platformSessionId: Number(row.execution_session_id) });
        const claim = Object.freeze({ binding, ownMerchantId: Number(context.seed_merchant_id) });
        admitted.add(claim);
        let result;
        try { result = await provision(claim); } finally { admitted.delete(claim); }
        if (result?.targetId !== binding.targetId || typeof result.sourceSha256 !== 'string'
          || !/^[0-9a-f]{64}$/.test(result.sourceSha256)) throw fail();
        await current(client, base);
        if (!await resumable(client, row, context)) throw fail();
        await client.query(`INSERT INTO identity.secureshop_scenes
          (scene_id,original_platform_owner_id,product_target_id,birth_launch_id,birth_scenario_id,birth_generation,birth_platform_session_id)
          VALUES($1,$2,$3,$4,$5,$6,$7)`,
        [row.scene_id,row.owner_id,row.target_id,row.launch_id,row.scenario_id,row.generation,row.execution_session_id]);
        for (const [actor, role] of [[11,'customer'],[12,'merchant'],[13,'admin']]) {
          await client.query(`INSERT INTO identity.secureshop_scene_principals(principal_id,scene_id,shop_user_id,seed_role)
            VALUES($1,$2,$3,$4)`, [randomUUID(),row.scene_id,actor,role]);
        }
        await client.query(`INSERT INTO identity.secureshop_scene_execution_grants
          (grant_id,scene_id,scene_generation,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
          VALUES($1,$2,1,$3,$4,$5,$6,$7)`,
        [randomUUID(),row.scene_id,row.launch_id,row.scenario_id,row.generation,row.owner_id,row.execution_session_id]);
        const changed = await client.query(`UPDATE secureshop_auth.practice_selections
          SET execution_session_id=$1,scene_id=$2 WHERE auth_session_id=$3 AND tenant_id=$4
            AND execution_session_id=$5 AND scene_id=$6 AND revision=$7`,
        [row.execution_session_id,row.scene_id,row.auth_session_id,row.tenant_id,
          row.source_execution_id,row.source_scene_id,row.source_selection_revision]);
        if (changed.rowCount !== 1) throw fail();
        const preference = await client.query(`UPDATE secureshop_auth.practice_preferences SET scene_id=$3
          WHERE tenant_id=$1 AND principal_id=$2 AND revision=$4`,
        [row.tenant_id,row.principal_id,row.scene_id,row.source_preference_revision]);
        if (preference.rowCount !== 1) throw fail();
        await client.query(`INSERT INTO secureshop_auth.practice_publications(operation_id,scene_id,source_sha256)
          VALUES($1,$2,$3)`, [id,row.scene_id,Buffer.from(result.sourceSha256,'hex')]);
        return project(id, 'published', row.scene_id);
      });
    },
  });
}
module.exports = { createSecureShopPracticeAdmissionRepository, assertPracticeAdmission };
