'use strict';
const {resolveAssessmentReleaseAdmission}=require('../../services/secureshopAssessmentReleaseAdmission');

const { assertSecureShopStandaloneAuthPrincipal } = require('../../services/secureshopStandaloneAuth');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail = code => Object.assign(new Error('Shop progress unavailable'), { code });

function createSecureShopAssessmentProgressRepository({ pool, executionTenantSlug = 'default', assessmentReleaseAdmission } = {}) {
  if (typeof pool?.connect !== 'function' || typeof executionTenantSlug !== 'string'
      || !/^[a-z][a-z0-9_-]{0,63}$/.test(executionTenantSlug)) {
    throw new TypeError('Shop progress database and execution tenant required');
  }
  const release = resolveAssessmentReleaseAdmission(assessmentReleaseAdmission, { identityPool: pool });

  async function consistent(work) {
    await release.assertCurrent();
    const client = await pool.connect();
    let discard;
    try {
      // The catalog, current mode generation, and reset-retired contribution
      // view are read in one statement below. READ COMMITTED makes a reset
      // committed before that statement visible without any mode-row mutation
      // privilege or a second authority transaction.
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch (rollbackError) { discard = rollbackError; }
      throw error;
    } finally {
      client.release(discard);
    }
  }

  async function requester(client, base, admin) {
    assertSecureShopStandaloneAuthPrincipal(base);
    const row = (await client.query(`SELECT t.tenant_id::text AS "tenantId",
        p.principal_id::text AS "principalId", p.shop_user_id AS "shopUserId",
        p.username, m.role
      FROM secureshop_auth.sessions s
      JOIN secureshop_auth.principals p USING(principal_id)
      JOIN secureshop_auth.tenant_memberships m ON m.principal_id=p.principal_id
      JOIN secureshop_auth.tenants t ON t.tenant_id=m.tenant_id
      JOIN secureshop_auth.session_membership_snapshots v
        ON v.session_id=s.session_id AND v.tenant_id=m.tenant_id
        AND v.membership_version=m.membership_version
      WHERE s.session_id=$1 AND p.principal_id=$2::uuid AND t.slug=$3
        AND p.shop_user_id=$4 AND s.credential_version=$5::bigint
        AND s.authority_version=$6::bigint AND t.is_active AND m.is_active
        AND p.is_active AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
        AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND s.credential_version=p.credential_version
        AND s.authority_version=p.authority_version
      FOR SHARE OF s,p,m,t`, [base.sessionId, base.principalId,
      executionTenantSlug, base.shopUserId, base.credentialVersion,
      base.authorityVersion])).rows[0];
    if (!row || row.principalId !== base.principalId || row.shopUserId !== base.shopUserId
        || row.username !== base.username || row.role !== base.role) {
      throw fail(admin ? 'SHOP_ADMIN_REQUIRED' : 'SHOP_AUTH_INVALID');
    }
    if (admin && row.role !== 'admin') throw fail('SHOP_ADMIN_REQUIRED');
    return row;
  }

  async function target(client, tenantId, principalId) {
    if (typeof principalId !== 'string' || !UUID.test(principalId)) throw fail('INVALID_INPUT');
    const row = (await client.query(`SELECT p.principal_id::text AS "principalId",
        p.shop_user_id AS "shopUserId", p.username, m.role
      FROM secureshop_auth.principals p
      JOIN secureshop_auth.tenant_memberships m ON m.principal_id=p.principal_id
      WHERE m.tenant_id=$1::uuid AND p.principal_id=$2::uuid AND m.is_active
        AND p.is_active AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
      FOR SHARE OF p,m`, [tenantId, principalId])).rows[0];
    if (!row) throw fail('SHOP_PROGRESS_UNAVAILABLE');
    return row;
  }

  async function project(client, tenantId, learners) {
    if (!learners.length) return [];
    const ids = learners.map(learner => learner.principalId);
    const rows = (await client.query(`SELECT target.principal_id::text AS "principalId",
        mode.generation, objective.objective_id AS "objectiveId", objective.label,
        EXISTS (SELECT 1 FROM secureshop_auth.active_assessment_contributions a
          WHERE a.tenant_id=$1::uuid AND a.principal_id=target.principal_id
            AND a.objective_id=objective.objective_id
            AND a.generation=mode.generation) AS completed
      FROM unnest($2::uuid[]) AS target(principal_id)
      JOIN secureshop_auth.tenant_modes mode
        ON mode.tenant_id=$1::uuid AND mode.principal_id=target.principal_id
      LEFT JOIN LATERAL (SELECT o.objective_id,o.label
        FROM secureshop_auth.assessment_objectives o
        LEFT JOIN secureshop_auth.assessment_configuration config
          ON config.tenant_id=$1::uuid AND config.objective_id=o.objective_id
        WHERE o.catalog_active AND COALESCE(config.is_enabled,o.is_enabled)
          AND o.qualification IN ('native-model','native-browser-judge')) objective ON true
      ORDER BY target.principal_id,objective.objective_id`, [tenantId, ids])).rows;
    const byPrincipal = new Map(ids.map(id => [id, []]));
    const generations = new Map();
    for (const row of rows) {
      const objectives = byPrincipal.get(row.principalId);
      if (!objectives || !Number.isSafeInteger(row.generation) || row.generation < 0
          || (generations.has(row.principalId)
            && generations.get(row.principalId) !== row.generation)) {
        throw fail('SHOP_PROGRESS_UNAVAILABLE');
      }
      generations.set(row.principalId, row.generation);
      if (row.objectiveId === null || !release.isAllowed(row.objectiveId)) continue;
      if (typeof row.objectiveId !== 'string' || typeof row.label !== 'string'
          || typeof row.completed !== 'boolean') throw fail('SHOP_PROGRESS_UNAVAILABLE');
      objectives.push(Object.freeze({ objectiveId: row.objectiveId,
        label: row.label, completed: row.completed }));
    }
    if (generations.size !== learners.length) throw fail('SHOP_PROGRESS_UNAVAILABLE');
    return learners.map(learner => {
      const objectives = byPrincipal.get(learner.principalId);
      return Object.freeze({ principalId: learner.principalId,
        shopUserId: learner.shopUserId, username: learner.username, role: learner.role,
        generation: generations.get(learner.principalId), objectives: Object.freeze(objectives),
        totalObjectives: objectives.length,
        completedObjectives: objectives.filter(row => row.completed).length });
    });
  }

  return Object.freeze({
    readSelf: ({ base }) => consistent(async client => {
      const actor = await requester(client, base, false);
      return (await project(client, actor.tenantId, [actor]))[0];
    }),
    readLearner: ({ base, targetPrincipalId }) => consistent(async client => {
      const actor = await requester(client, base, true);
      const learner = await target(client, actor.tenantId, targetPrincipalId);
      return (await project(client, actor.tenantId, [learner]))[0];
    }),
    listLearners: ({ base, limit = 25, cursor = null }) => consistent(async client => {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50
          || (cursor !== null && (!Number.isSafeInteger(cursor) || cursor < 0))) {
        throw fail('INVALID_INPUT');
      }
      const actor = await requester(client, base, true);
      const rows = (await client.query(`SELECT p.principal_id::text AS "principalId",
          p.shop_user_id AS "shopUserId", p.username, m.role
        FROM secureshop_auth.tenant_memberships m
        JOIN secureshop_auth.principals p ON p.principal_id=m.principal_id
        WHERE m.tenant_id=$1::uuid AND m.shop_user_id>$2
          AND m.is_active AND p.is_active
          AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
        ORDER BY m.shop_user_id LIMIT $3 FOR SHARE OF p,m`,
      [actor.tenantId, cursor ?? 0, limit + 1])).rows;
      const selected = rows.slice(0, limit);
      const learners = await project(client, actor.tenantId, selected);
      return Object.freeze({ learners: Object.freeze(learners),
        nextCursor: rows.length > limit ? selected.at(-1).shopUserId : null });
    }),
  });
}

module.exports = { createSecureShopAssessmentProgressRepository };
