'use strict';
const { createHash } = require('node:crypto');
const { createAnalyticsModeRepository } = require('./secureshopAnalyticsModeRepository');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const WORKSHOP = 'secureshop_agent_security';
function unavailable() {
  return Object.assign(new Error('Canonical shop mode unavailable'), { code: 'ANALYTICS_MODE_STALE' });
}
function createSecureShopModeRepository(pool) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function') {
    throw new TypeError('Canonical identity pool required');
  }
  const legacy = createAnalyticsModeRepository(pool);
  async function read(ownerId, key, scope, atEffect) {
    if (!Number.isSafeInteger(ownerId) || ownerId < 1 || key !== WORKSHOP) throw unavailable();
    const execution = createLaunchScope(scope);
    if (execution.platformOwnerId !== ownerId) throw unavailable();
    // A single read-only snapshot is safe inside an agents/review effect lease.
    // Missing shop mode state must never select legacy workshop authority.
    const row = (await pool.query(`SELECT o.realm,o.shop_tenant_id,t.is_active AS tenant_active,e.principal_id,
      m.mode,m.generation,m.revision::text AS revision
      FROM identity.secureshop_authority_owners o
      LEFT JOIN secureshop_auth.tenants t ON t.tenant_id=o.shop_tenant_id AND t.owner_id=o.id
      LEFT JOIN secureshop_auth.execution_sessions e ON e.tenant_id=t.tenant_id
        AND e.session_id=$2 AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp()
      LEFT JOIN secureshop_auth.tenant_modes m ON m.tenant_id=t.tenant_id AND m.principal_id=e.principal_id
      WHERE o.id=$1 AND o.is_active=1 AND NOT o.source_deleted`, [ownerId,execution.platformSessionId])).rows[0];
    if (!row) throw unavailable();
    if (row.realm === 'platform' && row.shop_tenant_id === null) {
      return legacy[atEffect ? 'getEvaluationScopeAtEffect' : 'getEvaluationScope'](ownerId, key);
    }
    if (row.realm !== 'shop' || !row.shop_tenant_id || !row.principal_id || row.tenant_active !== true
        || !['vuln','fixed'].includes(row.mode) || !Number.isSafeInteger(row.generation)
        || row.generation < 0 || typeof row.revision !== 'string'
        || !/^[1-9][0-9]{0,18}$/.test(row.revision)
        || BigInt(row.revision) > 9223372036854775807n) throw unavailable();
    return Object.freeze({ generation: row.generation, mode: row.mode,
      modeStamp: createHash('sha256').update(JSON.stringify(['shop-tenant-mode-v1',
        row.shop_tenant_id,row.principal_id,row.generation,row.revision,row.mode])).digest('hex') });
  }
  return Object.freeze({ getEvaluationScope: (ownerId,key,scope) => read(ownerId,key,scope,false),
    async getPrincipalMode(context) {
      const row = (await pool.query(`SELECT m.mode,m.revision::text AS revision
        FROM secureshop_auth.execution_authority_state e
        JOIN secureshop_auth.tenant_modes m ON m.tenant_id=e.tenant_id AND m.principal_id=e.principal_id
        WHERE e.session_id=$1 AND e.tenant_id=$2 AND e.principal_id=$3
          AND e.is_active=1 AND e.expires_at>clock_timestamp()`,
      [context.sessionId,context.tenantId,context.principalId])).rows[0];
      if (!row) throw Object.assign(unavailable(), { code: 'SHOP_AUTH_INVALID' });
      return Object.freeze(row);
    },
    async setPrincipalMode(context, {mode,expectedRevision}) {
      try {
        const row = (await pool.query('SELECT * FROM secureshop_auth.set_principal_mode($1,$2,$3,$4,$5)',
          [context.sessionId,context.tenantId,context.principalId,expectedRevision,mode])).rows[0];
        if (!row) throw unavailable();
        return Object.freeze(row);
      } catch (error) {
        if (error.code === '40001') throw Object.assign(unavailable(), {code:'SHOP_MODE_CONFLICT'});
        if (error.code === '28000') throw Object.assign(unavailable(), {code:'SHOP_AUTH_INVALID'});
        throw error;
      }
    },
    getEvaluationScopeAtEffect: (ownerId,key,scope) => read(ownerId,key,scope,true) });
}
module.exports = { createSecureShopModeRepository };
