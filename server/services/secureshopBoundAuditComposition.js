'use strict';
const { createBoundAuditStore, createBoundAuditReader } = require('../database/postgres/secureshopBoundAuditRepository');
const { createSecureShopBoundAuditCleanup } = require('./secureshopBoundAuditCleanup');
// Explicit candidate injection; activation additionally requires schema/readiness
// qualification. One bundle owns the reader, both writers and deletion receipts.
function createSecureShopBoundAuditComposition({ agentsPool, reviewPool, includeRunArtifacts = false } = {}) {
  if(typeof includeRunArtifacts!=='boolean')throw new TypeError('Explicit audit artifact capability required');
  const agents = createBoundAuditStore({ store: 'agents', pool: agentsPool });
  const review = createBoundAuditStore({ store: 'review', pool: reviewPool });
  const reader = createBoundAuditReader({ agents, review });
  const cleanJournals = createSecureShopBoundAuditCleanup({ agentsPool, reviewPool });
  const cleanup = includeRunArtifacts
    ? require('./secureshopAuditRunCleanup').createSecureShopAuditRunCleanup({pool:agentsPool,cleanJournals}) : cleanJournals;
  return Object.freeze({ agents, review, reader, cleanup });
}
async function assertSecureShopBoundAuditReadiness({ agentsPool, reviewPool, includeRunArtifacts = false } = {}) {
  if(typeof includeRunArtifacts!=='boolean')throw new TypeError('Explicit audit artifact capability required');
  const unavailable = () => Object.assign(new Error('SecureShop audit schema or permissions are not ready'),
    { code: 'SECURESHOP_AUDIT_UNAVAILABLE' });
  const writable = ['event_id','launch_id','scenario_id','generation','original_platform_owner_id',
    'original_platform_session_id','shop_user_id','shop_role','actor','action','target','params_json',
    'outcome','source_kind','source_id'];
  const databases = await Promise.all([['agents',agentsPool],['review',reviewPool]].map(async ([store,pool]) => {
    if (typeof pool?.query !== 'function') throw unavailable();
    const schema = `secureshop_${store}`;
    const names = [`${schema}.bound_audit_events`, `${schema}.bound_audit_owner_deletion_receipts`];
    const probe = (await pool.query(`SELECT current_user AS role,current_database() AS database,
      to_regclass($1) AS events,to_regclass($2) AS receipts,to_regprocedure($3) AS cleanup`,
    [...names,`${schema}.destroy_bound_audit_owner(integer,uuid)`])).rows[0];
    if (probe?.role !== `dvaia_${schema}_runtime` || !probe.database || !probe.events || !probe.receipts || !probe.cleanup) throw unavailable();
    const row = (await pool.query(`SELECT
      has_table_privilege(current_user,$1,'SELECT') AND has_table_privilege(current_user,$2,'SELECT') AS readable,
      NOT has_table_privilege(current_user,$1,'UPDATE,DELETE,TRUNCATE')
        AND NOT has_table_privilege(current_user,$2,'INSERT,UPDATE,DELETE,TRUNCATE')
        AND NOT has_any_column_privilege(current_user,$1,'UPDATE')
        AND NOT has_any_column_privilege(current_user,$2,'INSERT,UPDATE') AS immutable,
      (SELECT bool_and(has_column_privilege(current_user,$1,value,'INSERT')) FROM unnest($4::text[]) value) AS appendable,
      NOT has_column_privilege(current_user,$1,'created_at','INSERT') AS clock_owned,
      has_function_privilege(current_user,$3,'EXECUTE') AS cleanup_allowed,
      NOT EXISTS (SELECT 1 FROM pg_proc p,
        LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE p.oid=to_regprocedure($3) AND a.grantee=0 AND a.privilege_type='EXECUTE') AS private_cleanup`,
    [...names,`${schema}.destroy_bound_audit_owner(integer,uuid)`,writable])).rows[0];
    if (!row || ['readable','immutable','appendable','clock_owned','cleanup_allowed','private_cleanup'].some(key => row[key] !== true)) throw unavailable();
    return probe.database;
  }));
  if (new Set(databases).size !== 2) throw unavailable();
  if(includeRunArtifacts)await require('./secureshopAuditRunReadiness').assertSecureShopAuditRunReadiness({pool:agentsPool});
  return true;
}
module.exports = { createSecureShopBoundAuditComposition, assertSecureShopBoundAuditReadiness };
