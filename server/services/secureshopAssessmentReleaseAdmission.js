'use strict';

// An explicitly injected disposable-qualification capability, never a release
// switch. It cannot alter catalog rows, evidence, Judge provenance or credit.
const { isAssessmentReleaseAllowed, RELEASE_EXCLUDED_OBJECTIVE_IDS } = require('../config/secureshopCurriculum');
const { createLaunchScope } = require('./secureshopConversationBinding');
const issued = new WeakMap();
const STORE_NAMES = Object.freeze({ identity: 'identity', agents: 'secureshop_agents',
  review: 'secureshop_review', commerce: 'secureshop' });
const POOL_KEYS = Object.freeze({ identityPool: 'identity', agentsPool: 'agents',
  reviewPool: 'review', commercePool: 'commerce' });
const IDENTITY_SQL = `SELECT current_database() AS database, current_user AS role,
  session_user AS session_role, inet_server_addr()::text AS server_address,
  inet_server_port() AS server_port, pg_postmaster_start_time()::text AS server_started`;
const fail = () => Object.assign(new Error('Disposable assessment admission unavailable'),
  { code: 'SHOP_CANDIDATE_ADMISSION_INVALID' });
function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function endpoint(raw, store, role) {
  if (typeof raw !== 'string') throw fail();
  const url = new URL(raw);
  const match = /^\/owasp_ai_goat_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
  if (url.protocol !== 'postgresql:' || url.hostname !== '127.0.0.1'
      || !/^[1-9][0-9]{0,4}$/.test(url.port) || Number(url.port) > 65535
      || url.username !== `dvaia_${store}_${role}` || url.password || url.search || url.hash
      || !match || match[2] !== store || url.href !== raw) throw fail();
  return Object.freeze({ url: raw, nonce: match[1], port: url.port,
    database: url.pathname.slice(1), role: url.username });
}
async function readIdentity(record) {
  // Check the exact retained pool, not merely a caller-supplied URL description.
  if (record.pool.options?.connectionString !== record.endpoint.url) throw fail();
  const result = await record.pool.query(IDENTITY_SQL);
  const row = result?.rows?.[0];
  if (result?.rows?.length !== 1 || !row || row.database !== record.endpoint.database
      || row.role !== record.endpoint.role || row.session_role !== record.endpoint.role
      || typeof row.server_address !== 'string' || !row.server_address
      || !Number.isInteger(row.server_port) || row.server_port < 1 || row.server_port > 65535
      || typeof row.server_started !== 'string' || !row.server_started) throw fail();
  return JSON.stringify([row.server_address, row.server_port, row.server_started]);
}

async function createDisposableAssessmentReleaseAdmission({ stores, objectiveIds } = {}) {
  if (!exact(stores, Object.keys(STORE_NAMES)) || !Array.isArray(objectiveIds)
      || objectiveIds.length < 1 || objectiveIds.length > 4
      || new Set(objectiveIds).size !== objectiveIds.length
      || objectiveIds.some(id => !RELEASE_EXCLUDED_OBJECTIVE_IDS.includes(id))) throw fail();
  const records = [], pools = {}, seenPools = new Set();
  let nonce, port;
  for (const [key, store] of Object.entries(STORE_NAMES)) {
    const entry = stores[key];
    if (!exact(entry, ['runtimePool', 'migrationPool', 'runtimeUrl', 'migrationUrl'])) throw fail();
    for (const role of ['runtime', 'migration']) {
      const pool = entry[`${role}Pool`];
      if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function'
          || seenPools.has(pool)) throw fail();
      seenPools.add(pool);
      const selected = endpoint(entry[`${role}Url`], store, role);
      nonce ??= selected.nonce; port ??= selected.port;
      if (selected.nonce !== nonce || selected.port !== port) throw fail();
      records.push(Object.freeze({ pool, endpoint: selected }));
      if (role === 'runtime') pools[key] = pool;
    }
  }
  const identities = await Promise.all(records.map(readIdentity));
  if (new Set(identities).size !== 1) throw fail();
  const token = Object.freeze(Object.create(null));
  issued.set(token, Object.freeze({ records: Object.freeze(records),
    pools: Object.freeze(pools), ids: Object.freeze([...objectiveIds]), server: identities[0] }));
  return token;
}

const DEFAULT = Object.freeze({ isAllowed: isAssessmentReleaseAllowed,
  isCandidate: () => false, async assertCurrent() {}, async assertScope() {} });

function resolveAssessmentReleaseAdmission(token, supplied = {}) {
  if (token === undefined) return DEFAULT;
  const metadata = issued.get(token);
  if (!metadata || !supplied.identityPool || Object.keys(supplied).some(key => !POOL_KEYS[key])
      || Object.entries(supplied).some(([key, pool]) => pool !== metadata.pools[POOL_KEYS[key]])) throw fail();
  const isCandidate = id => metadata.ids.includes(id);
  async function assertCurrent() {
    const identities = await Promise.all(metadata.records.map(readIdentity));
    if (identities.some(value => value !== metadata.server)) throw fail();
  }
  async function assertScope(raw) {
    const scope = createLaunchScope(raw);
    await assertCurrent();
    // Candidate admission is shop-only, current-session and reset-generation
    // bound. Existing persona and effect fences remain independently required.
    const result = await metadata.pools.identity.query(`SELECT l.launch_id
      FROM identity.secureshop_authority_sessions s
      JOIN identity.secureshop_authority_owners o ON o.id=s.user_id
      JOIN secureshop_auth.execution_authority_state e ON e.session_id=s.id
      JOIN identity.secureshop_launches l ON l.platform_session_id=s.id
      WHERE s.id=$1 AND s.user_id=$2 AND s.realm='shop' AND o.realm='shop'
        AND s.shop_execution_session_id=s.id AND o.shop_tenant_id=e.tenant_id
        AND e.owner_id=o.id AND s.is_active=1 AND o.is_active=1 AND e.is_active=1
        AND s.expires_at>clock_timestamp() AND e.expires_at>clock_timestamp()
        AND l.launch_id=$3 AND l.scenario_id=$4 AND l.generation=$5
        AND l.original_platform_owner_id=o.id AND l.status='active'
        AND l.expires_at>clock_timestamp()`, [scope.platformSessionId, scope.platformOwnerId,
      scope.launchId, scope.scenarioId, scope.generation]);
    if (result?.rows?.length !== 1 || result.rows[0].launch_id !== scope.launchId) throw fail();
  }
  return Object.freeze({ isAllowed: id => isAssessmentReleaseAllowed(id) || isCandidate(id),
    isCandidate, assertCurrent, assertScope });
}

module.exports = { createDisposableAssessmentReleaseAdmission, resolveAssessmentReleaseAdmission };
