'use strict';

// Explicit initialization of converted repositories. Does not import user data,
// provision cluster roles, start the app, or touch the legacy SQLite stores.
const repositories = Object.freeze([
  ['identity', 'IDENTITY', null, 'initializeIdentity'],
  ['aria', 'SQL_WORKSHOP', 'sqlWorkshopDb', 'initializeSqlWorkshopDb'],
  ['nova', 'NOSQL_WORKSHOP', 'nosqlWorkshopDb', 'initializeNosqlWorkshopDb'],
  ['xss', 'XSS_WORKSHOP', 'xssWorkshopDb', 'initializeXssWorkshopDb'],
  ['mcp', 'MCP_WORKSHOP', 'mcpWorkshopDb', 'initializeMcpWorkshopDb'],
  ['csrf', 'CSRF_WORKSHOP', 'csrfWorkshopDb', 'initializeCsrfWorkshopDb'],
  ['supply_chain', 'SUPPLY_CHAIN_WORKSHOP', 'supplyChainWorkshopDb', 'initializeSupplyChainWorkshopDb'],
  ['finflow', 'FINFLOW_WORKSHOP', 'sensitiveInfoWorkshopDb', 'initializeFinflowWorkshopDb'],
  ['excessive_agency', 'EXCESSIVE_AGENCY', 'excessiveAgencyLabDb', 'initializeExcessiveAgencyLabDb'],
  ['ctf', 'CTF', 'ctfDb', 'initializeCtfDb'],
  ['legacy_challenge','LEGACY_CHALLENGE','legacyChallengeDb','initializeLegacyChallengeDb'],
  ['sensitive_lookup','SENSITIVE_LOOKUP','sensitiveLookupDb','initializeSensitiveLookupDb'],
  ['secureshop','SECURESHOP','secureshopInitialization','initializeSecureShopCommerceDb'],
  ['secureshop_agents','SECURESHOP_AGENTS','secureshopInitialization','initializeSecureShopAgentsDb'],
  ['session_disclosure','SESSION_DISCLOSURE','sessionDisclosureDb','initializeSessionDisclosureDb'],
  ['secureshop_review','SECURESHOP_REVIEW','secureshopReviewDb','initializeSecureShopReviewDb'],
]);
const requiredStoreManifest = Object.freeze(repositories.map(([schema, prefix]) => Object.freeze({
  schema,
  runtimeRole: `dvaia_${schema}_runtime`,
  runtimeVariable: `${prefix}_DATABASE_URL`,
  migrationVariable: `${prefix}_MIGRATION_DATABASE_URL`,
})));
function configurationPlan(env) {
  return requiredStoreManifest.map(row => ({ ...row,
    configured: Boolean(env[row.runtimeVariable] && env[row.migrationVariable]),
  }));
}
const INITIALIZATION_PHASES = new Set(['maintenance_begin','postgres_import','pool_create','repository_initialize','catalog_seed','identity_pool_drain','pool_drain','maintenance_finish']);
const ERROR_CLASSES = new Set(['Error','TypeError','ReferenceError','SyntaxError','RangeError','AggregateError']);
function diagnostic(error, fallback, context = {}) {
  const safe = new Error(fallback);
  safe.code = typeof error?.code === 'string' && /^[A-Z0-9_]{1,80}$/.test(error.code) ? error.code : fallback;
  if (typeof error?.migration === 'string' && /^[0-9]{4}_[a-zA-Z0-9_-]+\.sql$/.test(error.migration)) safe.migration = error.migration;
  safe.errorClass = ERROR_CLASSES.has(error?.name) ? error.name : 'Error';
  if (INITIALIZATION_PHASES.has(context.phase)) safe.phase = context.phase;
  if (repositories.some(([schema]) => schema === context.store)) safe.store = context.store;
  return safe;
}
function initializationFailureSummary(error) {
  const allowed = new Set(['APPLICATION_INITIALIZATION_REQUIRES_EXIT','APPLICATION_INITIALIZATION_FAILED','INITIALIZATION_POOL_DRAIN_FAILED','INITIALIZATION_DRAIN_TIMEOUT','INITIALIZATION_LEASE_CLOSE_FAILED','MODULE_NOT_FOUND','ENOENT','EACCES','EPERM','ENOSPC','EIO','ETIMEDOUT','ECONNREFUSED','ECONNRESET','APPLICATION_MAINTENANCE_BEGIN_UNCERTAIN','APPLICATION_MAINTENANCE_DIRTY','APPLICATION_MAINTENANCE_VERSION_MISMATCH','APPLICATION_MAINTENANCE_CONTROL_INVALID','APPLICATION_MAINTENANCE_LOCK_REQUIRED','APPLICATION_MAINTENANCE_QUERY_TIMEOUT','APPLICATION_MAINTENANCE_FINISH_UNCERTAIN','APPLICATION_LEASE_NOT_HELD','APPLICATION_LEASE_LOST','APPLICATION_LEASE_CLOSE_FAILED','APPLICATION_MAINTENANCE_BUSY']);
  const project = value => {
    const code = typeof value?.code === 'string' && (allowed.has(value.code) || /^[0-9][A-Z0-9]{4}$/.test(value.code)) ? value.code : 'APPLICATION_INITIALIZATION_FAILED';
    return { code, ...(ERROR_CLASSES.has(value?.errorClass) ? { errorClass: value.errorClass } : {}), ...(INITIALIZATION_PHASES.has(value?.phase) ? { phase: value.phase } : {}), ...(repositories.some(([schema]) => schema === value?.store) ? { store: value.store } : {}), ...(typeof value?.migration === 'string' && /^[0-9]{4}_[a-zA-Z0-9_-]+\.sql$/.test(value.migration) ? { migration: value.migration } : {}) };
  };
  return { ...project(error), causes: Array.isArray(error?.errors) ? error.errors.slice(0,8).map(project) : [] };
}
async function initializeApplication({ maintenanceScope } = {}) {
  const env = process.env;
  const missing = configurationPlan(env).filter(row => !row.configured);
  if (missing.length) throw new Error(`Missing PostgreSQL configuration: ${missing.map(row => `${row.runtimeVariable} / ${row.migrationVariable}`).join(', ')}`);
  // Also covers direct CLI, start --init-db and compatibility deployment aliases.
  const scopeTools = maintenanceScope ? require('../../scripts/lib/application-maintenance-scope') : null;
  const lease = maintenanceScope
    ? scopeTools.assertApplicationMaintenanceScope(maintenanceScope, env)
    : await require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({ mode: 'maintenance', env });
  let pg;
  const owned = [];
  let primary, maintenanceEpoch;
  const context = { phase: 'maintenance_begin' };
  const drainFailures = [];
  try {
    if (!maintenanceScope) maintenanceEpoch = await lease.beginMaintenance();
    lease.assertHeld();
    context.phase = 'postgres_import';
    pg = require('../../server/database/postgres');
    for (const [schema, , moduleName, method] of repositories) {
      context.store = schema; context.phase = 'pool_create';
      lease.assertHeld();
      if (schema === 'identity') {
        const runtime = pg.createPool(env, 'IDENTITY_DATABASE_URL'); owned.push(runtime);
        const migration = pg.createPool(env, 'IDENTITY_MIGRATION_DATABASE_URL'); owned.push(migration);
        context.phase = 'repository_initialize';
        await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(runtime, migration);
        lease.assertHeld();
        context.phase = 'catalog_seed';
        await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
        lease.assertHeld();
        await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(runtime);
        lease.assertHeld();
        await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(migration);
        lease.assertHeld();
        context.phase = 'identity_pool_drain';
        const closed = await Promise.allSettled([runtime, migration].map(pool => Promise.resolve().then(() => pool.end())));
        for (const result of closed) if (result.status === 'rejected') drainFailures.push(diagnostic(result.reason, 'INITIALIZATION_POOL_DRAIN_FAILED'));
        if (drainFailures.length) throw Object.assign(new Error('Pool drain failed'), { code: 'INITIALIZATION_POOL_DRAIN_FAILED' });
      } else {
        context.phase = 'repository_initialize';
        await require(`../../server/database/postgres/${moduleName}`)[method]();
        lease.assertHeld();
      }
      console.log(`Initialized PostgreSQL repository: ${schema}`);
    }
  } catch (error) { primary = diagnostic(error, 'APPLICATION_INITIALIZATION_FAILED', context); }
  // Recheck explicitly owned pools: createPool removes failed end promises from
  // its registry, so a later closePostgresPools alone cannot prove their drain.
  let timer;
  try {
    await Promise.race([
      (async () => {
        const results = await Promise.allSettled(owned.map(pool => Promise.resolve().then(() => pool.end())));
        for (const result of results) if (result.status === 'rejected') drainFailures.push(diagnostic(result.reason, 'INITIALIZATION_POOL_DRAIN_FAILED'));
        if (pg && !maintenanceScope) await pg.closePostgresPools();
      })(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('Drain deadline'), { code: 'INITIALIZATION_DRAIN_TIMEOUT' })), 30000); }),
    ]);
  } catch (error) { drainFailures.push(diagnostic(error, 'INITIALIZATION_POOL_DRAIN_FAILED')); }
  finally { clearTimeout(timer); }
  // A repository can have failed its private end() and removed that pool from
  // the registry before throwing. On initialization failure conservatively keep
  // the session until process exit; do not advertise an unproven clean unlock.
  if (!primary && !drainFailures.length) {
    try { lease.assertHeld(); if (!maintenanceScope) { await lease.finishMaintenance(maintenanceEpoch); lease.assertHeld(); await lease.close(); } }
    catch (error) { primary = diagnostic(error, 'INITIALIZATION_LEASE_CLOSE_FAILED'); }
  }
  if (primary || drainFailures.length) {
    if (maintenanceScope) scopeTools.invalidateApplicationMaintenanceScope(maintenanceScope);
    const errors = [...(primary ? [primary] : []), ...drainFailures];
    const failure = new AggregateError(errors, 'PostgreSQL initialization failed; maintenance lease retained');
    failure.code = 'APPLICATION_INITIALIZATION_REQUIRES_EXIT';
    if (primary?.migration) failure.migration = primary.migration;
    throw failure;
  }
}

if (require.main === module) {
  (async () => {
    const args=process.argv.slice(2),entry=require('../../scripts/application-journal-bound-maintenance');
    const profile=entry.selectProfile(args);
    if(args.some(x=>x!=='--plan'&&!x.startsWith('--maintenance-profile='))||args.filter(x=>x==='--plan').length>1)throw TypeError('Invalid initialization arguments');
    require('dotenv').config({ quiet: true });
    if(args.includes('--plan')) { console.log(JSON.stringify(configurationPlan(process.env),null,2)); return; }
    if(profile!==entry.PROFILE)throw TypeError('Unsupported maintenance profile');
    await entry.runProspectiveJournalBoundMaintenance({installationRoot:require('node:path').resolve(__dirname,'../..')});
  })().catch(error => {
    console.error('PostgreSQL initialization failed:', JSON.stringify(initializationFailureSummary(error)));
    if (error.code === 'APPLICATION_INITIALIZATION_REQUIRES_EXIT') process.exit(1);
    else process.exitCode = 1;
  });
}

module.exports = { repositories, requiredStoreManifest, configurationPlan, initializeApplication, initializationFailureSummary };
