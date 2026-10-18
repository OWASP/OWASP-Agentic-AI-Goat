'use strict';

const { createPool, closePostgresPools } = require('../server/database/postgres');
const { catalogSnapshot } = require('./qualify-workshop-catalog-provenance-promotion');
const curriculum = require('../server/config/secureshopCurriculum');

async function withPools(operation) {
  const pools = {
    identity: createPool(process.env, 'IDENTITY_DATABASE_URL'),
    identityMigration: createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL'),
    agents: createPool(process.env, 'SECURESHOP_AGENTS_DATABASE_URL'),
    agentsMigration: createPool(process.env, 'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL'),
    commerce: createPool(process.env, 'SECURESHOP_DATABASE_URL'),
    commerceMigration: createPool(process.env, 'SECURESHOP_MIGRATION_DATABASE_URL'),
    review: createPool(process.env, 'SECURESHOP_REVIEW_DATABASE_URL'),
    reviewMigration: createPool(process.env, 'SECURESHOP_REVIEW_MIGRATION_DATABASE_URL'),
  };
  try { return await operation(pools); }
  finally { await Promise.allSettled(Object.values(pools).map(pool => pool.end())); await closePostgresPools(); }
}
async function reconcile() {
  const pool = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  try { return await require('../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(pool); }
  finally { await pool.end(); await closePostgresPools(); }
}
function applyManagedConfiguration(load = () => require('../server/services/secureshopQualifiedManagedConfiguration').load()) {
  const managed = load();
  if (managed.SS_BOUND_REVIEWS_ENABLED !== 'true') throw new Error('SecureShop managed activation is disabled');
  Object.assign(process.env, managed);
  return managed;
}
function assertCurriculumDefinition(value = curriculum) {
  const rows = value.OBJECTIVES;
  const ids = rows.map(row => row.id);
  const mechanisms = new Set(curriculum.QUALIFIED_MECHANISMS);
  const qualified = rows.filter(row => mechanisms.has(row.qualification)).map(row => row.id);
  const pending = rows.filter(row => row.qualification === 'pending').map(row => row.id);
  if (!ids.length || ids.some(id => typeof id !== 'string' || !id)
      || new Set(ids).size !== ids.length || qualified.length + pending.length !== ids.length
      || JSON.stringify(value.QUALIFIED_OBJECTIVE_IDS) !== JSON.stringify(qualified)
      || JSON.stringify(value.PENDING_OBJECTIVE_IDS) !== JSON.stringify(pending)
      || rows.some(row => row.defaultEnabled !== false)
      || value.CHALLENGE.defaultVisible !== false) throw new Error('SecureShop curriculum readiness mismatch');
}
function assertCatalogRows(rows, value = curriculum) {
  assertCurriculumDefinition(value);
  if (rows.length !== value.OBJECTIVES.length
      || JSON.stringify(rows.map(row => row.objective_id)) !== JSON.stringify(value.OBJECTIVES.map(row => row.id))) {
    throw new Error('SecureShop catalog objective identity changed during activation');
  }
  const pending = new Set(value.PENDING_OBJECTIVE_IDS);
  if (rows.some(row => pending.has(row.objective_id) && row.is_enabled !== false)) {
    throw new Error('SecureShop pending objective cannot be enabled during activation');
  }
}
async function readiness({ candidate = false } = {}) {
  if (typeof candidate !== 'boolean') throw new Error('Invalid readiness mode');
  assertCurriculumDefinition();
  const managed = applyManagedConfiguration(candidate ? () => {
    const path = require('node:path');
    const config = require('../server/services/secureshopQualifiedManagedConfiguration');
    const root = path.resolve(__dirname, '..');
    return require('./install/secureshop-qualified-system-setup').loadCandidate({root});
  } : undefined);
  // This standalone gate does not pass through server/index.js, so apply the
  // already validated private values before importing policy-bound services.
  Object.assign(process.env, managed);
  return withPools(async pools => {
    const composition = require('../server/services/secureshopBoundReviewComposition');
    await composition.assertSecureShopBoundReviewReadiness({ identityPool:pools.identity,
      agentsPool:pools.agents, commercePool:pools.commerce, reviewPool:pools.review,
      migrationPools:{ identity:pools.identityMigration, agents:pools.agentsMigration,
        commerce:pools.commerceMigration, review:pools.reviewMigration },
      requiredObjectives:curriculum.QUALIFIED_OBJECTIVE_IDS });
    await composition.assertPersonaInboxReadiness({ identityPool:pools.identity, agentsPool:pools.agents });
    await require('../server/services/secureshopMcpTrustProduction').assertSecureShopMcpTrustReadiness({
      identityPool:pools.identity, agentsPool:pools.agents });
    await require('../server/services/secureshopSsrfProduction').assertSecureShopSsrfReadiness({
      identityPool:pools.identity, agentsPool:pools.agents });
    const rows = (await pools.identity.query(`SELECT e.is_visible,o.objective_id,o.is_enabled,o.hint_enabled,o.solution_enabled
      FROM workshop_platform.exercises e JOIN workshop_platform.objectives o USING(workshop_key)
      WHERE e.workshop_key=$1 AND e.catalog_active=true AND o.catalog_active=true ORDER BY o.ordinal`,
    [curriculum.WORKSHOP_KEY])).rows;
    assertCatalogRows(rows);
    return Object.freeze({ ready:true, objectiveIds:rows.map(row => row.objective_id),
      visible:rows.some(row => row.is_visible === true),
      enabledObjectives:rows.filter(row => row.is_enabled === true).map(row => row.objective_id),
      structuralPanels:curriculum.EXERCISES.map(row => row.id), managed:true });
  });
}
async function main(argument) {
  require('dotenv').config({ quiet:true });
  if (argument === '--catalog') return catalogSnapshot();
  if (argument === '--reconcile') return reconcile();
  if (argument === '--readiness') return readiness();
  if (argument === '--candidate-readiness') return readiness({candidate:true});
  throw new Error('Usage: node scripts/qualify-secureshop-qualified-activation.js --catalog|--reconcile|--readiness');
}
if (require.main === module) main(process.argv[2]).then(result => {
  process.stdout.write(`SECURESHOP_ACTIVATION_QUALIFICATION=${JSON.stringify(result)}\n`);
}).catch(error => { console.error('SecureShop activation qualification failed:', error.code || error.message); process.exitCode=1; });
module.exports = { applyManagedConfiguration, assertCurriculumDefinition, assertCatalogRows, reconcile, readiness, main };
