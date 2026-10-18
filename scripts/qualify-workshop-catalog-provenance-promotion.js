'use strict';

const { hashDocument } = require('../docs/modernization/drafts/catalogDefaultProvenance.candidate');
const { inspectStores, assertPrivateConfigBytes } = require('./qualify-sensitive-info-reset-promotion');
const { repositories } = require('../db/postgres/initialize-application');

const EXPECTED_NAMES = Object.freeze(repositories.map(([name]) => name));
const LEARNER_TABLES = Object.freeze([
  'workshop_platform.completions',
  'workshop_platform.activity_counters',
  'workshop_platform.time_tracking',
  'workshop_platform.user_state',
  'workshop_platform.objective_judgments',
  'workshop_platform.objective_evidence',
]);

function hash(value) {
  return hashDocument(value);
}

async function catalogSnapshot(dependencies = {}) {
  const postgres = require('../server/database/postgres');
  const createPool = dependencies.createPool || postgres.createPool;
  const closePostgresPools = dependencies.closePostgresPools || postgres.closePostgresPools;
  const pool = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  try {
    const exercises = (await pool.query(`SELECT workshop_key,challenge_name,challenge_description,
      category,difficulty,route,is_visible,show_hints,show_solutions,catalog_active,ordinal
      FROM workshop_platform.exercises ORDER BY workshop_key`)).rows;
    const objectives = (await pool.query(`SELECT workshop_key,objective_id,label,category,
      hint_content,solution_content,is_enabled,hint_enabled,solution_enabled,catalog_active,ordinal
      FROM workshop_platform.objectives ORDER BY workshop_key,objective_id`)).rows;
    const fields = {};
    for (const row of exercises) {
      for (const name of ['challenge_name','challenge_description','category','difficulty','route']) {
        fields[`exercise:${row.workshop_key}::${name}`] = hash({ present: true, value: row[name] });
      }
    }
    for (const row of objectives) {
      for (const name of ['label','category','hint_content','solution_content']) {
        fields[`objective:${row.workshop_key}:${row.objective_id}:${name}`] =
          hash({ present: true, value: row[name] });
      }
    }
    const learner = {};
    for (const relation of LEARNER_TABLES) {
      const rows = (await pool.query(`SELECT to_jsonb(t) AS value FROM ${relation} t
        ORDER BY to_jsonb(t)::text`)).rows.map(row => row.value);
      learner[relation] = { rows: rows.length, sha256: hash(rows) };
    }
    const revision = Number((await pool.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
    const hasProvenance = (await pool.query(`SELECT to_regclass(
      'workshop_platform.catalog_field_defaults') IS NOT NULL AS present`)).rows[0].present;
    const provenance = hasProvenance ? (await pool.query(`SELECT count(*)::integer AS count,
      count(*) FILTER (WHERE provenance_state='managed')::integer AS managed,
      count(*) FILTER (WHERE provenance_state='custom')::integer AS custom,
      count(*) FILTER (WHERE provenance_state='legacy_unknown')::integer AS legacy_unknown
      FROM workshop_platform.catalog_field_defaults`)).rows[0]
      : { count: 0, managed: 0, custom: 0, legacy_unknown: 0 };
    return {
      fields,
      settingsSha256: hash({
        exercises: exercises.map(({ workshop_key,is_visible,show_hints,show_solutions,catalog_active,ordinal }) =>
          ({ workshop_key,is_visible,show_hints,show_solutions,catalog_active,ordinal })),
        objectives: objectives.map(({ workshop_key,objective_id,is_enabled,hint_enabled,
          solution_enabled,catalog_active,ordinal }) => ({ workshop_key,objective_id,is_enabled,
          hint_enabled,solution_enabled,catalog_active,ordinal })),
      }),
      learner,
      revision,
      counts: { exercises: exercises.length, objectives: objectives.length },
      provenance,
    };
  } finally {
    await pool.end();
    await closePostgresPools();
  }
}

async function assertCatalogReadiness(dependencies = {}) {
  const postgres = require('../server/database/postgres');
  const createPool = dependencies.createPool || postgres.createPool;
  const closePostgresPools = dependencies.closePostgresPools || postgres.closePostgresPools;
  const assertPersonaInboxReadiness = dependencies.assertPersonaInboxReadiness
    || require('../server/services/secureshopBoundReviewComposition').assertPersonaInboxReadiness;
  const availabilityFactory = dependencies.createSecureShopPersonaInboxAvailability
    || require('../server/services/secureshopPersonaInboxAvailability').createSecureShopPersonaInboxAvailability;
  const identityPool = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const agentsPool = createPool(process.env, 'SECURESHOP_AGENTS_DATABASE_URL');
  try {
    await assertPersonaInboxReadiness({ identityPool, agentsPool });
    const availability = await availabilityFactory(identityPool).read();
    const provenance = (await identityPool.query(`SELECT count(*)::integer AS count
      FROM workshop_platform.catalog_field_defaults`)).rows[0].count;
    if (!availability.registered || availability.visible || availability.enabled.size !== 0 || provenance <= 0) {
      throw Object.assign(new Error('catalog provenance readiness is incomplete'), {
        code: 'CATALOG_PROVENANCE_NOT_READY',
      });
    }
    return { ready: true, registered: true, visible: false, enabledObjectives: [], provenanceRows: provenance };
  } finally {
    await Promise.allSettled([identityPool.end(), agentsPool.end()]);
    await closePostgresPools();
  }
}

async function initializeIdentityOnly(dependencies = {}) {
  const postgres = require('../server/database/postgres');
  const createPool = dependencies.createPool || postgres.createPool;
  const closePostgresPools = dependencies.closePostgresPools || postgres.closePostgresPools;
  const initializeIdentityRepository = dependencies.initializeIdentityRepository
    || require('../server/database/postgres/identityRepository').initializeIdentityRepository;
  const seedWorkshopPlatform = dependencies.seedWorkshopPlatform
    || require('../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform;
  const runtime = createPool(process.env, 'IDENTITY_DATABASE_URL');
  const migration = createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
  try {
    const applied = await initializeIdentityRepository(runtime, migration);
    await seedWorkshopPlatform(migration);
    return { store: 'identity', applied };
  } finally {
    await Promise.allSettled([runtime.end(), migration.end()]);
    await closePostgresPools();
  }
}

async function main(argument) {
  assertPrivateConfigBytes();
  require('dotenv').config({ quiet: true });
  assertPrivateConfigBytes();
  let result;
  if (argument === '--initialize-identity') result = await initializeIdentityOnly();
  else if (argument === '--ledger') result = await inspectStores();
  else if (argument === '--replay') result = await inspectStores({ replay: true });
  else if (argument === '--catalog') result = await catalogSnapshot();
  else if (argument === '--readiness') result = await assertCatalogReadiness();
  else throw Object.assign(new Error('invalid catalog provenance qualification argument'), {
    code: 'INVALID_ARGUMENT',
  });
  assertPrivateConfigBytes();
  return result;
}

if (require.main === module) main(process.argv[2]).then(result => {
  process.stdout.write(`WORKSHOP_CATALOG_QUALIFICATION=${JSON.stringify(result)}\n`);
}).catch(error => {
  console.error('Workshop catalog provenance promotion qualification failed:', error.code || error.name);
  process.exitCode = 1;
});

module.exports = { EXPECTED_NAMES, LEARNER_TABLES, catalogSnapshot, assertCatalogReadiness,
  initializeIdentityOnly, main };
