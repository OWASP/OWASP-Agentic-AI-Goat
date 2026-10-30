'use strict';

// Explicit disposable launcher bootstrap. Importing this module creates no
// pools, loads no application configuration and performs no initialization.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const path = require('node:path');
const BOOTSTRAP_STAGES = new Set(['environment', 'pool_creation', 'identity_predecessor',
  'identity_migration_transition', 'identity_fresh_schema', 'identity_schema', 'platform_seed',
  'aria_schema', 'nova_schema', 'fixed_fixtures', 'catalog_assertions', 'cleanup', 'unknown']);
const BOOTSTRAP_ERROR_CODES = new Set(['ERR_ASSERTION', 'MODULE_NOT_FOUND', 'ENOENT', 'EACCES', 'EPERM',
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'TYPE_ERROR']);

function safeBootstrapFailure(error) {
  const stage = BOOTSTRAP_STAGES.has(error?.bootstrapStage) ? error.bootstrapStage : 'unknown';
  let candidate = String(error?.code || '').toUpperCase();
  if (!candidate && error?.name === 'TypeError') candidate = 'TYPE_ERROR';
  const errorCode = /^[0-9A-Z]{5}$/.test(candidate) || BOOTSTRAP_ERROR_CODES.has(candidate)
    ? candidate : 'EXECUTION_FAILED';
  return Object.freeze({ stage, errorCode });
}

function validateBootstrapEnvironment(env) {
  if (env.PG_TEST_DISPOSABLE !== 'yes' || env.SQL_NOSQL_ROUTE_ISOLATED !== '1'
      || env.PLATFORM_DATABASE_ENGINE !== 'postgres' || env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw new Error('Explicit isolated PostgreSQL bootstrap flags required');
  }
  const workspace = env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;
  if (typeof workspace !== 'string' || !path.isAbsolute(workspace)
      || fs.realpathSync(workspace) !== fs.realpathSync(process.cwd())) {
    throw new Error('Exact isolated bootstrap workspace required');
  }
  let port;
  for (const [family, prefix] of [['identity', 'IDENTITY'], ['aria', 'SQL_WORKSHOP'], ['nova', 'NOSQL_WORKSHOP']]) {
    for (const role of ['runtime', 'migration']) {
      const name = `${prefix}${role === 'migration' ? '_MIGRATION' : ''}_DATABASE_URL`;
      let url;
      try { url = new URL(env[name]); } catch { throw new Error('Explicit owned database URL required'); }
      if (!['postgres:', 'postgresql:'].includes(url.protocol) || url.hostname !== '127.0.0.1'
          || !url.port || url.pathname !== `/owasp_ai_goat_test_sql_nosql_route_${family}`
          || url.username !== `dvaia_${family}_${role}` || url.search || url.hash
          || (port !== undefined && url.port !== port)) {
        throw new Error('Exact owned loopback database and runtime/migration role required');
      }
      port = url.port;
    }
  }
}

function fixedSessionFixtures(nonce) {
  assert.match(nonce, /^[a-f0-9]{32}$/);
  return Object.freeze({
    ARIA: Object.freeze({ term: `OWASP_AI_GOAT_FIXED_ARIA_${nonce}`, publicId: `FIXED-ARIA-${nonce}` }),
    NOVA: Object.freeze({ term: `OWASP_AI_GOAT_FIXED_NOVA_${nonce}`, publicId: `FIXED-NOVA-PUBLIC-${nonce}`, restrictedId: `FIXED-NOVA-RESTRICTED-${nonce}` }),
  });
}
async function seedFixedSessionFixtures({ ariaMigration, novaMigration, nonce }) {
  const fixtures = fixedSessionFixtures(nonce);
  // Verify both authorities before the first write. Runtime roles remain read-only
  // for catalogs; this fixture provisioning runs only in the guarded bootstrap.
  for (const [pool, expected] of [[ariaMigration, 'dvaia_aria_migration'], [novaMigration, 'dvaia_nova_migration']]) {
    assert.equal((await pool.query('SELECT current_user AS role')).rows[0].role, expected);
  }
  const a = fixtures.ARIA; const n = fixtures.NOVA;
  await ariaMigration.query("INSERT INTO aria.products(product_id,name,category,price,description,stock,available) VALUES($1,$2,'fixture',1,'owned fixture',1,1)", [a.publicId, a.term]);
  for (const [id, visibility] of [[n.publicId, 'public'], [n.restrictedId, 'restricted']]) {
    await novaMigration.query("INSERT INTO nova.papers(paper_id,title,abstract,authors,topics,year,citations,cited_by,access_level) VALUES($1,$2,'owned fixture','[]','[]',2026,1,'[]',$3)", [id, n.term, visibility]);
  }
}

async function insertTraceMigrationEvidence(pool, runId, ownerKey, startSequence = 1) {
  await pool.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);
  await pool.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[runId,ownerKey]);
  const prior={decisionSource:'model',provider:'ollama',model:'llama3.1:8b',attempt:1};
  await pool.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,$3,'migration_prior','decision',$4::jsonb)",[runId,ownerKey,startSequence,JSON.stringify(prior)]);
  return prior;
}

async function assertTraceMigrationHead(pool, {runId,ownerKey,prior,startSequence=1}) {
  assert.deepEqual((await pool.query('SELECT metadata FROM graph_runtime.events WHERE run_id=$1 AND sequence=$2',[runId,startSequence])).rows[0].metadata,prior);
  await pool.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,$3,'response_source','decision',$4::jsonb)",
    [runId,ownerKey,startSequence+1,JSON.stringify({responseSource:'model',errorCode:'CONTROLLED'})]);
  const promptPolicySnapshot={policyCount:1,policyVersion:'7',role:'admin',sha256:'a'.repeat(64)};
  await pool.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,$3,'prompt_policy','decision',$4::jsonb)",
    [runId,ownerKey,startSequence+2,JSON.stringify({promptPolicySnapshot})]);
  for(const invalid of [
    null,{...promptPolicySnapshot,text:'forbidden'},{...promptPolicySnapshot,role:'system'},
    {...promptPolicySnapshot,policyCount:1.5},{...promptPolicySnapshot,policyVersion:'0'},
    {...promptPolicySnapshot,sha256:'A'.repeat(64)}
  ]){
    await assert.rejects(pool.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,200,'invalid_policy','decision',$3::jsonb)",
      [runId,ownerKey,JSON.stringify({promptPolicySnapshot:invalid})]),error=>error?.code==='23514');
  }
}

function migrationOverlay(migrationRoot, directoryNames) {
  const migrationFile = require.resolve('../../db/postgres/migrate');
  const source = fs.readFileSync(migrationFile, 'utf8');
  const nativeRequire = createRequire(migrationFile);
  const virtualFs = {
    ...fsp,
    readdir: async directory => directoryNames.has(directory)
      ? directoryNames.get(directory)
      : fsp.readdir(directory),
    readFile: async (file, encoding) => {
      for (const [directory] of directoryNames) {
        if (file === directory || !file.startsWith(`${directory}${path.sep}`)) continue;
        return fsp.readFile(path.join(migrationRoot, path.basename(file)), encoding);
      }
      return fsp.readFile(file, encoding);
    },
  };
  const localRequire = request => (request === 'fs/promises' || request === 'node:fs/promises') ? virtualFs : nativeRequire(request);
  const module = { exports: {} };
  vm.runInThisContext(`(function(require,module,exports,__dirname){${source}\n})`, {
    filename: migrationFile,
  })(localRequire, module, module.exports, path.dirname(migrationFile));
  return module.exports;
}

async function qualifyTraceMigrations({identityMigration,env}) {
  const migrationRoot=path.resolve(__dirname,'../../db/postgres/identity-migrations');
  const scratchRoot=path.resolve(env.LOGS_DIR||path.join(process.cwd(),'logs'));
  const migrationNames=fs.readdirSync(migrationRoot).filter(name=>name.endsWith('.sql')).sort();
  const predecessorNames=migrationNames.filter(name=>name<'0101_');
  const predecessor=path.join(scratchRoot,'virtual-identity-predecessor');
  const directories=new Map([[predecessor,predecessorNames],[migrationRoot,migrationNames]]);
  {
    const {migrate}=migrationOverlay(migrationRoot,directories);
    await migrate(identityMigration,predecessor);
    const populated={runId:'00000000-0000-4000-8000-000000000101',ownerKey:'["MigrationQualification","populated"]'};
    populated.prior=await insertTraceMigrationEvidence(identityMigration,populated.runId,populated.ownerKey);
    const applied=await migrate(identityMigration,migrationRoot);
    assert.deepEqual(applied,migrationNames.filter(name=>name>='0101_'));
    assert.ok(applied.includes('0101_graph_response_source.sql'));
    assert.ok(applied.includes('0102_graph_prompt_policy_snapshot.sql'));
    await assertTraceMigrationHead(identityMigration,populated);
    assert.deepEqual(await migrate(identityMigration,migrationRoot),[]);

    const schemas=(await identityMigration.query("SELECT nspname FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','public') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%' ORDER BY nspname")).rows.map(row=>row.nspname);
    for(const schema of schemas){
      assert.match(schema,/^[a-z][a-z0-9_]*$/);
      await identityMigration.query(`DROP SCHEMA "${schema}" CASCADE`);
    }
    const fresh=await migrate(identityMigration,migrationRoot);
    assert.deepEqual(fresh,migrationNames);
    assert.ok(fresh.includes('0101_graph_response_source.sql'));
    assert.ok(fresh.includes('0102_graph_prompt_policy_snapshot.sql'));
    const clean={runId:'00000000-0000-4000-8000-000000000102',ownerKey:'["MigrationQualification","fresh"]'};
    clean.prior=await insertTraceMigrationEvidence(identityMigration,clean.runId,clean.ownerKey);
    await assertTraceMigrationHead(identityMigration,clean);
    assert.deepEqual(await migrate(identityMigration,migrationRoot),[]);
  }
}

async function bootstrap({ env = process.env } = {}) {
  let bootstrapStage = 'environment';
  try { validateBootstrapEnvironment(env); }
  catch (error) { error.bootstrapStage = bootstrapStage; throw error; }
  const originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('Network/provider calls forbidden during database bootstrap'); };
  const pools = [];
  let closePostgresPools;
  try {
    bootstrapStage = 'pool_creation';
    const postgres = require('../../server/database/postgres');
    closePostgresPools = postgres.closePostgresPools;
    const pool = name => {
      const value = postgres.createPool(env, name); pools.push(value); return value;
    };
    const identityRuntime = pool('IDENTITY_DATABASE_URL');
    const identityMigration = pool('IDENTITY_MIGRATION_DATABASE_URL');
    const ariaRuntime = pool('SQL_WORKSHOP_DATABASE_URL');
    const ariaMigration = pool('SQL_WORKSHOP_MIGRATION_DATABASE_URL');
    const novaRuntime = pool('NOSQL_WORKSHOP_DATABASE_URL');
    const novaMigration = pool('NOSQL_WORKSHOP_MIGRATION_DATABASE_URL');
    const identityApi = require('../../server/database/postgres/identityRepository');
    bootstrapStage = 'identity_migration_transition';
    await qualifyTraceMigrations({identityMigration,env});
    bootstrapStage = 'identity_fresh_schema';
    assert.deepEqual(await identityApi.initializeIdentityRepository(identityRuntime, identityMigration),[]);
    bootstrapStage = 'identity_schema';
    bootstrapStage = 'platform_seed';
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    const ariaStore = require('../../server/database/postgres/sqlWorkshopDb').createSqlWorkshopDb(ariaRuntime);
    const novaStore = require('../../server/database/postgres/nosqlWorkshopDb').createNosqlWorkshopDb(novaRuntime);
    bootstrapStage = 'aria_schema'; await ariaStore.initializeSqlWorkshopDb(ariaMigration);
    bootstrapStage = 'nova_schema'; await novaStore.initializeNosqlWorkshopDb(novaMigration);
    if (env.SQL_NOSQL_ROUTE_FIXED_SESSION === '1') {
      bootstrapStage = 'fixed_fixtures';
      await seedFixedSessionFixtures({ ariaMigration, novaMigration, nonce: env.SQL_NOSQL_ROUTE_FIXTURE_NONCE });
    }
    bootstrapStage = 'catalog_assertions';
    const objective = (await identityMigration.query(`SELECT label,hint_content,solution_content FROM workshop_platform.objectives
      WHERE workshop_key='nosql_injection_workshop' AND objective_id='nosqli_9'`)).rows[0];
    assert.equal(objective.label, 'Extract Author Contact Data');
    assert.equal(objective.hint_content.title, 'Extract Author Contact Data');
    assert.equal(objective.solution_content.title, 'Extract Author Contact Data');
    const archival = (await novaMigration.query("SELECT title,approach FROM nova.nosql_injection_solutions WHERE objective_id='nosqli_9'")).rows[0];
    assert.equal(archival.title, 'Extract Author Contact Data');
    assert.match(archival.approach, /synthetic email addresses/);
  } catch (error) {
    error.bootstrapStage = bootstrapStage;
    throw error;
  } finally {
    try {
      const results = await Promise.allSettled(pools.map(pool => pool.end()));
      if (closePostgresPools) await closePostgresPools();
      if (results.some(result => result.status === 'rejected')) {
        const error = new Error('Bootstrap pool cleanup failed'); error.bootstrapStage = 'cleanup'; throw error;
      }
    } finally { global.fetch = originalFetch; }
  }
}

module.exports = { bootstrap, validateBootstrapEnvironment, seedFixedSessionFixtures, fixedSessionFixtures,
  qualifyTraceMigrations, assertTraceMigrationHead, safeBootstrapFailure };
if (require.main === module) bootstrap().then(() => {
  process.stdout.write('SQL_NOSQL_ROUTE_BOOTSTRAP_READY\n');
}, error => {
  process.stderr.write(`SQL_NOSQL_ROUTE_BOOTSTRAP_FAILED ${JSON.stringify(safeBootstrapFailure(error))}\n`);
  process.exitCode = 1;
});
