'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { initializeIdentityRepository } = require(
  '../../server/database/postgres/identityRepository');
const { withTransaction } = require('../../server/database/postgres');
const { bump } = require('../../server/database/postgres/workshopPlatformSupport');
const { toChallengeKey } = require('../../server/config/workshopCatalog');
const legacyXssSolutions = require('../../server/data/xssWorkshopSolutions').solutions;
const provenance = require('../../server/database/postgres/catalogDefaultProvenance');
const { createWorkshopPlatformSeed } = require(
  '../../docs/modernization/drafts/workshopPlatformSeed.provenance.candidate');
const { createWorkshopConfigRepository } = require(
  '../../server/database/postgres/workshopConfigRepository');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_CATALOG_PROVENANCE_MIGRATION_URL
  && process.env.PG_CATALOG_PROVENANCE_RUNTIME_URL;
const ROOT = path.join(__dirname, '../..');
const WORKSHOP = 'catalog_provenance_lab';
const seed = createWorkshopPlatformSeed({ withTransaction, bump, provenance, toChallengeKey,
  legacyXssSolutions });
const empty = () => Object.create(null);
function ownedUrl(key) {
  const value = new URL(process.env[key]);
  assert.ok(['127.0.0.1','localhost'].includes(value.hostname));
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  return value.href;
}
function input(version, { title = 'Managed title', hint = { title:'Managed hint',hints:['alpha'] },
  includeExercise = true, includePrimary = true, extra = [], extraHints = {} } = {}) {
  const objectives = includePrimary ? [{ id:'primary',text:title,category:'training',defaultEnabled:true },
    { id:'missing_content',text:'Missing content',defaultEnabled:true }, ...extra] : extra;
  return { catalogVersion:version,
    catalog:includeExercise ? { [WORKSHOP]:objectives } : {},
    hints:includeExercise ? { [WORKSHOP]:{ ...(includePrimary ? { primary:hint } : {}),...extraHints } } : {},
    solutions:includeExercise ? { [WORKSHOP]:{} } : {},
    challenges:includeExercise ? [{ key:toChallengeKey(WORKSHOP),name:'Provenance lab',
      description:'Managed description',category:'ai',difficulty:'advanced',route:'/catalog-provenance',
      defaultVisible:true }] : [] };
}
async function revisions(pool) {
  const config = Number((await pool.query(
    'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
  const rows = (await pool.query(`SELECT scope_type,scope_key,category,revision
    FROM workshop_platform.revisions WHERE category='workshop_config' ORDER BY scope_type,scope_key`)).rows;
  return { config, global:Number(rows.find(row => row.scope_type === 'global')?.revision || 0),
    scoped:Number(rows.find(row => row.scope_type === 'workshop' && row.scope_key === WORKSHOP)?.revision || 0) };
}
async function row(pool, id = 'primary') {
  return (await pool.query(`SELECT e.catalog_active AS exercise_active,e.is_visible,o.catalog_active,
    o.is_enabled,o.label,o.hint_content FROM workshop_platform.exercises e
    JOIN workshop_platform.objectives o USING(workshop_key)
    WHERE e.workshop_key=$1 AND o.objective_id=$2`,[WORKSHOP,id])).rows[0];
}
function heldAfterConfigLock(pool) {
  let acquiredResolve; let releaseResolve; let held = false;
  const acquired = new Promise(resolve => { acquiredResolve = resolve; });
  const release = new Promise(resolve => { releaseResolve = resolve; });
  return { pool:{ async connect() {
    const client = await pool.connect();
    return new Proxy(client,{ get(target,key) {
      if (key === 'query') return async (...args) => {
        const result = await target.query(...args);
        if (!held && String(args[0]).includes(
          'SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE')) {
          held = true; acquiredResolve(); await release;
        }
        return result;
      };
      const value = target[key]; return typeof value === 'function' ? value.bind(target) : value;
    }});
  } }, acquired, release:releaseResolve };
}
function waitAcquired(value) {
  return Promise.race([value,new Promise((_,reject)=>setTimeout(
    ()=>reject(new Error('catalog operation did not acquire the configuration lock')),2000))]);
}

test('catalog provenance serializes seed/admin changes and preserves ambiguous, custom and tombstoned state', {
  skip:!enabled, timeout:60000,
}, async t => {
  const migration = new Pool({ connectionString:ownedUrl('PG_CATALOG_PROVENANCE_MIGRATION_URL'),max:4 });
  const runtime = new Pool({ connectionString:ownedUrl('PG_CATALOG_PROVENANCE_RUNTIME_URL'),max:10 });
  t.after(async () => Promise.allSettled([runtime.end(),migration.end()]));
  const migrationDir = path.join(ROOT,'db/postgres/identity-migrations');
  const priorDir = fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-catalog-provenance-prior-'));
  t.after(() => fs.rmSync(priorDir,{recursive:true,force:true}));
  for (const name of fs.readdirSync(migrationDir).filter(name => name.endsWith('.sql')
    && name !== '9999_workshop_catalog_field_provenance.sql')) {
    fs.copyFileSync(path.join(migrationDir,name),path.join(priorDir,name));
  }
  await migrate(migration,priorDir);
  await migration.query(`INSERT INTO workshop_platform.exercises
    (workshop_key,challenge_key,challenge_name,challenge_description,category,difficulty,route,ordinal,is_visible)
    VALUES($1,$1,'Legacy instructor name','Legacy instructor description','legacy','hard','/legacy-custom',900,true)`,
  ['legacy_catalog_lab']);
  await migration.query(`INSERT INTO workshop_platform.objectives
    (workshop_key,objective_id,label,ordinal,hint_content,is_enabled)
    VALUES('legacy_catalog_lab','legacy','Legacy instructor label',0,'{"title":"Legacy custom"}'::jsonb,true)`);
  assert.deepEqual(await initializeIdentityRepository(runtime,migration),
    ['9999_workshop_catalog_field_provenance.sql']);
  assert.deepEqual(await initializeIdentityRepository(runtime,migration),[]);
  const legacySeed = input('catalog-v1');
  legacySeed.catalog.legacy_catalog_lab = [{id:'legacy',text:'New canonical label'}];
  legacySeed.hints.legacy_catalog_lab = {legacy:{title:'New canonical hint'}};
  legacySeed.solutions.legacy_catalog_lab = {};
  legacySeed.challenges.push({key:'legacy_catalog_lab',name:'New canonical name',description:'New canonical description',
    category:'ai',difficulty:'easy',route:'/new-route',defaultVisible:true});
  await seed(runtime,legacySeed);
  const legacy = (await migration.query(`SELECT e.challenge_name,e.route,o.label,o.hint_content
    FROM workshop_platform.exercises e JOIN workshop_platform.objectives o USING(workshop_key)
    WHERE e.workshop_key='legacy_catalog_lab'`)).rows[0];
  assert.equal(legacy.challenge_name,'Legacy instructor name'); assert.equal(legacy.route,'/legacy-custom');
  assert.equal(legacy.label,'Legacy instructor label'); assert.deepEqual(legacy.hint_content,{title:'Legacy custom'});
  assert.equal((await migration.query(`SELECT count(*)::integer AS count
    FROM workshop_platform.catalog_field_defaults WHERE workshop_key='legacy_catalog_lab'
    AND provenance_state='legacy_unknown'`)).rows[0].count,9);

  await seed(runtime,input('catalog-v1'));
  let current = await row(migration);
  assert.equal(current.label,'Managed title'); assert.deepEqual(current.hint_content,{title:'Managed hint',hints:['alpha']});
  const missing = (await migration.query(`SELECT source_document,applied_default_document
    FROM workshop_platform.catalog_field_defaults WHERE entity_kind='objective' AND workshop_key=$1
    AND objective_id='missing_content' AND field_name='hint_content'`,[WORKSHOP])).rows[0];
  assert.deepEqual(missing.source_document,{present:false});
  assert.deepEqual(missing.applied_default_document,{present:true,value:null});
  let before = await revisions(migration);
  await seed(runtime,input('catalog-v1',{hint:{hints:['alpha'],title:'Managed hint'}}));
  assert.deepEqual(await revisions(migration),before,'canonical JSON key order is a no-op');
  await seed(runtime,input('catalog-v2',{title:'Managed title v2',hint:null}));
  current = await row(migration); assert.equal(current.label,'Managed title v2'); assert.equal(current.hint_content,null);
  let after = await revisions(migration);
  assert.deepEqual(after,{config:before.config+1,global:before.global+1,scoped:before.scoped});
  await seed(runtime,input('catalog-v2-restored',{title:'Managed title v2',
    hint:{title:'Managed restored',hints:['restored']}}));
  after=await revisions(migration);

  const adminRepo=createWorkshopConfigRepository(runtime,{isSecureShopReady:()=>true});
  await adminRepo.updateExercise({key:WORKSHOP,challengeName:'Instructor catalog title',category:'ai',
    difficulty:'advanced',isVisible:false,showSolutions:false,
    description:'Instructor catalog description',route:'/instructor-catalog'});
  let exerciseRow=(await migration.query(`SELECT challenge_name,challenge_description,category,difficulty,
    route,is_visible FROM workshop_platform.exercises WHERE workshop_key=$1`,[WORKSHOP])).rows[0];
  assert.deepEqual(exerciseRow,{challenge_name:'Instructor catalog title',
    challenge_description:'Instructor catalog description',category:'ai',difficulty:'advanced',
    route:'/instructor-catalog',is_visible:false});
  const metadataStates=()=>migration.query(`SELECT field_name,provenance_state
    FROM workshop_platform.catalog_field_defaults WHERE entity_kind='exercise' AND workshop_key=$1
    ORDER BY field_name`,[WORKSHOP]);
  let states=(await metadataStates()).rows;
  assert.deepEqual(states.filter(value=>value.provenance_state==='custom').map(value=>value.field_name),
    ['challenge_description','challenge_name','route']);
  await seed(runtime,input('catalog-v2-admin-source'));
  exerciseRow=(await migration.query(`SELECT challenge_name,challenge_description,route,is_visible
    FROM workshop_platform.exercises WHERE workshop_key=$1`,[WORKSHOP])).rows[0];
  assert.deepEqual(exerciseRow,{challenge_name:'Instructor catalog title',
    challenge_description:'Instructor catalog description',route:'/instructor-catalog',is_visible:false});
  const beforeVisibilityStates=(await metadataStates()).rows;
  await adminRepo.setExerciseVisibility(WORKSHOP,true);
  assert.equal((await migration.query(`SELECT is_visible FROM workshop_platform.exercises
    WHERE workshop_key=$1`,[WORKSHOP])).rows[0].is_visible,true);
  assert.deepEqual((await metadataStates()).rows,beforeVisibilityStates,
    'visibility-only administration must not mark default-controlled content');
  after=await revisions(migration);

  const adminFirst = heldAfterConfigLock(runtime);
  const adminRepo1 = createWorkshopConfigRepository(adminFirst.pool,{isSecureShopReady:()=>true});
  const adminPromise = adminRepo1.updateHintContent(WORKSHOP,'primary',{title:'Instructor first'});
  let queuedSeed; let seedCompletedEarly;
  try {
    await waitAcquired(adminFirst.acquired);
    queuedSeed = seed(runtime,input('catalog-v3',{
      title:'Managed title v3',hint:{title:'Source v3',hints:['v3']}}));
    seedCompletedEarly = await Promise.race([queuedSeed.then(()=>true,()=>true),
      new Promise(resolve=>setTimeout(()=>resolve(false),80))]);
  } finally { adminFirst.release(); }
  const adminFirstResults=await Promise.allSettled([adminPromise,queuedSeed]);
  for(const result of adminFirstResults)if(result.status==='rejected')throw result.reason;
  assert.equal(seedCompletedEarly,false);
  current=await row(migration); assert.equal(current.label,'Managed title v3');
  assert.deepEqual(current.hint_content,{title:'Instructor first',hints:['restored']});
  before=after;after=await revisions(migration);
  assert.deepEqual(after,{config:before.config+2,global:before.global+1,scoped:before.scoped+1});

  await seed(runtime,input('catalog-v4',{title:'Managed title v4',hint:{title:'Source v4',hints:['v4']},
    extra:[{id:'seed_first',text:'Seed first',defaultEnabled:true}]}));
  const seedFirstHint={title:'Seed first A',hints:['A']};
  await seed(runtime,input('catalog-v4-hint',{title:'Managed title v4',hint:{title:'Source v4',hints:['v4']},
    extra:[{id:'seed_first',text:'Seed first',defaultEnabled:true}],extraHints:{seed_first:seedFirstHint}}));
  assert.deepEqual((await row(migration)).hint_content,{title:'Instructor first',hints:['restored']});
  // The first source addition safely upgrades the unchanged SQL-null storage baseline.
  assert.deepEqual((await row(migration,'seed_first')).hint_content,seedFirstHint);
  const seedFirst = heldAfterConfigLock(runtime);
  const beforeSeedFirstRace=await revisions(migration);
  const firstSeedPromise = createWorkshopPlatformSeed({withTransaction,bump,provenance,
    toChallengeKey,legacyXssSolutions})(seedFirst.pool,input('catalog-v5',{title:'Managed title v5',
      hint:{title:'Source v5',hints:['v5']},extra:[{id:'seed_first',text:'Seed first',defaultEnabled:true}],
      extraHints:{seed_first:{title:'Seed first B',hints:['B']}}}));
  const adminRepo2=createWorkshopConfigRepository(runtime,{isSecureShopReady:()=>true});
  let secondAdmin;let adminCompletedEarly;
  try {
    await waitAcquired(seedFirst.acquired);
    secondAdmin=adminRepo2.updateHintContent(WORKSHOP,'seed_first',{title:'Instructor second'});
    adminCompletedEarly=await Promise.race([secondAdmin.then(()=>true,()=>true),
      new Promise(resolve=>setTimeout(()=>resolve(false),80))]);
  } finally { seedFirst.release(); }
  const seedFirstResults=await Promise.allSettled([firstSeedPromise,secondAdmin]);
  for(const result of seedFirstResults)if(result.status==='rejected')throw result.reason;
  assert.equal(adminCompletedEarly,false);
  assert.deepEqual((await row(migration,'seed_first')).hint_content,{title:'Instructor second',hints:['B']});
  assert.deepEqual(await revisions(migration),{config:beforeSeedFirstRace.config+2,
    global:beforeSeedFirstRace.global+1,scoped:beforeSeedFirstRace.scoped+1});

  const rollbackBefore=await row(migration,'seed_first');const rollbackRevision=await revisions(migration);
  await migration.query(`DELETE FROM workshop_platform.catalog_field_defaults WHERE entity_kind='objective'
    AND workshop_key=$1 AND objective_id='seed_first' AND field_name='hint_content'`,[WORKSHOP]);
  await assert.rejects(adminRepo2.updateHintContent(WORKSHOP,'seed_first',{title:'Must roll back'}),
    /provenance missing/);
  assert.deepEqual(await row(migration,'seed_first'),rollbackBefore);
  assert.deepEqual(await revisions(migration),rollbackRevision);

  before=await revisions(migration);
  await seed(runtime,input('catalog-v6',{includePrimary:false,
    extra:[{id:'seed_first',text:'Seed first',defaultEnabled:true}]}));
  assert.equal((await row(migration)).catalog_active,false); assert.equal((await row(migration)).is_enabled,false);
  assert.deepEqual(await revisions(migration),{config:before.config+1,global:before.global+1,scoped:before.scoped});
  before=await revisions(migration);
  await seed(runtime,input('catalog-v7',{extra:[{id:'seed_first',text:'Seed first',defaultEnabled:true}]}));
  assert.equal((await row(migration)).catalog_active,true); assert.equal((await row(migration)).is_enabled,false);
  assert.deepEqual(await revisions(migration),{config:before.config+1,global:before.global+1,scoped:before.scoped});
  before=await revisions(migration);
  await seed(runtime,input('catalog-v8',{includeExercise:false}));
  assert.equal((await row(migration)).exercise_active,false); assert.equal((await row(migration)).is_visible,false);
  assert.deepEqual(await revisions(migration),{config:before.config+1,global:before.global+1,scoped:before.scoped});
  before=await revisions(migration);
  await seed(runtime,input('catalog-v9'));
  assert.equal((await row(migration)).exercise_active,true); assert.equal((await row(migration)).is_visible,false);
  assert.deepEqual(await revisions(migration),{config:before.config+1,global:before.global+1,scoped:before.scoped});
  assert.equal((await migration.query(`SELECT EXISTS(SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
    WHERE n.nspname='workshop_platform' AND c.relname='catalog_field_defaults'
      AND acl.grantee=0) AS allowed`)).rows[0].allowed,false);
});
