'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {Pool}=require('pg');
const helper=require('../../scripts/qualify-application-backups');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.BACKUP_PRESERVATION_TEST_URL;
const tables=Object.freeze({
  'workshop_platform.exercises':{},'workshop_platform.objectives':{},
  'workshop_platform.catalog_field_defaults':{},'workshop_platform.revisions':{},
  'workshop_platform.activity_counters':{},'workshop_platform.xss_legacy_solution_visibility':{},
  'workshop_platform.xss_legacy_solutions':{},
});
const document=value=>({present:true,value});
let pool,env;

async function resetFixture(){
  await pool.query('DROP SCHEMA IF EXISTS dvaia_qualification CASCADE; DROP SCHEMA IF EXISTS workshop_platform CASCADE; CREATE SCHEMA workshop_platform');
  await pool.query(`CREATE TABLE workshop_platform.exercises(
    workshop_key text PRIMARY KEY,challenge_name text,challenge_description text,category text,difficulty text,route text,
    catalog_active boolean NOT NULL,ordinal integer NOT NULL,is_visible boolean NOT NULL,show_hints boolean NOT NULL,
    show_solutions boolean NOT NULL,updated_by bigint,updated_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE workshop_platform.objectives(
      workshop_key text NOT NULL,objective_id text NOT NULL,label text,category text,hint_content jsonb,solution_content jsonb,
      catalog_active boolean NOT NULL,ordinal integer NOT NULL,is_enabled boolean NOT NULL,hint_enabled boolean NOT NULL,
      solution_enabled boolean NOT NULL,updated_by bigint,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(workshop_key,objective_id));
    CREATE TABLE workshop_platform.catalog_field_defaults(
      entity_kind text NOT NULL,workshop_key text NOT NULL,objective_id text NOT NULL,field_name text NOT NULL,
      provenance_state text NOT NULL,source_version text,source_hash text,source_document jsonb,
      applied_default_version text,applied_default_hash text,applied_default_document jsonb,
      observed_document jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(entity_kind,workshop_key,objective_id,field_name));
    CREATE TABLE workshop_platform.revisions(scope_type text,scope_key text,category text,revision integer,updated_at timestamptz,PRIMARY KEY(scope_type,scope_key,category));
    CREATE TABLE workshop_platform.activity_counters(user_id bigint,workshop_key text,activity_count integer,updated_at timestamptz,PRIMARY KEY(user_id,workshop_key));
    CREATE TABLE workshop_platform.xss_legacy_solution_visibility(challenge_id text PRIMARY KEY,solutions_enabled boolean,enabled_by bigint,enabled_at timestamptz,updated_at timestamptz);
    CREATE TABLE workshop_platform.xss_legacy_solutions(challenge_id text PRIMARY KEY,title text,difficulty text,hints text,examples text,approach text,tips text,updated_at timestamptz);`);
  await pool.query(`INSERT INTO workshop_platform.exercises VALUES
    ('owned','Owned','Instructor description','ai','advanced','/owned',true,1,true,true,false,NULL,'2026-09-19T00:00:00Z')`);
  await pool.query(`INSERT INTO workshop_platform.objectives VALUES
    ('owned','managed','Managed','cat',$1,$2,true,1,true,true,false,NULL,'2026-09-19T00:00:00Z'),
    ('owned','custom','Custom','cat',$3,$4,true,2,true,true,false,NULL,'2026-09-19T00:00:00Z'),
    ('owned','missing','Missing','cat',$5,$6,true,3,true,true,false,NULL,'2026-09-19T00:00:00Z'),
    ('owned','instructor','Instructor','cat',$7,$8,true,4,true,true,false,17,'2026-09-19T00:00:00Z')`,
  [{hints:['old default']},{solution:'managed'},{hints:['instructor']},{solution:'custom'},
    {hints:['legacy']},{solution:'legacy'},{hints:['row owned']},{solution:'row owned'}]);
  await pool.query(`INSERT INTO workshop_platform.revisions VALUES
      ('global','*','workshop_config',8,'2026-09-19T00:00:00Z'),('user','17','workshop_config',3,'2026-09-19T00:00:00Z');
    INSERT INTO workshop_platform.activity_counters VALUES(17,'owned',9,'2026-09-19T00:00:00Z');
    INSERT INTO workshop_platform.xss_legacy_solution_visibility VALUES('reflected',true,17,'2026-09-19T00:00:00Z','2026-09-19T00:00:00Z');
    INSERT INTO workshop_platform.xss_legacy_solutions VALUES('reflected','Edited','hard','[]','[]','custom','[]','2026-09-19T00:00:00Z')`);
  const managed=document({hints:['old default']}),custom=document({hints:['instructor']}),rowOwned=document({hints:['row owned']});
  await pool.query(`INSERT INTO workshop_platform.catalog_field_defaults
    (entity_kind,workshop_key,objective_id,field_name,provenance_state,source_version,source_hash,source_document,
     applied_default_version,applied_default_hash,applied_default_document,observed_document) VALUES
    ('objective','owned','managed','hint_content','managed','v1','old',$1,'v1','old',$1,$1),
    ('objective','owned','custom','hint_content','custom','v1','old',$2,NULL,NULL,NULL,$2),
    ('objective','owned','instructor','hint_content','managed','v1','row',$3,'v1','row',$3,$3)`,
  [managed,custom,rowOwned]);
}
async function backfillMissingProvenance(){
  await pool.query(`INSERT INTO workshop_platform.catalog_field_defaults
      (entity_kind,workshop_key,objective_id,field_name,provenance_state,source_version,source_hash,source_document,observed_document)
    SELECT entity_kind,workshop_key,objective_id,field_name,'legacy_unknown','v2','captured',
      jsonb_build_object('present',true,'value',target_value),jsonb_build_object('present',true,'value',target_value)
    FROM dvaia_qualification.catalog_fields WHERE provenance IS NULL`);
}

test.before(async()=>{
  if(!enabled)return;
  const url=new URL(process.env.BACKUP_PRESERVATION_TEST_URL);
  assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/dvaia_backup_preservation_[a-f0-9]+$/);
  env=helper.connectionEnvironment(url.href);pool=new Pool({connectionString:url.href,max:2});
});
test.after(async()=>{await pool?.end();});

test('actual SQL baseline accepts exact learner preservation and coherent additive defaults',{skip:!enabled},async()=>{
  await resetFixture();await helper.installPreservationBaseline(env,tables);
  await backfillMissingProvenance();
  const next=document({hints:['new default']});
  await pool.query("UPDATE workshop_platform.objectives SET hint_content=$1,updated_at=now() WHERE objective_id='managed'",[{hints:['new default']}]);
  await pool.query(`UPDATE workshop_platform.catalog_field_defaults SET source_version='v2',source_hash='new',source_document=$1,
    applied_default_version='v2',applied_default_hash='new',applied_default_document=$1,observed_document=$1,updated_at=now()
    WHERE objective_id='managed' AND field_name='hint_content'`,[next]);
  await pool.query(`UPDATE workshop_platform.catalog_field_defaults SET source_version='v2',source_hash='new-source',source_document=$1,updated_at=now()
    WHERE objective_id='custom' AND field_name='hint_content'`,[document({hints:['new source ignored']})]);
  await pool.query("UPDATE workshop_platform.catalog_field_defaults SET provenance_state='custom',updated_at=now() WHERE objective_id='instructor' AND field_name='hint_content'");
  await pool.query("UPDATE workshop_platform.revisions SET revision=revision+1,updated_at=now() WHERE scope_type='global' AND scope_key='*' AND category='workshop_config'");
  await pool.query(`INSERT INTO workshop_platform.objectives VALUES
    ('owned','seeded','Seeded','cat',$1,$2,true,5,false,false,false,NULL,now())`,[{hints:['seed']},{solution:'seed'}]);
  const result=await helper.verifyPreservedRows(env);
  assert.equal(result.additions['workshop_platform.objectives'],1);
  assert.deepEqual(result.revisionTransitions,{globalRevisionAdvanced:1,scopedRowsPreserved:1});
  assert.deepEqual(result.catalogTransitions,{
    'preserved-pre-provenance':15,
    'reconciled-managed-default':1,
    'preserved-custom':1,
    'preserved-instructor-row':4,
  });
});

test('actual SQL baseline rejects a stable first-pass instructor clobber',{skip:!enabled},async()=>{
  await resetFixture();await helper.installPreservationBaseline(env,tables);
  await backfillMissingProvenance();
  const clobber={hints:['seed clobber']};
  await pool.query("UPDATE workshop_platform.objectives SET hint_content=$1 WHERE objective_id='custom'",[clobber]);
  await pool.query("UPDATE workshop_platform.catalog_field_defaults SET observed_document=$1 WHERE objective_id='custom' AND field_name='hint_content'",[document(clobber)]);
  await assert.rejects(helper.verifyPreservedRows(env),/Instructor-owned catalog field changed/);
  await pool.query('DROP SCHEMA dvaia_qualification CASCADE');
});

test('actual SQL baseline rejects learner counter mutation',{skip:!enabled},async()=>{
  await resetFixture();await helper.installPreservationBaseline(env,tables);
  await backfillMissingProvenance();
  await pool.query("UPDATE workshop_platform.activity_counters SET activity_count=10 WHERE user_id=17");
  await assert.rejects(helper.verifyPreservedRows(env),/Preexisting rows changed in workshop_platform.activity_counters/);
  await pool.query('DROP SCHEMA dvaia_qualification CASCADE');
});

test('exported snapshot binds dump-side logical reads to one view across a concurrent commit',
  {skip:!enabled},async()=>{
    await pool.query(`DROP SCHEMA IF EXISTS dvaia_qualification CASCADE;
      DROP SCHEMA IF EXISTS workshop_platform CASCADE;
      DROP SCHEMA IF EXISTS dvaia_migrations CASCADE;
      CREATE SCHEMA dvaia_migrations;
      CREATE TABLE dvaia_migrations.ledger(name text PRIMARY KEY,checksum text,applied_at timestamptz);
      INSERT INTO dvaia_migrations.ledger VALUES('0001_fixture.sql','owned',now());
      CREATE SCHEMA workshop_platform;
      CREATE TABLE workshop_platform.snapshot_probe(id integer PRIMARY KEY,value text NOT NULL);
      INSERT INTO workshop_platform.snapshot_probe VALUES(1,'before');`);
    const keeper=await helper.openExportedSnapshot(env);
    try {
      const frozenBefore=await helper.databaseSnapshot(env,{snapshotId:keeper.snapshotId});
      await pool.query("INSERT INTO workshop_platform.snapshot_probe VALUES(2,'concurrent')");
      const frozenAfter=await helper.databaseSnapshot(env,{snapshotId:keeper.snapshotId});
      const current=await helper.databaseSnapshot(env);
      assert.deepEqual(frozenAfter,frozenBefore);
      assert.notDeepEqual(current,frozenBefore);
      assert.equal(frozenBefore.tables['workshop_platform.snapshot_probe'].rows,1);
      assert.equal(current.tables['workshop_platform.snapshot_probe'].rows,2);
    } finally { await keeper.close(); }
  });

test('pre-provenance catalog schema preserves every existing instructor field and detects clobber',
  {skip:!enabled},async()=>{
    const preProvenance={...tables};delete preProvenance['workshop_platform.catalog_field_defaults'];
    await resetFixture();await pool.query('DROP TABLE workshop_platform.catalog_field_defaults');
    await helper.installPreservationBaseline(env,preProvenance);
    const preserved=await helper.verifyPreservedRows(env);
    assert.deepEqual(preserved.catalogTransitions,{'preserved-pre-provenance-schema':21});

    await resetFixture();await pool.query('DROP TABLE workshop_platform.catalog_field_defaults');
    await helper.installPreservationBaseline(env,preProvenance);
    await pool.query("UPDATE workshop_platform.objectives SET solution_content=$1 WHERE objective_id='custom'",
      [{solution:'seed clobber'}]);
    await assert.rejects(helper.verifyPreservedRows(env),/Pre-provenance catalog field changed/);
    await pool.query('DROP SCHEMA dvaia_qualification CASCADE');
  });

test('whole preservation verification supports a non-catalog store with no workshop schema',
  {skip:!enabled},async()=>{
    await pool.query(`DROP SCHEMA IF EXISTS dvaia_qualification CASCADE;
      DROP SCHEMA IF EXISTS workshop_platform CASCADE;
      DROP SCHEMA IF EXISTS aria CASCADE;
      CREATE SCHEMA aria;CREATE TABLE aria.probe(id integer PRIMARY KEY,value text NOT NULL);
      INSERT INTO aria.probe VALUES(1,'preserved');`);
    await helper.installPreservationBaseline(env,{'aria.probe':{}});
    assert.deepEqual(await helper.verifyPreservedRows(env),{
      additions:{},catalogTransitions:{},
      revisionTransitions:{globalRevisionAdvanced:0,scopedRowsPreserved:0},
    });
    assert.equal((await pool.query('SELECT value FROM aria.probe WHERE id=1')).rows[0].value,'preserved');
  });

test('partial historical workshop catalog fails before managed fields can be ignored',
  {skip:!enabled},async()=>{
    await pool.query(`DROP SCHEMA IF EXISTS dvaia_qualification CASCADE;
      DROP SCHEMA IF EXISTS workshop_platform CASCADE;
      CREATE SCHEMA workshop_platform;
      CREATE TABLE workshop_platform.exercises(workshop_key text PRIMARY KEY,challenge_name text,
        challenge_description text,category text,difficulty text,route text,catalog_active boolean,ordinal integer,
        updated_by bigint,updated_at timestamptz);`);
    await assert.rejects(helper.installPreservationBaseline(env,{
      'workshop_platform.exercises':{},
    }),/Partial workshop catalog schema/);
    assert.equal((await pool.query("SELECT to_regnamespace('dvaia_qualification') AS value")).rows[0].value,null);
  });
