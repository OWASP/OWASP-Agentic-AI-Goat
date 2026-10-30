'use strict';
// Main-only native helper; importing allocates no database/process resources.
// Caller owns two isolated identity stores, pools, timeout and physical cleanup.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const sourceRoot=path.resolve(__dirname,'../..');
const MIGRATION_NAME='0055_finflow_admin_artifact_defaults.sql';
const MIGRATION_SHA256='56a19e666f359082a89995ef89d943d99b3a99e98330f680e84cc173b5812580';
const migrationDirectory=path.join(sourceRoot,'db/postgres/identity-migrations'),migrationPath=path.join(migrationDirectory,MIGRATION_NAME);
const IDS=['admin_secrets','admin_dirlist'],FIELDS=['solution_content','hint_content'];
const sha=value=>createHash('sha256').update(value).digest('hex');
const before=JSON.parse(fs.readFileSync(path.join(__dirname,'../postgres/fixtures/admin-curriculum-before.json'))),proposed=JSON.parse(fs.readFileSync(path.join(__dirname,'../postgres/fixtures/admin-curriculum-proposed.json')));
function migrationPlan(through){assert(['0047_secureshop_persona_inbox_catalog.sql','0054_finflow_log_policy_defaults.sql',MIGRATION_NAME].includes(through));const names=fs.readdirSync(migrationDirectory).filter(n=>/^\d{4}_[a-z0-9_]+\.sql$/.test(n)&&n<=through).sort();assert.equal(names.at(-1),through);return names.map(name=>{const file=path.join(migrationDirectory,name);assert.equal(fs.realpathSync(file),file);assert(fs.lstatSync(file).isFile());return {name,file,sha256:sha(fs.readFileSync(file))};});}
function createView(root,label,through){assert(['through0047','through0054','through0055','rollback'].includes(label));assert.equal(fs.realpathSync(root),root);const stat=fs.lstatSync(root);assert(stat.isDirectory()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o700);assert(root.startsWith(path.join(sourceRoot,'backups/private-recovery/') ));const target=path.join(root,label);fs.mkdirSync(target,{mode:0o700});for(const row of migrationPlan(through)){assert.equal(sha(fs.readFileSync(row.file)),row.sha256);fs.symlinkSync(row.file,path.join(target,row.name));assert.equal(fs.realpathSync(path.join(target,row.name)),row.file);}return target;}
async function qualify({freshRuntime,freshMigration,populatedRuntime,populatedMigration,viewRoot}){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const identities=[];for(const [runtime,migration]of [[freshRuntime,freshMigration],[populatedRuntime,populatedMigration]]){const r=(await runtime.query('SELECT current_user role,current_database() database')).rows[0],m=(await migration.query('SELECT current_user role,current_database() database')).rows[0];assert.equal(r.role,'dvaia_identity_runtime');assert.equal(m.role,'dvaia_identity_migration');assert.equal(r.database,m.database);assert.match(r.database,/^owasp_ai_goat_test_finflow_0055_[a-f0-9]{12}_(fresh|populated)$/);identities.push(r.database);}assert.notEqual(identities[0],identities[1]);assert(identities[0].endsWith('_fresh'));assert.equal(identities[1],identities[0].replace(/_fresh$/,'_populated'));
 const migrationSql=fs.readFileSync(migrationPath,'utf8');assert.equal(sha(migrationSql),MIGRATION_SHA256);
    const migrateApi = require(path.join(sourceRoot, 'db/postgres/migrate'));
    const identityApi = require(path.join(sourceRoot,
      'server/database/postgres/identityRepository'));
    const seedApi = require(path.join(sourceRoot,
      'server/database/postgres/workshopPlatformSeed'));
    const bcrypt = require(path.join(sourceRoot, 'node_modules/bcryptjs'));

    assert.equal(fs.realpathSync(migrationPath), migrationPath,
      '0055 must be registered in the canonical identity migration directory');
    assert.equal(sha(migrationSql), MIGRATION_SHA256);
    // Fresh: the real loader records 0055 before the seed inserts the catalog.
    await identityApi.initializeIdentityRepository(freshRuntime, freshMigration);
    await seedApi.seedWorkshopPlatform(freshMigration, seedInputs(seedApi, proposed));
    assert.equal((await freshMigration.query(`SELECT count(*)::integer AS count
      FROM dvaia_migrations.ledger WHERE name=$1`, [MIGRATION_NAME])).rows[0].count, 1);
    for (const id of IDS) {
      const row = await objective(freshRuntime, id);
      assert.deepEqual(row.solution_content, proposed[id].solution);
      assert.deepEqual(row.hint_content, proposed[id].hint);
    }
    assert.deepEqual((await provenance(freshRuntime)).map(row => row.provenance_state),
      ['managed', 'managed', 'managed', 'managed']);

    // Populated: establish the actual chronology. Objectives exist before 0048,
    // so 0048 records their fields as legacy_unknown rather than managed.
    const through0047=createView(viewRoot,'through0047','0047_secureshop_persona_inbox_catalog.sql');
    const through0054=createView(viewRoot,'through0054','0054_finflow_log_policy_defaults.sql');
    const through0055=createView(viewRoot,'through0055',MIGRATION_NAME);
    await migrateApi.migrate(populatedMigration, through0047);
    await populatedMigration.query(`INSERT INTO workshop_platform.exercises
      (workshop_key,challenge_key,challenge_name,challenge_description,category,difficulty,route,ordinal)
      VALUES('sensitive_info_disclosure','sensitive-info','Sensitive Information Disclosure',
        'legacy fixture','ai','intermediate','/workshop/sensitive-info',0)`);
    for (const [ordinal, id] of IDS.entries()) {
      await populatedMigration.query(`INSERT INTO workshop_platform.objectives
        (workshop_key,objective_id,label,category,ordinal,hint_content,solution_content)
        VALUES('sensitive_info_disclosure',$1,$2,'admin',$3,$4::jsonb,$5::jsonb)`,
      [id, `Legacy ${id}`, ordinal, JSON.stringify(before[id].hint),
        JSON.stringify(before[id].solution)]);
    }
    await migrateApi.migrate(populatedMigration, through0054);
    assert.deepEqual((await provenance(populatedRuntime)).map(row => row.provenance_state),
      ['legacy_unknown', 'legacy_unknown', 'legacy_unknown', 'legacy_unknown']);
    await seedApi.seedWorkshopPlatform(populatedMigration, seedInputs(seedApi, before));
    assert.deepEqual((await provenance(populatedRuntime)).map(row => row.provenance_state),
      ['legacy_unknown', 'legacy_unknown', 'legacy_unknown', 'legacy_unknown']);

    const passwordHash = await bcrypt.hash('0055-private-fixture', 4);
    const userId = (await populatedMigration.query(`INSERT INTO identity.users
      (username,email,password) VALUES('finflow-admin-0055-fixture',
      'finflow-admin-0055-fixture@fixture.invalid',$1) RETURNING id`, [passwordHash])).rows[0].id;
    const siblingId=(await populatedMigration.query("INSERT INTO identity.users(username,email,password) VALUES('finflow-0055-sibling','finflow-0055-sibling@fixture.invalid',$1) RETURNING id",[passwordHash])).rows[0].id;
    await populatedMigration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'sensitive_info_disclosure','admin_dirlist')",[siblingId]);
    const siblingBefore=await progress(populatedRuntime,siblingId);
    const siblingOwner=JSON.stringify(['FinFlow',String(siblingId)]),siblingRun=require('node:crypto').randomUUID();
    await populatedMigration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[siblingOwner]);
    await populatedMigration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,provider,model,decision_source,last_node,finished_at) VALUES($1,$2,0,'completed','controlled-projection','none','controlled-projection','respond',now())",[siblingRun,siblingOwner]);
    await populatedMigration.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,1,'respond','node_end','{}'::jsonb)",[siblingRun,siblingOwner]);
    const siblingEvidence=async()=>({runs:(await populatedMigration.query('SELECT to_jsonb(r) row FROM graph_runtime.runs r WHERE run_id=$1',[siblingRun])).rows,events:(await populatedMigration.query('SELECT to_jsonb(e) row FROM graph_runtime.events e WHERE run_id=$1 ORDER BY sequence',[siblingRun])).rows});const siblingEvidenceBefore=await siblingEvidence();
    await populatedMigration.query(`INSERT INTO workshop_platform.user_state
      (user_id,workshop_key,generation,started_at)
      VALUES($1,'sensitive_info_disclosure',7,'2026-09-14T12:00:00Z')`, [userId]);
    await populatedMigration.query(`INSERT INTO workshop_platform.completions
      (user_id,workshop_key,objective_id,completed_at,updated_at)
      VALUES($1,'sensitive_info_disclosure','admin_secrets','2026-09-14T12:01:00Z',
      '2026-09-14T12:02:00Z')`, [userId]);
    await populatedMigration.query(`INSERT INTO workshop_platform.time_tracking
      (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
      VALUES($1,'sensitive_info_disclosure','2026-09-14T12:00:00Z',
      '2026-09-14T12:03:00Z',180)`, [userId]);

    const customHint = { title: 'Instructor hint', hints: ['Keep exactly.'] };
    await populatedMigration.query(`UPDATE workshop_platform.objectives SET
      solution_content=$1::jsonb,hint_content=$2::jsonb,is_enabled=false,
      catalog_active=true,hint_enabled=true,solution_enabled=false,updated_by=$3
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_secrets'`,
    [JSON.stringify(before.admin_secrets.solution), JSON.stringify(customHint), userId]);
    await populatedMigration.query(`UPDATE workshop_platform.objectives SET
      solution_content=NULL,hint_content=$1::jsonb,is_enabled=true,
      catalog_active=true,hint_enabled=false,solution_enabled=true,updated_by=$2
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_dirlist'`,
    [JSON.stringify(before.admin_dirlist.hint), userId]);
    const rowsBefore = await Promise.all(IDS.map(id => objective(populatedRuntime, id)));
    const progressBefore = await progress(populatedRuntime, userId);
    const revisionBefore = await revision(populatedRuntime);

    const applied = await migrateApi.migrate(populatedMigration,through0055);
    assert.deepEqual(applied, [MIGRATION_NAME]);
    const rowsAfter = await Promise.all(IDS.map(id => objective(populatedRuntime, id)));
    assert.deepEqual(rowsAfter[0].solution_content, proposed.admin_secrets.solution);
    assert.deepEqual(rowsAfter[0].hint_content, customHint);
    assert.equal(rowsAfter[1].solution_content, null);
    assert.deepEqual(rowsAfter[1].hint_content, proposed.admin_dirlist.hint);
    assert.deepEqual(rowsAfter.map(stableProperties), rowsBefore.map(stableProperties),
      '0055 preserves toggles, updated_by, labels, category, ordinal and catalog state');
    assert.deepEqual(await progress(populatedRuntime, userId), progressBefore,
      '0055 preserves learner progress and time');
    assert.equal(await revision(populatedRuntime), revisionBefore + 1);

    const revisionAfterMigration = await revision(populatedRuntime);
    await seedApi.seedWorkshopPlatform(populatedMigration, seedInputs(seedApi, proposed));
    const afterSeed = await Promise.all(IDS.map(id => objective(populatedRuntime, id)));
    assert.deepEqual(afterSeed.map(stableProperties), rowsAfter.map(stableProperties));
    assert.deepEqual(afterSeed.map(row => row.solution_content),
      [proposed.admin_secrets.solution, null]);
    assert.deepEqual(afterSeed.map(row => row.hint_content),
      [customHint, proposed.admin_dirlist.hint]);
    assert.deepEqual(await progress(populatedRuntime, userId), progressBefore);
    assert.equal(await revision(populatedRuntime), revisionAfterMigration,
      'legacy_unknown reconciliation metadata does not bump catalog revision');
    const afterSeedProvenance = await provenance(populatedRuntime);
    for (const row of afterSeedProvenance) {
      assert.equal(row.provenance_state, 'legacy_unknown');
      assert.equal(row.applied_default_version, null);
      assert.equal(row.applied_default_hash, null);
      assert.equal(row.applied_default_document, null);
      assert.deepEqual(row.source_document,
        { present: true, value: snapshotContent(proposed, row.objective_id, row.field_name) });
      const actual = afterSeed.find(item => item.objective_id === row.objective_id)[row.field_name];
      assert.deepEqual(row.observed_document, { present: true, value: actual });
    }

    // Exercise every accepted legacy field independently. Its sibling field is
    // custom or NULL, so broad row replacement would fail these checks.
    const client = await populatedMigration.connect();
    try {
      for (const [index, id] of IDS.entries()) {
        for (const field of FIELDS) {
          const sibling = field === 'solution_content' ? 'hint_content' : 'solution_content';
          const siblingValue = index === 0 ? { fixture: `${id}-${sibling}` } : null;
          const rollbackBefore=await objective(populatedRuntime,id),rollbackRevision=await revision(populatedRuntime);
          await client.query('BEGIN');
          await client.query(`UPDATE workshop_platform.objectives SET ${field}=$1::jsonb,
            ${sibling}=$2::jsonb WHERE workshop_key='sensitive_info_disclosure' AND objective_id=$3`,
          [JSON.stringify(snapshotContent(before, id, field)),
            siblingValue === null ? null : JSON.stringify(siblingValue), id]);
          const beforeFieldRevision = Number((await client.query(
            'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
          await client.query(migrationSql);
          const row = (await client.query(`SELECT ${field} AS changed,${sibling} AS sibling
            FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure'
            AND objective_id=$1`, [id])).rows[0];
          assert.deepEqual(row.changed, snapshotContent(proposed, id, field), `${id}.${field}`);
          assert.deepEqual(row.sibling, siblingValue, `${id}.${sibling} preserved`);
          assert.equal(Number((await client.query(
            'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision),
          beforeFieldRevision + 1);
          await client.query('ROLLBACK');
          assert.deepEqual(await objective(populatedRuntime,id),rollbackBefore);assert.equal(await revision(populatedRuntime),rollbackRevision);
        }
      }
    } finally {
      try{await client.query('ROLLBACK');}finally{client.release();}
    }

    const seedNoopBefore={rows:await Promise.all(IDS.map(id=>objective(populatedRuntime,id))),provenance:await provenance(populatedRuntime),revision:await revision(populatedRuntime),progress:await progress(populatedRuntime,userId)};
    await seedApi.seedWorkshopPlatform(populatedMigration,seedInputs(seedApi,proposed));
    assert.deepEqual({rows:await Promise.all(IDS.map(id=>objective(populatedRuntime,id))),provenance:await provenance(populatedRuntime),revision:await revision(populatedRuntime),progress:await progress(populatedRuntime,userId)},seedNoopBefore);
    const replayRows = await Promise.all(IDS.map(id => objective(populatedRuntime, id)));
    const replayProgress = await progress(populatedRuntime, userId);
    const replayProvenance = await provenance(populatedRuntime);
    const replayLedger = (await populatedMigration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    const replayRevision = await revision(populatedRuntime);
    assert.deepEqual(await migrateApi.migrate(populatedMigration,through0055), []);
    assert.deepEqual(await Promise.all(IDS.map(id => objective(populatedRuntime, id))), replayRows);
    assert.deepEqual(await progress(populatedRuntime, userId), replayProgress);
    assert.deepEqual(await provenance(populatedRuntime), replayProvenance);
    assert.deepEqual((await populatedMigration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, replayLedger);
    assert.equal(await revision(populatedRuntime), replayRevision);

    // A deliberately failing next loader entry proves migration content,
    // revision and ledger insertion share one transaction.
    const failing=createView(viewRoot,'rollback',MIGRATION_NAME);
    const failureName = '0056_qualification_failure.sql';
    fs.writeFileSync(path.join(failing, failureName), `${migrationSql}\nDO $$
      BEGIN RAISE EXCEPTION 'owned 0055 qualification rollback'; END $$;\n`,{mode:0o600,flag:'wx'});
    await populatedMigration.query(`UPDATE workshop_platform.objectives SET solution_content=$1::jsonb
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_secrets'`,
    [JSON.stringify(before.admin_secrets.solution)]);
    const failureRow = await objective(populatedRuntime, 'admin_secrets');
    const failureProgress = await progress(populatedRuntime, userId);
    const failureRevision = await revision(populatedRuntime);
    await assert.rejects(migrateApi.migrate(populatedMigration, failing),
      /owned 0055 qualification rollback/);
    assert.deepEqual(await objective(populatedRuntime, 'admin_secrets'), failureRow);
    assert.deepEqual(await progress(populatedRuntime, userId), failureProgress);
    assert.equal(await revision(populatedRuntime), failureRevision);
    assert.equal((await populatedMigration.query(`SELECT count(*)::integer AS count
      FROM dvaia_migrations.ledger WHERE name=$1`, [failureName])).rows[0].count, 0);
    assert.deepEqual(await progress(populatedRuntime,siblingId),siblingBefore);assert.deepEqual(await siblingEvidence(),siblingEvidenceBefore);
    return {freshManagedFields:4,populatedLegacyUnknownFields:4,customHintPreserved:true,nullSolutionPreserved:true,fieldRollbackCases:4,secondMigrationNoop:true,siblingPreserved:true,failedLoaderRollback:true,scope:'0055 historical-default qualification; no actor/Judge proof'};
}
function snapshotContent(collection, id, field) {
  return collection[id][field === 'solution_content' ? 'solution' : 'hint'];
}
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function seedInputs(seedApi, values) {
  const hints = clone(require(path.join(sourceRoot, 'server/data/workshopHints')));
  const solutions = clone(seedApi.solutionFixtures());
  for (const id of IDS) {
    hints.sensitive_info_disclosure[id] = clone(values[id].hint);
    solutions.sensitive_info_disclosure[id] = clone(values[id].solution);
  }
  return { hints, solutions };
}
async function objective(poolValue, id) {
  return (await poolValue.query(`SELECT workshop_key,objective_id,label,category,ordinal,
    is_enabled,catalog_active,hint_enabled,solution_enabled,hint_content,solution_content,
    updated_by,updated_at FROM workshop_platform.objectives
    WHERE workshop_key='sensitive_info_disclosure' AND objective_id=$1`, [id])).rows[0];
}
function stableProperties(row) {
  const value = { ...row };
  delete value.solution_content;
  delete value.hint_content;
  delete value.updated_at;
  return value;
}
async function revision(poolValue) {
  return Number((await poolValue.query(
    'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
}
async function provenance(poolValue) {
  return (await poolValue.query(`SELECT objective_id,field_name,provenance_state,
    source_version,source_document,applied_default_version,applied_default_hash,
    applied_default_document,observed_document
    FROM workshop_platform.catalog_field_defaults
    WHERE entity_kind='objective' AND workshop_key='sensitive_info_disclosure'
      AND objective_id=ANY($1::text[]) AND field_name=ANY($2::text[])
    ORDER BY objective_id,field_name`, [IDS, FIELDS])).rows;
}
async function progress(poolValue, userId) {
  const state = (await poolValue.query(`SELECT user_id,workshop_key,generation,started_at,updated_at
    FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`,
  [userId])).rows;
  const completions = (await poolValue.query(`SELECT user_id,workshop_key,objective_id,completed_at,updated_at
    FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'
    ORDER BY objective_id`, [userId])).rows;
  const time = (await poolValue.query(`SELECT id,user_id,workshop_key,session_start,last_heartbeat,
    duration_seconds FROM workshop_platform.time_tracking WHERE user_id=$1
    AND workshop_key='sensitive_info_disclosure' ORDER BY id`, [userId])).rows;
  return { state, completions, time };
}


module.exports={qualify,migrationPlan,MIGRATION_SHA256};
