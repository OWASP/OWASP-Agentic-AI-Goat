'use strict';
const{test}=require('node:test'),assert=require('node:assert/strict');
const{createPool}=require('../../server/database/postgres');
const{initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const{COLUMNS,mapPlatformSnapshot}=require('../../db/postgres/map-platform-snapshot');
const{importPlatformIdentity}=require('../../db/postgres/import-platform-identity');
const{normalizeArchiveOwnerBinding,verifyArchiveOwnerBinding,assertVerifiedArchiveOwnerBinding}=require('../../db/postgres/archive-owner-binding');
const { FAMILIES } = require('../../db/postgres/map-platform-solutions');
const { fixture, legacyXssContent, legacyXssVisibility } = require('../fixtures/platformAdditionalSolutions');
function solutionsFixture() {
  const tables = {};
  for (const config of Object.values(FAMILIES)) {
    tables[config.contentTable] = config.objectiveIds.map((id, index) => ({
      ...(config.contentHasId ? { id: index + 1 } : {}), [config.idColumn]: id,
      title: `Edited ${id}`, difficulty: 'Intermediate', hints: '["preserved solution hint"]',
      examples: '[{"prompt":"example","explanation":"why"}]', approach: 'Instructor edited approach', tips: '[]',
      ...(config.contentHasTimestamp ? { updated_at: '2026-01-01 00:00:00' } : {}),
    }));
    tables[config.visibilityTable] = config.objectiveIds.map((id, index) => ({
      ...(config.visibilityHasId ? { id: index + 1 } : {}), [config.idColumn]: id,
      solutions_enabled: index % 2, updated_at: '2026-01-01 00:00:00',
      ...(config.visibilityTracksActor ? { enabled_by: null, enabled_at: null } : {}),
    }));
  }
  return { sources: { 'users_auth.db': { tables } }, archiveDigest: 'b'.repeat(64) };
}

const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_PLATFORM_IDENTITY_TEST_RUNTIME_URL;
const row=(table,values)=>Object.fromEntries(COLUMNS[table].split(' ').map(k=>[k,values[k]??null]));
function input(password){
 const stamp='2026-01-02T00:00:00.123456Z',tables=Object.fromEntries(Object.keys(COLUMNS).map(k=>[k,[]]));
 tables.workshop_objectives_progress=[row('workshop_objectives_progress',{id:5,user_id:7,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',completed:1,completed_at:stamp,created_at:stamp,updated_at:stamp})];
 tables.workshop_time_tracking=[row('workshop_time_tracking',{id:19,user_id:7,workshop_key:'sql_injection_workshop',session_start:stamp,last_heartbeat:stamp,duration_seconds:123})];
 tables.workshop_user_modes=[row('workshop_user_modes',{user_id:7,workshop_key:'sql_injection_workshop',mode:'vuln',created_at:stamp,updated_at:stamp})];
 tables.workshop_hints=[row('workshop_hints',{id:1,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',title:'Preserved hint',hints:JSON.stringify(['First hint'])})];
 const platform={tables,identityMap:{7:71},archiveDigest:'c'.repeat(64)};
 const mapped=mapPlatformSnapshot(platform);platform.review={archiveDigest:platform.archiveDigest,missingDefaults:Object.fromEntries(Object.entries(mapped.report.missingCatalogRows).filter(([,v])=>v.length).map(([k])=>[k,'catalog_visibility_defaults_without_content'])),retainedTables:mapped.report.unmappedTables.map(r=>r.table)};
 return{identity:{users:[{id:71,username:'preserved-admin',email:'preserved@example.invalid',password,role:'admin',admin_level:1,created_at:stamp}],permissions:[{id:1,admin_id:71,permission_name:'user_management',granted_at:stamp}]},platform};
}
test('combined import checks constraints atomically and preserves historical platform state',{skip:!enabled},async()=>{
 for(const key of ['PG_PLATFORM_IDENTITY_TEST_RUNTIME_URL','PG_PLATFORM_IDENTITY_TEST_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);
 const runtime=createPool(process.env,'PG_PLATFORM_IDENTITY_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_PLATFORM_IDENTITY_TEST_MIGRATION_URL');
 try{
  await initializeIdentityRepository(runtime,migration);const password=await require('bcryptjs').hash('fixture-only',4),data=input(password);data.solutions=solutionsFixture();data.solutions.archiveDigest=data.platform.archiveDigest;
  data.identityAuxiliary=require('../fixtures/identityAuxiliaryImport').fixture(data.platform.archiveDigest);
  data.additionalSolutions=fixture();Object.assign(data.additionalSolutions,{archiveDigest:data.platform.archiveDigest,identityMap:{7:71},naiveTimestamps:'UTC'});
  const additionalTables=data.additionalSolutions.sources['users_auth.db'].tables;
  const legacyKeys=['reflected','stored_user','stored_llm','email'];
  additionalTables.xss_workshop_solutions=legacyKeys.map((key,index)=>({...legacyXssContent(key),id:900+index}));
  additionalTables.xss_workshop_solution_visibility=legacyKeys.map((key,index)=>({...legacyXssVisibility(key),id:910+index,enabled_by:7}));
  additionalTables.xss_workshop_solutions[0].hints='Instructor raw legacy hint';
  const snapshot=async()=>({counts:(await runtime.query('SELECT (SELECT count(*) FROM identity.import_batches)::int AS batches,(SELECT count(*) FROM identity.archive_owner_bindings)::int AS owner_bindings,(SELECT count(*) FROM identity.users)::int AS users,(SELECT count(*) FROM workshop_platform.objectives)::int AS objectives,(SELECT count(*) FROM workshop_platform.completions)::int AS completions,(SELECT count(*) FROM identity.historical_import_provenance)::int AS provenance,(SELECT revision FROM workshop_platform.config_revision WHERE id=1) AS revision')).rows[0],sequence:(await migration.query('SELECT last_value,is_called FROM identity.users_id_seq')).rows[0],timeSequence:(await migration.query('SELECT last_value,is_called FROM workshop_platform.time_tracking_id_seq')).rows[0],objectives:(await runtime.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows});
  const legacySnapshot=async()=>({content:(await runtime.query('SELECT * FROM workshop_platform.xss_legacy_solutions ORDER BY challenge_id')).rows,visibility:(await runtime.query('SELECT * FROM workshop_platform.xss_legacy_solution_visibility ORDER BY challenge_id')).rows});
  const auxiliarySnapshot=async()=>Object.fromEntries(await Promise.all(['email_verification_tokens','email_agent_progress','sent_emails_log','system_config'].map(async table=>[table,(await migration.query(`SELECT * FROM identity.${table} ORDER BY 1`)).rows])));
  const beforeAuxiliary=await auxiliarySnapshot();
  const beforeLegacy=await legacySnapshot();
  const before=await snapshot();assert.equal((await importPlatformIdentity(migration,data)).dryRun,true);assert.deepEqual(await snapshot(),before);assert.deepEqual(await legacySnapshot(),beforeLegacy);assert.deepEqual(await auxiliarySnapshot(),beforeAuxiliary);
  const wrongAuxiliary=structuredClone(data);wrongAuxiliary.identityAuxiliary.identityUserIds.push(99);await assert.rejects(importPlatformIdentity(migration,wrongAuxiliary),/exactly match/);
  const noAdmin=structuredClone(data);noAdmin.identity.permissions=[];await assert.rejects(importPlatformIdentity(migration,noAdmin),/administrator/);
  const wrongActor=structuredClone(data);wrongActor.additionalSolutions.identityMap[7]=72;await assert.rejects(importPlatformIdentity(migration,wrongActor),/mapping/);
  const missing=structuredClone(data);missing.platform.identityMap={7:72};await assert.rejects(importPlatformIdentity(migration,missing),/mapping/);
  await migration.query("UPDATE identity.system_config SET config_value='false' WHERE config_key='allow_registration'");await assert.rejects(importPlatformIdentity(migration,data),/configuration/);await migration.query("UPDATE identity.system_config SET config_value='true' WHERE config_key='allow_registration'");
  await migration.query("CREATE FUNCTION workshop_platform.fail_combined_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'late platform fixture failure'; END $$");await migration.query('CREATE TRIGGER fail_combined_fixture BEFORE INSERT ON workshop_platform.completions FOR EACH ROW EXECUTE FUNCTION workshop_platform.fail_combined_fixture()');
  await assert.rejects(importPlatformIdentity(migration,data,{dryRun:false}),/late platform fixture failure/);assert.deepEqual(await snapshot(),before);assert.deepEqual(await legacySnapshot(),beforeLegacy);assert.deepEqual(await auxiliarySnapshot(),beforeAuxiliary);await migration.query('DROP TRIGGER fail_combined_fixture ON workshop_platform.completions');await migration.query('DROP FUNCTION workshop_platform.fail_combined_fixture()');
  await migration.query("CREATE FUNCTION identity.fail_batch_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (SELECT count(*) FROM workshop_platform.objectives WHERE solution_content->>'approach'='Instructor edited approach')<>52 OR (SELECT count(*) FROM identity.users)<>1 OR (SELECT count(*) FROM workshop_platform.xss_legacy_solutions)<>4 OR (SELECT count(*) FROM workshop_platform.objectives WHERE solution_content IS NOT NULL)<>100 THEN RAISE EXCEPTION 'prior writes missing'; END IF; RAISE EXCEPTION 'late batch fixture failure'; END $$");
  await migration.query('CREATE TRIGGER fail_batch_fixture BEFORE INSERT ON identity.import_batches FOR EACH ROW EXECUTE FUNCTION identity.fail_batch_fixture()');
  await assert.rejects(importPlatformIdentity(migration,data,{dryRun:false}),/late batch fixture failure/);assert.deepEqual(await snapshot(),before);assert.deepEqual(await legacySnapshot(),beforeLegacy);assert.deepEqual(await auxiliarySnapshot(),beforeAuxiliary);
  await migration.query('DROP TRIGGER fail_batch_fixture ON identity.import_batches');await migration.query('DROP FUNCTION identity.fail_batch_fixture()');
  const report=await importPlatformIdentity(migration,data,{dryRun:false});assert.equal(report.applied,true);assert.equal(report.solutions.counts.solutions,52);assert.equal(report.additionalSolutions.counts.solutions,48);
  assert.equal(report.identityAuxiliary.counts.email_verification_tokens,1);
  const auxiliaryRows=await auxiliarySnapshot();
  assert.equal(auxiliaryRows.email_agent_progress[0].user_email,'private-email@example.test');
  assert.equal(auxiliaryRows.email_verification_tokens[0].token_hash,require('node:crypto').createHash('sha256').update('private-verification-fixture').digest('hex'));
  assert.equal(auxiliaryRows.system_config[0].config_value,'false');
  const importedLegacy=await legacySnapshot();assert.equal(importedLegacy.content.length,4);assert.equal(importedLegacy.visibility.length,4);
  assert.equal(importedLegacy.content.find(row=>row.challenge_id==='reflected').hints,'Instructor raw legacy hint');assert.ok(importedLegacy.visibility.every(row=>row.enabled_by===71));
  const batches=(await runtime.query('SELECT * FROM identity.import_batches')).rows;assert.equal(batches.length,1);assert.equal(batches[0].plan_sha256,report.planSha256);assert.equal(batches[0].archive_sha256,report.archiveDigest);
  const expectedBinding=normalizeArchiveOwnerBinding({archiveDigest:data.platform.archiveDigest,identityMap:data.platform.identityMap});
  assert.equal(report.identityMapSha256,expectedBinding.identityMapSha256);
  const storedBinding=(await runtime.query('SELECT archive_sha256,identity_map_sha256,identity_map FROM identity.archive_owner_bindings')).rows;
  assert.deepEqual(storedBinding,[{archive_sha256:expectedBinding.archiveDigest,identity_map_sha256:expectedBinding.identityMapSha256,identity_map:{'7':71}}]);
  const ownerProof=await verifyArchiveOwnerBinding(runtime,expectedBinding);
  assert.equal(assertVerifiedArchiveOwnerBinding(ownerProof,expectedBinding).identityMap['7'],71);
  await assert.rejects(runtime.query("UPDATE identity.archive_owner_bindings SET identity_map='{}'"),{code:'42501'});
  await assert.rejects(migration.query('DELETE FROM identity.archive_owner_bindings'),{code:'55000'});
  for(const privateValue of [password,'preserved-admin','preserved@example.invalid','Instructor edited approach','First hint','Instructor raw legacy hint','Legacy tab content','private-verification-fixture','private-email@example.test','private subject','private configuration'])assert.equal(JSON.stringify(batches).includes(privateValue),false);
  for(const objective of (await snapshot()).objectives){const family=FAMILIES[objective.workshop_key],index=family?.objectiveIds.indexOf(objective.objective_id)??-1;if(index>=0){assert.equal(objective.solution_enabled,index%2===1);assert.equal(objective.solution_content.approach,'Instructor edited approach');assert.deepEqual(objective.solution_content.hints,['preserved solution hint']);}}

  assert.equal((await snapshot()).counts.objectives,Object.values(require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES).flat().length);assert.equal((await snapshot()).counts.provenance,1);
  assert.equal((await runtime.query('SELECT password FROM identity.users WHERE id=71')).rows[0].password,password);
  assert.equal((await runtime.query("SELECT to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US') AS stamp FROM workshop_platform.completions")).rows[0].stamp,'2026-01-02 00:00:00.123456');
  assert.equal((await runtime.query('SELECT mode FROM workshop_platform.user_modes')).rows[0].mode,'vuln');assert.equal((await runtime.query('SELECT duration_seconds FROM workshop_platform.time_tracking')).rows[0].duration_seconds,123);
  const hints=(await runtime.query("SELECT hint_content FROM workshop_platform.objectives WHERE workshop_key='sql_injection_workshop' AND objective_id='sqli_1'")).rows[0].hint_content;assert.equal(hints.title,'Preserved hint');
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
  assert.deepEqual((await runtime.query("SELECT hint_content FROM workshop_platform.objectives WHERE workshop_key='sql_injection_workshop' AND objective_id='sqli_1'")).rows[0].hint_content,hints);assert.equal((await snapshot()).counts.completions,1);assert.deepEqual(await legacySnapshot(),importedLegacy);
 }finally{await Promise.all([runtime.end(),migration.end()]);}
});
