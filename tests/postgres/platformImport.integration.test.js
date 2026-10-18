'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {createPool}=require('../../server/database/postgres');const {migrate}=require('../../db/postgres/migrate');
const {COLUMNS}=require('../../db/postgres/map-platform-snapshot');const {applyPlatformSnapshot}=require('../../db/postgres/import-platform-snapshot');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_PLATFORM_IMPORT_TEST_MIGRATION_URL;
function row(table,values){return Object.fromEntries(COLUMNS[table].split(' ').map(key=>[key,Object.hasOwn(values,key)?values[key]:null]));}
function input(){const digest='a'.repeat(64),stamp='2026-01-02T00:00:00.123456Z';const tables=Object.fromEntries(Object.keys(COLUMNS).map(key=>[key,[]]));tables.workshop_objectives_progress=[row('workshop_objectives_progress',{id:5,user_id:7,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',completed:1,completed_at:stamp,created_at:stamp,updated_at:stamp})];tables.workshop_time_tracking=[row('workshop_time_tracking',{id:19,user_id:7,workshop_key:'sql_injection_workshop',session_start:'2026-01-01T00:00:00Z',last_heartbeat:stamp,duration_seconds:123})];return{tables,identityMap:{7:71},archiveDigest:digest,review:{archiveDigest:digest,missingDefaults:{exercises:'catalog_visibility_defaults_without_content',objectiveVisibility:'catalog_visibility_defaults_without_content',hintVisibility:'catalog_visibility_defaults_without_content'},retainedTables:[]}};}
test('platform apply is transaction-bound, historical-only, atomic and empty-target fenced',{skip:!enabled},async()=>{
 const pool=createPool(process.env,'PG_PLATFORM_IMPORT_TEST_MIGRATION_URL');let client;
 try{
  await migrate(pool,path.join(__dirname,'../../db/postgres/identity-migrations'));client=await pool.connect();
  await client.query("INSERT INTO identity.users(id,username,email,password) VALUES(71,'import_fixture','fixture@example.test',$1)",[require('bcryptjs').hashSync('fixture-private-password',4)]);
  await assert.rejects(applyPlatformSnapshot(client,input()),{code:'25P01'});
  await client.query('BEGIN');await client.query('DELETE FROM workshop_platform.config_revision WHERE id=1');await assert.rejects(applyPlatformSnapshot(client,input()),{code:'PLATFORM_IMPORT_REQUIRES_FRESH_REVISION'});await client.query('ROLLBACK');
  await client.query('BEGIN');await client.query('UPDATE workshop_platform.config_revision SET revision=1 WHERE id=1');await assert.rejects(applyPlatformSnapshot(client,input()),{code:'PLATFORM_IMPORT_REQUIRES_FRESH_REVISION'});await client.query('ROLLBACK');
  const exhausted=input();exhausted.tables.workshop_time_tracking[0].id=2147483647;let queried=false;await assert.rejects(applyPlatformSnapshot({query:async()=>{queried=true;}},exhausted),{code:'TIME_TRACKING_SEQUENCE_EXHAUSTED'});assert.equal(queried,false);

  await client.query('BEGIN');await applyPlatformSnapshot(client,input());await client.query('ROLLBACK');assert.equal((await client.query('SELECT count(*)::int AS n FROM workshop_platform.completions')).rows[0].n,0);
  await client.query('BEGIN');const missing=input();missing.identityMap={7:999};await assert.rejects(applyPlatformSnapshot(client,missing),{code:'TARGET_IDENTITY_MISSING'});await client.query('ROLLBACK');
  await client.query('BEGIN');await client.query("INSERT INTO graph_runtime.owners(owner_key) VALUES('old-guest')");await assert.rejects(applyPlatformSnapshot(client,input()),{code:'PLATFORM_IMPORT_REQUIRES_EMPTY_TARGET'});await client.query('ROLLBACK');
  await client.query('BEGIN');const result=await applyPlatformSnapshot(client,input());await client.query('COMMIT');assert.equal(result.provenanceKind,'historical_completion');
  assert.equal((await client.query('SELECT count(*)::int AS n FROM workshop_platform.objectives')).rows[0].n,Object.values(require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES).flat().length);assert.equal((await client.query('SELECT count(*)::int AS n FROM workshop_platform.objective_judgments')).rows[0].n,0);
  const secureShop=(await client.query("SELECT e.is_visible,o.is_enabled,o.hint_enabled,o.solution_enabled FROM workshop_platform.exercises e JOIN workshop_platform.objectives o USING(workshop_key) WHERE e.workshop_key='secureshop_agent_security'")).rows;
  assert.equal(secureShop.length,require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES.secureshop_agent_security.length);assert.ok(secureShop.every(row=>Object.values(row).every(flag=>flag===false)));
  const provenance=(await client.query('SELECT * FROM identity.historical_import_provenance')).rows[0];assert.equal(provenance.historical_user_id,'71');assert.equal(provenance.provenance_kind,'historical_completion');assert.match(provenance.source_row_sha256,/^[a-f0-9]{64}$/);
  assert.equal((await client.query('SELECT started_at FROM workshop_platform.user_state')).rows[0].started_at.toISOString(),'2026-01-01T00:00:00.000Z');
  const next=(await client.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat) VALUES(71,'sql_injection_workshop',now(),now()) RETURNING id")).rows[0].id;assert.equal(next,20);
  await client.query('BEGIN');await client.query('UPDATE workshop_platform.config_revision SET revision=0 WHERE id=1');await assert.rejects(applyPlatformSnapshot(client,input()),{code:'PLATFORM_IMPORT_REQUIRES_EMPTY_TARGET'});await client.query('ROLLBACK');
  await assert.rejects(client.query('DELETE FROM identity.historical_import_provenance'),{code:'55000'});
 }finally{if(client)client.release();await pool.end();}
});
