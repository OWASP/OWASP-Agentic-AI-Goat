'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),crypto=require('node:crypto');
const {Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
const {input,review}=require('../fixtures/legacyChallengeArchive');
const {importLegacyChallengeArchive}=require('../../db/postgres/import-legacy-challenge-archive');
const {createLegacyChallengeDb}=require('../../server/database/postgres/legacyChallengeDb');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_LEGACY_CHALLENGE_IMPORT_ADMIN_URL;
async function fixture(fn){
 const url=new URL(process.env.PG_LEGACY_CHALLENGE_IMPORT_ADMIN_URL);
 assert.ok(['postgres:','postgresql:'].includes(url.protocol));assert.ok(['127.0.0.1','localhost','[::1]'].includes(url.hostname));assert.equal(url.pathname,'/postgres');assert.equal(url.search,'');assert.equal(url.hash,'');
 const admin=new Pool({connectionString:url.href,max:1}),name=`owasp_ai_goat_test_legacy_import_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
 let migration,runtime;
 try{
  await admin.query(`CREATE DATABASE ${name} OWNER dvaia_legacy_challenge_migration`);
  await admin.query(`REVOKE ALL ON DATABASE ${name} FROM PUBLIC`);
  await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_legacy_challenge_runtime`);
  function connection(role){const u=new URL(url);u.pathname=`/${name}`;u.username=role;u.password='';return new Pool({connectionString:u.href,max:2});}
  migration=connection('dvaia_legacy_challenge_migration');runtime=connection('dvaia_legacy_challenge_runtime');
  await migrate(migration,path.join(__dirname,'../../db/postgres/workshop-migrations/legacy_challenge'));
  await fn(migration,runtime);
 }finally{
  await Promise.all([migration?.end(),runtime?.end()]);
  await admin.query(`DROP DATABASE IF EXISTS ${name}`);await admin.end();
 }
}
test('native legacy import validates dryrun, rolls back late failure, preserves raw state and immutable provenance',{skip:!enabled},async()=>fixture(async(migration,runtime)=>{
 const raw=input();
 const state=async()=>({users:(await runtime.query('SELECT * FROM legacy_challenge.users')).rows,seq:(await migration.query('SELECT last_value,is_called FROM legacy_challenge.users_id_seq')).rows});
 const before=await state();assert.equal((await importLegacyChallengeArchive(migration,raw)).applied,false);assert.deepEqual(await state(),before);
 assert.equal((await migration.query('SELECT count(*)::int n FROM legacy_challenge.import_batches')).rows[0].n,0);
 await migration.query("CREATE FUNCTION legacy_challenge.reject_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'late fixture failure'; END $$");
 await migration.query('CREATE TRIGGER reject_fixture BEFORE INSERT ON legacy_challenge.import_batches FOR EACH ROW EXECUTE FUNCTION legacy_challenge.reject_fixture()');
 await assert.rejects(importLegacyChallengeArchive(migration,raw,{apply:true}),/late fixture failure/);assert.deepEqual(await state(),before);
 await migration.query('DROP TRIGGER reject_fixture ON legacy_challenge.import_batches');
 const invalid=input();invalid.tables.users.push({...invalid.tables.users[0],id:42,email:'other@example.invalid'});
 await assert.rejects(importLegacyChallengeArchive(migration,invalid),{code:'23505'});assert.deepEqual(await state(),before);
 const report=await importLegacyChallengeArchive(migration,raw,{apply:true});assert.equal(report.provenanceRows,10);
 assert.equal((await migration.query('SELECT count(*)::int n FROM legacy_challenge.ai_conversations')).rows[0].n,raw.tables.ai_conversations.length);
 await assert.rejects(runtime.query('SELECT * FROM legacy_challenge.ai_conversations'),{code:'42501'});
 assert.equal((await runtime.query('SELECT content FROM legacy_challenge.comments WHERE id=11')).rows[0].content,raw.tables.comments[0].content);
 assert.equal((await runtime.query("SELECT to_char(created_at,'YYYY-MM-DD HH24:MI:SS.US') stamp FROM legacy_challenge.users WHERE id=41")).rows[0].stamp,'2025-01-02 03:04:05.123456');
 assert.equal((await runtime.query('SELECT file_path FROM legacy_challenge.files')).rows[0].file_path,raw.tables.files[0].file_path);
 assert.equal((await runtime.query('SELECT user_id FROM legacy_challenge.orders')).rows[0].user_id,41);
 assert.equal((await runtime.query("INSERT INTO legacy_challenge.users(username,email,password) VALUES('next','next@example.invalid','fixture') RETURNING id")).rows[0].id,42);
 await assert.rejects(migration.query('DELETE FROM legacy_challenge.import_batches'),{code:'55000'});
 await assert.rejects(runtime.query('SELECT * FROM legacy_challenge.import_provenance'),{code:'42501'});
 await assert.rejects(importLegacyChallengeArchive(migration,raw,{apply:true}),{code:'LEGACY_CHALLENGE_IMPORT_REQUIRES_EMPTY_TARGET'});
 await createLegacyChallengeDb(runtime).initializeLegacyChallengeDb(migration);
 assert.equal((await runtime.query('SELECT count(*)::int n FROM legacy_challenge.products')).rows[0].n,1);
}));
test('empty imported demo state stays empty after repeated runtime initialization',{skip:!enabled},async()=>fixture(async(migration,runtime)=>{
 const raw=input();for(const table of Object.keys(raw.tables))raw.tables[table]=[];review(raw);
 await importLegacyChallengeArchive(migration,raw,{apply:true});
 const store=createLegacyChallengeDb(runtime);await store.initializeLegacyChallengeDb(migration);await store.initializeLegacyChallengeDb(migration);
 for(const table of ['users','products','comments'])assert.equal((await runtime.query(`SELECT count(*)::int n FROM legacy_challenge.${table}`)).rows[0].n,0);
 assert.equal((await migration.query('SELECT count(*)::int n FROM legacy_challenge.import_batches')).rows[0].n,1);
}));
