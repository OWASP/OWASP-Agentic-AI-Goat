'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const{createPool}=require('../../server/database/postgres');
const{migrate}=require('../../db/postgres/migrate');
const{fixture}=require('../fixtures/xssArchive');
const{importXssArchive}=require('../../db/postgres/import-xss-archive');
const{createNativeOwnerProof}=require('./helpers/archiveOwnerBinding');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_XSS_IMPORT_TEST_MIGRATION_URL;
test('XSS native import replaces only migration emails, rolls back invalid links and preserves historical state', {skip:!enabled},async()=>{
 const pool=createPool(process.env,'PG_XSS_IMPORT_TEST_MIGRATION_URL'),runtime=createPool(process.env,'PG_XSS_IMPORT_TEST_RUNTIME_URL');
 let ownerFixture;
 try{
  await migrate(pool,path.join(__dirname,'../../db/postgres/workshop-migrations/xss'));
  const baseline=(await pool.query('SELECT * FROM xss.emails ORDER BY id')).rows;
  const raw=fixture(),ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};raw.ownerBinding=ownerBinding;raw.opaqueOwnerResolutions=[{sourceKey:'0007',disposition:'map_source_identity',sourceId:'7'}];
  ownerFixture=await createNativeOwnerProof(pool,ownerBinding);
  await importXssArchive(pool,raw,{ownerProof:ownerFixture.ownerProof});assert.deepEqual((await pool.query('SELECT * FROM xss.emails ORDER BY id')).rows,baseline);
  await pool.query("UPDATE xss.emails SET body='changed' WHERE id=1");await assert.rejects(importXssArchive(pool,raw,{ownerProof:ownerFixture.ownerProof}),{code:'XSS_IMPORT_REQUIRES_MIGRATION_EMAIL_DEFAULTS'});await pool.query('UPDATE xss.emails SET body=$1 WHERE id=1',[baseline[0].body]);
  const invalid=structuredClone(raw);invalid.sources['xss_email_challenge.db'].tables.email_templates[0].user_id=8;
  await assert.rejects(importXssArchive(pool,invalid,{apply:true,ownerProof:ownerFixture.ownerProof}),{code:'UNMAPPED_ARCHIVE_OWNER'});assert.deepEqual((await pool.query('SELECT * FROM xss.emails ORDER BY id')).rows,baseline);assert.equal((await pool.query('SELECT count(*)::int n FROM xss.profiles')).rows[0].n,0);
  const result=await importXssArchive(pool,raw,{apply:true,ownerProof:ownerFixture.ownerProof});assert.equal(result.counts.emails,1);
  assert.equal((await runtime.query('SELECT subject,html_content,is_favorite FROM xss.email_templates')).rows[0].subject,'Original subject');
  assert.equal((await runtime.query('SELECT count(*)::int n FROM xss.xss_email_judge_receipts')).rows[0].n,0);
  const batch=(await pool.query('SELECT * FROM xss.import_batches')).rows[0];assert.equal(batch.review_metadata.missing.length,2);assert.equal(JSON.stringify(batch).includes('fixture@example.test'),false);
  await require('../../server/database/postgres/xssWorkshopDb').createXssWorkshopDb(runtime).initializeXssWorkshopDb(pool);
  assert.equal((await runtime.query('SELECT count(*)::int n FROM xss.emails')).rows[0].n,1);
  const next=(await pool.query("INSERT INTO xss.emails(subject,sender,body) VALUES('next','sender','body') RETURNING id")).rows[0].id;assert.equal(next,10);
  await assert.rejects(importXssArchive(pool,raw,{apply:true,ownerProof:ownerFixture.ownerProof}),{code:'XSS_IMPORT_REQUIRES_EMPTY_TARGET'});
  await assert.rejects(pool.query('DELETE FROM xss.import_batches'),{code:'55000'});
 }finally{if(ownerFixture)await ownerFixture.cleanup();await Promise.all([pool.end(),runtime.end()]);}
});
