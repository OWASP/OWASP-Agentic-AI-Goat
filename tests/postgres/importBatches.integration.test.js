'use strict';
const{test}=require('node:test'),assert=require('node:assert/strict');const{createPool}=require('../../server/database/postgres');const{initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_IMPORT_BATCHES_TEST_RUNTIME_URL;
test('immutable import batch metadata is bounded, transactional and read-only at runtime',{skip:!enabled},async()=>{
 for(const key of ['PG_IMPORT_BATCHES_TEST_RUNTIME_URL','PG_IMPORT_BATCHES_TEST_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const runtime=createPool(process.env,'PG_IMPORT_BATCHES_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_IMPORT_BATCHES_TEST_MIGRATION_URL');
 try{await initializeIdentityRepository(runtime,migration);const sql="INSERT INTO identity.import_batches(archive_sha256,importer_version,plan_sha256,counts,coverage,review_decisions) VALUES($1,'combined-v1',$2,$3,$4,$5)";const args=['a'.repeat(64),'b'.repeat(64),{users:2,completions:1},{mappedTables:7,retainedTables:3},{exercises:'catalog_visibility_defaults_without_content',unknown_table:'retained_archive_only'}];
 const c=await migration.connect();try{await c.query('BEGIN');await c.query(sql,args);await c.query('ROLLBACK');}finally{c.release();}
 assert.equal((await runtime.query('SELECT count(*)::int AS n FROM identity.import_batches')).rows[0].n,0);
 await migration.query(sql,args);await assert.rejects(migration.query(sql,args),{code:'23505'});await assert.rejects(runtime.query(sql,args),{code:'42501'});
 for(const query of ['DELETE FROM identity.import_batches','UPDATE identity.import_batches SET counts=\'{}\'','TRUNCATE identity.import_batches']){await assert.rejects(runtime.query(query),{code:'42501'});await assert.rejects(migration.query(query),{code:'55000'});}
 for(const [index,value] of [[2,[]],[2,null],[2,{users:-1}],[2,{users:1.5}],[2,{users:{password:'forbidden'}}],[4,{exercises:'arbitrary payload'}]]){const bad=[...args];bad[1]='c'.repeat(64);bad[index]=JSON.stringify(value);await assert.rejects(migration.query(sql,bad),error=>['23514','23502'].includes(error.code));}
 const row=(await runtime.query('SELECT * FROM identity.import_batches')).rows[0];assert.deepEqual(row.counts,{users:2,completions:1});assert.ok(row.committed_at instanceof Date);
 }finally{await Promise.all([runtime.end(),migration.end()]);}
});
