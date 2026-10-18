'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {createCtfAuthorityBootstrapRepository,TABLES}=require('../server/database/postgres/ctfAuthorityBootstrapRepository');
const {createCtfAuthorityBootstrap}=require('../server/services/ctfAuthorityBootstrap');
const op='11111111-1111-4111-8111-111111111111';
function sourcePool(rows,role='dvaia_ctf_migration'){
 const queries=[];let released=0;
 return {queries,get released(){return released;},async connect(){return {async query(sql,args){queries.push({sql,args});if(sql.includes('current_user'))return {rows:[{role,login:role}]};if(sql.includes('bootstrap_control'))return {rows:[{operation_id:op,revision:'7',state:'fenced'}]};if(sql.startsWith('SELECT (to_jsonb'))return {rows};return {rows:[]};},release(){released++;}};}};
}
test('source page preserves bigint text and uses primary key cursor after relation lock',async()=>{
 const p=sourcePool([{encoded:'{"id":1,"completion_time":"9223372036854775807"}',cursor:'["1"]'}]);
 const repo=createCtfAuthorityBootstrapRepository({ctfPool:p});const result=await repo.sourcePage(op,'7','ctf_progress',null);
 assert.equal(JSON.parse(result.canonical)[0].completion_time,'9223372036854775807');assert.equal(result.after,'["1"]');assert.equal(result.done,true);
 const sql=p.queries.map(x=>x.sql);const lock=sql.findIndex(x=>x.startsWith('LOCK TABLE'));const control=sql.findIndex(x=>x.includes('bootstrap_control'));assert.ok(lock>=0,'relation lock must be present');assert.ok(control>=0,'bootstrap control read must be present');assert.ok(lock<control);
 assert.match(sql.find(x=>x.startsWith('SELECT (to_jsonb')),/completion_time::text.*id>\(\$1::jsonb->>0\)::integer.*ORDER BY id LIMIT 128/);assert.equal(p.released,1);
});
test('composite key pagination uses both typed primary key fields',async()=>{
 const p=sourcePool([]);await createCtfAuthorityBootstrapRepository({ctfPool:p}).sourcePage(op,'7','stage_default_fields','["3","label"]');
 const q=p.queries.find(x=>x.sql.startsWith('SELECT (to_jsonb'));assert.match(q.sql,/\(stage_number,field_name\)>\(\(\$1::jsonb->>0\)::integer,\(\$1::jsonb->>1\)::text\)/);assert.deepEqual(q.args,['["3","label"]']);
});
test('runtime role is refused before reading source and client is released',async()=>{
 const p=sourcePool([],'dvaia_ctf_runtime');await assert.rejects(createCtfAuthorityBootstrapRepository({ctfPool:p}).sourcePage(op,'7','ctf_config',null),/MIGRATION_ROLE_REQUIRED/);assert.equal(p.released,1);assert.equal(p.queries.some(x=>x.sql.startsWith('LOCK TABLE')),false);
});
test('single oversized row fails explicitly instead of truncating retained snapshot',async()=>{
 const p=sourcePool([{encoded:JSON.stringify({id:1,value:'x'.repeat(262144)}),cursor:'["1"]'}]);await assert.rejects(createCtfAuthorityBootstrapRepository({ctfPool:p}).sourcePage(op,'7','ctf_config',null),/ROW_TOO_LARGE/);
});
test('preparation visits every table and all pages without activating runtime',async()=>{
 const pages=[];let finalized;
 const repository={async fence(){return '7';},async begin(){},async sourcePage(o,r,t,after){return {canonical:'[]',hash:'a'.repeat(64),after:after===null?'["128"]':'["256"]',done:after!==null};},async stagePage(o,r,t,n){pages.push([t,n]);},async verifySource(){},async importAndPrepare(input){finalized=input;return {prepared:true,runtimeReady:false};}};
 assert.deepEqual(await createCtfAuthorityBootstrap({repository}).prepare({operationId:op}),{prepared:true,runtimeReady:false});assert.equal(pages.length,TABLES.length*2);assert.equal(finalized.manifest.length,pages.length);assert.match(finalized.manifestSha256,/^[a-f0-9]{64}$/);
});
test('incomplete repository cannot silently downgrade preparation to a partial success',()=>assert.throws(()=>createCtfAuthorityBootstrap({repository:{}}),/Complete bootstrap/));
test('fenced operation refuses a different identity store without overlapping store leases',async()=>{
 let borrowed=0;const calls=[];
 const pool=(store)=>({async connect(){assert.equal(borrowed++,0);return {async query(sql){calls.push([store,sql]);if(sql.includes('current_user'))return {rows:[{role:`dvaia_${store}_migration`,login:`dvaia_${store}_migration`}]};if(sql.includes('ctf_bootstrap_store'))return {rows:[{store_id:'identity-new'}]};if(sql.includes('bootstrap_control'))return {rows:[{state:'fenced',operation_id:op,identity_store_id:'identity-old',revision:'7'}]};return {rows:[]};},release(){borrowed--;}};}});
 await assert.rejects(createCtfAuthorityBootstrapRepository({identityPool:pool('identity'),ctfPool:pool('ctf')}).fence(op),/CHECKPOINT_MISMATCH/);assert.equal(borrowed,0);assert.equal(calls.some(([,sql])=>sql.startsWith('UPDATE')),false);
});
test('preparation readiness denies checkpoint revision drift and never grants runtime readiness',async()=>{
 let reads=0;const h='a'.repeat(64);
 const pool=(store)=>({async connect(){return {async query(sql){if(sql.includes('current_user'))return {rows:[{role:`dvaia_${store}_migration`,login:`dvaia_${store}_migration`}]};if(sql.includes('bootstrap_control'))return {rows:[{operation_id:op,store_id:'source',identity_store_id:'identity',state:'prepared',revision:String(++reads===1?7:8),manifest_sha256:h}]};if(sql.includes('bootstrap_sessions'))return {rows:[{source_store_id:'source',state:'prepared',source_revision:'7',manifest_sha256:h}]};if(sql.includes('ctf_bootstrap_store'))return {rows:[{store_id:'identity'}]};if(sql.includes('AS drift'))return {rows:[{drift:false}]};return {rows:[]};},release(){}};}});
 const result=await createCtfAuthorityBootstrapRepository({identityPool:pool('identity'),ctfPool:pool('ctf')}).preparationStatus(op);assert.deepEqual(result,{prepared:false,runtimeReady:false,reason:'bootstrap_checkpoint_unavailable'});
});
function preparedRepository({drift=false,identityStore='identity'}={}){
 const calls=[];let borrowed=0;const h='b'.repeat(64);
 const pool=store=>({async connect(){assert.equal(borrowed++,0,'store transactions must not overlap');return {async query(sql,args){
  calls.push({store,sql,args});
  if(sql.includes('current_user'))return {rows:[{role:`dvaia_${store}_migration`,login:`dvaia_${store}_migration`}]};
  if(sql.includes('bootstrap_control'))return {rows:[{operation_id:op,store_id:'source',identity_store_id:'identity',state:'prepared',revision:'7',manifest_sha256:h}]};
  if(sql.includes('bootstrap_sessions'))return {rows:[{source_store_id:'source',state:'prepared',source_revision:'7',manifest_sha256:h}]};
  if(sql.includes('ctf_bootstrap_store'))return {rows:[{store_id:identityStore}]};
  if(sql.includes('AS drift'))return {rows:[{drift}]};
  return {rows:[]};
 },release(){borrowed--;}};}});
 return {repository:createCtfAuthorityBootstrapRepository({identityPool:pool('identity'),ctfPool:pool('ctf')}),calls,h};
}
test('prepared status revalidates reset/deletion drift including ban-only owner authorities',async()=>{
 const good=preparedRepository();assert.deepEqual(await good.repository.preparationStatus(op),{prepared:true,runtimeReady:false,reason:'writer_cutover_required'});
 const stale=preparedRepository({drift:true});assert.equal((await stale.repository.preparationStatus(op)).prepared,false);
 const sql=stale.calls.map(x=>x.sql);const user=sql.findIndex(x=>x.startsWith('SELECT u.id'));const graph=sql.findIndex(x=>x.startsWith('SELECT g.owner_key'));const check=sql.findIndex(x=>x.includes('AS drift'));
 assert.ok(user>=0,'user authority read must be present');assert.ok(graph>=0,'graph authority read must be present');assert.ok(check>=0,'drift check must be present');assert.ok(user<graph&&graph<check);assert.match(sql[check],/FROM identity.ctf_authority a/);assert.match(sql[check],/student_deletion_jobs/);assert.match(sql[check],/g.generation IS DISTINCT FROM a.owner_generation/);
});
test('standalone prepared status rejects reverse identity-store binding mismatch',async()=>{
 const {repository}=preparedRepository({identityStore:'other-identity'});assert.equal((await repository.preparationStatus(op)).prepared,false);
});
test('prepared replay validates owners before returning and never reimports stale preparation',async()=>{
 const stale=preparedRepository({drift:true});await assert.rejects(stale.repository.importAndPrepare({operationId:op,revision:'7',manifest:[],manifestSha256:stale.h}),/CHECKPOINT_MISMATCH/);
 assert.equal(stale.calls.some(x=>x.sql.startsWith('INSERT INTO identity.')),false);assert.ok(stale.calls.some(x=>x.sql.includes('AS drift')));
 const good=preparedRepository();assert.equal((await good.repository.importAndPrepare({operationId:op,revision:'7',manifest:[],manifestSha256:good.h})).prepared,true);assert.ok(good.calls.some(x=>x.sql.includes('AS drift')));
});
test('legacy registered owner gets generation zero only when absent, preserving existing generations',async()=>{
 const {importBootstrapRow}=require('../server/database/postgres/ctfAuthorityBootstrapImport');
 for(const initial of [undefined,'17']){
  let generation=initial;const calls=[];const c={async query(sql,args){calls.push({sql,args});if(sql.startsWith('SELECT id FROM identity.users'))return {rows:[{id:81}]};if(sql.includes('AS blocked'))return {rows:[{blocked:false}]};if(sql.startsWith('INSERT INTO graph_runtime.owners')){generation??='0';return {rows:[]};}if(sql.startsWith('SELECT generation'))return {rows:[{generation}]};return {rows:[]};}};
  await importBootstrapRow(c,'ctf_participants',{id:9,user_id:81,started_at:'2026-01-01T00:00:00Z',is_active:1},op);
  assert.equal(generation,initial??'0');const insert=calls.find(x=>x.sql.startsWith('INSERT INTO graph_runtime.owners'));assert.match(insert.sql,/ON CONFLICT\(owner_key\) DO NOTHING/);assert.deepEqual(insert.args,['["CTF","81"]']);const lock=calls.findIndex(x=>x.sql.includes('FOR UPDATE'));const insertion=calls.indexOf(insert);assert.ok(lock>=0,'user lock must be present');assert.ok(insertion>=0,'owner insertion must be present');assert.ok(lock<insertion);
 }
});
test('deletion-blocked registered owner cannot create a graph generation',async()=>{
 const {importBootstrapRow}=require('../server/database/postgres/ctfAuthorityBootstrapImport');let writes=0;
 await assert.rejects(importBootstrapRow({async query(sql){if(sql.startsWith('INSERT'))writes++;return {rows:sql.includes('AS blocked')?[{blocked:true}]:[{id:81}]};}},'ctf_participants',{user_id:81},op),/LEGACY_DATA_UNAVAILABLE/);assert.equal(writes,0);
});
test('TRUNCATE observation reuses held connection while source page uses its separate pool',async()=>{
 const {observeTruncateWait}=require('./postgres/ctfAuthorityBootstrap.integration.test');let held=false,sourceStarted=false,observed=false,resolveRead;let connects=0;
 const pool={query(){throw Error('must not acquire pool again for observation');},async connect(){assert(!held);held=true;connects++;return {async query(sql){if(sql.includes('pg_locks')){await Promise.resolve();assert(sourceStarted);observed=true;return {rows:[{waiting:true}]};}if(sql==='ROLLBACK')resolveRead?.({done:true});return {rows:[]};},release(){held=false;}};}};
 await observeTruncateWait(pool,()=>{assert(held);sourceStarted=true;return new Promise(resolve=>{resolveRead=resolve;});});assert(observed);assert.equal(connects,1);assert.equal(held,false);
});
