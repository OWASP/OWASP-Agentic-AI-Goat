'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {createCtfAuthorityBootstrapRepository,TABLES}=require('../../server/database/postgres/ctfAuthorityBootstrapRepository');
const {createCtfAuthorityBootstrap}=require('../../server/services/ctfAuthorityBootstrap');
const {canonicalCtfJson}=require('../../server/services/ctfLifecycleCommands');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_DELIVERY_ACTIVATION_ISOLATED==='1';
const one=async(p,s,a=[])=>(await p.query(s,a)).rows[0];
const sha=s=>createHash('sha256').update(s).digest('hex');
function lostPreparationCommit(pool){let fired=false;return {get fired(){return fired;},async connect(){const c=await pool.connect();let changed=false;return {async query(s,a){const r=await c.query(s,a);if(s.startsWith("UPDATE ctf.bootstrap_control SET state='prepared'"))changed=true;if(s==='COMMIT'&&changed&&!fired){fired=true;throw Error('OWNED_POST_COMMIT_RESPONSE_LOSS');}return r;},release(d){c.release(d);}};}};}
// The lock holder has its own max-one migration pool. Observe pg_locks on
// that already borrowed connection; sourcePage uses the original distinct pool.
async function observeTruncateWait(lockPool,readPage){
 const lock=await lockPool.connect();let read;
 try{
  await lock.query('BEGIN');await lock.query('TRUNCATE ctf.ctf_events');
  read=Promise.resolve().then(readPage);read.catch(()=>{});
  let waiting=false;const deadline=Date.now()+1000;
  while(Date.now()<deadline&&!waiting){waiting=(await one(lock,"SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='ctf.ctf_events'::regclass AND mode='AccessShareLock' AND NOT granted) AS waiting")).waiting;if(!waiting)await new Promise(resolve=>setTimeout(resolve,10));}
  await lock.query('ROLLBACK');assert((await read).done);assert(waiting,'observed source page waiting on TRUNCATE relation lock');
 }finally{await lock.query('ROLLBACK').catch(()=>{});lock.release();if(read)await read.catch(()=>{});}
}
module.exports={observeTruncateWait};
test('real bootstrap feeds paged activation and unchanged-checkpoint maintenance recovery',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],dbs=new Set(),pairs=[];t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_ACTIVATION_${state}_${kind}_${role}_URL`);assert(keys.every(k=>process.env[k]));
   const urls=keys.map(k=>new URL(process.env[k]));for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_activation_/);}
   assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!dbs.has(urls[0].pathname));dbs.add(urls[0].pathname);
   const [runtime,migration]=keys.map(k=>createPool(process.env,k));pools.push(runtime,migration);stores[kind]={runtime,migration};
   const directory=path.resolve(__dirname,'../../db/postgres',kind==='IDENTITY'?'identity-migrations':'workshop-migrations/ctf');
   const target=kind==='IDENTITY'?'0115_ctf_delivery_activation.sql':'0011_delivery_activation.sql';
   const prefix=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-bootstrap-prefix-'));t.after(()=>fs.rmSync(prefix,{recursive:true,force:true}));
   for(const n of fs.readdirSync(directory).filter(n=>n.endsWith('.sql')&&n<target))fs.copyFileSync(path.join(directory,n),path.join(prefix,n));
   await migrate(migration,prefix);
   if(kind==='CTF'&&state==='POPULATED')await require('../../server/database/postgres/ctfDb').seed(migration);
   fs.copyFileSync(path.join(directory,target),path.join(prefix,target));await migrate(migration,prefix);assert.deepEqual(await migrate(migration,prefix),[]);
  }
  const i=stores.IDENTITY,c=stores.CTF;
  if(state==='FRESH')await require('../../server/database/postgres/ctfDb').seed(c.migration);
  const count=state==='POPULATED'?130:2;
  await i.migration.query("INSERT INTO identity.users(id,username,email,password,role,admin_level) SELECT x,'bootstrap-'||x,'bootstrap-'||x||'@fixture.invalid',$1,'student',0 FROM generate_series(1001,$2) x",['$2b$04$'+'a'.repeat(53),1000+count]);
  await c.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username,started_at) SELECT x,x,'bootstrap-'||x,'2026-01-01T00:00:00.123456Z' FROM generate_series(1001,$1) x",[1000+count]);
  // Normal registered-but-never-attempted users deliberately have no graph owner.
  assert.equal((await one(i.migration,'SELECT count(*)::int AS n FROM graph_runtime.owners')).n,0);
  await c.migration.query("INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at,completed_at,completion_time) VALUES(1001,1,'completed','2026-01-01','2026-01-02',9007199254740993)");
  await c.migration.query("INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response) VALUES(1001,1,1,'owned historical attempt','owned response')");
  const normalized='long retained payload '.repeat(100).trim();
  await c.migration.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES(9,$1,$2,1001)',[sha(normalized),normalized]);
  const sourceRows=async table=>{const wide=table==='ctf_progress'?"||jsonb_build_object('completion_time',t.completion_time::text)":table==='ctf_leaderboard'?"||jsonb_build_object('total_completion_time',t.total_completion_time::text)":'';return (await c.migration.query(`SELECT (to_jsonb(t)${wide})::text AS encoded FROM ctf.${table} t`)).rows.map(x=>canonicalCtfJson(JSON.parse(x.encoded))).sort();};
  const before=Object.fromEntries(await Promise.all(TABLES.map(async table=>[table,await sourceRows(table)])));
  const repository=createCtfAuthorityBootstrapRepository({identityPool:i.migration,ctfPool:c.migration});const operationId=randomUUID();
  const lost=lostPreparationCommit(c.migration);await assert.rejects(createCtfAuthorityBootstrap({repository:createCtfAuthorityBootstrapRepository({identityPool:i.migration,ctfPool:lost})}).prepare({operationId}),/OWNED_POST_COMMIT_RESPONSE_LOSS/);assert(lost.fired);
  assert.equal((await one(c.migration,'SELECT state FROM ctf.bootstrap_control')).state,'prepared');assert.equal((await one(i.migration,'SELECT state FROM identity.ctf_bootstrap_sessions')).state,'staging');
  const result=await createCtfAuthorityBootstrap({repository}).prepare({operationId});assert(result.prepared);assert.equal(result.runtimeReady,false);
  assert.equal((await one(i.migration,'SELECT count(*)::int AS n FROM identity.ctf_participant_bindings')).n,count);
  assert.equal((await one(i.migration,'SELECT completion_time::text AS n FROM identity.ctf_progress_bindings')).n,'9007199254740993');
  assert.equal((await one(i.migration,'SELECT min(generation)::text AS g,max(generation)::text AS m FROM graph_runtime.owners')).g,'0');
  assert.equal((await one(i.migration,"SELECT normalized_payload FROM identity.ctf_adaptive_memory WHERE kind='payload'")).normalized_payload,normalized);
  for(const table of TABLES){assert.deepEqual(await sourceRows(table),before[table]);const staged=(await i.migration.query('SELECT canonical_rows,page_sha256 FROM identity.ctf_bootstrap_pages WHERE operation_id=$1 AND table_name=$2 ORDER BY page_number',[operationId,table])).rows;staged.forEach(x=>assert.equal(sha(x.canonical_rows),x.page_sha256));assert.deepEqual(staged.flatMap(x=>JSON.parse(x.canonical_rows).map(canonicalCtfJson)).sort(),before[table]);}
  if(count>128)assert.equal((await one(i.migration,"SELECT count(*)::int AS n FROM identity.ctf_bootstrap_pages WHERE table_name='ctf_participants'")).n,2);
  const receiptSnapshot=async()=>canonicalCtfJson((await i.migration.query('SELECT to_jsonb(s) AS s FROM identity.ctf_bootstrap_sessions s')).rows.concat((await i.migration.query('SELECT to_jsonb(p) AS p FROM identity.ctf_bootstrap_pages p ORDER BY table_name,page_number')).rows));
  const receipts=await receiptSnapshot();await createCtfAuthorityBootstrap({repository}).prepare({operationId});assert.equal(await receiptSnapshot(),receipts);
  await assert.rejects(c.runtime.query("UPDATE ctf.ctf_config SET value=value WHERE key='ctf_enabled'"),e=>e.code==='55000');
  await assert.rejects(i.runtime.query("UPDATE identity.ctf_bootstrap_sessions SET state='staging'"),e=>e.code==='42501');
  const {createCtfDeliveryActivationOperator}=require('../../server/database/postgres/ctfDeliveryActivationOperator');
  const {createCtfDeliveryActivation}=require('../../server/database/postgres/ctfDeliveryActivation');
  const operator=createCtfDeliveryActivationOperator({identityMigrationPool:i.migration,ctfMigrationPool:c.migration});
  const activationId=randomUUID();
  let activated=await operator.activate({activationId,bootstrapOperationId:operationId,pageBudget:1});
  for(let n=0;activated.staged&&n<8;n++)activated=await operator.activate({activationId,bootstrapOperationId:operationId,pageBudget:1});
  assert(activated.activation);assert.equal(activated.trafficStarted,false);
  const deliveryKey=`PG_CTF_ACTIVATION_${state}_CTF_DELIVERY_URL`;
  assert(process.env[deliveryKey],'Explicit owned delivery LOGIN URL required');
  const deliveryUrl=new URL(process.env[deliveryKey]),ctfUrl=new URL(process.env[`PG_CTF_ACTIVATION_${state}_CTF_RUNTIME_URL`]);
  assert.equal(deliveryUrl.host,ctfUrl.host);assert.equal(deliveryUrl.pathname,ctfUrl.pathname);assert.equal(decodeURIComponent(deliveryUrl.username),'dvaia_ctf_delivery');
  const {createCtfDeliveryPool}=require('../../server/database/postgres/ctfDeliveryPool');
  const delivery=await createCtfDeliveryPool({env:{...process.env,CTF_DELIVERY_DATABASE_URL:deliveryUrl.href},activation:activated.activation});pools.push(delivery);
  const verifier=createCtfDeliveryActivation({identityPool:i.runtime,ctfPool:c.runtime});
  await verifier.verify(activated.activation);
  assert.equal((await one(c.migration,'SELECT initialized FROM ctf.projection_cursor')).initialized,true);
  await assert.rejects(c.runtime.query("UPDATE ctf.ctf_config SET value=value WHERE key='ctf_enabled'"),e=>e.code==='42501');
  await operator.revokeForMaintenance();await assert.rejects(verifier.verify(activated.activation));
  const resumed=await operator.resumeAfterMaintenance({activationId,transferId:randomUUID()});assert.equal(resumed.resumed,true);
  await verifier.verify(activated.activation);
  assert.equal(await receiptSnapshot(),receipts);
  for(const table of TABLES)assert.deepEqual(await sourceRows(table),before[table]);
  // Actual leased deletion uses the dedicated delivery principal; no manual
  // tombstone or receipt seeds substitute for admission/projection/ACK.
  const {createCtfDeletionRepository}=require('../../server/database/postgres/ctfDeletionRepository');
  const {projectCtfDeletion}=require('../../server/database/postgres/ctfDeletionProjectionAdapter');
  const {withCtfTransaction}=require('../../server/database/postgres/ctfLifecycleRepository');
  const deletion=createCtfDeletionRepository(i.runtime),jobId=randomUUID(),leaseToken=randomUUID();
  await i.migration.query('UPDATE identity.users SET is_active=0 WHERE id=1001');
  await i.migration.query("UPDATE graph_runtime.owners SET generation=generation+1 WHERE owner_key='[\"CTF\",\"1001\"]'");
  await i.migration.query("INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by,state,lease_token,lease_expires_at) VALUES($1,1001,1002,'running',$2,clock_timestamp()+interval '5 minutes')",[jobId,leaseToken]);
  const steps=['revoke_runs','secureshop','excessive_agency','session_disclosure','sql_injection_workshop','nosql_injection_workshop','mcp_workshop','csrf_workshop','direct_prompt_injection','indirect_prompt_injection','supply_chain_rce','ctf','legacy_challenge','sensitive_lookup','xss','finflow','identity'];
  for(let n=0;n<steps.length;n++)await i.migration.query("INSERT INTO identity.student_deletion_steps(job_id,step_key,ordinal,state,completed_at) VALUES($1,$2,$3,$4,CASE WHEN $3<11 THEN clock_timestamp() ELSE NULL END)",[jobId,steps[n],n,n<11?'completed':'pending']);
  await i.migration.query('INSERT INTO identity.student_deletion_run_blocks(owner_key,job_id) VALUES($1,$2)',['["CTF","1001"]',jobId]);
  const deletionScope={jobId,leaseToken,subjectId:1001},event=await deletion.admit(deletionScope);
  const receipt=await withCtfTransaction(delivery,client=>projectCtfDeletion(client,event));
  await deletion.acknowledge(deletionScope,event,receipt);
  const deliveryEvidence=async()=>({outbox:(await i.runtime.query('SELECT * FROM identity.ctf_outbox ORDER BY sequence')).rows,receipts:(await c.runtime.query('SELECT * FROM ctf.projection_receipts ORDER BY sequence')).rows,cursor:(await c.runtime.query('SELECT * FROM ctf.projection_cursor')).rows});
  const evidenceBeforeResume=await deliveryEvidence();
  const retained=await one(c.runtime,'SELECT * FROM ctf.ctf_participants WHERE id=1002');assert(retained);
  await operator.revokeForMaintenance();
  await operator.resumeAfterMaintenance({activationId,transferId:randomUUID()});
  assert.deepEqual(await one(c.runtime,'SELECT * FROM ctf.ctf_participants WHERE id=1002'),retained);
  assert.deepEqual(await deliveryEvidence(),evidenceBeforeResume);
  assert.equal((await one(i.runtime,"SELECT failure_code FROM identity.ctf_authority WHERE scope_key='owner:1001'")).failure_code,'student_deleted');
  await operator.revokeForMaintenance();
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='blocked',failure_code='student_deleted',blocked_operation_id=$1 WHERE scope_key='owner:1002'",[event.operationId||event.command.operationId]);
  await assert.rejects(operator.resumeAfterMaintenance({activationId,transferId:randomUUID()}),/authority drift/);
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='ready',failure_code=NULL,blocked_operation_id=NULL WHERE scope_key='owner:1002'");
  await i.migration.query("UPDATE identity.ctf_authority SET owner_generation=owner_generation+1 WHERE scope_key='owner:1001'");
  await assert.rejects(operator.resumeAfterMaintenance({activationId,transferId:randomUUID()}));
  await i.migration.query("UPDATE identity.ctf_authority SET owner_generation=owner_generation-1 WHERE scope_key='owner:1001'");
  await operator.revokeForMaintenance();
  await i.migration.query("UPDATE graph_runtime.owners SET generation=1 WHERE owner_key='[\"CTF\",\"1002\"]'");
  await assert.rejects(operator.resumeAfterMaintenance({activationId,transferId:randomUUID()}),/owner drift/);
  await i.migration.query("UPDATE graph_runtime.owners SET generation=0 WHERE owner_key='[\"CTF\",\"1002\"]'");
  await i.migration.query('INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by) VALUES($1,1002,1001)',[randomUUID()]);
  await assert.rejects(operator.resumeAfterMaintenance({activationId,transferId:randomUUID()}),/owner drift/);
 }
});
