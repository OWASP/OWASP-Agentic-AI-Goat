'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {createCtfAuthorityBootstrapRepository,TABLES}=require('../../server/database/postgres/ctfAuthorityBootstrapRepository');
const {createCtfAuthorityBootstrap}=require('../../server/services/ctfAuthorityBootstrap');
const {canonicalCtfJson}=require('../../server/services/ctfLifecycleCommands');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_TELEMETRY_ISOLATED==='1';
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
test('ordered heartbeat preserves owner authority and semantic state through real activation',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],dbs=new Set(),pairs=[];t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_TELEMETRY_${state}_${kind}_${role}_URL`);assert(keys.every(k=>process.env[k]));
   const urls=keys.map(k=>new URL(process.env[k]));for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_telemetry_/);}
   assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!dbs.has(urls[0].pathname));dbs.add(urls[0].pathname);
   const [runtime,migration]=keys.map(k=>createPool(process.env,k));pools.push(runtime,migration);stores[kind]={runtime,migration};
   const directory=path.resolve(__dirname,'../../db/postgres',kind==='IDENTITY'?'identity-migrations':'workshop-migrations/ctf');
   const target=kind==='IDENTITY'?'0117_ctf_ordered_telemetry.sql':'0012_ordered_telemetry_receipts.sql';
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
  await c.migration.query("INSERT INTO ctf.ctf_sessions(participant_id,session_token,is_active,total_active_time) VALUES(1001,$1,1,0),(1001,'owned-inactive',0,5000),(1002,'sibling-active',1,7000)",['owned-active 🌍 \"quoted\"\nline']);
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
  const deliveryKey=`PG_CTF_TELEMETRY_${state}_CTF_DELIVERY_URL`;
  assert(process.env[deliveryKey],'Explicit owned delivery LOGIN URL required');
  const deliveryUrl=new URL(process.env[deliveryKey]),ctfUrl=new URL(process.env[`PG_CTF_TELEMETRY_${state}_CTF_RUNTIME_URL`]);
  assert.equal(deliveryUrl.host,ctfUrl.host);assert.equal(deliveryUrl.pathname,ctfUrl.pathname);assert.equal(decodeURIComponent(deliveryUrl.username),'dvaia_ctf_delivery');
  const {createCtfDeliveryPool}=require('../../server/database/postgres/ctfDeliveryPool');
  const delivery=await createCtfDeliveryPool({env:{...process.env,CTF_DELIVERY_DATABASE_URL:deliveryUrl.href},activation:activated.activation});pools.push(delivery);
  const verifier=createCtfDeliveryActivation({identityPool:i.runtime,ctfPool:c.runtime});
  await verifier.verify(activated.activation);
  assert.equal((await one(c.migration,'SELECT initialized FROM ctf.projection_cursor')).initialized,true);
  await assert.rejects(c.runtime.query("UPDATE ctf.ctf_config SET value=value WHERE key='ctf_enabled'"),e=>e.code==='42501');
  const {createCtfTelemetryRepository}=require('../../server/database/postgres/ctfTelemetryRepository');
  const {createCtfLifecycleRepository}=require('../../server/database/postgres/ctfLifecycleRepository');
  const {projectCtfBatch}=require('../../server/services/ctfProjectionWorker');
  const {heartbeatPublicResponse}=require('../../server/services/ctfTelemetryContract');
  const token='owned-platform-'+randomUUID();
  const sessionId=(await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(1001,$1,clock_timestamp()+interval '1 hour') RETURNING id",[sha(token)])).id;
  const session={actorId:'1001',sessionId:String(sessionId),rawToken:token},telemetry=createCtfTelemetryRepository(i.runtime),identity=createCtfLifecycleRepository(i.runtime);
  const work=()=>projectCtfBatch({identity,ctfPool:delivery,maxEvents:1});
  const semantic=async()=>({authority:(await i.runtime.query('SELECT scope_key,revision,owner_generation,adaptive_revision,clear_revision FROM identity.ctf_authority ORDER BY scope_key')).rows,progress:(await c.runtime.query('SELECT * FROM ctf.ctf_progress ORDER BY id')).rows,scopes:(await c.runtime.query('SELECT * FROM ctf.projection_scopes ORDER BY scope_key')).rows});
  const semanticBefore=await semantic();
  const noop=await telemetry.admit({session,operationId:randomUUID()});assert.deepEqual(heartbeatPublicResponse(noop),{status:'ok'});
  const input={session,operationId:randomUUID(),registrationToken:'owned-active 🌍 \"quoted\"\nline'};
  await telemetry.admit(input);
  const admittedRow=await one(i.runtime,'SELECT canonical_command,command_hash FROM identity.ctf_outbox WHERE operation_id=$1',[input.operationId]);
  const spaced=JSON.stringify(JSON.parse(admittedRow.canonical_command),null,2);
  await assert.rejects(i.runtime.query('SELECT identity.enqueue_ctf_heartbeat($1,$2,$3,$4,$5,$6,$7)',[1001,sessionId,sha(token),input.operationId,input.registrationToken,spaced,sha(spaced)]),/CTF heartbeat command invalid/);
  await work();
  const receiptRow=await one(c.runtime,'SELECT * FROM ctf.projection_receipts WHERE operation_id=$1',[input.operationId]);
  const spacedReceipt=JSON.stringify(JSON.parse(receiptRow.canonical_result),null,2);
  await assert.rejects(i.runtime.query('SELECT identity.ack_ctf_heartbeat($1,$2,$3,$4,$5)',[input.operationId,receiptRow.sequence,admittedRow.command_hash,spacedReceipt,sha(spacedReceipt)]),/CTF heartbeat receipt invalid/);
  assert.equal((await one(c.runtime,"SELECT total_active_time FROM ctf.ctf_sessions WHERE participant_id=1001 AND is_active=1")).total_active_time,1000);
  assert.equal((await telemetry.admit(input)).replayed,true);assert.deepEqual(await work(),[]);
  await telemetry.admit({...input,operationId:randomUUID()});await work();
  assert.equal((await one(c.runtime,"SELECT total_active_time FROM ctf.ctf_sessions WHERE participant_id=1001 AND is_active=1")).total_active_time,2000);
  for(const locator of ['owned-inactive','sibling-active','missing']){const op=randomUUID();await telemetry.admit({session,operationId:op,registrationToken:locator});await work();const result=await one(c.runtime,'SELECT canonical_result FROM ctf.projection_receipts WHERE operation_id=$1',[op]);assert.deepEqual(JSON.parse(result.canonical_result).data,{matched:false,incrementMs:0});}
  assert.equal((await one(c.runtime,"SELECT total_active_time FROM ctf.ctf_sessions WHERE session_token='owned-inactive'")).total_active_time,5000);
  assert.equal((await one(c.runtime,"SELECT total_active_time FROM ctf.ctf_sessions WHERE session_token='sibling-active'")).total_active_time,7000);
  assert.deepEqual(await semantic(),semanticBefore);
  const evidence=async()=>({outbox:(await i.runtime.query('SELECT * FROM identity.ctf_outbox ORDER BY sequence')).rows,receipts:(await c.runtime.query('SELECT * FROM ctf.projection_receipts ORDER BY sequence')).rows,cursor:(await c.runtime.query('SELECT * FROM ctf.projection_cursor')).rows});
  const beforeResume=await evidence();await operator.revokeForMaintenance();await operator.resumeAfterMaintenance({activationId,transferId:randomUUID()});await verifier.verify(activated.activation);assert.deepEqual(await evidence(),beforeResume);
  // Pending heartbeat precedes reset. Canonical preparation derives the reset scope.
  await i.migration.query("UPDATE identity.users SET role='admin',admin_level=1 WHERE id=1002");
  const adminToken='owned-admin-'+randomUUID(),adminId=(await one(i.migration,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(1002,$1,clock_timestamp()+interval '1 hour') RETURNING id",[sha(adminToken)])).id;
  const admin={actorId:'1002',sessionId:String(adminId),rawToken:adminToken};
  const {createCtfAuthorityRequestRepository}=require('../../server/database/postgres/ctfAuthorityRequestRepository');
  const {createCtfAuthorityPrepare}=require('../../server/services/ctfAuthorityPrepare');
  const prepare=createCtfAuthorityPrepare({repository:createCtfAuthorityRequestRepository(i.runtime)});
  await telemetry.admit({...input,operationId:randomUUID()});
  const reset=await prepare({kind:'owner_reset',input:{ownerId:'1001'},session:admin});
  await identity.enqueue({...reset,kind:'owner_reset',operationId:randomUUID(),...admin});
  await work();
  assert.equal((await one(c.runtime,"SELECT total_active_time FROM ctf.ctf_sessions WHERE participant_id=1001 AND is_active=1")).total_active_time,3000);
  await work();
  assert.equal((await one(i.runtime,"SELECT owner_generation::text FROM identity.ctf_authority WHERE scope_key='owner:1001'")).owner_generation,'1');
  await i.migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[sessionId]);
  await assert.rejects(telemetry.admit({session,operationId:randomUUID()}),{code:'28000'});
  await assert.rejects(telemetry.admit(input),{code:'28000'});
 }
});
