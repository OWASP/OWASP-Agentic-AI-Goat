'use strict';
// Disposable identity foundation. This proves the forward migration and SQL
// error classes; the rendered Learner-B cohort separately proves owner_reset.
const test=require('node:test'),assert=require('node:assert/strict');
const path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {createPool,withTransaction,verifyServer}=require('../../server/database/postgres');
const {migrate,readMigrations,executionSql}=require('../../db/postgres/migrate');
const ROOT=path.resolve(__dirname,'../..'),DIR=path.join(ROOT,'db/postgres/identity-migrations');
const ENABLED=process.env.CTF_PUBLICATION_STALE_NATIVE==='1';
const sha=value=>createHash('sha256').update(value).digest('hex');
const one=async(pool,sql,args=[])=>(await pool.query(sql,args)).rows[0];

function urls(state){
 const names=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_PUBLICATION_STALE_${state}_${role}_URL`);
 assert(names.every(name=>typeof process.env[name]==='string'&&process.env[name].length));
 const pair=names.map(name=>new URL(process.env[name]));
 for(const url of pair){
  assert.equal(url.hostname,'127.0.0.1');
  assert.match(url.pathname,new RegExp(`^/owasp_ai_goat_test_ctf_publication_stale_[a-f0-9]{12}_${state.toLowerCase()}$`));
  assert.equal(url.search,'');assert.equal(url.hash,'');
 }
 assert.equal(pair[0].pathname,pair[1].pathname);assert.equal(pair[0].port,pair[1].port);
 assert.equal(decodeURIComponent(pair[0].username),'dvaia_identity_runtime');
 assert.equal(decodeURIComponent(pair[1].username),'dvaia_identity_migration');
 return names;
}

async function migrateThrough0154(pool){
 const source=(await readMigrations(DIR)).filter(item=>item.name<='0154_ctf_global_reset_adaptive_memory.sql');
 assert.equal(source.at(-1)?.name,'0154_ctf_global_reset_adaptive_memory.sql');
 await withTransaction(pool,async client=>{
  await verifyServer(client);
  await client.query('SELECT pg_advisory_xact_lock(1886610804,1)');
  await client.query('CREATE SCHEMA IF NOT EXISTS dvaia_migrations');
  await client.query(`CREATE TABLE IF NOT EXISTS dvaia_migrations.ledger(
   name text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())`);
  assert.equal((await one(client,'SELECT count(*)::integer AS n FROM dvaia_migrations.ledger')).n,0);
  for(const item of source){
   await client.query(executionSql(item));
   await client.query('INSERT INTO dvaia_migrations.ledger(name,checksum) VALUES($1,$2)',[item.name,item.checksum]);
  }
 });
}

async function seedBoundDecision(pool){
 const password='$2b$04$'+'a'.repeat(53),token=sha('owner-'+randomUUID()),foreignToken=sha('foreign-'+randomUUID());
 await pool.query(`INSERT INTO identity.users(id,username,email,password,role)
  VALUES(701,'stale-owner','stale-owner@fixture.invalid',$1,'student'),
        (702,'foreign-owner','foreign-owner@fixture.invalid',$1,'student')`,[password]);
 const ownerSession=(await one(pool,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(701,$1,now()+interval '1 hour') RETURNING id",[token])).id;
 const foreignSession=(await one(pool,"INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(702,$1,now()+interval '1 hour') RETURNING id",[foreignToken])).id;
 const admission=randomUUID(),proposal=randomUUID(),decision=randomUUID(),run=randomUUID(),command='{}';
 await pool.query(`INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash,state,actor_id,session_id)
  VALUES(1,$1,'admit_attempt',$2,$3,'applied',701,$4)`,[admission,command,sha(command),ownerSession]);
 await pool.query(`INSERT INTO identity.ctf_attempt_admissions(operation_id,owner_id,owner_generation,participant_id,
  progress_id,stage_id,attempt_number,failed_counter_increment,occurred_at,applied_sequence)
  VALUES($1,701,0,801,901,1,1,false,now(),1)`,[admission]);
 await pool.query(`INSERT INTO identity.ctf_decision_proposals(proposal_id,run_id,admission_operation_id,
  owner_id,session_id,canonical_evidence,evidence_hash,evidence)
  VALUES($1,$2,$3,701,$4,$5,$6,$7::jsonb)`,[proposal,run,admission,ownerSession,command,sha(command),command]);
 await pool.query(`INSERT INTO identity.ctf_decisions(decision_id,run_id,owner_id,session_id,owner_key,
  owner_generation,global_revision,stage_revision,participant_id,progress_id,stage_id,stage_digest,
  evidence_hash,evidence,verdict,accepted,sequence,proposal_id)
  VALUES($1,$2,701,$3,$4,0,0,0,801,901,1,$5,$6,$7::jsonb,'fail',false,2,$8)`,
 [decision,run,ownerSession,'["CTF","701"]','a'.repeat(64),sha(command),command,proposal]);
 await pool.query("UPDATE identity.ctf_authority SET lifecycle_state='ready' WHERE scope_key='global'");
 await pool.query("INSERT INTO identity.ctf_authority(scope_key,lifecycle_state,owner_generation) VALUES('owner:701','ready',0)");
 await pool.query("INSERT INTO identity.ctf_authority(scope_key,lifecycle_state) VALUES('stage:1','ready')");
 await pool.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',['["CTF","701"]']);
 await pool.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')",[run,'["CTF","701"]']);
 return{decision,ownerSession,foreignSession,token,foreignToken};
}

test('identity 0155 distinguishes authenticated stale publication from foreign or revoked sessions',
 {skip:!ENABLED,timeout:180000},async t=>{
  assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
  assert.equal(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE,ROOT);
  const pools=[],paths=new Set();
  t.after(async()=>{const settled=await Promise.allSettled(pools.map(pool=>pool.end()));
   const failed=settled.filter(result=>result.status==='rejected');
   if(failed.length)throw new AggregateError(failed.map(result=>result.reason),'Owned identity pools failed to close');});
  for(const state of ['FRESH','POPULATED']){
   const [runtimeName,migrationName]=urls(state),pathname=new URL(process.env[runtimeName]).pathname;
   assert(!paths.has(pathname));paths.add(pathname);
   const runtime=createPool(process.env,runtimeName),migration=createPool(process.env,migrationName);
   pools.push(runtime,migration);
   assert.equal((await one(runtime,'SELECT current_user AS role')).role,'dvaia_identity_runtime');
   assert.equal((await one(migration,"SELECT to_regclass('dvaia_migrations.ledger') AS value")).value,null);
   if(state==='POPULATED')await migrateThrough0154(migration);
   const bound=state==='POPULATED'?await seedBoundDecision(migration):null;
   const before=bound?(await migration.query('SELECT * FROM identity.ctf_decisions ORDER BY decision_id')).rows:null;
   if(bound){
    await migration.query("UPDATE identity.ctf_authority SET owner_generation=1 WHERE scope_key='owner:701'");
    await assert.rejects(runtime.query('SELECT identity.authorize_ctf_current_publication($1,701,$2,$3)',
     [bound.decision,bound.ownerSession,bound.token]),{code:'42501'});
   }
   const applied=await migrate(migration,DIR);
   assert.equal(applied.at(-1),'0155_ctf_authenticated_publication_stale.sql');
   assert.equal(state==='POPULATED'?applied.length:applied.length>1,state==='POPULATED'?1:true);
   const ledger=(await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
   assert.deepEqual(await migrate(migration,DIR),[]);
   assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
   const functionState=await one(migration,`SELECT p.prosrc,p.prosecdef,p.proconfig,
    has_function_privilege('dvaia_identity_runtime',p.oid,'EXECUTE') AS runtime_execute,
    EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
    FROM pg_proc p WHERE p.oid='identity.authorize_ctf_current_publication(uuid,integer,integer,text)'::regprocedure`);
   assert.equal(functionState.prosecdef,true);
   assert.deepEqual(functionState.proconfig,['search_path=pg_catalog']);
   assert.equal(functionState.runtime_execute,true);assert.equal(functionState.public_execute,false);
   assert.equal(functionState.prosrc.split("ERRCODE='PCT01'").length,2);
   const evidence=bound||await seedBoundDecision(migration);
   if(before)assert.deepEqual((await migration.query('SELECT * FROM identity.ctf_decisions ORDER BY decision_id')).rows,before);
   const call=(actor,session,token)=>runtime.query('SELECT identity.authorize_ctf_current_publication($1,$2,$3,$4)',
    [evidence.decision,actor,session,token]);
   await assert.rejects(call(702,evidence.foreignSession,evidence.foreignToken),{code:'42501'});
   await assert.rejects(call(701,evidence.foreignSession,evidence.foreignToken),{code:'42501'});
   await assert.rejects(call(701,evidence.ownerSession,sha('wrong token')),{code:'28000'});
   if(bound)await migration.query("UPDATE identity.ctf_authority SET owner_generation=0 WHERE scope_key='owner:701'");
   await assert.rejects(call(701,evidence.ownerSession,evidence.token),{code:'42501'},
    'unready/non-generation scope must not be classified as an owner reset');
   await migration.query("UPDATE identity.ctf_authority SET owner_generation=1 WHERE scope_key='owner:701'");
   await assert.rejects(call(701,evidence.ownerSession,evidence.token),{code:'PCT01'});
   await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[evidence.ownerSession]);
   await assert.rejects(call(701,evidence.ownerSession,evidence.token),{code:'28000'});
   assert.deepEqual(await migrate(migration,DIR),[]);
  }
 });
