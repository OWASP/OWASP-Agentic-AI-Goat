'use strict';
// SQL authority qualification only; explicit disposable identity pairs, no model or HTTP.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_CANONICAL_ADMIN_ISOLATED==='1';
const target='0123_ctf_canonical_admin_policy.sql';
const sha=x=>createHash('sha256').update(x).digest('hex');
test('fresh and populated canonical admin migration preserves authority, pending outbox and no-op ledger',{skip:!enabled,timeout:180000},async t=>{
 const {createPool}=require('../../server/database/postgres');
 const {migrate}=require('../../db/postgres/migrate');
 const {buildCtfLifecycleCommand,canonicalCtfJson}=require('../../server/services/ctfLifecycleCommands');
 const used=new Set();
 for(const state of ['FRESH','POPULATED']){
  require('./platformAuthCtfScope').pair(process.env,`PG_CTF_CANONICAL_ADMIN_${state}`);
  const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_CANONICAL_ADMIN_${state}_${role}_URL`);
  assert(keys.every(k=>process.env[k]),'Explicit disposable pairs required');
  const urls=keys.map(k=>new URL(process.env[k]));
  for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_ctf_adminpolicy_[a-z0-9_]+$/);}
  assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!used.has(urls[0].pathname));used.add(urls[0].pathname);
  const [runtime,migration]=keys.map(k=>createPool(process.env,k));t.after(async()=>{await require('./platformAuthCtfScope').cleanup([()=>Promise.all([runtime.end(),migration.end()])]);});
  assert.equal((await runtime.query('SELECT current_user AS role')).rows[0].role,'dvaia_identity_runtime');
  const directory=path.resolve(__dirname,'../../db/postgres/identity-migrations'),prefix=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-admin-policy-'));
  t.after(()=>fs.rmSync(prefix,{recursive:true,force:true}));
  for(const name of fs.readdirSync(directory).filter(n=>n.endsWith('.sql')&&n<target))fs.copyFileSync(path.join(directory,name),path.join(prefix,name));
  if(state==='FRESH')fs.copyFileSync(path.join(directory,target),path.join(prefix,target));
  await migrate(migration,prefix);
  const token='owned-'+randomUUID();
  await migration.query("INSERT INTO identity.users(id,username,email,password,role,admin_level) VALUES(701,'policy-subject','policy@fixture.invalid',$1,'admin',1),(702,'policy-sibling','sibling@fixture.invalid',$1,'student',0)",['$2b$04$'+'a'.repeat(53)]);
  const session=(await migration.query("INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(701,$1,clock_timestamp()+interval '1 hour') RETURNING id",[sha(token)])).rows[0].id;
  // Migration-owned initial binding, not a production bootstrap/activation claim.
  await migration.query("UPDATE identity.ctf_authority SET lifecycle_state='ready' WHERE scope_key='global'");
  await migration.query('INSERT INTO identity.ctf_config_binding VALUES(true,0,true,true,true,true,false,true,true,true,-1,-1,1000,0,0,0,0,0,$1)',[randomUUID()]);
  const make=async(client,kind,body,scope)=>{const occurredAt=(await client.query("SELECT to_char(date_trunc('milliseconds',transaction_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS at")).rows[0].at;const operationId=randomUUID(),built=buildCtfLifecycleCommand(kind,body,{operationId,actorId:'701',occurredAt,scope}),{commandHash,...content}=built,canonical=canonicalCtfJson(content);return{operationId,args:[701,session,sha(token),operationId,canonical,sha(canonical)]};};
  const baseScope={globalRevision:'0',ownerId:null,ownerGeneration:null,participantId:null,progressId:null,stageId:null,stageRevision:null};
  const sql='SELECT * FROM identity.enqueue_ctf_user_command($1,$2,$3,$4,$5,$6)';
  // Timestamp capture and enqueue share this exact checked-out client/transaction.
  // COMMIT uncertainty is never retried or treated as a successful fixture write.
  const commitCommand=async(kind,body,scope)=>{const client=await runtime.connect();try{
   await client.query('BEGIN');const command=await make(client,kind,body,scope);
   assert.equal((await client.query(sql,command.args)).rows[0].state,'pending');
   await client.query('COMMIT');return command;
  }catch(error){try{await client.query('ROLLBACK');}catch{}throw error;}finally{client.release();}};
  let prior;
  if(state==='POPULATED'){
   prior=await commitCommand('register',{username:'policy-subject',email:null,teamName:null,teachingSessionToken:'synthetic-locator',clientIp:null,userAgent:null},{...baseScope,ownerId:'701',ownerGeneration:'0'});
  }
  const snapshot=async()=>({authority:(await migration.query('SELECT * FROM identity.ctf_authority ORDER BY scope_key')).rows,outbox:(await migration.query('SELECT * FROM identity.ctf_outbox ORDER BY sequence')).rows,sibling:(await migration.query('SELECT * FROM identity.users WHERE id=702')).rows});
  const before=await snapshot(),ledger=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
  if(state==='POPULATED'){fs.copyFileSync(path.join(directory,target),path.join(prefix,target));assert.deepEqual(await migrate(migration,prefix),[target]);}assert.deepEqual(await snapshot(),before);
  assert.deepEqual(await migrate(migration,prefix),[]);assert.deepEqual(await snapshot(),before);
  assert.deepEqual((await migration.query('SELECT * FROM dvaia_migrations.ledger WHERE name<>$1 ORDER BY name',[target])).rows,ledger.filter(r=>r.name!==target));
  for(const role of ['student','admin','super_admin'])for(const level of [0,1,2]){
   await migration.query('UPDATE identity.users SET role=$1,admin_level=$2 WHERE id=701',[role,level]);
   const client=await runtime.connect();try{await client.query('BEGIN');const command=await make(client,'config_mutation',{key:'ctf_visible_to_students',value:'false'},baseScope);
    if(role!=='student'&&level>=1)assert.equal((await client.query(sql,command.args)).rows[0].state,'pending');
    else await assert.rejects(client.query(sql,command.args),{code:'42501'});
   }finally{await client.query('ROLLBACK');client.release();}
  }
  // Admin-operation historical recovery independently rechecks both role and level.
  await migration.query("UPDATE identity.users SET role='super_admin',admin_level=1 WHERE id=701");
  const command=await commitCommand('config_mutation',{key:'ctf_visible_to_students',value:'false'},baseScope);
  const read=()=>runtime.query('SELECT identity.read_ctf_user_operation($1,$2,$3,$4)',[command.operationId,701,session,sha(token)]);
  await read();
  for(const [role,level]of [['student',1],['admin',0]]){await migration.query('UPDATE identity.users SET role=$1,admin_level=$2 WHERE id=701',[role,level]);await assert.rejects(read(),{code:'42501'});}
  await migration.query("UPDATE identity.users SET role='admin',admin_level=1 WHERE id=701");await read();
  if(prior)assert.deepEqual((await migration.query('SELECT * FROM identity.ctf_outbox WHERE operation_id=$1',[prior.operationId])).rows,before.outbox);
  assert.deepEqual((await migration.query('SELECT * FROM identity.users WHERE id=702')).rows,before.sibling);
  for(const signature of ['identity.lock_ctf_predefense(integer,integer,text,jsonb,boolean)','identity.lock_ctf_predefense_recovery_state(integer,integer,text,uuid)'])assert.equal((await migration.query("SELECT has_function_privilege('dvaia_identity_runtime',$1,'EXECUTE') AS allowed",[signature])).rows[0].allowed,false);
 }
});
