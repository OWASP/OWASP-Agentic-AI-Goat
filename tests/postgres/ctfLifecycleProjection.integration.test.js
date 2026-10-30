'use strict';
// SQL-only candidate gate. Explicit disposable URLs; no app configuration or worker/model proof.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID,createHash}=require('node:crypto');
const {createPool}=require('../../server/database/postgres'),{migrate}=require('../../db/postgres/migrate');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_LIFECYCLE_SCHEMA_ISOLATED==='1';
const targets={IDENTITY:'0105_ctf_lifecycle_projection.sql',CTF:'0007_ordered_projection_receipts.sql'};
const dirs={IDENTITY:path.resolve(__dirname,'../../db/postgres/identity-migrations'),CTF:path.resolve(__dirname,'../../db/postgres/workshop-migrations/ctf')};
const hash=s=>createHash('sha256').update(s).digest('hex');
// Error context only: never query text, parameter values, tokens or environment.
async function diagnosticQuery(client,sql,params,phase){
 try{return await client.query(sql,params);}catch(error){
  const diagnostic={phase,code:typeof error.code==='string'?error.code.slice(0,8):null};
  for(const key of ['position','internalPosition'])diagnostic[key]=/^[0-9]{1,10}$/.test(String(error[key]||''))?String(error[key]):null;
  diagnostic.where=typeof error.where==='string'?error.where.split('\n').filter(line=>/^PL\/pgSQL function [A-Za-z0-9_.]+\(/.test(line)).join('\n').slice(0,1024):null;
  console.error('CTF_SQL_CONTEXT '+JSON.stringify(diagnostic));throw error;
 }
}
function result(kind,operationId,sequence,data,outcome='applied'){return {version:1,kind,operationId,sequence:String(sequence),commandHash:'a'.repeat(64),outcome,data};}
test('CTF 2B SQL fresh/populated/noop, closed validators, grants, receipt replay and blocked scopes',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],databases=new Set();t.after(async()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_LIFECYCLE_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>typeof process.env[k]==='string'&&process.env[k]),'Explicit disposable pair required');
   const urls=keys.map(k=>new URL(process.env[k]));for(const u of urls){assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_ctf_lifecycle_/);}
   assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!databases.has(urls[0].pathname));databases.add(urls[0].pathname);
   const [runtime,migration]=keys.map(k=>createPool(process.env,k));pools.push(runtime,migration);stores[kind]={runtime,migration};
   assert.equal((await runtime.query('SELECT current_user AS role')).rows[0].role,`dvaia_${kind.toLowerCase()}_runtime`);
   assert.equal((await migration.query("SELECT to_regclass('dvaia_migrations.ledger') AS value")).rows[0].value,null);
   const prefix=fs.mkdtempSync(path.join(os.tmpdir(),'ctf2b-prefix-'));t.after(()=>fs.rmSync(prefix,{recursive:true,force:true}));
   for(const n of fs.readdirSync(dirs[kind]).filter(n=>n.endsWith('.sql')&&n<targets[kind]))fs.copyFileSync(path.join(dirs[kind],n),path.join(prefix,n));
   if(state==='POPULATED')await migrate(migration,prefix);
  }
  const {IDENTITY:i,CTF:c}=stores;let history;
  if(state==='POPULATED'){
   await require('../../server/database/postgres/ctfDb').seed(c.migration);
   await c.migration.query("UPDATE ctf.ctf_stages SET stage_name='Instructor sentinel' WHERE id=1");
   await c.migration.query("INSERT INTO ctf.ctf_participants(id,user_id,username) VALUES(501,701,'synthetic'),(502,702,'sibling')");
   await c.migration.query("INSERT INTO ctf.ctf_progress(id,participant_id,stage_id,status) VALUES(601,501,1,'in_progress'),(602,502,1,'completed')");
   await c.migration.query("INSERT INTO ctf.ctf_judgments(run_id,participant_id,stage_id,progress_id,stage_digest,verdict,accepted,metadata) VALUES($1,501,1,601,$2,'pass',1,'{\"retained\":true}')",[randomUUID(),'a'.repeat(64)]);
   history={progress:(await c.runtime.query('SELECT * FROM ctf.ctf_progress ORDER BY id')).rows,judgments:(await c.runtime.query('SELECT * FROM ctf.ctf_judgments ORDER BY run_id')).rows};
  }
  for(const kind of ['IDENTITY','CTF']){
   const {migration}=stores[kind],full=fs.mkdtempSync(path.join(os.tmpdir(),'ctf2b-full-'));t.after(()=>fs.rmSync(full,{recursive:true,force:true}));
   for(const n of fs.readdirSync(dirs[kind]).filter(n=>n.endsWith('.sql')&&n<=targets[kind]))fs.copyFileSync(path.join(dirs[kind],n),path.join(full,n));
   assert((await migrate(migration,full)).includes(targets[kind]));const ledger=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
   assert.deepEqual(await migrate(migration,full),[]);assert.deepEqual((await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
  }
  if(history){assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_progress ORDER BY id')).rows,history.progress);assert.deepEqual((await c.runtime.query('SELECT * FROM ctf.ctf_judgments ORDER BY run_id')).rows,history.judgments);assert.equal((await c.runtime.query('SELECT stage_name FROM ctf.ctf_stages WHERE id=1')).rows[0].stage_name,'Instructor sentinel');}
  for(const table of ['ctf_participant_bindings','ctf_progress_bindings','ctf_registration_reservations','ctf_attempt_admissions'])for(const permission of ['INSERT','UPDATE','DELETE','TRUNCATE'])assert.equal((await i.runtime.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[`identity.${table}`,permission])).rows[0].allowed,false);
  for(const permission of ['UPDATE','DELETE','TRUNCATE'])assert.equal((await c.runtime.query("SELECT has_table_privilege(current_user,'ctf.projection_receipts',$1) AS allowed",[permission])).rows[0].allowed,false);
  const beforeAdmission=(await i.runtime.query('SELECT * FROM identity.ctf_authority ORDER BY scope_key')).rows;
  const forgedBase={version:1,kind:'config_mutation',actorId:'701',operationId:randomUUID(),occurredAt:'2026-09-26T00:00:00.000Z',scope:{globalRevision:'0',ownerGeneration:null,ownerId:null,participantId:null,progressId:null,stageId:null,stageRevision:null},body:{key:'ctf_enabled',value:'true'}};
  for(const mutate of [v=>v.version=null,v=>v.actorId=null,v=>v.body.value='garbage',v=>{v.kind='global_reset';v.body={};v.scope.ownerId='701';v.scope.ownerGeneration='0';},v=>v.scope.globalRevision=0]){
   const v=structuredClone(forgedBase);mutate(v);const raw=JSON.stringify(v);
   await assert.rejects(i.runtime.query('SELECT * FROM identity.enqueue_ctf_user_command($1,$2,$3,$4,$5,$6)',['701','1','a'.repeat(64),v.operationId,raw,hash(raw)]),/CTF (command|authority scalar|config)/);
   assert.deepEqual((await i.runtime.query('SELECT * FROM identity.ctf_authority ORDER BY scope_key')).rows,beforeAdmission);
   assert.equal((await i.runtime.query('SELECT count(*)::integer AS n FROM identity.ctf_outbox')).rows[0].n,0);
  }
  const badDate=result('start',randomUUID(),1,{progressId:'1',status:'in_progress',startedAt:'2026-02-30T00:00:00.000Z',completedAt:null,completionTime:null,attemptsCount:0,failedAttempts:0,successfulAttempts:0,hintsUsed:0,hintPenaltyTotal:0});
  assert.equal((await c.runtime.query('SELECT ctf.valid_projection_result($1) AS valid',[JSON.stringify(badDate)])).rows[0].valid,false);
  const lastSequence=await qualifyIncarnation(i),resetSequence=String(lastSequence+1n),deniedSequence=String(lastSequence+2n);
  const op=randomUUID(),valid=result('global_reset',op,resetSequence,{removedParticipants:0});
  assert.equal((await c.runtime.query('SELECT ctf.valid_projection_result($1) AS valid',[JSON.stringify(valid)])).rows[0].valid,true);
  await assert.rejects(i.runtime.query('SELECT identity.ctf_result_matches($1::jsonb)',[JSON.stringify(valid)]),/permission denied/);
  const insert=raw=>c.runtime.query('INSERT INTO ctf.projection_receipts(sequence,operation_id,kind,command_hash,canonical_result,result_hash) VALUES($5,$1,\'global_reset\',$2,$3,$4)',[op,'a'.repeat(64),raw,hash(raw),resetSequence]);
  for(const value of [{...valid,version:'1'},{...valid,sequence:1},{...valid,data:{removedParticipants:0,extra:true}},{...valid,data:{removedParticipants:null}}])await assert.rejects(insert(JSON.stringify(value)),/constraint/);
  await assert.rejects(insert(JSON.stringify(valid).replace('"version":1','"version":1,"version":1')),/constraint/);
  await insert(JSON.stringify(valid));assert.equal((await c.runtime.query('SELECT canonical_result FROM ctf.projection_receipts WHERE operation_id=$1',[op])).rows[0].canonical_result,JSON.stringify(valid));
  await assert.rejects(insert(JSON.stringify(valid)),/unique/);await assert.rejects(c.migration.query('DELETE FROM ctf.projection_receipts WHERE operation_id=$1',[op]),/immutable/);
  // No activation by runtime. Privileged fixture seed establishes exact isolated pending event only.
  await i.migration.query("INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash) VALUES($4,$1,'global_reset',$2,$3)",[op,JSON.stringify({scope:{ownerId:null,stageId:null},body:{}}),'a'.repeat(64),resetSequence]);
  await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=$1,next_sequence=$2 WHERE scope_key='global'",[op,resetSequence]);
  const ack=v=>i.runtime.query('SELECT * FROM identity.ack_ctf_projection($1,$2,$3,$4,$5)',[v.operationId,v.sequence,v.commandHash,JSON.stringify(v),hash(JSON.stringify(v))]);
  assert.equal((await ack(valid)).rows[0].state,'applied');assert.equal((await ack(valid)).rows[0].state,'applied');await assert.rejects(ack({...valid,data:{removedParticipants:1}}),/replay mismatch/);
  const deniedOp=randomUUID(),denied=result('register',deniedOp,deniedSequence,{admitted:false,reason:'capacity_reached',participantId:null,recovered:false,active:false,banned:false,registeredAt:null},'capacity_reached');
  await i.migration.query("INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash) VALUES($4,$1,'register',$2,$3)",[deniedOp,JSON.stringify({scope:{ownerId:'703',stageId:null},body:{}}),'a'.repeat(64),deniedSequence]);
  await i.migration.query("INSERT INTO identity.ctf_authority(scope_key,owner_generation,lifecycle_state,pending_operation_id) VALUES('owner:703',0,'pending',$1)",[deniedOp]);await i.migration.query("UPDATE identity.ctf_authority SET next_sequence=$1 WHERE scope_key='global'",[deniedSequence]);
  await i.migration.query('INSERT INTO identity.ctf_registration_reservations(operation_id,sequence,owner_id,units) VALUES($1,$2,703,1)',[deniedOp,deniedSequence]);
  assert.equal((await ack(denied)).rows[0].state,'blocked');assert.equal((await ack(denied)).rows[0].state,'blocked');
  assert.equal((await i.runtime.query("SELECT state FROM identity.ctf_registration_reservations WHERE operation_id=$1",[deniedOp])).rows[0].state,'held');
  const scope=(await i.runtime.query("SELECT lifecycle_state,pending_operation_id,blocked_operation_id,applied_sequence::text FROM identity.ctf_authority WHERE scope_key='global'")).rows[0];assert.deepEqual(scope,{lifecycle_state:'blocked',pending_operation_id:null,blocked_operation_id:deniedOp,applied_sequence:resetSequence});
 }
});

async function qualifyIncarnation(i){
 const password='$2b$04$'+'a'.repeat(53),token='b'.repeat(64),adminToken='c'.repeat(64);
 await i.migration.query("INSERT INTO identity.users(id,username,email,password,role,admin_level) VALUES(701,'ctf-owner','owner@fixture.invalid',$1,'student',0),(702,'ctf-admin','admin@fixture.invalid',$1,'admin',1)",[password]);
 const ownerSession=(await i.migration.query("INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(701,$1,now()+interval '1 hour') RETURNING id",[token])).rows[0].id;
 const adminSession=(await i.migration.query("INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES(702,$1,now()+interval '1 hour') RETURNING id",[adminToken])).rows[0].id;
 await i.migration.query("UPDATE identity.ctf_authority SET lifecycle_state='ready' WHERE scope_key='global'");
 const seed=randomUUID();await i.migration.query(`INSERT INTO identity.ctf_config_binding VALUES(true,0,true,true,true,true,true,true,true,true,-1,-1,1000,0,0,0,0,0,$1)`,[seed]);
 await i.migration.query("INSERT INTO identity.ctf_authority(scope_key,lifecycle_state) VALUES('stage:1','ready')");
 await i.migration.query("INSERT INTO identity.ctf_stage_bindings VALUES(1,1,0,0,$1,1,true,'none','full',0,100,-1,0,$2)",['d'.repeat(64),seed]);
 const scope=async(owner=true,stage=false,participant=null)=>{const g=(await i.runtime.query("SELECT revision::text FROM identity.ctf_authority WHERE scope_key='global'")).rows[0];const o=(await i.runtime.query("SELECT owner_generation::text FROM identity.ctf_authority WHERE scope_key='owner:701'")).rows[0];return{globalRevision:g.revision,ownerId:owner?'701':null,ownerGeneration:owner?(o?.owner_generation||'0'):null,participantId:participant,stageId:stage?'1':null,stageRevision:stage?'0':null,progressId:null};};
 const enqueue=async(kind,body,sc,operation=randomUUID())=>{const client=await i.runtime.connect();try{await client.query('BEGIN');const time=(await client.query("SELECT date_trunc('milliseconds',transaction_timestamp()) AS now")).rows[0].now.toISOString();const command={version:1,kind,actorId:['global_reset','config_mutation'].includes(kind)?'702':'701',operationId:operation,occurredAt:time,scope:sc,body};const raw=JSON.stringify(command);const row=(await diagnosticQuery(client,'SELECT * FROM identity.enqueue_ctf_user_command($1,$2,$3,$4,$5,$6)',[command.actorId,['global_reset','config_mutation'].includes(kind)?adminSession:ownerSession,['global_reset','config_mutation'].includes(kind)?adminToken:token,operation,raw,hash(raw)],'enqueue')).rows[0];await client.query('COMMIT');return{row,command};}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}};
 const ack=async(event,data)=>{const r={...result(event.command.kind,event.command.operationId,event.row.sequence,data),commandHash:event.row.command_hash};const raw=JSON.stringify(r);return(await diagnosticQuery(i.runtime,'SELECT * FROM identity.ack_ctf_projection($1,$2,$3,$4,$5)',[r.operationId,r.sequence,r.commandHash,raw,hash(raw)],'acknowledge')).rows[0];};
 const body={username:'ctf-owner',email:null,teamName:null,teachingSessionToken:'synthetic',clientIp:null,userAgent:null};
 const registered=(id,time)=>({admitted:true,reason:null,participantId:id,recovered:false,active:true,banned:false,registeredAt:time});
 const first=await enqueue('register',body,await scope());const tuple=async op=>(await i.runtime.query('SELECT owner_generation_after::text,registration_disposition,registration_participant_before::text FROM identity.ctf_outbox WHERE operation_id=$1',[op])).rows[0];
 assert.deepEqual(await tuple(first.command.operationId),{owner_generation_after:'1',registration_disposition:'new',registration_participant_before:null});
 const replay=await enqueue('register',body,first.command.scope,first.command.operationId);assert.equal(replay.row.sequence,first.row.sequence);assert.equal((await tuple(first.command.operationId)).owner_generation_after,'1');
 const before=(await i.runtime.query('SELECT * FROM identity.ctf_authority ORDER BY scope_key')).rows;
 await assert.rejects(enqueue('global_reset',{},await scope(false)),/requires drained delivery/);assert.deepEqual((await i.runtime.query('SELECT * FROM identity.ctf_authority ORDER BY scope_key')).rows,before);
 const laterConfig=await enqueue('config_mutation',{key:'ctf_enabled',value:'true'},await scope(false));
 await ack(first,registered('901',first.command.occurredAt));await ack(first,registered('901',first.command.occurredAt));
 assert.equal((await i.runtime.query("SELECT global_revision::text FROM identity.ctf_participant_bindings WHERE owner_id=701")).rows[0].global_revision,first.command.scope.globalRevision);
 await ack(laterConfig,{key:'ctf_enabled',value:'true'});
 const start=await enqueue('start',{},await scope(true,true,'901'));
 const progress={progressId:'951',status:'in_progress',startedAt:start.command.occurredAt,completedAt:null,completionTime:null,attemptsCount:0,failedAttempts:0,successfulAttempts:0,hintsUsed:0,hintPenaltyTotal:0};await ack(start,progress);
 const historic=(await i.runtime.query('SELECT * FROM identity.ctf_progress_bindings WHERE progress_id=951')).rows[0];
 const recover=await enqueue('register',body,await scope());assert.deepEqual(await tuple(recover.command.operationId),{owner_generation_after:'1',registration_disposition:'active_recovery',registration_participant_before:'901'});await ack(recover,{...registered('901',first.command.occurredAt),recovered:true});
 assert.equal((await i.runtime.query("SELECT registered_at FROM identity.ctf_participant_bindings WHERE owner_id=701")).rows[0].registered_at.toISOString(),first.command.occurredAt);
 const reset=await enqueue('global_reset',{},await scope(false));await ack(reset,{removedParticipants:1});await ack(reset,{removedParticipants:1});
 assert.equal((await i.runtime.query("SELECT generation::text FROM graph_runtime.owners WHERE owner_key='[\"CTF\",\"701\"]'")).rows[0].generation,'1');
 const next=await enqueue('register',body,await scope());assert.deepEqual(await tuple(next.command.operationId),{owner_generation_after:'2',registration_disposition:'reactivate',registration_participant_before:'901'});
 await ack(next,registered('902',next.command.occurredAt));const nextStart=await enqueue('start',{},await scope(true,true,'902'));await ack(nextStart,{...progress,progressId:'952',startedAt:nextStart.command.occurredAt});
 assert.deepEqual((await i.runtime.query('SELECT * FROM identity.ctf_progress_bindings WHERE progress_id=951')).rows[0],historic);
 assert.equal((await i.runtime.query('SELECT owner_generation::text FROM identity.ctf_progress_bindings WHERE progress_id=952')).rows[0].owner_generation,'2');
 // Mutation of the server-derived tuple is forbidden even to the fixture owner.
 await assert.rejects(i.migration.query("UPDATE identity.ctf_outbox SET registration_disposition='new' WHERE operation_id=$1",[next.command.operationId]),/immutable/);
 await assert.rejects(i.migration.query('UPDATE identity.ctf_outbox SET owner_generation_after=99 WHERE operation_id=$1',[next.command.operationId]),/immutable/);
 for(const bad of [{after:'99',disposition:'new',prior:null},{after:'1',disposition:'active_recovery',prior:null},{after:'1',disposition:'invented',prior:null}]){
  const forged={...first.command,operationId:randomUUID()},raw=JSON.stringify(forged);
  await assert.rejects(i.migration.query(`INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash,canonical_command,owner_generation_after,registration_disposition,registration_participant_before)
   VALUES(1000,$1,'register',$2::jsonb,$3,$2,$4,$5,$6)`,[forged.operationId,raw,hash(raw),bad.after,bad.disposition,bad.prior]),/check constraint/);
 }
 return BigInt(nextStart.row.sequence);
}
