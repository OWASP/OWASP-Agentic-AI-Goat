'use strict';
// Owned disposable PostgreSQL only. Synthetic Windows records test schema, never
// native observation, executable recovery or installed/learner state.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto'),{performance}=require('node:perf_hooks');
const {owner,cases:ownerCases}=require('../fixtures/maintenanceWindowsOwnerSchemaCases');
const {isSupportedLocalAncestorBinding}=require('../../scripts/lib/setup-local-process-identity');
const {acquireApplicationMaintenanceLease}=require('../../server/services/applicationMaintenanceLease');
const {requiredStoreManifest}=require('../../db/postgres/initialize-application');
const {encodeReplayArtifacts,encodeCtfReplayBinding}=require('../../server/database/postgres/applicationMaintenanceReplayEncoding');
const CASES=['fresh','populated','concurrency'],HEX='b'.repeat(64),NAMES=['0001_maintenance_fence.sql','0002_local_recovery.sql','0003_canonical_inprocess_recovery.sql','0004_executable_recovery_admission.sql','0005_windows_owner_records.sql'];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function environments(env=process.env){
 assert.equal(env.PG_TEST_DISPOSABLE,'yes');let identity;
 return Object.fromEntries(CASES.map(name=>[name,Object.fromEntries(['RUNTIME','MIGRATION'].map(role=>{
  const raw=env[`PG_MAINTENANCE_V5_${name.toUpperCase()}_${role}_URL`];assert.equal(typeof raw,'string');const u=new URL(raw);
  assert(['postgres:','postgresql:'].includes(u.protocol));assert.equal(u.hostname,'127.0.0.1');assert.match(u.port,/^[1-9][0-9]*$/);assert(Number(u.port)<=65535);assert.equal(u.search,'');assert.equal(u.hash,'');assert.equal(u.username,`dvaia_identity_${role.toLowerCase()}`);
  const match=u.pathname.match(new RegExp(`^/dvaia_test_maintenance_v5_([a-f0-9]{12})_${name}$`));assert(match);const key=match[1]+':'+u.port;if(identity)assert.equal(key,identity);else identity=key;return[role,u.href];
 }))]));
}
async function bounded(promise,ms){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned schema deadline')),ms);})]);}finally{clearTimeout(timer);}}
async function transaction(q,work,{rollback=false}={}){await q('BEGIN');try{const value=await work();await q('SET CONSTRAINTS ALL IMMEDIATE');await q(rollback?'ROLLBACK':'COMMIT');return value;}catch(error){await q('ROLLBACK');throw error;}}
const denied=error=>['P0001','23514','23502','23503','23505','42501'].includes(error.code);
function diagnostic(error,location){
 const raw=error?.code||'',code=/^[A-Z0-9]{5}$/.test(raw)||/^APPLICATION_[A-Z0-9_]{1,96}$/.test(raw)||raw==='ERR_ASSERTION'?raw:'SCHEMA_FIXTURE_FAILURE';
 const kind=['AssertionError','TypeError','RangeError','SyntaxError'].includes(error?.name)?error.name:'Error';
 return{location,code,kind};
}
function observingClientFactory(Client,sqls,onFailure){return config=>{
 const client=new Client(config),query=client.query.bind(client);
 client.query=async(statement,args)=>{try{return await query(statement,args);}catch(error){
  const index=sqls.indexOf(statement);onFailure({code:/^[A-Z0-9]{5}$/.test(error?.code||'')?error.code:'QUERY_FAILURE',migration:index<0?'lease-query':NAMES[index]});throw error;
 }};return client;
};}
async function original(q,record,{prospective=true}={}){
 const op=randomUUID(),installation=(await q('SELECT installation_id FROM dvaia_maintenance.control')).rows[0].installation_id;
 const captured=record?.version===3&&isSupportedLocalAncestorBinding(record)?{...record,installationId:installation,operationId:op}:record;
 await q("UPDATE dvaia_maintenance.control SET epoch=epoch+1,operation_id=$1,state='dirty',finished_at=NULL WHERE singleton",[op]);
 const e=(await q('SELECT epoch FROM dvaia_maintenance.control')).rows[0].epoch,pub=randomUUID(),serialized=JSON.stringify(captured);
 await q('INSERT INTO dvaia_maintenance.epochs SELECT epoch,operation_id,owner_host_sha256,begun_at,NULL FROM dvaia_maintenance.control');
 await q("INSERT INTO dvaia_maintenance.epoch_bindings(epoch,operation_id,profile,workspace_sha256,store_manifest_sha256,publication_id,publication_sha256,source_manifest_sha256,owner_record,owner_record_sha256) VALUES($1,$2,'upgrade-canonical16-v1',$3,$3,$4,$3,$3,$5::jsonb,encode(sha256(convert_to($5::jsonb::text,'UTF8')),'hex'))",[e,op,HEX,pub,serialized]);
 for(const [i,s]of requiredStoreManifest.entries())await q('INSERT INTO dvaia_maintenance.epoch_stores VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[e,i+1,s.schema,'123456789',100+i,'dvaia_'+s.schema,s.runtimeRole,'dvaia_'+s.schema+'_migration',s.schema==='ctf'?'dvaia_ctf_delivery':null,HEX]);
 if(!prospective)return{e,op,pub,serialized,installation};
 const ids={identityStoreId:randomUUID(),ctfStoreId:randomUUID(),bootstrapId:randomUUID(),activationId:randomUUID()},ctf=encodeCtfReplayBinding({workspaceId:HEX,provisioningSha256:HEX,...ids});
 const artifacts=['administrator','ctf-authority','delivery','environment-publication','provisioning'].map(kind=>({kind,relativePath:kind==='environment-publication'?`additive-environment-${pub}.json`:kind==='delivery'?'ctf-delivery.json':kind+'.json',schemaVersion:kind==='ctf-authority'?2:1,bindingSha256:kind==='ctf-authority'?ctf.sha256:HEX,contentSha256:kind==='ctf-authority'?null:HEX,artifactId:kind==='ctf-authority'?ids.activationId:kind==='environment-publication'?pub:null}));
 const encoded=encodeReplayArtifacts(artifacts);
 await q("INSERT INTO dvaia_maintenance.epoch_replay_profiles(epoch,operation_id,profile,source_manifest_sha256,artifact_manifest_sha256,identity_store_id,ctf_store_id,bootstrap_id,activation_id,writer_policy) VALUES($1,$2,'canonical16-ctf-inprocess-v1',$3,$4,$5,$6,$7,$8,'inprocess-only')",[e,op,HEX,encoded.sha256,ids.identityStoreId,ids.ctfStoreId,ids.bootstrapId,ids.activationId]);
 for(const a of artifacts)await q('INSERT INTO dvaia_maintenance.epoch_replay_artifacts VALUES($1,$2,$3,$4,$5,$6,$7)',[e,a.kind,a.relativePath,a.schemaVersion,a.bindingSha256,a.contentSha256,a.artifactId]);
 await q("INSERT INTO dvaia_maintenance.ctf_journal_lock_intents VALUES($1,$2,'original',$2,NULL,$3,$4,encode(sha256(convert_to($5::jsonb::text,'UTF8')),'hex'))",[e,op,randomUUID(),ctf.sha256,serialized]);
 await q("INSERT INTO dvaia_maintenance.epoch_execution_admissions(epoch,operation_id,profile,launch_policy,source_manifest_sha256,owner_record_sha256,launcher_policy_sha256) VALUES($1,$2,'canonical16-ctf-recovery-v1','exclusive-inprocess-no-helpers-v1',$3,encode(sha256(convert_to($4::jsonb::text,'UTF8')),'hex'),$3)",[e,op,HEX,serialized]);
 return{e,op,pub,serialized,ctf,encoded,installation};
}
function contextOwner(record,x){return record?.version===3&&isSupportedLocalAncestorBinding(record)?{...record,operationId:x.op,installationId:x.installation}:record;}
async function phase(q,x,id,name,time){await q('INSERT INTO dvaia_maintenance.recovery_phase_receipts VALUES($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,clock_timestamp()))',[x.e,id,name,x.op,x.encoded.sha256,HEX,['published','finished'].includes(name)?x.pub:null,['published','finished'].includes(name)?HEX:null,time||null]);}
async function attempt(q,x,record){
 const id=randomUUID(),bytes=JSON.stringify(contextOwner(record,x));await q("INSERT INTO dvaia_maintenance.recovery_attempts(attempt_id,epoch,original_operation_id,recovery_owner_record,proof_digest,state) VALUES($1,$2,$3,$4::jsonb,$5,'claimed')",[id,x.e,x.op,bytes,HEX]);
 await q("INSERT INTO dvaia_maintenance.ctf_journal_lock_intents VALUES($1,$2,'recovery',$3,$2,$4,$5,encode(sha256(convert_to($6::jsonb::text,'UTF8')),'hex'))",[x.e,id,x.op,randomUUID(),x.ctf.sha256,bytes]);await phase(q,x,id,'claimed');return{id,bytes};
}
async function abandon(q,x,a,observer){
 const time=(await q('SELECT clock_timestamp()::text AS value')).rows[0].value;
 await q("UPDATE dvaia_maintenance.recovery_attempts SET state='failed',finished_at=$2 WHERE attempt_id=$1",[a.id,time]);
 await q("INSERT INTO dvaia_maintenance.recovery_abandonment_observations(epoch,attempt_id,operation_id,prior_state,prior_owner_sha256,observer_record,observer_record_sha256,proof_sha256,finished_at) VALUES($1,$2,$3,'claimed',encode(sha256(convert_to($4::jsonb::text,'UTF8')),'hex'),$5::jsonb,encode(sha256(convert_to($5::jsonb::text,'UTF8')),'hex'),$6,$7)",[x.e,a.id,x.op,a.bytes,JSON.stringify(contextOwner(observer,x)),HEX,time]);
}
async function publish(q,x,a){await q("UPDATE dvaia_maintenance.recovery_attempts SET state='reconciled' WHERE attempt_id=$1",[a.id]);await phase(q,x,a.id,'reconciled');await q("UPDATE dvaia_maintenance.recovery_attempts SET state='published',publication_id=$2,publication_sha256=$3 WHERE attempt_id=$1",[a.id,x.pub,HEX]);await phase(q,x,a.id,'published');}
async function claim(q,x,a,record){return(await q("INSERT INTO dvaia_maintenance.recovery_finish_claims(epoch,attempt_id,ordinal,previous_claim_id,operation_id,publication_id,publication_sha256,artifact_manifest_sha256,owner_record,owner_record_sha256,proof_sha256) VALUES($1,$2,NULL,NULL,$3,$4,$5,$6,$7::jsonb,encode(sha256(convert_to($7::jsonb::text,'UTF8')),'hex'),$5) RETURNING claim_id",[x.e,a.id,x.op,x.pub,HEX,x.encoded.sha256,JSON.stringify(contextOwner(record,x))])).rows[0].claim_id;}
async function finish(q,x,a,claimId,exactTime){
 const time=exactTime||(await q('SELECT clock_timestamp()::text AS value')).rows[0].value;
 if(a){await q("UPDATE dvaia_maintenance.recovery_attempts SET state='finished',finished_at=$2 WHERE attempt_id=$1",[a.id,time]);await phase(q,x,a.id,'finished',time);}
 await q('INSERT INTO dvaia_maintenance.epoch_finish_receipts VALUES($1,$2,$3,$4,$5,$6,$7)',[x.e,x.op,a?.id||null,x.encoded.sha256,x.pub,HEX,time]);
 if(a)await q("INSERT INTO dvaia_maintenance.recovery_finish_claim_results VALUES($1,$2,$3,'finished',$4)",[x.e,a.id,claimId,time]);
 await q("UPDATE dvaia_maintenance.control SET state='clean',finished_at=$1 WHERE singleton",[time]);await q('UPDATE dvaia_maintenance.epochs SET finished_at=$2 WHERE epoch=$1',[x.e,time]);
}

test('v5 fixture rejects non-owned URLs and redacts diagnostics before connecting',()=>{
 const env={PG_TEST_DISPOSABLE:'yes'};for(const name of CASES)for(const role of ['RUNTIME','MIGRATION'])env[`PG_MAINTENANCE_V5_${name.toUpperCase()}_${role}_URL`]=`postgresql://dvaia_identity_${role.toLowerCase()}@127.0.0.1:54321/dvaia_test_maintenance_v5_abcdef012345_${name}`;
 assert.equal(Object.keys(environments(env)).length,3);const key='PG_MAINTENANCE_V5_FRESH_RUNTIME_URL';for(const raw of [undefined,env[key].replace('127.0.0.1','localhost'),env[key]+'?password=private',env[key].replace('abcdef012345','123456abcdef'),env[key].replace('_runtime@','_migration@')])assert.throws(()=>environments({...env,[key]:raw}));assert.deepEqual(diagnostic({message:'private',code:'42501'},'fixed'),{location:'fixed',code:'42501',kind:'Error'});assert.deepEqual(diagnostic({message:'private credentials',name:'AssertionError',code:'ERR_ASSERTION',actual:'private'},'fixed'),{location:'fixed',code:'ERR_ASSERTION',kind:'AssertionError'});assert.equal(diagnostic({code:'APPLICATION_MAINTENANCE_UPGRADE_UNCERTAIN'},'fixed').code,'APPLICATION_MAINTENANCE_UPGRADE_UNCERTAIN');assert(!JSON.stringify(diagnostic({code:'private-secret',name:'private-secret',message:'private-secret'},'fixed')).includes('private-secret'));
});

test('v5 query observer is transparent and retains only closed migration names and SQLSTATE',async()=>{
 const original=Object.assign(Error('private query credentials'),{code:'42601',connectionString:'private'}),events=[];
 class ControlledClient{query(statement,args){assert.equal(args[0],'private parameter');if(statement==='known migration')return Promise.reject(original);return Promise.resolve({rows:[{value:1}]});}}
 const client=observingClientFactory(ControlledClient,['known migration'],event=>events.push(event))({});
 await assert.rejects(client.query('known migration',['private parameter']),error=>error===original);assert.deepEqual(events,[{code:'42601',migration:NAMES[0]}]);assert(!JSON.stringify(events).includes('private'));assert.deepEqual(await client.query('other',['private parameter']),{rows:[{value:1}]});
});

test('0005 Windows owner schema qualification',{skip:process.env.APPLICATION_MAINTENANCE_V5_ISOLATED!=='1',timeout:180000},async()=>{
 assert.equal(process.env.APPLICATION_MAINTENANCE_V5_MAIN_WORKSPACE,'1');const envs=environments(),{Client}=require('pg'),root=await fs.realpath(process.cwd()),evidence=await fs.realpath(process.env.MAINTENANCE_V5_EVIDENCE);assert.equal(root,path.resolve(__dirname,'../..'));assert.equal(root,await fs.realpath(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));assert.equal(path.dirname(evidence),path.join(root,'tasks/maintenance-v5-native-evidence'));assert.match(path.basename(evidence),/^run-[A-Za-z0-9_-]+$/);const metadata=await fs.stat(evidence);assert.equal(metadata.uid,process.getuid());assert.equal(metadata.mode&0o777,0o700);
 const clients=new Set(),leases=new Set(),state={passed:false,cases:[],limits:['Synthetic owner/store inputs only; no native Windows or recovery proof','Three owned PostgreSQL stores; no application/learner stores']};let primary;
 const checkpoint=async location=>{state.location=location;await fs.writeFile(path.join(evidence,'maintenance-v5-result.json'),JSON.stringify(state,null,2)+'\n',{mode:0o600});};
 const connect=async url=>{assert(clients.size<6);const c=new Client({connectionString:url,connectionTimeoutMillis:2000,statement_timeout:3000,query_timeout:4000});clients.add(c);c.on('error',()=>{});await c.connect();return c;};
 const close=async c=>{await bounded(c.end(),4000);clients.delete(c);};
 const sqls=await Promise.all(NAMES.map(name=>fs.readFile(path.join(root,'db/postgres/maintenance-migrations',name),'utf8'))),vectors=ownerCases();
 try{for(const name of CASES){
  await checkpoint(name+'-bootstrap');const c=await connect(envs[name].MIGRATION),q=c.query.bind(c);
  await transaction(q,async()=>{await q('SELECT pg_advisory_xact_lock(1886610804,90)');await q('CREATE SCHEMA dvaia_maintenance');await q('REVOKE ALL ON SCHEMA dvaia_maintenance FROM PUBLIC');await q('CREATE TABLE dvaia_maintenance.ledger(name text PRIMARY KEY,checksum text NOT NULL)');await q(sqls[0]);await q('INSERT INTO dvaia_maintenance.ledger VALUES($1,$2)',[NAMES[0],sha(sqls[0])]);await q("INSERT INTO dvaia_maintenance.control(singleton,version,installation_id,database_oid,epoch,state,operation_id,owner_host_sha256,finished_at) SELECT true,1,$1,oid,1,'clean',$2,$3,clock_timestamp() FROM pg_database WHERE datname=current_database()",[randomUUID(),randomUUID(),HEX]);await q('INSERT INTO dvaia_maintenance.epochs SELECT epoch,operation_id,owner_host_sha256,begun_at,finished_at FROM dvaia_maintenance.control');});
  const apply=async i=>transaction(q,async()=>{await q('SELECT pg_advisory_xact_lock(1886610804,90)');const existing=(await q('SELECT checksum FROM dvaia_maintenance.ledger WHERE name=$1',[NAMES[i]])).rows;if(existing.length){assert.equal(existing[0].checksum,sha(sqls[i]));return;}await q(sqls[i]);await q('INSERT INTO dvaia_maintenance.ledger VALUES($1,$2)',[NAMES[i],sha(sqls[i])]);});
  const runtimeUpgrade=async()=>{await checkpoint(name+'-actual-lease-acquire');const lease=await acquireApplicationMaintenanceLease({mode:'maintenance',env:{IDENTITY_DATABASE_URL:envs[name].RUNTIME,IDENTITY_MIGRATION_DATABASE_URL:envs[name].MIGRATION,PG_TLS:'disable',PG_POOL_BUDGET:'16'},clientFactory:observingClientFactory(Client,sqls,value=>{state.databaseFailure=value;}),timeoutMs:3000,probeMs:30000});leases.add(lease);try{await checkpoint(name+'-actual-lease-clean');const clean=await lease.assertClean();await checkpoint(name+'-actual-lease-upgrade');const ready=await lease.upgradeExecutionSchema(clean);await checkpoint(name+'-actual-lease-ready');assert.deepEqual(ready,clean);assert.deepEqual(await lease.assertExecutionReady(),clean);await assert.rejects(lease.upgradeExecutionSchema(clean),{code:'APPLICATION_MAINTENANCE_UPGRADE_UNAVAILABLE'});}finally{await lease.close();leases.delete(lease);}};
  if(name==='fresh'){await checkpoint(name+'-actual-upgrade1-to5');await runtimeUpgrade();await runtimeUpgrade();}
  for(let i=1;i<4;i++)await apply(i);
  const legacy={version:2,ancestry:'complete-supported-chain',fixture:'historical-v2-preserved'};await transaction(q,async()=>{const x=await original(q,legacy,{prospective:false});const time=(await q('SELECT clock_timestamp()::text AS value')).rows[0].value;await q("UPDATE dvaia_maintenance.control SET state='clean',finished_at=$1 WHERE singleton",[time]);await q('UPDATE dvaia_maintenance.epochs SET finished_at=$2 WHERE epoch=$1',[x.e,time]);await q("INSERT INTO dvaia_maintenance.recovery_attempts(attempt_id,epoch,original_operation_id,recovery_owner_record,proof_digest,state,finished_at) VALUES($1,$2,$3,$4::jsonb,$5,'failed',$6)",[randomUUID(),x.e,x.op,JSON.stringify({historical:'unqualified-object'}),HEX,time]);});
  if(name==='populated'){await q('CREATE TABLE public.retained_probe(id int PRIMARY KEY,value text)');await q("INSERT INTO public.retained_probe VALUES(1,'preserved')");}
  const history=async()=>JSON.stringify((await q('SELECT row_to_json(a) AS value FROM dvaia_maintenance.recovery_attempts a ORDER BY attempt_id')).rows),before=await history();
  await checkpoint(name+'-migration-gates');await assert.rejects(transaction(q,()=>q(sqls[4])),e=>e.code==='P0001');await assert.rejects(transaction(q,async()=>{await q('SELECT pg_advisory_xact_lock(1886610804,90)');await q("UPDATE dvaia_maintenance.control SET state='dirty',finished_at=NULL WHERE singleton");await q(sqls[4]);}),e=>e.code==='P0001');
  if(name!=='fresh'){await transaction(q,async()=>{await q('SELECT pg_advisory_xact_lock(1886610804,90)');await q(sqls[4]);},{rollback:true});assert.equal((await q("SELECT to_regprocedure('dvaia_maintenance.supported_owner_record(jsonb)') IS NULL AS absent")).rows[0].absent,true);}
  await apply(4);await apply(4);await runtimeUpgrade();assert.equal(await history(),before);if(name==='populated')assert.deepEqual((await q('SELECT * FROM public.retained_probe')).rows,[{id:1,value:'preserved'}]);assert.deepEqual((await q('SELECT name,checksum FROM dvaia_maintenance.ledger ORDER BY name')).rows,NAMES.map((n,i)=>({name:n,checksum:sha(sqls[i])})));
  await checkpoint(name+'-validator-parity');for(const [label,value]of vectors.valid)assert.equal((await q('SELECT dvaia_maintenance.supported_owner_record($1::jsonb) AS admitted',[JSON.stringify(value)])).rows[0].admitted,true,label);for(const [label,value]of vectors.invalid)assert.equal((await q('SELECT dvaia_maintenance.supported_owner_record($1::jsonb) AS admitted',[value===undefined?null:JSON.stringify(value)])).rows[0].admitted,false,label);
  for(const expression of ['owner_exact_keys(NULL,NULL)','owner_windows_sid(NULL)','owner_windows_filetime(NULL)','owner_windows_tuple(NULL)','supported_owner_record(NULL)'])assert.equal((await q('SELECT dvaia_maintenance.'+expression+' AS admitted')).rows[0].admitted,false);
  assert.equal((await q('SELECT dvaia_maintenance.supported_owner_record($1::jsonb) AS admitted',[JSON.stringify(legacy)])).rows[0].admitted,true);assert.equal((await q('SELECT dvaia_maintenance.supported_owner_record($1::jsonb) AS admitted',[JSON.stringify(owner()).replace('"pid":500','"pid":500.0')])).rows[0].admitted,true);
  const runtime=await connect(envs[name].RUNTIME);await runtime.query('SELECT * FROM dvaia_maintenance.control');await runtime.query('SELECT * FROM dvaia_maintenance.ledger');for(const statement of ['SELECT dvaia_maintenance.supported_owner_record(NULL)','SELECT dvaia_maintenance.owner_windows_sid(NULL)',"UPDATE dvaia_maintenance.control SET state='clean'",'SELECT * FROM dvaia_maintenance.recovery_attempts'])await assert.rejects(runtime.query(statement),e=>e.code==='42501');await close(runtime);
  const privileges=(await q("SELECT bool_and(NOT has_function_privilege('dvaia_identity_runtime',p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) AS denied FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='dvaia_maintenance' AND p.proname IN ('owner_exact_keys','owner_windows_sid','owner_windows_filetime','owner_windows_tuple','supported_owner_record')")).rows[0].denied;assert.equal(privileges,true);
  await checkpoint(name+'-owner-sites');for(const [,record]of vectors.valid){await transaction(q,async()=>{const x=await original(q,record);await q('SET CONSTRAINTS ALL IMMEDIATE');await q('SET CONSTRAINTS ALL DEFERRED');await finish(q,x);},{rollback:true});await transaction(q,async()=>{const x=await original(q,record),a=await attempt(q,x,record);await abandon(q,x,a,record);await q('SET CONSTRAINTS ALL IMMEDIATE');await q('SET CONSTRAINTS ALL DEFERRED');},{rollback:true});await transaction(q,async()=>{const x=await original(q,record),a=await attempt(q,x,record);await publish(q,x,a);await q('SET CONSTRAINTS ALL IMMEDIATE');await q('SET CONSTRAINTS ALL DEFERRED');const id=await claim(q,x,a,record);await finish(q,x,a,id);},{rollback:true});}
  for(const [label,record]of vectors.invalid.filter(([,v])=>v&&typeof v==='object'&&!Array.isArray(v))){await assert.rejects(transaction(q,()=>original(q,record),{rollback:true}),denied,label);await assert.rejects(transaction(q,async()=>{const x=await original(q,owner());await attempt(q,x,record);},{rollback:true}),denied,label);await assert.rejects(transaction(q,async()=>{const x=await original(q,owner()),a=await attempt(q,x,owner());await abandon(q,x,a,record);},{rollback:true}),denied,label);await assert.rejects(transaction(q,async()=>{const x=await original(q,owner()),a=await attempt(q,x,owner());await publish(q,x,a);await claim(q,x,a,record);},{rollback:true}),denied,label);}
  await assert.rejects(transaction(q,async()=>{const x=await original(q,owner()),a=await attempt(q,x,owner());await publish(q,x,a);await claim(q,x,a,owner());await finish(q,x,a,null);},{rollback:true}),denied);
  if(name==='concurrency'){
   await checkpoint(name+'-common-row-barrier');const other=await connect(envs[name].MIGRATION),observer=await connect(envs[name].MIGRATION),pid=(await q('SELECT pg_backend_pid() AS pid')).rows[0].pid,otherPid=(await other.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
   await q('BEGIN');await q('SELECT * FROM dvaia_maintenance.control WHERE singleton FOR UPDATE');await other.query('BEGIN');const pending=other.query('UPDATE dvaia_maintenance.control SET epoch=epoch WHERE singleton');let pendingError;const tracked=pending.catch(e=>{pendingError=e;});const deadline=performance.now()+2000;let blocked=false;while(performance.now()<deadline){if((await observer.query('SELECT $2::int=ANY(pg_blocking_pids($1::int)) AS blocked',[otherPid,pid])).rows[0].blocked){blocked=true;break;}await new Promise(r=>setTimeout(r,10));}assert.equal(blocked,true);await q('ROLLBACK');await tracked;if(pendingError)throw pendingError;await other.query('ROLLBACK');await close(other);await close(observer);
  }
  await checkpoint(name+'-exact-original-completion');
  let completed;
  await transaction(q,async()=>{
   await q('SELECT pg_advisory_xact_lock(1886610804,90)');
   completed=await original(q,owner());
  });
  // Admission's deferred replay-profile guard must commit while dirty, as in
  // production. Finish is a later transaction with its own exact receipt.
  await checkpoint(name+'-exact-original-finish');
  await transaction(q,async()=>{
   await q('SELECT pg_advisory_xact_lock(1886610804,90)');
   const exactTime=(await q("SELECT (date_trunc('milliseconds',clock_timestamp())+interval '151 microseconds')::text AS value")).rows[0].value;
   await finish(q,completed,undefined,undefined,exactTime);
  });
  const receiptBefore=(await q('SELECT row_to_json(f) AS receipt FROM dvaia_maintenance.epoch_finish_receipts f WHERE epoch=$1',[completed.e])).rows[0].receipt;
  let leasedClient;
  const completionLease=await acquireApplicationMaintenanceLease({mode:'maintenance',env:{IDENTITY_DATABASE_URL:envs[name].RUNTIME,IDENTITY_MIGRATION_DATABASE_URL:envs[name].MIGRATION,PG_TLS:'disable',PG_POOL_BUDGET:'16'},clientFactory:config=>(leasedClient=new Client(config)),timeoutMs:3000,probeMs:30000});
  leases.add(completionLease);
  try{
   const exact=(await leasedClient.query('SELECT finished_at,finished_at=$1 AS rounded_matches FROM dvaia_maintenance.control',[new Date(receiptBefore.finished_at)])).rows[0];
   assert(exact.finished_at instanceof Date);assert.equal(exact.rounded_matches,false,'fixture must exercise lost microseconds');
   const expected={epoch:String(completed.e),sourceManifestSha256:HEX};
   assert.deepEqual(await completionLease.assertProspectiveOriginalComplete(),expected);
   assert.deepEqual(await completionLease.assertProspectiveOriginalComplete(),expected,'exact completion replay');
   // Each genuine SQL mutation remains uncommitted and is rolled back before
   // deferred schema validation; immutable receipt and history stay unchanged.
   for(const [sql,code]of [
    ["UPDATE dvaia_maintenance.control SET finished_at=finished_at+interval '1 microsecond' WHERE singleton",'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'],
    ["UPDATE dvaia_maintenance.control SET operation_id='11111111-1111-4111-8111-111111111111' WHERE singleton",'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'],
    ["UPDATE dvaia_maintenance.control SET epoch=epoch+1 WHERE singleton",'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'],
    ["UPDATE dvaia_maintenance.control SET state='dirty',finished_at=NULL WHERE singleton",'APPLICATION_MAINTENANCE_DIRTY']
   ]){
    await leasedClient.query('BEGIN');
    try{await leasedClient.query(sql);await assert.rejects(completionLease.assertProspectiveOriginalComplete(),{code});}
    finally{await leasedClient.query('ROLLBACK');}
    assert.deepEqual(await completionLease.assertProspectiveOriginalComplete(),expected);
   }
  }finally{await completionLease.close();leases.delete(completionLease);}
  assert.deepEqual((await q('SELECT row_to_json(f) AS receipt FROM dvaia_maintenance.epoch_finish_receipts f WHERE epoch=$1',[completed.e])).rows[0].receipt,receiptBefore);
  state.cases.push(name+'-exact-microsecond-completion-and-current-control-fences');
  assert.equal(await history(),before);state.cases.push(name+'-schema-parity-sites-gates-noop-rollback-privileges-retained');await close(c);
 }state.passed=true;}catch(error){primary=error;state.error=diagnostic(error,state.location);}finally{const leaseCleanup=await Promise.allSettled([...leases].map(l=>bounded(l.close(),4000)));const cleanup=await Promise.allSettled([...clients].map(async c=>{try{await bounded(c.query('ROLLBACK'),1000);}finally{await bounded(c.end(),4000);}}));state.cleanupComplete=leaseCleanup.every(r=>r.status==='fulfilled')&&cleanup.every(r=>r.status==='fulfilled');await checkpoint(state.location||'complete');}
 if(primary)throw Object.assign(Error('Owned Windows owner schema qualification failed'),state.error);assert.equal(state.cleanupComplete,true);
});
