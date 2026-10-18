'use strict';
// SQL-only fixture. Synthetic owner/store records never constitute recovery proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto'),{performance}=require('node:perf_hooks');
const {acquireApplicationMaintenanceLease:acquire}=require('../../server/services/applicationMaintenanceLease');
const {requiredStoreManifest}=require('../../db/postgres/initialize-application');
const {encodeReplayArtifacts,encodeCtfReplayBinding}=require('../../server/database/postgres/applicationMaintenanceReplayEncoding');
const control=require('../../server/database/postgres/applicationMaintenanceControl');
const CASES=['fresh','populated','concurrency'],HEX='b'.repeat(64),TABLES=['epoch_execution_admissions','recovery_abandonment_observations','recovery_finish_claims','recovery_finish_claim_results'];
const MIGRATIONS=[['0002_local_recovery.sql',control.MAINTENANCE_RECOVERY_SHA256],['0003_canonical_inprocess_recovery.sql',control.MAINTENANCE_REPLAY_SHA256],['0004_executable_recovery_admission.sql',control.MAINTENANCE_EXECUTION_SHA256]];
function environments(env=process.env){
 assert.equal(env.PG_TEST_DISPOSABLE,'yes');let identity;
 return Object.fromEntries(CASES.map(name=>{
  const urls=['RUNTIME','MIGRATION'].map(role=>{const raw=env[`PG_MAINTENANCE_V4_${name.toUpperCase()}_${role}_URL`];assert.equal(typeof raw,'string');const u=new URL(raw);
   assert(['postgres:','postgresql:'].includes(u.protocol));assert.equal(u.hostname,'127.0.0.1');assert.match(u.port,/^[1-9][0-9]*$/);assert(Number(u.port)<=65535);assert.equal(u.search,'');assert.equal(u.hash,'');assert.equal(u.username,'dvaia_identity_'+role.toLowerCase());
   const match=u.pathname.match(new RegExp('^/dvaia_test_maintenance_v4_([a-f0-9]{12})_'+name+'$'));assert(match);const key=match[1]+':'+u.port;if(identity)assert.equal(key,identity);else identity=key;return u.href;});
  return[name,{IDENTITY_DATABASE_URL:urls[0],IDENTITY_MIGRATION_DATABASE_URL:urls[1],PG_TLS:'disable',PG_POOL_BUDGET:'16'}];
 }));
}
function failure(error,location){return{location,code:/^[A-Z0-9]{5}$/.test(error?.code||'')?error.code:'SCHEMA_FIXTURE_FAILURE',position:/^[1-9][0-9]{0,8}$/.test(error?.position||'')?error.position:null,routine:/^[A-Za-z_][A-Za-z0-9_]{0,79}$/.test(error?.routine||'')?error.routine:null};}
const hash=x=>createHash('sha256').update(x).digest('hex');
function binding(root){return{version:1,profile:'upgrade-canonical16-v1',workspaceRoot:root,publicationId:randomUUID(),publicationSha256:HEX,sourceManifestSha256:'c'.repeat(64),stores:requiredStoreManifest.map((s,i)=>({storeKey:s.schema,clusterIdentifier:'123456789',databaseOid:i+100,databaseName:'dvaia_'+s.schema,runtimeRole:s.runtimeRole,migrationRole:'dvaia_'+s.schema+'_migration',deliveryRole:s.schema==='ctf'?'dvaia_ctf_delivery':null,endpointPolicySha256:'d'.repeat(64)}))};}
async function bounded(p,ms){let timer;try{return await Promise.race([p,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned schema cleanup deadline')),ms);})]);}finally{clearTimeout(timer);}}
async function installProfile(q,epoch,alter=()=>{}){
 const b=(await q('SELECT * FROM dvaia_maintenance.epoch_bindings WHERE epoch=$1',[epoch])).rows[0];
 const ids={identityStoreId:randomUUID(),ctfStoreId:randomUUID(),bootstrapId:randomUUID(),activationId:randomUUID()};
 const ctf=encodeCtfReplayBinding({workspaceId:b.workspace_sha256,provisioningSha256:HEX,...ids});
 const artifacts=['administrator','ctf-authority','delivery','environment-publication','provisioning'].map(kind=>({kind,relativePath:kind==='environment-publication'?`additive-environment-${b.publication_id}.json`:kind==='delivery'?'ctf-delivery.json':kind+'.json',schemaVersion:kind==='ctf-authority'?2:1,bindingSha256:kind==='ctf-authority'?ctf.sha256:HEX,contentSha256:kind==='ctf-authority'?null:HEX,artifactId:kind==='ctf-authority'?ids.activationId:kind==='environment-publication'?b.publication_id:null}));
 const encoded=encodeReplayArtifacts(artifacts),spec={artifacts,digest:encoded.sha256,originalLock:true};alter(spec);if(spec.rehash)spec.digest=encodeReplayArtifacts(spec.artifacts).sha256;
 await q("INSERT INTO dvaia_maintenance.epoch_replay_profiles(epoch,operation_id,profile,source_manifest_sha256,artifact_manifest_sha256,identity_store_id,ctf_store_id,bootstrap_id,activation_id,writer_policy) VALUES($1,$2,'canonical16-ctf-inprocess-v1',$3,$4,$5,$6,$7,$8,'inprocess-only')",[epoch,b.operation_id,b.source_manifest_sha256,spec.digest,ids.identityStoreId,ids.ctfStoreId,ids.bootstrapId,ids.activationId]);
 for(const a of spec.artifacts)await q('INSERT INTO dvaia_maintenance.epoch_replay_artifacts VALUES($1,$2,$3,$4,$5,$6,$7)',[epoch,a.kind,a.relativePath,a.schemaVersion,a.bindingSha256,a.contentSha256,a.artifactId]);
 if(spec.originalLock)await q("INSERT INTO dvaia_maintenance.ctf_journal_lock_intents VALUES($1,$2,'original',$2,NULL,$3,$4,$5)",[epoch,b.operation_id,randomUUID(),ctf.sha256,b.owner_record_sha256]);
 return {b,ids,encoded,ctf};
}

const ownerJson=JSON.stringify({version:2,ancestry:'complete-supported-chain',fixture:'synthetic-schema-only'});
async function executionAdmission(q,e,spec,change={}){
 const v={operation:spec.b.operation_id,source:spec.b.source_manifest_sha256,owner:spec.b.owner_record_sha256,profile:'canonical16-ctf-recovery-v1',...change};
 await q('INSERT INTO dvaia_maintenance.epoch_execution_admissions(epoch,operation_id,profile,launch_policy,source_manifest_sha256,owner_record_sha256,launcher_policy_sha256) VALUES($1,$2,$3,\'exclusive-inprocess-no-helpers-v1\',$4,$5,$6)',[e,v.operation,v.profile,v.source,v.owner,HEX]);
}
async function epoch(q,template,{admission=true,change={},storesFirst=true}={}){
 const op=randomUUID();await q("UPDATE dvaia_maintenance.control SET epoch=epoch+1,operation_id=$1,state='dirty',finished_at=NULL WHERE singleton",[op]);
 const e=(await q('SELECT epoch FROM dvaia_maintenance.control')).rows[0].epoch;
 await q('INSERT INTO dvaia_maintenance.epochs SELECT epoch,operation_id,owner_host_sha256,begun_at,NULL FROM dvaia_maintenance.control');
 await q('INSERT INTO dvaia_maintenance.epoch_bindings SELECT $1,$2,profile,reason_code,workspace_sha256,store_manifest_sha256,publication_id,publication_sha256,source_manifest_sha256,owner_record,owner_record_sha256,created_at FROM dvaia_maintenance.epoch_bindings WHERE epoch=$3',[e,op,template]);
 const stores=()=>q('INSERT INTO dvaia_maintenance.epoch_stores SELECT $1,ordinal,store_key,cluster_identifier,database_oid,database_name,runtime_role,migration_role,delivery_role,endpoint_policy_sha256 FROM dvaia_maintenance.epoch_stores WHERE epoch=$2',[e,template]);
 if(storesFirst)await stores();const spec=await installProfile(q,e);if(admission)await executionAdmission(q,e,spec,change);if(!storesFirst)await stores();return{epoch:e,spec};
}
async function phase(q,x,id,name,time){
 await q('INSERT INTO dvaia_maintenance.recovery_phase_receipts(epoch,attempt_id,phase,operation_id,binding_sha256,proof_sha256,publication_id,publication_sha256,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz,clock_timestamp()))',[x.epoch,id,name,x.spec.b.operation_id,x.spec.encoded.sha256,HEX,['published','finished'].includes(name)?x.spec.b.publication_id:null,['published','finished'].includes(name)?x.spec.b.publication_sha256:null,time||null]);
}
async function claimed(q,x,id=randomUUID()){
 await q("INSERT INTO dvaia_maintenance.recovery_attempts(attempt_id,epoch,original_operation_id,recovery_owner_record,proof_digest,state) VALUES($1,$2,$3,$4::jsonb,$5,'claimed')",[id,x.epoch,x.spec.b.operation_id,ownerJson,HEX]);
 await q("INSERT INTO dvaia_maintenance.ctf_journal_lock_intents VALUES($1,$2,'recovery',$3,$2,$4,$5,encode(sha256(convert_to($6::jsonb::text,'UTF8')),'hex'))",[x.epoch,id,x.spec.b.operation_id,randomUUID(),x.spec.ctf.sha256,ownerJson]);
 await phase(q,x,id,'claimed');return id;
}
async function advance(q,x,id,to){
 if(to==='reconciled')await q("UPDATE dvaia_maintenance.recovery_attempts SET state='reconciled' WHERE attempt_id=$1",[id]);
 else await q("UPDATE dvaia_maintenance.recovery_attempts SET state='published',publication_id=$2,publication_sha256=$3 WHERE attempt_id=$1",[id,x.spec.b.publication_id,x.spec.b.publication_sha256]);
 await phase(q,x,id,to);
}
async function now(q){return(await q('SELECT clock_timestamp()::text AS value')).rows[0].value;}
async function abandon(q,x,id,{before=false,prior='claimed',omit=false,observationOnly=false,change={}}={}){
 const time=await now(q),v={operation:x.spec.b.operation_id,time,owner:ownerJson,prior,...change};
 const observation=()=>q('INSERT INTO dvaia_maintenance.recovery_abandonment_observations(epoch,attempt_id,operation_id,prior_state,prior_owner_sha256,observer_record,observer_record_sha256,proof_sha256,finished_at) VALUES($1,$2,$3,$4,encode(sha256(convert_to($5::jsonb::text,\'UTF8\')),\'hex\'),$6::jsonb,encode(sha256(convert_to($6::jsonb::text,\'UTF8\')),\'hex\'),$7,$8)',[x.epoch,id,v.operation,v.prior,v.owner,ownerJson,HEX,v.time]);
 if(observationOnly){await observation();return time;}
 if(before&&!omit)await observation();await q("UPDATE dvaia_maintenance.recovery_attempts SET state='failed',finished_at=$2 WHERE attempt_id=$1",[id,time]);if(!before&&!omit)await observation();return time;
}
async function finishClaim(q,x,id,change={}){
 const v={publication:x.spec.b.publication_id,digest:x.spec.b.publication_sha256,artifact:x.spec.encoded.sha256,ordinal:null,previous:null,...change};
 return(await q('INSERT INTO dvaia_maintenance.recovery_finish_claims(epoch,attempt_id,ordinal,previous_claim_id,operation_id,publication_id,publication_sha256,artifact_manifest_sha256,owner_record,owner_record_sha256,proof_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,encode(sha256(convert_to($9::jsonb::text,\'UTF8\')),\'hex\'),$10) RETURNING claim_id,ordinal,previous_claim_id',[x.epoch,id,v.ordinal,v.previous,x.spec.b.operation_id,v.publication,v.digest,v.artifact,ownerJson,HEX])).rows[0];
}
async function finish(q,x,id=null,claim=null,change={}){
 const time=await now(q),v={time,publication:x.spec.b.publication_id,attempt:id,resultTime:time,...change};
 if(id){await q("UPDATE dvaia_maintenance.recovery_attempts SET state='finished',finished_at=$2 WHERE attempt_id=$1",[id,time]);await phase(q,x,id,'finished',time);}
 await q('INSERT INTO dvaia_maintenance.epoch_finish_receipts(epoch,operation_id,recovery_attempt_id,profile_binding_sha256,publication_id,publication_sha256,finished_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[x.epoch,x.spec.b.operation_id,v.attempt,x.spec.encoded.sha256,v.publication,x.spec.b.publication_sha256,time]);
 if(claim)await q('INSERT INTO dvaia_maintenance.recovery_finish_claim_results(epoch,attempt_id,claim_id,phase,finished_at) VALUES($1,$2,$3,\'finished\',$4)',[x.epoch,id,claim,v.resultTime]);
 await q("UPDATE dvaia_maintenance.control SET state='clean',finished_at=$1 WHERE singleton",[time]);await q('UPDATE dvaia_maintenance.epochs SET finished_at=$2 WHERE epoch=$1',[x.epoch,time]);
}
async function transaction(q,work,{rollback=false,isolation='READ COMMITTED'}={}){
 assert(['READ COMMITTED','REPEATABLE READ'].includes(isolation));await q('BEGIN ISOLATION LEVEL '+isolation);
 try{const result=await work();await q('SET CONSTRAINTS ALL IMMEDIATE');await q(rollback?'ROLLBACK':'COMMIT');return result;}catch(error){await q('ROLLBACK');throw error;}
}
async function waitBlocked(q,pid,blocker,deadline){
 while(performance.now()<deadline){const rows=(await q('SELECT $2::int=ANY(pg_blocking_pids($1::int)) AS blocked',[pid,blocker])).rows;if(performance.now()>=deadline)break;if(rows[0].blocked)return;await new Promise(r=>setTimeout(r,10));}
 throw Error('Exact backend blocking not observed');
}
const constraintCodes=e=>['P0001','P0002','23503','23505','23514','23502'].includes(e.code);

test('0004 admission rejects wrong nonce/port/role/protocol before creating resources',()=>{
 const valid={PG_TEST_DISPOSABLE:'yes'};for(const name of CASES)for(const role of ['RUNTIME','MIGRATION'])valid[`PG_MAINTENANCE_V4_${name.toUpperCase()}_${role}_URL`]=`postgresql://dvaia_identity_${role.toLowerCase()}@127.0.0.1:54321/dvaia_test_maintenance_v4_abcdef012345_${name}`;
 assert.equal(Object.keys(environments(valid)).length,3);
 const key='PG_MAINTENANCE_V4_FRESH_RUNTIME_URL';for(const value of [undefined,valid[key].replace('postgresql:','https:'),valid[key].replace(':54321',''),valid[key]+'?x=1',valid[key]+'#x',valid[key].replace('abcdef012345','123456abcdef'),valid[key].replace('_runtime@','_migration@'),valid[key].replace('127.0.0.1','localhost')])assert.throws(()=>environments({...valid,[key]:value}));
});
test('0004 diagnostics exclude private query and connection fields',()=>{const result=failure({code:'40001',position:'123',routine:'ExecUpdate',message:'private',connectionString:'private'},'race');assert.deepEqual(result,{location:'race',code:'40001',position:'123',routine:'ExecUpdate'});assert(!JSON.stringify(failure({code:'private',position:'0',routine:'/private'},'fixed')).includes('/private'));});
test('0004 blocker observation rejects late success and requires exact PID tuple',async()=>{const calls=[];await assert.rejects(waitBlocked(async(sql,args)=>{calls.push(args);const end=performance.now()+8;while(performance.now()<end){}return{rows:[{blocked:true}]};},31,42,performance.now()+3));assert.deepEqual(calls,[[31,42]]);});

test('0004 schema-only qualification',{skip:process.env.APPLICATION_MAINTENANCE_V4_ISOLATED!=='1',timeout:180000},async()=>{
 const envs=environments(),{Client}=require('pg'),root=await fs.realpath(process.cwd()),evidence=await fs.realpath(process.env.MAINTENANCE_V4_EVIDENCE);assert.equal(root,await fs.realpath(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));if(process.env.APPLICATION_MAINTENANCE_V4_MAIN_WORKSPACE==='1'){assert.equal(root,path.resolve(__dirname,'../..'));assert.equal(path.dirname(evidence),path.join(root,'tasks/maintenance-v4-native-evidence'));assert.match(path.basename(evidence),/^run-[A-Za-z0-9_-]+$/);const st=await fs.stat(evidence);assert.equal(st.uid,process.getuid());assert.equal(st.mode&0o777,0o700);}else assert.equal(path.dirname(root),evidence);
 const clients=new Set(),leases=new Set(),state={passed:false,cases:[],limits:['Three owned databases; synthetic16 tuples/owner records are SQL inputs only','No proof issuer, executable recovery, setup, model, browser or installed data']};let primary;
 const checkpoint=async label=>{state.location=label;await fs.writeFile(path.join(evidence,'maintenance-v4-result.json'),JSON.stringify(state,null,2)+'\n',{mode:0o600});};
 const connect=async url=>{assert(clients.size<6);const c=new Client({connectionString:url,connectionTimeoutMillis:2000,statement_timeout:3000,query_timeout:4000});clients.add(c);c.on('error',()=>{});await c.connect();return c;};
 const close=async c=>{await bounded(c.end(),4000);clients.delete(c);};
 const take=async(env,extra={})=>{const l=await acquire({env,mode:'maintenance',timeoutMs:3000,probeMs:30000,...extra});leases.add(l);return l;};
 const release=async l=>{await l.close();leases.delete(l);};
 const ordinary=async env=>{const l=await take(env);try{const t=await l.beginMaintenance();await l.finishMaintenance(t);return t;}finally{await release(l);}};
 const sqls=await Promise.all(MIGRATIONS.map(async([name,digest])=>{const bytes=await fs.readFile(path.join(root,'db/postgres/maintenance-migrations',name),'utf8');assert.equal(hash(bytes),digest);return bytes;}));
 try{for(const name of CASES){
  await checkpoint(name+'-bootstrap-prefixes');const env=envs[name];await ordinary(env);const c=await connect(env.IDENTITY_MIGRATION_DATABASE_URL),q=c.query.bind(c);
  const apply=async index=>transaction(q,async()=>{await q('SELECT pg_advisory_xact_lock(1886610804,90)');const [file,digest]=MIGRATIONS[index],row=(await q('SELECT checksum FROM dvaia_maintenance.ledger WHERE name=$1',[file])).rows;if(row.length)assert.equal(row[0].checksum,digest);else{await q(sqls[index]);await q('INSERT INTO dvaia_maintenance.ledger VALUES($1,$2)',[file,digest]);}});
  await apply(0);await ordinary(env);const l=await take(env);const template=await l.beginRecoveryEligible(binding(root));await l.finishMaintenance(template);await release(l);
  // Nonempty historical failed attempt predates0003 and has no new receipts.
  const historical=randomUUID();await q("INSERT INTO dvaia_maintenance.recovery_attempts(attempt_id,epoch,original_operation_id,recovery_owner_record,proof_digest,state,finished_at) VALUES($1,$2,$3,$4::jsonb,$5,'failed',clock_timestamp())",[historical,template.epoch,template.operationId,ownerJson,HEX]);
  if(name==='populated'){await q('CREATE TABLE public.retained_probe(id int PRIMARY KEY,value text)');await q("INSERT INTO public.retained_probe VALUES(1,'nonempty-preserved')");}
  const history=async()=>JSON.stringify((await q('SELECT row_to_json(a) AS value FROM dvaia_maintenance.recovery_attempts a WHERE attempt_id=$1',[historical])).rows);
  const retained=await history();await apply(1);await ordinary(env);const oldLedger=(await q('SELECT * FROM dvaia_maintenance.ledger ORDER BY name')).rows;
  await checkpoint(name+'-install-gates');await assert.rejects(transaction(q,()=>q(sqls[2])),e=>e.code==='P0001');
  await assert.rejects(transaction(q,async()=>{await q('SELECT pg_advisory_xact_lock(1886610804,90)');await q("UPDATE dvaia_maintenance.control SET state='dirty',finished_at=NULL WHERE singleton");await q(sqls[2]);}),e=>e.code==='P0001');
  await transaction(q,async()=>{await q('SELECT pg_advisory_xact_lock(1886610804,90)');await q(sqls[2]);assert.notEqual((await q("SELECT to_regclass('dvaia_maintenance.epoch_execution_admissions')::text AS value")).rows[0].value,null);},{rollback:true});
  assert.equal((await q("SELECT to_regclass('dvaia_maintenance.epoch_execution_admissions') AS value")).rows[0].value,null);assert.deepEqual((await q('SELECT * FROM dvaia_maintenance.ledger ORDER BY name')).rows,oldLedger);
  await apply(2);await apply(2);await ordinary(env);assert.equal(await history(),retained);if(name==='populated')assert.deepEqual((await q('SELECT * FROM public.retained_probe')).rows,[{id:1,value:'nonempty-preserved'}]);state.cases.push(name+'-fresh-prefix1-4-gates-rollback-populated-noop');
  // Actual lease/control, with a fixture delegate injecting the schema extension
  // inside the same real admission transaction; this is not a proof capability.
  let injected=false,extendedSpec;
  const extended=await take(env,{clientFactory:config=>{const raw=new Client(config),query=raw.query.bind(raw);raw.query=async(statement,args)=>{if(statement==='COMMIT'&&!injected){injected=true;const e=(await query('SELECT epoch FROM dvaia_maintenance.control')).rows[0].epoch;extendedSpec=await installProfile(query,e);await executionAdmission(query,e,extendedSpec);}return query(statement,args);};return raw;}});
  const extendedToken=await extended.beginRecoveryEligible(binding(root));await assert.rejects(extended.finishMaintenance(extendedToken),{code:'APPLICATION_MAINTENANCE_RECOVERY_PROOF_UNAVAILABLE'});await release(extended);
  await transaction(q,()=>finish(q,{epoch:extendedToken.epoch,spec:extendedSpec}));state.cases.push(name+'-generic-extended-finish-denied');
  for(const mutation of ["DELETE FROM dvaia_maintenance.ledger WHERE name='0003_canonical_inprocess_recovery.sql'","UPDATE dvaia_maintenance.ledger SET checksum=repeat('0',64) WHERE name='0004_executable_recovery_admission.sql'","INSERT INTO dvaia_maintenance.ledger VALUES('0005_unexpected.sql',repeat('0',64))"]){
   let raw;const guard=await take(env,{clientFactory:config=>(raw=new Client(config))});
   try{await raw.query('BEGIN');await raw.query(mutation);await assert.rejects(guard.assertClean(),{code:'APPLICATION_MAINTENANCE_VERSION_MISMATCH'});await raw.query('ROLLBACK');await guard.assertClean();}finally{await raw.query('ROLLBACK');await release(guard);}
  }state.cases.push(name+'-actual-malformed-ledger-denied');
  const make=opts=>transaction(q,()=>epoch(q,template.epoch,opts));
  const rollbackCase=async(label,work,negative=true)=>{await checkpoint(name+'-'+label);if(negative)await assert.rejects(transaction(q,work,{rollback:true}),constraintCodes);else await transaction(q,work,{rollback:true});state.cases.push(name+'-'+label);};
  for(const change of [{operation:randomUUID()},{source:'0'.repeat(64)},{owner:'0'.repeat(64)},{profile:'other'}])await rollbackCase('bad-admission-'+Object.keys(change)[0],()=>epoch(q,template.epoch,{change}));
  for(const storesFirst of [true,false])await rollbackCase('admission-order-'+storesFirst,()=>epoch(q,template.epoch,{storesFirst}),false);
  await rollbackCase('duplicate-admission',async()=>{const x=await epoch(q,template.epoch);await executionAdmission(q,x.epoch,x.spec);});
  const prior=await make({admission:false});await rollbackCase('retroactive-admission',()=>executionAdmission(q,prior.epoch,prior.spec));
  await rollbackCase('missing-profile-parent',()=>q("INSERT INTO dvaia_maintenance.epoch_execution_admissions(epoch,operation_id,profile,launch_policy,source_manifest_sha256,owner_record_sha256,launcher_policy_sha256) VALUES($1,$2,'canonical16-ctf-recovery-v1','exclusive-inprocess-no-helpers-v1',$3,$3,$3)",[template.epoch,template.operationId,HEX]));
  for(const priorState of ['claimed','reconciled'])for(const before of [true,false])await rollbackCase('abandon-'+priorState+'-'+before,async()=>{const x=await epoch(q,template.epoch),id=await claimed(q,x);if(priorState==='reconciled')await advance(q,x,id,'reconciled');await abandon(q,x,id,{prior:priorState,before});await claimed(q,x);},false);
  for(const [label,options]of [['missing',{omit:true}],['wrong-prior',{prior:'reconciled'}],['wrong-owner',{change:{owner:JSON.stringify({version:2,ancestry:'complete-supported-chain',wrong:true})}}],['wrong-operation',{change:{operation:randomUUID()}}],['wrong-time',{change:{time:'2000-01-01 00:00:00+00'}}]])await rollbackCase('abandon-'+label,async()=>{const x=await epoch(q,template.epoch),id=await claimed(q,x);await abandon(q,x,id,options);});
  await rollbackCase('orphan-observation',async()=>{const x=await epoch(q,template.epoch),id=await claimed(q,x);await abandon(q,x,id,{observationOnly:true});});
  await rollbackCase('abandon-wrong-phase-count',async()=>{const x=await epoch(q,template.epoch),id=await claimed(q,x);await phase(q,x,id,'reconciled');await abandon(q,x,id);});
  const original=await make();await transaction(q,()=>finish(q,original));assert.equal((await q('SELECT recovery_attempt_id FROM dvaia_maintenance.epoch_finish_receipts WHERE epoch=$1',[original.epoch])).rows[0].recovery_attempt_id,null);state.cases.push(name+'-original-no-attempt-finish');
  const published=async()=>{const x=await make();x.id=await transaction(q,()=>claimed(q,x));await transaction(q,()=>advance(q,x,x.id,'reconciled'));await transaction(q,()=>advance(q,x,x.id,'published'));return x;};
  const originalPublisher=await published();await transaction(q,()=>finish(q,originalPublisher,originalPublisher.id));assert.equal((await q('SELECT count(*)::int n FROM dvaia_maintenance.recovery_finish_claims WHERE epoch=$1',[originalPublisher.epoch])).rows[0].n,0);state.cases.push(name+'-original-live-publisher-no-claim-finish-schema-only');
  const x=await published();for(const change of [{ordinal:1},{previous:randomUUID()},{publication:randomUUID()},{digest:'0'.repeat(64)},{artifact:'0'.repeat(64)}])await rollbackCase('bad-finish-claim-'+Object.keys(change)[0],()=>finishClaim(q,x,x.id,change));
  const first=await transaction(q,()=>finishClaim(q,x,x.id)),second=await transaction(q,()=>finishClaim(q,x,x.id));assert.equal(first.ordinal,1);assert.equal(second.ordinal,2);assert.equal(second.previous_claim_id,first.claim_id);
  await rollbackCase('missing-result',()=>finish(q,x,x.id));await rollbackCase('stale-result',()=>finish(q,x,x.id,first.claim_id));await rollbackCase('result-time',()=>finish(q,x,x.id,second.claim_id,{resultTime:'2000-01-01 00:00:00+00'}));await rollbackCase('result-publication',()=>finish(q,x,x.id,second.claim_id,{publication:randomUUID()}));
  await transaction(q,()=>finish(q,x,x.id,second.claim_id));assert.equal((await q('SELECT claim_id FROM dvaia_maintenance.recovery_finish_claim_results WHERE epoch=$1',[x.epoch])).rows[0].claim_id,second.claim_id);state.cases.push(name+'-latest-claim-result-finish');
  // Rows exist in all four tables; zero-row immutable probes cannot pass this check.
  const abandoned=await make(),failedId=await transaction(q,()=>claimed(q,abandoned));await transaction(q,()=>abandon(q,abandoned,failedId));
  for(const table of TABLES){assert((await q(`SELECT count(*)::int n FROM dvaia_maintenance.${table}`)).rows[0].n>0);await assert.rejects(q(`UPDATE dvaia_maintenance.${table} SET epoch=epoch`),e=>e.code==='P0001');await assert.rejects(q(`DELETE FROM dvaia_maintenance.${table}`),e=>e.code==='P0001');}
  const runtime=await connect(env.IDENTITY_DATABASE_URL);for(const table of TABLES){for(const statement of [`SELECT * FROM dvaia_maintenance.${table}`,`DELETE FROM dvaia_maintenance.${table}`,`UPDATE dvaia_maintenance.${table} SET epoch=epoch`,`INSERT INTO dvaia_maintenance.${table} SELECT * FROM dvaia_maintenance.${table}`])await assert.rejects(runtime.query(statement),e=>e.code==='42501');const acl=(await q("SELECT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=$1::regclass AND a.grantee=0) AS granted",['dvaia_maintenance.'+table])).rows[0];assert.equal(acl.granted,false);}
  const functions=['serialize_execution_write','guard_execution_admission','guard_finish_claim','check_execution_epoch'];for(const fn of functions)await assert.rejects(runtime.query(`SELECT dvaia_maintenance.${fn}()`),e=>e.code==='42501');
  const acl=(await q("SELECT p.proname,has_function_privilege('dvaia_identity_runtime',p.oid,'EXECUTE') AS runtime,EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='dvaia_maintenance' AND p.proname=ANY($1::text[])",[functions])).rows;assert.equal(acl.length,4);assert(acl.every(r=>!r.runtime&&!r.public));await close(runtime);state.cases.push(name+'-immutable-ACL');
  if(name==='concurrency'){
   const a=await connect(env.IDENTITY_MIGRATION_DATABASE_URL),b=await connect(env.IDENTITY_MIGRATION_DATABASE_URL),qa=a.query.bind(a),qb=b.query.bind(b),apid=(await qa('SELECT pg_backend_pid() AS pid')).rows[0].pid,bpid=(await qb('SELECT pg_backend_pid() AS pid')).rows[0].pid;
   const start=async isolation=>{for(const query of [qa,qb]){await query('BEGIN ISOLATION LEVEL '+isolation);await query('SELECT epoch FROM dvaia_maintenance.control');}};
   const rollbackBoth=async()=>{const results=await bounded(Promise.allSettled([qa('ROLLBACK'),qb('ROLLBACK')]),5000);assert(results.every(r=>r.status==='fulfilled'));};
   const competing=async(label,isolation,predates=false)=>{
    await checkpoint(name+'-'+label);let current;
    if(predates){await qb('BEGIN ISOLATION LEVEL REPEATABLE READ');await qb('SELECT epoch FROM dvaia_maintenance.control');await qa('BEGIN ISOLATION LEVEL REPEATABLE READ');current=await epoch(qa,template.epoch);}
    else{current=await make();await start(isolation);}
    const winning=randomUUID(),losing=randomUUID();let pending;
    try{await claimed(qa,current,winning);const deadline=performance.now()+5000;
     pending=(async()=>{await claimed(qb,current,losing);await qb('SET CONSTRAINTS ALL IMMEDIATE');await qb('COMMIT');return{ok:true};})().catch(error=>({ok:false,code:error.code}));
     await waitBlocked(q,bpid,apid,deadline);await qa('SET CONSTRAINTS ALL IMMEDIATE');await qa('COMMIT');const outcome=await bounded(pending,Math.max(1,deadline-performance.now()));assert(performance.now()<deadline);assert.equal(outcome.ok,false);assert.equal(outcome.code,isolation==='READ COMMITTED'?'P0001':'40001');await qb('ROLLBACK');
     const rows=(await q('SELECT attempt_id,state FROM dvaia_maintenance.recovery_attempts WHERE epoch=$1 ORDER BY attempt_id',[current.epoch])).rows;assert.deepEqual(rows,[{attempt_id:winning,state:'claimed'}]);state.cases.push(name+'-'+label);
    }finally{await rollbackBoth();if(pending)await bounded(pending,5000);}
   };
   await competing('RR-nonterminal-race','REPEATABLE READ');await competing('RC-nonterminal-race','READ COMMITTED');await competing('RR-snapshot-before-admission','REPEATABLE READ',true);
   for(const finishing of [false,true]){
    const current=await published(),baseClaim=await transaction(q,()=>finishClaim(q,current,current.id));await start('REPEATABLE READ');let pending;
    try{const newest=await finishClaim(qa,current,current.id),deadline=performance.now()+5000;
     pending=(async()=>{if(finishing)await finish(qb,current,current.id,baseClaim.claim_id);else await finishClaim(qb,current,current.id);await qb('SET CONSTRAINTS ALL IMMEDIATE');await qb('COMMIT');return{ok:true};})().catch(error=>({ok:false,code:error.code}));
     await waitBlocked(q,bpid,apid,deadline);await qa('SET CONSTRAINTS ALL IMMEDIATE');await qa('COMMIT');const outcome=await bounded(pending,Math.max(1,deadline-performance.now()));assert(performance.now()<deadline);assert.deepEqual(outcome,{ok:false,code:'40001'});await qb('ROLLBACK');
     assert.equal((await q('SELECT state FROM dvaia_maintenance.recovery_attempts WHERE attempt_id=$1',[current.id])).rows[0].state,'published');assert.deepEqual((await q('SELECT claim_id,ordinal FROM dvaia_maintenance.recovery_finish_claims WHERE epoch=$1 ORDER BY ordinal',[current.epoch])).rows,[{claim_id:baseClaim.claim_id,ordinal:1},{claim_id:newest.claim_id,ordinal:2}]);assert.equal((await q('SELECT count(*)::int n FROM dvaia_maintenance.recovery_finish_claim_results WHERE epoch=$1',[current.epoch])).rows[0].n,0);state.cases.push(name+(finishing?'-RR-finish-vs-new-claim':'-RR-concurrent-claim'));
    }finally{await rollbackBoth();if(pending)await bounded(pending,5000);}
   }
   await close(a);await close(b);
  }
  assert.equal(await history(),retained);const ledgerBefore=(await q('SELECT * FROM dvaia_maintenance.ledger ORDER BY name')).rows;await apply(2);assert.deepEqual((await q('SELECT * FROM dvaia_maintenance.ledger ORDER BY name')).rows,ledgerBefore);assert.equal(await history(),retained);await close(c);
 }
 state.passed=true;
 }catch(error){primary=error;state.failure=failure(error,state.location);throw error;}
 finally{
  const failures=[];try{const outcomes=await bounded(Promise.allSettled([...leases].map(l=>l.close()).concat([...clients].map(c=>c.end()))),10000);for(const r of outcomes)if(r.status==='rejected')failures.push(r.reason);}catch(error){failures.push(error);}
  state.cleanup={failed:failures.length>0,count:failures.length};await checkpoint('terminal');if(failures.length)throw new AggregateError([...(primary?[primary]:[]),...failures],'Owned schema cleanup failed');
 }
});
module.exports={environments,failure,waitBlocked,CASES};
