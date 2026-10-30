'use strict';
// Disposable SQL guard qualification. Migration-role synthetic admissions and
// provider receipts are fixtures, never model provenance or mounted-route proof.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID,createHash}=require('node:crypto');
const {createPool}=require('../../server/database/postgres'),{migrate}=require('../../db/postgres/migrate');
const {hashPayload}=require('../../server/services/promptInjectionCTF');
const {validateCtfDecisionDocument}=require('../../server/services/ctfDecisionService');
const hash=s=>createHash('sha256').update(s).digest('hex');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_DECISION_RECOVERY_ISOLATED==='1';
const target={IDENTITY:'0108_ctf_decision_recovery.sql',CTF:'0008_authoritative_decision_delivery.sql'};
const dirs={IDENTITY:path.resolve(__dirname,'../../db/postgres/identity-migrations'),CTF:path.resolve(__dirname,'../../db/postgres/workshop-migrations/ctf')};
async function q(pool,sql,args){try{return await pool.query(sql,args);}catch(e){console.error('CTF_DECISION_SQL_CONTEXT '+JSON.stringify({code:e.code,position:e.position,internalPosition:e.internalPosition,where:typeof e.where==='string'?e.where.split('\n').filter(x=>/^PL\/pgSQL function [A-Za-z0-9_.]+\(/.test(x)).join('\n').slice(0,1024):null}));throw e;}}
test('0108 fresh/populated/noop authenticated historical read and explicit authorization recovery',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],names=new Set();t.after(()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_DECISION_RECOVERY_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit disposable database pair required');const urls=keys.map(k=>new URL(process.env[k]));
   for(const url of urls){assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/owasp_ai_goat_test_ctf_decision_recovery_/);}
   assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);assert(!names.has(urls[0].pathname));names.add(urls[0].pathname);
   const [runtime,migration]=keys.map(k=>createPool(process.env,k));pools.push(runtime,migration);stores[kind]={runtime,migration};
   assert.equal((await runtime.query('SELECT current_user AS role')).rows[0].role,`dvaia_${kind.toLowerCase()}_runtime`);
   const subset=before=>{const d=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-decision-migrations-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));for(const name of fs.readdirSync(dirs[kind]).filter(n=>n.endsWith('.sql')&&(before?n<target[kind]:n<=target[kind])))fs.copyFileSync(path.join(dirs[kind],name),path.join(d,name));return d;};
   if(state==='POPULATED')await migrate(migration,subset(true));
   if(state==='POPULATED'&&kind==='IDENTITY')await migration.query("INSERT INTO identity.ctf_decisions(decision_id,run_id,owner_id,session_id,owner_key,owner_generation,global_revision,stage_revision,participant_id,progress_id,stage_id,stage_digest,evidence_hash,evidence,verdict,accepted,sequence) VALUES($1,$2,9001,9001,'historical',0,0,0,9001,9001,1,$3,$3,'{\"retained\":true}','pass',true,900000)",[randomUUID(),randomUUID(),'a'.repeat(64)]);
   const history=state==='POPULATED'&&kind==='IDENTITY'?(await runtime.query('SELECT * FROM identity.ctf_decisions')).rows:null;
   const full=subset(false);assert((await migrate(migration,full)).includes(target[kind]));assert.deepEqual(await migrate(migration,full),[]);
   if(history){const row=(await runtime.query('SELECT * FROM identity.ctf_decisions')).rows[0];for(const [key,value] of Object.entries(history[0]))assert.deepEqual(row[key],value);assert.equal(row.proposal_id,null);}
  }
  await decisionCases(stores.IDENTITY);
 }
});
async function decisionCases({runtime:r,migration:m}){
 const stage={id:1,stage_number:1,stage_name:'Synthetic recovery',adaptive_mode:'payload',level_score:100};
 const stageSnapshot=JSON.stringify(Object.keys(stage).sort().map(k=>[k,stage[k]]));
 const seed=randomUUID(),stageHash=hash(stageSnapshot);
 await m.query("UPDATE identity.ctf_authority SET lifecycle_state='ready' WHERE scope_key='global'");
 await m.query("INSERT INTO identity.ctf_authority(scope_key,lifecycle_state) VALUES('stage:1','ready')");
 await m.query('INSERT INTO identity.ctf_config_binding VALUES(true,0,true,true,true,true,true,true,true,true,-1,-1,1000,0,0,0,0,0,$1)',[seed]);
 await m.query("INSERT INTO identity.ctf_stage_bindings VALUES(1,1,0,0,$1,1,true,'payload','full',0,100,-1,0,$2)",[stageHash,seed]);
 for(const table of ['ctf_decision_inputs','ctf_decision_proposals','ctf_decisions'])for(const privilege of ['INSERT','UPDATE','DELETE','TRUNCATE'])assert.equal((await r.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[`identity.${table}`,privilege])).rows[0].allowed,false);
 const password=require('bcryptjs').hashSync('owned-disposable-not-a-platform-credential',4);
 assert.match(password,/^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$/);
 let counter=100;
 async function proposal({payload,verdict='pass',guardian=true,observedSecret=guardian,claimOnly=false}={}){
  const owner=++counter,ownerKey=JSON.stringify(['CTF',String(owner)]),run=randomUUID(),admission=randomUUID(),proposalId=randomUUID();payload??=`unique controlled payload ${owner}`;
  const token=hash(`session-${owner}`);
  await m.query("INSERT INTO identity.users(id,username,email,password,role) VALUES($1,$2,$3,$4,'student')",[owner,`owner-${owner}`,`owner-${owner}@fixture.invalid`,password]);
  const session=(await m.query("INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour') RETURNING id",[owner,token])).rows[0].id;
  await m.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);await m.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[run,ownerKey]);
  await m.query("INSERT INTO identity.ctf_authority(scope_key,owner_generation,lifecycle_state) VALUES($1,0,'ready')",[`owner:${owner}`]);
  await m.query('INSERT INTO identity.ctf_participant_bindings VALUES($1,0,$1,0,0,true,false,now()-interval \'1 minute\',0,$2)',[owner,seed]);
  await m.query("INSERT INTO identity.ctf_progress_bindings VALUES($1,0,1,$1,$1,0,0,0,$2,'in_progress',now()-interval '1 minute',null,1,1,0,0,0,null,0,$3)",[owner,stageHash,seed]);
  const revision=(await r.query("SELECT revision::text FROM identity.ctf_authority WHERE scope_key='global'")).rows[0].revision;
  const binding={ownerId:String(owner),sessionId:String(session),admissionId:admission,runId:run,ownerGeneration:'0',globalRevision:revision,stageRevision:'0',participantId:String(owner),progressId:String(owner),stageId:'1',stageNumber:1,stageDigest:stageHash};
  const seq=(await m.query("UPDATE identity.ctf_authority SET next_sequence=next_sequence+1,applied_sequence=next_sequence+1 WHERE scope_key='global' RETURNING next_sequence::text")).rows[0].next_sequence;
  await m.query("INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash,state,actor_id,session_id) VALUES($1,$2,'admit_attempt',$3,$4,'applied',$5,$6)",[seq,admission,JSON.stringify({scope:{globalRevision:revision,stageRevision:'0'}}),'a'.repeat(64),owner,session]);
  await m.query('INSERT INTO identity.ctf_attempt_admissions VALUES($1,$2,0,$2,$2,1,1,true,clock_timestamp(),$3)',[admission,owner,seq]);
  const normalized=hashPayload(payload),input={version:1,binding,payload,techniqueTag:'other',normalizedPayload:normalized.normalized,payloadHash:normalized.hash},raw=JSON.stringify(input);
  const otherSession=(await m.query("INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour') RETURNING id",[owner,hash(`other-${owner}`)])).rows[0].id;
  const wrongRaw=JSON.stringify({...input,binding:{...binding,sessionId:String(otherSession)}});
  await assert.rejects(r.query('SELECT identity.claim_ctf_projection_input($1,$2,$3,$4,$5,$6)',[owner,otherSession,hash(`other-${owner}`),wrongRaw,hash(wrongRaw),stageSnapshot]),/input admission mismatch/);
  const captureArgs=[owner,session,token,raw,hash(raw),stageSnapshot];
  assert.equal((await q(r,'SELECT identity.claim_ctf_projection_input($1,$2,$3,$4,$5,$6) AS capture',captureArgs)).rows[0].capture.claimed,true);
  assert.deepEqual((await q(r,'SELECT identity.claim_ctf_projection_input($1,$2,$3,$4,$5,$6) AS capture',captureArgs)).rows[0].capture,{claimed:false,admissionId:admission,proposalId:null});
  const subject={owner,session,token,otherSession,admission,run,proposalId,sessionContext:{actorId:owner,sessionId:session,rawToken:`session-${owner}`}};
  if(claimOnly)return subject;
  const receipt={verdict:guardian?verdict:'unavailable',provider:guardian?'ollama':null,model:guardian?'synthetic-controlled-receipt':null,judgeVersion:guardian?'controlled-v1':null,rubricVersion:'ctf-visible-secret-v2'},judgeReceipt=JSON.stringify(receipt),visibleResponse='SYNTHETIC';
  const doc={...input,visibleResponse,observedSecret,guardian:guardian?{version:'ctf-guardian-provenance-v1',provider:'ollama',model:'synthetic-controlled-receipt',rawResponseSha256:hash(visibleResponse),visibleResponseSha256:hash(visibleResponse),rawResponseBytes:9,visibleResponseBytes:9}:null,judgment:{...receipt,receiptHash:hash(judgeReceipt)},judgeReceipt};
  const bytes=validateCtfDecisionDocument(doc);
  const forged=JSON.stringify({...doc,judgment:{...doc.judgment,receiptHash:'f'.repeat(64)}});
  await assert.rejects(r.query('SELECT identity.stage_ctf_server_proposal($1,$2,$3,$4,$5,$6)',[proposalId,owner,session,token,forged,hash(forged)]),/proposal schema invalid/);
  await q(r,'SELECT identity.stage_ctf_server_proposal($1,$2,$3,$4,$5,$6)',[proposalId,owner,session,token,bytes.canonicalEvidence,bytes.evidenceHash]);
  assert.equal((await q(r,'SELECT identity.claim_ctf_projection_input($1,$2,$3,$4,$5,$6) AS capture',captureArgs)).rows[0].capture.proposalId,proposalId);
  return {...subject,doc,authorize:async()=>(await q(r,'SELECT * FROM identity.authorize_ctf_decision($1,$2,$3,$4,$5)',[proposalId,owner,session,token,randomUUID()])).rows[0]};
 }

 const {createCtfDecisionRecoveryRepository}=require('../../server/database/postgres/ctfDecisionRecoveryRepository');
 const {createCtfDecisionRepository}=require('../../server/database/postgres/ctfDecisionRepository');
 const {createCtfDecisionRecoveryService}=require('../../server/services/ctfDecisionRecoveryService');
 const recovery=createCtfDecisionRecoveryRepository(r),decisions=createCtfDecisionRepository(r);
 const service=createCtfDecisionRecoveryService({recovery,decisions});
 const read=x=>recovery.read({admissionId:x.admission,session:x.sessionContext});
 const recover=(x,extra={})=>service.recover({admissionId:x.admission,session:x.sessionContext,...extra});
 const sqlDenied=error=>error.code==='28000';
 assert.equal((await r.query("SELECT has_function_privilege(current_user,'identity.read_ctf_decision_recovery(uuid,integer,integer,text)','EXECUTE') AS allowed")).rows[0].allowed,true);
 assert.equal((await r.query("SELECT count(*)::int AS n FROM pg_proc p, LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='identity.read_ctf_decision_recovery(uuid,integer,integer,text)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'")).rows[0].n,0);
 const claim=await proposal({claimOnly:true});
 assert.equal((await read(claim)).state,'claimed_without_proposal');
 assert.equal((await recover(claim,{resumeAuthorization:true})).state,'claimed_without_proposal');
 assert.equal((await r.query('SELECT count(*)::int n FROM identity.ctf_decision_proposals WHERE admission_operation_id=$1',[claim.admission])).rows[0].n,0);
 assert.equal((await recovery.read({admissionId:claim.admission,session:{actorId:claim.owner,sessionId:claim.otherSession,rawToken:`other-${claim.owner}`}})).state,'not_found');
 await assert.rejects(recovery.read({admissionId:claim.admission,session:{...claim.sessionContext,rawToken:'incorrect synthetic token'}}),sqlDenied);
 const sibling=await proposal({claimOnly:true});
 assert.equal((await recovery.read({admissionId:claim.admission,session:sibling.sessionContext})).state,'not_found');
 assert.equal((await read(sibling)).state,'claimed_without_proposal');
 const revoked=await proposal();await m.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[revoked.session]);await assert.rejects(read(revoked),sqlDenied);
 const expired=await proposal();await m.query("UPDATE identity.user_sessions SET expires_at=now()-interval '1 second' WHERE id=$1",[expired.session]);await assert.rejects(read(expired),sqlDenied);
 const deleted=await proposal();await m.query('INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by) VALUES($1,$2,9999)',[randomUUID(),deleted.owner]);await assert.rejects(read(deleted),sqlDenied);
 // Run-block independently denies even when its tombstone belongs to another
 // subject (migration-role synthetic cross-table negative, never platform data).
 const blocked=await proposal(),job=randomUUID();await m.query('INSERT INTO identity.student_deletion_jobs(job_id,subject_user_id,requested_by) VALUES($1,9998,9999)',[job]);
 await m.query('INSERT INTO identity.student_deletion_run_blocks(owner_key,job_id) VALUES($1,$2)',[JSON.stringify(['CTF',String(blocked.owner)]),job]);await assert.rejects(read(blocked),sqlDenied);
 const staged=await proposal();assert.equal((await read(staged)).state,'proposal_staged');
 await m.query("UPDATE graph_runtime.runs SET status='completed' WHERE run_id=$1",[staged.run]);
 assert.equal((await recover(staged,{resumeAuthorization:true})).state,'ineligible_staged_proposal');
 const edited=await proposal();await m.query("UPDATE identity.ctf_stage_bindings SET stage_digest=$1 WHERE stage_id=1",['e'.repeat(64)]);
 assert.equal((await read(edited)).state,'proposal_staged');assert.equal((await recover(edited,{resumeAuthorization:true})).state,'ineligible_staged_proposal');
 await m.query('UPDATE identity.ctf_stage_bindings SET stage_digest=$1 WHERE stage_id=1',[stageHash]);
 const valid=await proposal(),first=await recover(valid,{resumeAuthorization:true});assert.equal(first.state,'authorized_receipt');assert.equal(first.currentCompletion,false);assert.equal(first.receipt.accepted,true);
 const saved=(await r.query('SELECT * FROM identity.ctf_decisions WHERE decision_id=$1',[first.receipt.decision_id])).rows[0];
 await m.query("UPDATE graph_runtime.runs SET status='completed' WHERE run_id=$1",[valid.run]);
 await m.query("UPDATE identity.ctf_authority SET revision=revision+1 WHERE scope_key='global'");
 await m.query('UPDATE identity.ctf_stage_bindings SET stage_digest=$1 WHERE stage_id=1',['e'.repeat(64)]);
 await m.query('UPDATE identity.ctf_participant_bindings SET active=false WHERE owner_id=$1',[valid.owner]);
 const historical=await recover(valid,{resumeAuthorization:true});assert.equal(historical.state,'historical_receipt');assert.equal(historical.currentCompletion,false);assert.equal(historical.receipt.decision_id,first.receipt.decision_id);
 assert.deepEqual((await r.query('SELECT * FROM identity.ctf_decisions WHERE decision_id=$1',[first.receipt.decision_id])).rows[0],saved);
 await m.query('UPDATE identity.ctf_stage_bindings SET stage_digest=$1 WHERE stage_id=1',[stageHash]);
 const loss=await proposal();let authorizationCalls=0;
 const lossy=createCtfDecisionRecoveryService({recovery,decisions:{async authorize(...args){authorizationCalls++;await decisions.authorize(...args);throw Object.assign(new Error('Synthetic lost response after actual committed authorization'),{code:'CTF_TRANSACTION_UNCERTAIN'});}}});
 const args={admissionId:loss.admission,session:loss.sessionContext,resumeAuthorization:true};
 assert.equal((await lossy.recover(args)).state,'authorization_uncertain');assert.equal((await lossy.recover(args)).state,'historical_receipt');assert.equal(authorizationCalls,1);
 assert.equal((await r.query('SELECT count(*)::int n FROM identity.ctf_decisions WHERE proposal_id=$1',[loss.proposalId])).rows[0].n,1);
 // No provider or new-admission API exists in the recovery composition. All
 // synthetic evidence above was staged explicitly once by fixture setup.
}
