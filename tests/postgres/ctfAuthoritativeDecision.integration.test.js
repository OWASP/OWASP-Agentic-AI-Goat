'use strict';
// Disposable SQL guard qualification. Migration-role synthetic admissions and
// provider receipts are fixtures, never model provenance or mounted-route proof.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {randomUUID,createHash}=require('node:crypto');
const {createPool}=require('../../server/database/postgres'),{migrate}=require('../../db/postgres/migrate');
const {hashPayload,isNearDuplicate}=require('../../server/services/promptInjectionCTF');
const {validateCtfDecisionDocument}=require('../../server/services/ctfDecisionService');
const hash=s=>createHash('sha256').update(s).digest('hex');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_DECISION_SCHEMA_ISOLATED==='1';
const target={IDENTITY:'0106_ctf_authoritative_decisions.sql',CTF:'0007_ordered_projection_receipts.sql'};
const dirs={IDENTITY:path.resolve(__dirname,'../../db/postgres/identity-migrations'),CTF:path.resolve(__dirname,'../../db/postgres/workshop-migrations/ctf')};
async function q(pool,sql,args){try{return await pool.query(sql,args);}catch(e){console.error('CTF_DECISION_SQL_CONTEXT '+JSON.stringify({code:e.code,position:e.position,internalPosition:e.internalPosition,where:typeof e.where==='string'?e.where.split('\n').filter(x=>/^PL\/pgSQL function [A-Za-z0-9_.]+\(/.test(x)).join('\n').slice(0,1024):null}));throw e;}}
test('0106 fresh/populated/noop and actual decision functions: session, epochs, admission, receipt and adaptive guards',{skip:!enabled,timeout:180000},async t=>{
 const pools=[],names=new Set();t.after(()=>Promise.allSettled(pools.map(p=>p.end())));
 for(const state of ['FRESH','POPULATED']){
  const stores={};
  for(const kind of ['IDENTITY','CTF']){
   const keys=['RUNTIME','MIGRATION'].map(role=>`PG_CTF_DECISION_${state}_${kind}_${role}_URL`);
   assert(keys.every(k=>process.env[k]),'Explicit disposable database pair required');const urls=keys.map(k=>new URL(process.env[k]));
   for(const url of urls){assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/owasp_ai_goat_test_ctf_decision_/);}
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
 const seed=randomUUID(),stageHash='d'.repeat(64);
 await m.query("UPDATE identity.ctf_authority SET lifecycle_state='ready' WHERE scope_key='global'");
 await m.query("INSERT INTO identity.ctf_authority(scope_key,lifecycle_state) VALUES('stage:1','ready')");
 await m.query('INSERT INTO identity.ctf_config_binding VALUES(true,0,true,true,true,true,true,true,true,true,-1,-1,1000,0,0,0,0,0,$1)',[seed]);
 await m.query("INSERT INTO identity.ctf_stage_bindings VALUES(1,1,0,0,$1,1,true,'payload','full',0,100,-1,0,$2)",[stageHash,seed]);
 for(const table of ['ctf_decision_inputs','ctf_decision_proposals','ctf_decisions'])for(const privilege of ['INSERT','UPDATE','DELETE','TRUNCATE'])assert.equal((await r.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[`identity.${table}`,privilege])).rows[0].allowed,false);
 const password=require('bcryptjs').hashSync('owned-disposable-not-a-platform-credential',4);
 assert.match(password,/^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$/);
 let counter=100;
 async function proposal({payload,verdict='pass',guardian=true,observedSecret=guardian}={}){
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
  await assert.rejects(r.query('SELECT identity.capture_ctf_decision_input($1,$2,$3,$4,$5)',[owner,otherSession,hash(`other-${owner}`),wrongRaw,hash(wrongRaw)]),/input admission mismatch/);
  const captureArgs=[owner,session,token,raw,hash(raw)];
  assert.equal((await q(r,'SELECT identity.capture_ctf_decision_input($1,$2,$3,$4,$5) AS capture',captureArgs)).rows[0].capture.claimed,true);
  assert.deepEqual((await q(r,'SELECT identity.capture_ctf_decision_input($1,$2,$3,$4,$5) AS capture',captureArgs)).rows[0].capture,{claimed:false,admissionId:admission,proposalId:null});
  const receipt={verdict:guardian?verdict:'unavailable',provider:guardian?'ollama':null,model:guardian?'synthetic-controlled-receipt':null,judgeVersion:guardian?'controlled-v1':null,rubricVersion:'ctf-visible-secret-v2'},judgeReceipt=JSON.stringify(receipt),visibleResponse='SYNTHETIC';
  const doc={...input,visibleResponse,observedSecret,guardian:guardian?{version:'ctf-guardian-provenance-v1',provider:'ollama',model:'synthetic-controlled-receipt',rawResponseSha256:hash(visibleResponse),visibleResponseSha256:hash(visibleResponse),rawResponseBytes:9,visibleResponseBytes:9}:null,judgment:{...receipt,receiptHash:hash(judgeReceipt)},judgeReceipt};
  const bytes=validateCtfDecisionDocument(doc);
  const forged=JSON.stringify({...doc,judgment:{...doc.judgment,receiptHash:'f'.repeat(64)}});
  await assert.rejects(r.query('SELECT identity.stage_ctf_server_proposal($1,$2,$3,$4,$5,$6)',[proposalId,owner,session,token,forged,hash(forged)]),/proposal schema invalid/);
  await q(r,'SELECT identity.stage_ctf_server_proposal($1,$2,$3,$4,$5,$6)',[proposalId,owner,session,token,bytes.canonicalEvidence,bytes.evidenceHash]);
  assert.equal((await q(r,'SELECT identity.capture_ctf_decision_input($1,$2,$3,$4,$5) AS capture',captureArgs)).rows[0].capture.proposalId,proposalId);
  return {owner,session,token,proposalId,doc,authorize:async()=>(await q(r,'SELECT * FROM identity.authorize_ctf_decision($1,$2,$3,$4,$5)',[proposalId,owner,session,token,randomUUID()])).rows[0]};
 }
 const revoked=await proposal();await m.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[revoked.session]);await assert.rejects(revoked.authorize(),/SESSION_REVOKED/);
 const stale=await proposal();await m.query("UPDATE identity.ctf_authority SET revision=revision+1 WHERE scope_key='global'");await assert.rejects(stale.authorize(),/scope stale/);
 const noSecret=await proposal({observedSecret:false});assert.equal((await noSecret.authorize()).accepted,false);
 const unavailable=await proposal({guardian:false});assert.equal((await unavailable.authorize()).verdict,'unavailable');
 const pending=await proposal({verdict:'inconclusive'});const pendingResult=await pending.authorize();assert.equal(pendingResult.verdict,'inconclusive');assert.equal(pendingResult.accepted,false);
 const valid=await proposal({payload:'ALPHA\u00a0BRAVO😀 charlie delta echo'});const accepted=await valid.authorize();assert.equal(accepted.accepted,true);assert.equal(accepted.replayed,false);
 const saved=(await r.query('SELECT * FROM identity.ctf_decisions WHERE decision_id=$1',[accepted.decision_id])).rows[0];assert(saved.completion_time_ms>=0);assert(saved.authorized_at instanceof Date);
 const race=await proposal({payload:'alpha bravo charlie delta echo'});assert.equal((await race.authorize()).verdict,'blocked');
 await m.query("UPDATE identity.ctf_authority SET revision=revision+1 WHERE scope_key='global'");await m.query('UPDATE identity.ctf_participant_bindings SET active=false WHERE owner_id=$1',[valid.owner]);const historic=await valid.authorize();assert.equal(historic.decision_id,accepted.decision_id);assert.equal(historic.replayed,true);assert.equal(historic.accepted,true);assert.deepEqual((await r.query('SELECT * FROM identity.ctf_decisions WHERE decision_id=$1',[accepted.decision_id])).rows[0],saved);
 await m.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[valid.session]);await assert.rejects(valid.authorize(),/SESSION_REVOKED/);
 const overflow=await proposal();for(let n=0;n<257;n++){const normalized=`overflow distinct payload ${n}`;await m.query("INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,payload_hash,normalized_payload,legacy_source) VALUES($1,'payload',1,0,0,$2,$3,'synthetic fixture')",[randomUUID(),hash(normalized),normalized]);}await assert.rejects(overflow.authorize(),/adaptive snapshot unavailable/);
 for(const [a,b] of [['İΣß😀 hello\u00a0world abc','i hello world abc'],['abcdefghijklmno','abcdefghijklmno'],['short','other']]){const x=hashPayload(a),y=hashPayload(b);const actual=(await m.query('SELECT identity.ctf_ascii_payload_similar($1,$2) AS similar',[x.normalized,y.normalized])).rows[0].similar;const expected=x.normalized.length>=10&&isNearDuplicate('not-an-exact-hash',x.normalized,[{payload_hash:y.hash,normalized_snippet:y.normalized}]).blocked;assert.equal(actual,expected);}
 await assert.rejects(m.query('DELETE FROM identity.ctf_decision_proposals WHERE proposal_id=$1',[valid.proposalId]),/immutable/);
}
