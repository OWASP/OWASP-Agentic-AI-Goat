'use strict';
// Disposable identity-store contract check. The owning launcher provisions two
// isolated roles and a database named owasp_ai_goat_test_ctf_stage6_profile_*.
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {hashPayload}=require('../../server/services/promptInjectionCTF');
const {reviewerProfileEvidence}=require('../../server/services/ctfDefenseLayers');
const {stageSnapshot}=require('../../server/agent-runtime/ctfStageJudge');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.CTF_STAGE6_PROFILE_ISOLATED==='1';
const sha=value=>createHash('sha256').update(value).digest('hex');
const stage={id:6,stage_number:6,defense_style:'["meta_rotation_handoff_reviewer_v1"]',stage_name:'Synthetic Stage 6',adaptive_mode:'none',level_score:100};

test('forward Stage 6 reviewer profile SQL accepts only exact bound shape and preserves legacy',{skip:!enabled,timeout:180000},async()=>{
 const keys=['PG_CTF_STAGE6_PROFILE_IDENTITY_RUNTIME_URL','PG_CTF_STAGE6_PROFILE_IDENTITY_MIGRATION_URL'];
 assert(keys.every(key=>process.env[key]),'Explicit disposable identity URL pair required');
 const urls=keys.map(key=>new URL(process.env[key]));
 for(const url of urls){assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/owasp_ai_goat_test_ctf_stage6_profile_/);}
 assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].port,urls[1].port);assert.notEqual(urls[0].username,urls[1].username);
 const runtime=createPool(process.env,keys[0]),migration=createPool(process.env,keys[1]);
 try{
  assert.equal((await runtime.query('SELECT current_user AS role')).rows[0].role,'dvaia_identity_runtime');
  const directory=require('node:path').resolve(__dirname,'../../db/postgres/identity-migrations');
  const applied=await migrate(migration,directory);
  assert(applied.some(name=>name.includes('0129_ctf_stage6_reviewer_profile_binding.sql')));
  assert(applied.some(name=>name.includes('0130_ctf_stage6_reviewer_profile_jsonb_operator.sql')));
  assert.deepEqual(await migrate(migration,directory),[]);
  const profile=reviewerProfileEvidence(stage);
  const valid=async value=>(await migration.query('SELECT identity.ctf_stage6_reviewer_profile_valid($1::jsonb) AS valid',[JSON.stringify(value)])).rows[0].valid;
  assert.equal(await valid({...stage,__ctf_reviewer_profile:profile}),true);
  assert.equal(await valid({id:5,stage_number:5,defense_style:'["meta_structured_artifact_reviewer_v1"]'}),true);
  assert.equal(await valid({...stage,defense_style:'["meta_llm_judge"]'}),true);
  for(const value of [stage,{...stage,stage_number:7,__ctf_reviewer_profile:profile},{...stage,stage_number:null,__ctf_reviewer_profile:profile},{id:6,defense_style:stage.defense_style,__ctf_reviewer_profile:profile},{...stage,__ctf_reviewer_profile:{...profile,policyDigest:'0'.repeat(64)}},{...stage,defense_style:'["meta_llm_judge"]',__ctf_reviewer_profile:profile},{...stage,defense_style:'[malformed',__ctf_reviewer_profile:profile}])assert.equal(await valid(value),false);
  assert.equal(JSON.parse(stageSnapshot(stage))[0][0],'__ctf_reviewer_profile');
  const visible='SYNTHETIC_TOKEN',payload='synthetic request',normalized=hashPayload(payload),receipt={verdict:'pass',provider:'ollama',model:'llama3.1:8b',judgeVersion:'controlled-v1',rubricVersion:'ctf-visible-secret-v2',reviewerProfile:profile},judgeReceipt=JSON.stringify(receipt);
  const evidence={version:1,binding:{ownerId:'7',sessionId:'8',admissionId:'00000000-0000-0000-0000-000000000001',runId:'00000000-0000-0000-0000-000000000002',ownerGeneration:'0',globalRevision:'0',stageRevision:'0',participantId:'9',progressId:'10',stageId:'6',stageNumber:6,stageDigest:sha(stageSnapshot(stage))},payload,normalizedPayload:normalized.normalized,payloadHash:normalized.hash,visibleResponse:visible,observedSecret:true,techniqueTag:'other',guardian:{version:'ctf-guardian-provenance-v1',provider:'ollama',model:'llama3.1:8b',rawResponseSha256:sha(visible),visibleResponseSha256:sha(visible),rawResponseBytes:Buffer.byteLength(visible),visibleResponseBytes:Buffer.byteLength(visible),reviewerProfile:profile},judgment:{verdict:'pass',provider:'ollama',model:'llama3.1:8b',judgeVersion:'controlled-v1',rubricVersion:'ctf-visible-secret-v2',receiptHash:sha(judgeReceipt)},judgeReceipt};
  const matches=async value=>(await migration.query('SELECT identity.ctf_decision_document_matches($1::jsonb) AS matched',[JSON.stringify(value)])).rows[0].matched;
  assert.equal(await matches(evidence),true);
  const old={...evidence,binding:{...evidence.binding,stageId:'5',stageNumber:5},guardian:{...evidence.guardian},judgeReceipt:JSON.stringify({...receipt})};delete old.guardian.reviewerProfile;const oldReceipt=JSON.parse(old.judgeReceipt);delete oldReceipt.reviewerProfile;old.judgeReceipt=JSON.stringify(oldReceipt);old.judgment={...old.judgment,receiptHash:sha(old.judgeReceipt)};
  assert.equal(await matches(old),true);
  for(const mutate of [e=>{e.binding.stageNumber=7;},e=>{e.guardian.reviewerProfile.policyDigest='0'.repeat(64);},e=>{const r=JSON.parse(e.judgeReceipt);delete r.reviewerProfile;e.judgeReceipt=JSON.stringify(r);e.judgment.receiptHash=sha(e.judgeReceipt);},e=>{e.guardian.reviewerProfile.extra=true;}]){const changed=structuredClone(evidence);mutate(changed);assert.equal(await matches(changed),false);}
  const constraints=(await migration.query("SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='graph_runtime.events'::regclass AND conname IN ('events_reviewer_profile_check','events_metadata_keys_check','events_stage6_reviewer_veto_check')")).rows;
  assert.equal(constraints.length,3);assert(constraints.some(row=>row.definition.includes('ctf-stage6-learner-claimed-rotation-handoff')));assert(constraints.some(row=>row.definition.includes('modelVerdict')));
  const owner=JSON.stringify(['CTF',String(900000+Math.floor(Math.random()*90000))]),run=randomUUID();
  await runtime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)',[owner]);
  await runtime.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')",[run,owner]);
  const insert=(sequence,metadata)=>runtime.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,$3,'ctf_output_reviewer','decision',$4::jsonb)",[run,owner,sequence,JSON.stringify(metadata)]);
  const trace={reviewerProfileId:profile.id,reviewerProfileVersion:profile.version,reviewerPolicyDigest:profile.policyDigest,decisionSource:'model',verdict:'SAFE'};
  await insert(1,trace);
  const veto={...trace,verdict:'LEAKED',modelVerdict:'SAFE',policyShapeRejected:true};
  await insert(2,veto);
  await insert(3,{reviewerProfileId:'ctf-stage5-learner-claimed-telemetry',reviewerProfileVersion:'structured-artifact-v1',reviewerPolicyDigest:'a'.repeat(64),verdict:'SAFE'});
  for(const changed of [
   {modelVerdict:'SAFE',policyShapeRejected:true,verdict:'LEAKED'},
   {...veto,reviewerProfileId:null},
   {...veto,verdict:null},
   {...veto,reviewerPolicyDigest:'0'.repeat(64)},
   {...veto,modelVerdict:'LEAKED'},
   {...veto,policyShapeRejected:false},
   {...veto,rawProtectedText:'must-not-persist'},
  ])await assert.rejects(insert(4,changed),{code:'23514'});
  assert.equal((await runtime.query('SELECT count(*)::integer AS count FROM graph_runtime.events WHERE run_id=$1',[run])).rows[0].count,3);
 }finally{await Promise.allSettled([runtime.end(),migration.end()]);}
});
