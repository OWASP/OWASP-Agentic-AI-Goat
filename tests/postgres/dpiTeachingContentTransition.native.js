'use strict';
// Source-only candidate. A separately approved owned launcher must provision both URL pairs.
const test=require('node:test'),assert=require('node:assert/strict');
const {Pool}=require('pg');
const {randomUUID,createHash}=require('node:crypto');
const fs=require('node:fs'),path=require('node:path');
const express=require('express');
const bcrypt=require('bcryptjs');
const {createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {createWorkshopProgressRepository}=require('../../server/database/postgres/workshopProgressRepository');
const {createPostgresHintsRouter,createPostgresSolutionsRouter}=require('../../server/routes/postgresWorkshopContent');
const {initializeIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {seedWorkshopPlatform,solutionFixtures}=require('../../server/database/postgres/workshopPlatformSeed');
const {createWorkshopConfigRepository}=require('../../server/database/postgres/workshopConfigRepository');
const prior=require('../fixtures/dpiTeachingDefaults.pre-decoder.json');
const current=require('../../server/data/promptInjectionSolutions').solutions;
const hints=require('../../server/data/workshopHints');
const wk='direct_prompt_injection',prefix='PG_DPI_CONTENT_';
const variants=['FRESH','POPULATED'];
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&variants.every(v=>['MIGRATION','RUNTIME'].every(r=>process.env[prefix+v+'_'+r+'_URL']));
function url(key){const value=new URL(process.env[key]);assert.ok(['127.0.0.1','localhost'].includes(value.hostname));assert.match(value.pathname,/^\/owasp_ai_goat_test_[a-z0-9_]+$/);return value.href;}
async function learnerSnapshot(pool){const result={};for(const table of ['completions','time_tracking','objective_evidence','objective_judgments','revisions'])result[table]=(await pool.query(`SELECT row_to_json(t) AS value FROM workshop_platform.${table} t ${table==='revisions'?"WHERE scope_type='user'":''} ORDER BY row_to_json(t)::text`)).rows;return result;}
async function apiParity(config,expectedHint){const app=express();app.use('/hints',createPostgresHintsRouter(config));app.use('/solutions',createPostgresSolutionsRouter(config));const server=app.listen(0,'127.0.0.1');await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});const base=`http://127.0.0.1:${server.address().port}`;const get=async p=>{const r=await fetch(base+p,{signal:AbortSignal.timeout(3000)});return {status:r.status,body:await r.json()};};try{
for(const [id,value] of Object.entries(current)){await config.setObjectiveSolutionVisibility(wk,id,true);const response=await get('/solutions/prompt-injection/'+id);assert.equal(response.status,200);const canonical=await config.getStudentContent(wk,id,'solution');assert.deepEqual(response.body.solution,canonical);}
assert.equal((await get('/solutions/prompt-injection/interact')).status,403);
assert.deepEqual((await get('/hints/'+wk+'/obfuscation')).body.hint,expectedHint);
await config.setObjectiveHintVisibility(wk,'obfuscation',false);assert.equal((await get('/hints/'+wk+'/obfuscation')).status,403);assert.equal((await get('/solutions/prompt-injection/obfuscation')).status,200);
await config.setMasterSolutionVisibility(wk,false);assert.equal((await get('/solutions/prompt-injection/obfuscation')).status,403);await config.setObjectiveHintVisibility(wk,'obfuscation',true);assert.equal((await get('/hints/'+wk+'/obfuscation')).status,200);
const snapshot=await config.getSnapshot();assert.deepEqual((await get('/hints/'+wk+'/status')).body.objectives,await config.getHintVisibilityMap(wk));assert.deepEqual((await get('/solutions/prompt-injection/status')).body.objectives,await config.getSolutionVisibilityMap(wk));assert.equal(snapshot.exercises[wk].objectives.obfuscation.solutionVisible,false);
}finally{server.closeAllConnections();await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));}}
async function snapshot(pool){return {rows:(await pool.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows,provenance:(await pool.query('SELECT * FROM workshop_platform.catalog_field_defaults ORDER BY entity_kind,workshop_key,objective_id,field_name')).rows,revision:(await pool.query('SELECT * FROM workshop_platform.config_revision')).rows};}
test('DPI exact retained defaults fresh, populated preservation and no-op native candidate',{skip:!enabled,timeout:120000},async()=>{
 for(const variant of variants){const migration=new Pool({connectionString:url(prefix+variant+'_MIGRATION_URL'),max:2}),runtime=new Pool({connectionString:url(prefix+variant+'_RUNTIME_URL'),max:2});try{
  await initializeIdentityRepository(runtime,migration);
  const config=createWorkshopConfigRepository(runtime);
  if(variant==='POPULATED'){
   await seedWorkshopPlatform(migration,{solutions:{...solutionFixtures(),[wk]:prior.solutions},hints:{...hints,[wk]:prior.hints}});
   // Canonical editor marks custom provenance; retain independent instructor controls.
   await config.updateSolutionContent(wk,'jailbreak',{title:'Instructor solution retained'});
   await config.updateHintContent(wk,'obfuscation',{title:'Instructor hint retained'});
   await config.setObjectiveSolutionVisibility(wk,'jailbreak',false);
   await config.setObjectiveHintVisibility(wk,'obfuscation',false);
   // Migration-role fixtures exercise unknown and unmarked custom historical states.
   await migration.query("UPDATE workshop_platform.objectives SET solution_content=solution_content||'{\"title\":\"Unmarked instructor edit\"}'::jsonb WHERE workshop_key=$1 AND objective_id='role_playing'",[wk]);
   await migration.query("UPDATE workshop_platform.catalog_field_defaults SET provenance_state='legacy_unknown' WHERE workshop_key=$1 AND objective_id='side_stepping' AND field_name='solution_content'",[wk]);
  }
  // Synthetic historical rows establish preservation only, never genuine objective proof.
  if(variant==='FRESH')await seedWorkshopPlatform(migration);
  const identity=createIdentityRepository(runtime),progress=createWorkshopProgressRepository(runtime);
  const users=[];for(const name of ['learner','sibling'])users.push((await identity.createUser({username:name,email:name+'@example.test',passwordHash:await bcrypt.hash('owned-test-only',4)})).id);
  for(const userId of users){await progress.syncObjectiveComplete(userId,wk,'interact');await progress.recordHeartbeat({userId,workshopKey:wk,now:1000000});await progress.recordHeartbeat({userId,workshopKey:wk,now:1030000});const digest=createHash('sha256').update('synthetic historical preservation fixture').digest('hex');await migration.query(`INSERT INTO workshop_platform.objective_evidence(user_id,workshop_key,scenario,generation,run_id,evidence_id,evidence_json,evidence_digest,expires_at) VALUES($1,$2,'teaching-copy-preservation',0,$3,'historical', '{"synthetic":true}'::jsonb,$4,now()+interval '1 day')`,[userId,wk,randomUUID(),digest]);await migration.query(`INSERT INTO workshop_platform.objective_judgments(user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,generation,verdict,result_json,disposition,evaluated_at) VALUES($1,$2,$3,'interact','dpi','teaching-copy-preservation','fixture-v1',$4,0,'fail','{"synthetic":true}'::jsonb,'not_pass',now())`,[userId,randomUUID(),wk,digest]);}
  const learnerBefore=await learnerSnapshot(runtime);
  const before=await snapshot(runtime);
  await seedWorkshopPlatform(migration);
  const after=await snapshot(runtime),rows=after.rows.filter(r=>r.workshop_key===wk);
  assert.equal(rows.length,8);
  for(const row of rows){
   if(row.objective_id==='interact'){assert.equal(row.solution_content,null);continue;}
   if(variant==='POPULATED'&&row.objective_id==='jailbreak')assert.equal(row.solution_content.title,'Instructor solution retained');
   else if(variant==='POPULATED'&&row.objective_id==='role_playing')assert.equal(row.solution_content.title,'Unmarked instructor edit');
   else if(variant==='POPULATED'&&row.objective_id==='side_stepping')assert.deepEqual(row.solution_content,prior.solutions.side_stepping);
   else assert.deepEqual(row.solution_content,current[row.objective_id]);
  }
  if(variant==='POPULATED'){
   assert.deepEqual(after.rows.filter(r=>r.workshop_key!==wk),before.rows.filter(r=>r.workshop_key!==wk));
   assert.equal(rows.find(r=>r.objective_id==='obfuscation').hint_content.title,'Instructor hint retained');
   assert.equal(rows.find(r=>r.objective_id==='obfuscation').hint_enabled,false);
   assert.equal(rows.find(r=>r.objective_id==='jailbreak').solution_enabled,false);
  }else assert.deepEqual(rows.find(r=>r.objective_id==='obfuscation').hint_content,hints[wk].obfuscation);
  assert.deepEqual(await learnerSnapshot(runtime),learnerBefore);
  const stable=await snapshot(runtime);assert.equal((await seedWorkshopPlatform(migration)).changed,false);assert.deepEqual(await snapshot(runtime),stable);assert.deepEqual(await learnerSnapshot(runtime),learnerBefore);
  await config.setMasterHintVisibility(wk,true);await config.setMasterSolutionVisibility(wk,true);
  await config.setObjectiveHintVisibility(wk,'obfuscation',true);await config.setObjectiveSolutionVisibility(wk,'obfuscation',true);
  assert.deepEqual(await config.getStudentContent(wk,'obfuscation','solution'),current.obfuscation);
  assert.deepEqual(await config.getStudentContent(wk,'obfuscation','hint'),rows.find(r=>r.objective_id==='obfuscation').hint_content);
  await apiParity(config,rows.find(r=>r.objective_id==='obfuscation').hint_content);
  await config.setMasterSolutionVisibility(wk,true);
  await config.setObjectiveHintVisibility(wk,'obfuscation',false);
  await assert.rejects(config.getStudentContent(wk,'obfuscation','hint'),{code:'FORBIDDEN'});
  assert.deepEqual(await config.getStudentContent(wk,'obfuscation','solution'),current.obfuscation);
 }finally{await Promise.all([runtime.end(),migration.end()]);}}
 if(process.env.DPI_CONTENT_EVIDENCE_ROOT)fs.writeFileSync(path.join(process.env.DPI_CONTENT_EVIDENCE_ROOT,'candidate-result.json'),JSON.stringify({status:'passed-controlled-content-only',variants,modelCalls:0,browser:false,syntheticHistoricalRows:true})+'\n');
});
