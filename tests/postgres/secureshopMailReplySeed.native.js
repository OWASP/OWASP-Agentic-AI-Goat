'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{Pool}=require('pg');
const {seedWorkshopPlatform,solutionFixtures}=require('../../server/database/postgres/workshopPlatformSeed');
const curriculum=require('../../server/config/secureshopCurriculum'),prior=require('../fixtures/secureshopMailReplyPriorDefaults.json');
test('reply native managed-default transition preserves instructor and sibling catalog state', {timeout:120000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(process.env.MAIL_REPLY_SEED_ONLY,'1');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const runtime=new Pool({connectionString:process.env.IDENTITY_DATABASE_URL,max:2}),migration=new Pool({connectionString:process.env.IDENTITY_MIGRATION_DATABASE_URL,max:2});
 const id='ss_mail_reply_redirect',key=curriculum.WORKSHOP_KEY;
 const snapshot=async()=>({objectives:(await runtime.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows,exercises:(await runtime.query('SELECT * FROM workshop_platform.exercises ORDER BY workshop_key')).rows,defaults:(await migration.query('SELECT * FROM workshop_platform.catalog_field_defaults ORDER BY entity_kind,workshop_key,objective_id,field_name')).rows,revision:(await runtime.query('SELECT * FROM workshop_platform.config_revision ORDER BY id')).rows});
 try{
  await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(runtime,migration);
  await seedWorkshopPlatform(migration);
  const fresh=await snapshot(),row=fresh.objectives.find(x=>x.objective_id===id),exercise=fresh.exercises.find(x=>x.workshop_key===key);
  assert.equal(exercise.is_visible,false);assert.equal(row.is_enabled,false);assert.equal(row.hint_enabled,false);assert.equal(row.solution_enabled,false);assert.deepEqual(row.hint_content,curriculum.HINTS[id]);assert.deepEqual(row.solution_content,curriculum.SOLUTIONS[id]);
  await seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(),fresh,'fresh second seed exact no-op including timestamps/provenance/revision');
  const hints=require('../../server/data/workshopHints'),solutions=solutionFixtures();
  await seedWorkshopPlatform(migration,{hints:{...hints,[key]:{...hints[key],[id]:prior.hint}},solutions:{...solutions,[key]:{...solutions[key],[id]:prior.solution}}});
  const old=(await snapshot()).objectives.find(x=>x.objective_id===id);assert.deepEqual(old.hint_content,prior.hint);assert.deepEqual(old.solution_content,prior.solution);
  await seedWorkshopPlatform(migration);const upgraded=await snapshot();assert.deepEqual(upgraded.objectives.find(x=>x.objective_id===id).hint_content,curriculum.HINTS[id]);assert.deepEqual(upgraded.objectives.find(x=>x.objective_id===id).solution_content,curriculum.SOLUTIONS[id]);
  assert.deepEqual(upgraded.objectives.filter(x=>x.objective_id!==id),fresh.objectives.filter(x=>x.objective_id!==id));
  await seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(),upgraded,'managed second seed exact no-op');
  const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(runtime,{isSecureShopReady:()=>true});
  await config.updateHintContent(key,id,{hints:['Instructor-owned reply hint']});await config.updateSolutionContent(key,id,{title:'Instructor-owned reply solution',description:'Retain custom lesson'});
  await config.updateHintContent(key,'ss_mail_header_construction',{hints:['Sibling instructor guidance']});
  await config.setExerciseVisibility(key,true);await config.setObjectiveVisibility(key,id,true);
  for(const kind of ['Hint','Solution'])await config['setMaster'+kind+'Visibility'](key,true);
  await config.setObjectiveHintVisibility(key,id,false);await config.setObjectiveSolutionVisibility(key,id,true);
  const customized=await snapshot();assert(customized.objectives.length>1);
  await seedWorkshopPlatform(migration);const observed=await snapshot();require('../fixtures/secureshopMailReplySeedContract').assertCustomObservationRefresh(customized,observed);
  await seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(),observed,'custom repeat exact no-op after observation refresh');
  const projection=(await config.setObjectiveHintVisibility(key,id,false)).exercise.objectives[id];assert.equal(projection.hintVisible,false);assert.equal(projection.solutionVisible,true);
  fs.writeFileSync(process.env.OWNED_LISTING_RESULT,JSON.stringify({status:'passed',scope:'Reply native catalog seed only; no learner completion, model or browser',actualModelCalls:0,freshHiddenDisabled:true,managedPriorExact:true,managedUpgrade:true,customPreserved:true,siblingCatalogPreserved:true,independentGates:true,exactSecondRunNoop:true},null,2));
 }finally{await Promise.allSettled([runtime.end(),migration.end()]);}
});
