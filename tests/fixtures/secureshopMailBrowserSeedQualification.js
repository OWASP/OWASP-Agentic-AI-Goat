'use strict';
const assert = require('node:assert/strict');
const KEY = 'secureshop_agent_security', ID = 'ss_mail_stored_browser_execution';
const SIBLING = 'ss_mail_header_construction';
const { document } = require('../../server/database/postgres/catalogDefaultProvenance');
async function snapshot(runtime, migration = runtime) {
 return {
  objectives: (await runtime.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows,
  exercises: (await runtime.query('SELECT * FROM workshop_platform.exercises ORDER BY workshop_key')).rows,
  defaults: (await migration.query('SELECT * FROM workshop_platform.catalog_field_defaults ORDER BY entity_kind,workshop_key,objective_id,field_name')).rows,
  revision: (await runtime.query('SELECT * FROM workshop_platform.config_revision ORDER BY id')).rows,
 };
}
function assertObservationRefresh(before, after, fields) {
 for (const part of ['objectives','exercises','revision']) assert.deepEqual(after[part],before[part],part+' must remain exact');
 assert.equal(after.defaults.length,before.defaults.length);let refreshed=0;
 for (let i=0;i<before.defaults.length;i++) {
  const old=before.defaults[i],next=after.defaults[i];
  if(old.entity_kind==='objective'&&old.workshop_key===KEY&&fields.includes(old.objective_id+':'+old.field_name)) {
   assert.equal(next.provenance_state,'custom');
   const row=before.objectives.find(x=>x.workshop_key===KEY&&x.objective_id===old.objective_id);assert(row);
   assert.deepEqual(next.observed_document,document(row[old.field_name]));
   assert(new Date(next.updated_at).getTime()>=new Date(old.updated_at).getTime());
   assert.deepEqual({...next,provenance_state:old.provenance_state,observed_document:old.observed_document,updated_at:old.updated_at},old,'Only custom observation/state/timestamp refresh allowed');
   refreshed++;
  } else assert.deepEqual(next,old,'Unrelated provenance remains exact');
 }
 assert.equal(refreshed,fields.length);
}
function seedOnClient(client) {
 // Reuse the production seed factory and all production dependencies/defaults;
 // only transaction ownership belongs to the caller's rollback-only fixture.
 const wrapper=require('../../server/database/postgres/workshopPlatformSeed');
 const catalog=require('../../server/config/workshopCatalog');
 const seed=require('../../server/database/postgres/workshopPlatformSeedCore').createWorkshopPlatformSeed({
  withTransaction:async(_pool,work)=>work(client),
  bump:require('../../server/database/postgres/workshopPlatformSupport').bump,
  provenance:require('../../server/database/postgres/catalogDefaultProvenance'),
  toChallengeKey:catalog.toChallengeKey,
  legacyXssSolutions:require('../../server/data/xssWorkshopSolutions').solutions,
 });
 return ()=>seed(null,{catalog:catalog.WORKSHOP_OBJECTIVES,hints:require('../../server/data/workshopHints'),
  solutions:wrapper.solutionFixtures(),challenges:require('../../db/postgres/workshopChallengeFixtures'),catalogVersion:wrapper.CATALOG_VERSION});
}
async function qualifyMailBrowserSeed({identity,migration,objectiveId=ID}) {
 assert([ID,'ss_pricing_competitor_disclosure'].includes(objectiveId),'Closed seed qualification objective');
 const targetId=objectiveId;
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert(identity?.query&&migration?.connect);
 const seed=require('../../server/database/postgres/workshopPlatformSeed');
 const curriculum=require('../../server/config/secureshopCurriculum');
 const prior=targetId==='ss_pricing_competitor_disclosure'?require('./secureshopPricingCompetitorPriorDefaults.json'):require('./secureshopMailBrowserPriorDefaults.json');
 assert.equal(prior.objectiveId,targetId);assert.equal(curriculum.isQualifiedObjective(targetId),true);
 assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2',[KEY,targetId])).rows[0].n,0,'Fresh qualification must precede initial catalog seed');
 await seed.seedWorkshopPlatform(migration);
 const fresh=await snapshot(identity,migration),target=fresh.objectives.find(x=>x.workshop_key===KEY&&x.objective_id===targetId),exercise=fresh.exercises.find(x=>x.workshop_key===KEY);
 assert(target&&exercise);assert.equal(exercise.is_visible,false);
 for(const field of ['is_enabled','hint_enabled','solution_enabled'])assert.equal(target[field],false);
 for(const [field,expected] of [['hint_content',curriculum.HINTS[targetId]],['solution_content',curriculum.SOLUTIONS[targetId]]]){assert(expected&&Object.keys(expected).length);assert.deepEqual(target[field],expected);}
 await seed.seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(identity,migration),fresh,'Fresh second seed exact no-op');
 const hints=require('../../server/data/workshopHints'),solutions=seed.solutionFixtures();
 await seed.seedWorkshopPlatform(migration,{hints:{...hints,[KEY]:{...hints[KEY],[targetId]:prior.hint}},solutions:{...solutions,[KEY]:{...solutions[KEY],[targetId]:prior.solution}}});
 const pending=await snapshot(identity,migration),old=pending.objectives.find(x=>x.workshop_key===KEY&&x.objective_id===targetId);
 assert.deepEqual(old.hint_content,prior.hint);assert.deepEqual(old.solution_content,prior.solution);
 await seed.seedWorkshopPlatform(migration);const upgraded=await snapshot(identity,migration),current=upgraded.objectives.find(x=>x.workshop_key===KEY&&x.objective_id===targetId);
 assert.deepEqual(current.hint_content,target.hint_content);assert.deepEqual(current.solution_content,target.solution_content);
 for(const field of ['is_enabled','hint_enabled','solution_enabled'])assert.equal(current[field],target[field],'Managed transition preserves '+field);
 assert.deepEqual(upgraded.objectives.filter(x=>x.workshop_key!==KEY||x.objective_id!==targetId),fresh.objectives.filter(x=>x.workshop_key!==KEY||x.objective_id!==targetId));
 assert.deepEqual(upgraded.exercises,fresh.exercises);
 const unrelatedDefault=row=>!(row.entity_kind==='objective'&&row.workshop_key===KEY&&row.objective_id===targetId&&['hint_content','solution_content'].includes(row.field_name));
 assert.deepEqual(upgraded.defaults.filter(unrelatedDefault),fresh.defaults.filter(unrelatedDefault),'Unrelated managed provenance preserved');
 await seed.seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(identity,migration),upgraded,'Managed second seed exact no-op');
 const client=await migration.connect();let discard;
 try {
  await client.query('BEGIN');
  try {
   const runSeed=seedOnClient(client),fields=[targetId+':label',targetId+':hint_content',targetId+':solution_content',SIBLING+':hint_content'];
   await client.query('UPDATE workshop_platform.objectives SET label=$5,hint_content=$3::jsonb,solution_content=$4::jsonb,is_enabled=true,hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2',[KEY,targetId,JSON.stringify({hints:['Instructor custom browser hint']}),JSON.stringify({title:'Instructor custom browser solution'}),'Instructor custom browser label']);
   await client.query('UPDATE workshop_platform.objectives SET hint_content=$3::jsonb WHERE workshop_key=$1 AND objective_id=$2',[KEY,SIBLING,JSON.stringify({hints:['Sibling custom hint']})]);
   await client.query('UPDATE workshop_platform.exercises SET is_visible=true,show_hints=true,show_solutions=true WHERE workshop_key=$1',[KEY]);
   const provenance=require('../../server/database/postgres/catalogDefaultProvenance');
   await provenance.markCustomFields(client,{entityKind:'objective',workshopKey:KEY,objectiveId:targetId},['label','hint_content','solution_content']);
   await provenance.markCustomFields(client,{entityKind:'objective',workshopKey:KEY,objectiveId:SIBLING},['hint_content']);
   const custom=await snapshot(client);await runSeed();const observed=await snapshot(client);assertObservationRefresh(custom,observed,fields);
   await runSeed();assert.deepEqual(await snapshot(client),observed,'Custom second seed exact no-op');
   await client.query('UPDATE workshop_platform.objectives SET hint_content=NULL,solution_content=NULL,hint_enabled=false,solution_enabled=false WHERE workshop_key=$1 AND objective_id=$2',[KEY,targetId]);
   const nulled=await snapshot(client);await runSeed();const nullObserved=await snapshot(client);assertObservationRefresh(nulled,nullObserved,[targetId+':hint_content',targetId+':solution_content']);
   await runSeed();assert.deepEqual(await snapshot(client),nullObserved,'Explicit-null second seed exact no-op');
  } finally {try{await client.query('ROLLBACK');}catch(error){discard=error;throw error;}}
 } finally {client.release(discard);}
 assert.deepEqual(await snapshot(identity,migration),upgraded,'Rollback restores full catalog/provenance/revision');
 return {status:'passed',objectiveId:targetId,objectiveRows:upgraded.objectives.length,defaultRows:upgraded.defaults.length,freshHiddenDisabled:true,nonemptyContent:true,priorManagedUpgrade:true,instructorCustomPreserved:true,explicitNullPreserved:true,independentGateValuesPreserved:true,siblingPreserved:true,exactSecondSeeds:4,rollbackRestored:true,scope:'Owned seed qualification only; custom/null representative SQL edits rolled back; no learner/model/browser proof'};
}
module.exports={qualifyMailBrowserSeed,assertObservationRefresh,snapshot};
