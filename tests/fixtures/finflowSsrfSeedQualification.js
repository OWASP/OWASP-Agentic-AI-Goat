'use strict';
// Uses the existing owned identity database, before its first canonical catalog seed.
const assert=require('node:assert/strict');
const KEY='sensitive_info_disclosure',IDS=Object.freeze(['ssrf_oob','ssrf_internal','ssrf_ollama']);
const {document}=require('../../server/database/postgres/catalogDefaultProvenance');
async function snapshot(pool){return {objectives:(await pool.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows,exercises:(await pool.query('SELECT * FROM workshop_platform.exercises ORDER BY workshop_key')).rows,defaults:(await pool.query('SELECT * FROM workshop_platform.catalog_field_defaults ORDER BY entity_kind,workshop_key,objective_id,field_name')).rows,revision:(await pool.query('SELECT * FROM workshop_platform.config_revision ORDER BY id')).rows};}
const target=row=>row.workshop_key===KEY&&IDS.includes(row.objective_id);
function assertRefresh(before,after,fields){
 for(const key of ['objectives','exercises','revision'])assert.deepEqual(after[key],before[key]);
 assert.equal(after.defaults.length,before.defaults.length);let n=0;
 for(let j=0;j<before.defaults.length;j++){const old=before.defaults[j],next=after.defaults[j];if(old.entity_kind==='objective'&&target(old)&&fields.includes(old.objective_id+':'+old.field_name)){assert.equal(next.provenance_state,'custom');const row=before.objectives.find(x=>x.workshop_key===KEY&&x.objective_id===old.objective_id);assert.deepEqual(next.observed_document,document(row[old.field_name]));assert(new Date(next.updated_at)>=new Date(old.updated_at));assert.deepEqual({...next,provenance_state:old.provenance_state,observed_document:old.observed_document,updated_at:old.updated_at},old);n++;}else assert.deepEqual(next,old);}
 assert.equal(n,fields.length);
}
function seedInTransaction(client){
 const wrapper=require('../../server/database/postgres/workshopPlatformSeed'),catalog=require('../../server/config/workshopCatalog');
 const seed=require('../../server/database/postgres/workshopPlatformSeedCore').createWorkshopPlatformSeed({withTransaction:async(_pool,work)=>work(client),bump:require('../../server/database/postgres/workshopPlatformSupport').bump,provenance:require('../../server/database/postgres/catalogDefaultProvenance'),toChallengeKey:catalog.toChallengeKey,legacyXssSolutions:require('../../server/data/xssWorkshopSolutions').solutions});
 return ()=>seed(null,{catalog:catalog.WORKSHOP_OBJECTIVES,hints:require('../../server/data/workshopHints'),solutions:wrapper.solutionFixtures(),challenges:require('../../db/postgres/workshopChallengeFixtures'),catalogVersion:wrapper.CATALOG_VERSION});
}
async function qualify({identity,migration}){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert(identity?.query&&migration?.connect);
 const seed=require('../../server/database/postgres/workshopPlatformSeed'),hints=require('../../server/data/workshopHints'),solutions=seed.solutionFixtures(),prior=require('./finflowSsrfPriorDefaults.json');assert.deepEqual(prior.objectiveIds,IDS);
 assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=ANY($2::text[])',[KEY,IDS])).rows[0].n,0);
 await seed.seedWorkshopPlatform(migration);const fresh=await snapshot(migration);assert.equal(fresh.objectives.filter(target).length,3);
 for(const row of fresh.objectives.filter(target)){assert.deepEqual(row.hint_content,hints[KEY][row.objective_id]);assert.deepEqual(row.solution_content,solutions[KEY][row.objective_id]);assert.equal(row.is_enabled,require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES[KEY].find(x=>x.id===row.objective_id).defaultEnabled!==false);for(const field of ['hint_enabled','solution_enabled'])assert.equal(row[field],false);}
 await seed.seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(migration),fresh);
 await seed.seedWorkshopPlatform(migration,{hints:{...hints,[KEY]:{...hints[KEY],...prior.hints}},solutions:{...solutions,[KEY]:{...solutions[KEY],...prior.solutions}}});
 const pending=await snapshot(migration);for(const row of pending.objectives.filter(target)){assert.deepEqual(row.hint_content,prior.hints[row.objective_id]);assert.deepEqual(row.solution_content,prior.solutions[row.objective_id]);}
 await seed.seedWorkshopPlatform(migration);const upgraded=await snapshot(migration);
 for(const row of upgraded.objectives.filter(target)){const old=fresh.objectives.find(x=>x.workshop_key===KEY&&x.objective_id===row.objective_id);assert.deepEqual({...row,updated_at:old.updated_at},old);}
 assert.deepEqual(upgraded.objectives.filter(x=>!target(x)),fresh.objectives.filter(x=>!target(x)));assert.deepEqual(upgraded.exercises,fresh.exercises);
 const unrelated=x=>!(x.entity_kind==='objective'&&target(x)&&['hint_content','solution_content'].includes(x.field_name));assert.deepEqual(upgraded.defaults.filter(unrelated),fresh.defaults.filter(unrelated));
 await seed.seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(migration),upgraded);
 const client=await migration.connect();let discard;
 try{await client.query('BEGIN');try{
  const runSeed=seedInTransaction(client),provenance=require('../../server/database/postgres/catalogDefaultProvenance'),fields=[];
  for(const id of IDS){await client.query('UPDATE workshop_platform.objectives SET hint_content=$3::jsonb,solution_content=$4::jsonb,is_enabled=true,hint_enabled=false,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2',[KEY,id,JSON.stringify({title:'Instructor '+id,hints:['Instructor-owned hint']}),JSON.stringify({title:'Instructor '+id,approach:'Instructor-owned solution'})]);await provenance.markCustomFields(client,{entityKind:'objective',workshopKey:KEY,objectiveId:id},['hint_content','solution_content']);fields.push(id+':hint_content',id+':solution_content');}
  const custom=await snapshot(client);await runSeed();const observed=await snapshot(client);assertRefresh(custom,observed,fields);await runSeed();assert.deepEqual(await snapshot(client),observed);
  await client.query('UPDATE workshop_platform.objectives SET hint_content=NULL,solution_content=NULL WHERE workshop_key=$1 AND objective_id=ANY($2::text[])',[KEY,IDS]);const nulled=await snapshot(client);await runSeed();const nullObserved=await snapshot(client);assertRefresh(nulled,nullObserved,fields);await runSeed();assert.deepEqual(await snapshot(client),nullObserved);
 }finally{try{await client.query('ROLLBACK');}catch(error){discard=error;throw error;}}}finally{client.release(discard);}
 assert.deepEqual(await snapshot(migration),upgraded);
 return {version:'finflow-ssrf-seed-v1',objectiveIds:[...IDS],freshDefaults:true,managedPriorUpgrade:true,instructorCustomPreserved:true,explicitNullPreserved:true,independentGatesPreserved:true,siblingCatalogPreserved:true,rollbackRestored:true,exactSecondSeeds:4};
}
module.exports={IDS,KEY,snapshot,assertRefresh,seedInTransaction,qualify};
