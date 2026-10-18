'use strict';
const assert=require('node:assert/strict');
async function qualifyCsrfTeachingContent({identity,migration,config}){
 const key='csrf_workshop',ids=['csrf_x1','csrf_x2','csrf_x3'];
 const seed=require('../../server/database/postgres/workshopPlatformSeed');
 const prior=require('../fixtures/csrfTeachingDefaults.pre-selected-read.json');
 const defaults=seed.solutionFixtures(),hints=require('../../server/data/workshopHints');
 const rows=async()=>(await identity.query('SELECT objective_id,hint_content,solution_content FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY objective_id',[key])).rows;
 const fresh=await rows();
 for(const id of ids){const row=fresh.find(x=>x.objective_id===id);assert.deepEqual(row.hint_content,hints[key][id]);assert.deepEqual(row.solution_content,defaults[key][id]);}
 // Controlled historical default installation through the same provenance-aware seed.
 await seed.seedWorkshopPlatform(migration,{solutions:{...defaults,[key]:Object.fromEntries(prior.solutions.map(x=>[x.objective_id,x]))},hints:{...hints,[key]:prior.hints}});
 for(const id of ids){const row=(await rows()).find(x=>x.objective_id===id);assert.deepEqual(row.hint_content,prior.hints[id]);assert.deepEqual(row.solution_content,prior.solutions.find(x=>x.objective_id===id));}
 const customHint={...(await rows()).find(x=>x.objective_id==='csrf_g1').hint_content,title:'Instructor CSRF recon hint',hints:['Observe the synthetic attack surface twice.']};
 await config.updateHintContent(key,'csrf_g1',{title:customHint.title,hints:customHint.hints});
 const customSolution={...(await rows()).find(x=>x.objective_id==='csrf_p1').solution_content,title:'Instructor POST solution',description:'Retain instructor-authored teaching content.'};
 await config.updateSolutionContent(key,'csrf_p1',{title:customSolution.title,description:customSolution.description});
 await seed.seedWorkshopPlatform(migration);
 const upgraded=await rows();for(const id of ids){const row=upgraded.find(x=>x.objective_id===id);assert.deepEqual(row.hint_content,hints[key][id]);assert.deepEqual(row.solution_content,defaults[key][id]);}
 assert.deepEqual(upgraded.find(x=>x.objective_id==='csrf_g1').hint_content,customHint);
 assert.deepEqual(upgraded.find(x=>x.objective_id==='csrf_p1').solution_content,customSolution);
 const snapshot=async()=>({rows:await rows(),provenance:(await identity.query('SELECT * FROM workshop_platform.catalog_field_defaults WHERE workshop_key=$1 ORDER BY entity_kind,objective_id,field_name',[key])).rows,revision:(await identity.query('SELECT * FROM workshop_platform.config_revision')).rows});
 const before=await snapshot();await seed.seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(),before);
 return {freshDefaults:true,managedPriorUpgrade:true,instructorPreserved:true,secondSeedNoop:true,objectiveIds:ids};
}
module.exports={qualifyCsrfTeachingContent};
