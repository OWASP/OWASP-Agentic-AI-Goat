'use strict';
const assert=require('node:assert/strict');
const key='mcp_workshop',id='mcp_audit_gap';
// Called only by the existing disposable main-owned MCP qualification.
async function qualify({migration}) {
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const seed=require('../../server/database/postgres/workshopPlatformSeed');
 const catalog=require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES;
 const hints=require('../../server/data/workshopHints'),solutions=seed.solutionFixtures(),prior=require('./mcpAuditPriorDefaults.json');
 const read=async client=>(await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows;
 const before=await read(migration),target=before.find(r=>r.workshop_key===key&&r.objective_id===id);
 assert(target);assert.equal(target.label,catalog[key].find(r=>r.id===id).text);
 assert.deepEqual(target.hint_content,hints[key][id]);assert.deepEqual(target.solution_content,solutions[key][id]);
 await seed.seedWorkshopPlatform(migration,{catalog:{...catalog,[key]:catalog[key].map(r=>r.id===id?{...r,text:prior.label}:r)},hints:{...hints,[key]:{...hints[key],[id]:prior.hint}},solutions:{...solutions,[key]:{...solutions[key],[id]:prior.solution}}});
 const old=(await read(migration)).find(r=>r.workshop_key===key&&r.objective_id===id);
 assert.equal(old.label,prior.label);assert.deepEqual(old.hint_content,prior.hint);assert.deepEqual(old.solution_content,prior.solution);
 await seed.seedWorkshopPlatform(migration);
 // Seed timestamps may change on the target; compare actual content and sibling rows separately.
 const restored=await read(migration),current=restored.find(r=>r.workshop_key===key&&r.objective_id===id);
 for(const field of ['label','hint_content','solution_content'])assert.deepEqual(current[field],target[field]);
 assert.deepEqual(restored.filter(r=>r!==current),before.filter(r=>r!==target));
 const snapshot=async client=>({objectives:await read(client),defaults:(await client.query('SELECT * FROM workshop_platform.catalog_field_defaults ORDER BY entity_kind,workshop_key,objective_id,field_name')).rows,revision:(await client.query('SELECT * FROM workshop_platform.config_revision ORDER BY id')).rows});
 const settled=await snapshot(migration);await seed.seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(migration),settled);
 const client=await migration.connect();let discard;
 try{await client.query('BEGIN');try{
  const provenance=require('../../server/database/postgres/catalogDefaultProvenance');
  for(const field of ['label','hint_content','solution_content'])for(const value of (field==='label'?['Instructor audit label']:[{title:'Instructor audit content'},null])){
   await client.query(`UPDATE workshop_platform.objectives SET ${field}=$3 WHERE workshop_key=$1 AND objective_id=$2`,[key,id,field==='label'||value===null?value:JSON.stringify(value)]);
   for(let n=0;n<2;n++)assert.equal((await provenance.reconcileField(client,{entityKind:'objective',workshopKey:key,objectiveId:id,fieldName:field,sourceValue:target[field],sourceVersion:'mcp-audit-qualification'})).changed,false);
   assert.deepEqual((await client.query(`SELECT ${field} AS value FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2`,[key,id])).rows[0].value,value);
  }
  // Real effective projection: each master and objective gate is independent.
  await client.query('UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key=$1',[key]);
  for(const [masterHint,masterSolution,hintGate,solutionGate] of [[true,true,true,true],[false,true,true,true],[true,false,true,true],[true,true,false,true],[true,true,true,false]]){
   await client.query('UPDATE workshop_platform.exercises SET show_hints=$2,show_solutions=$3 WHERE workshop_key=$1',[key,masterHint,masterSolution]);
   await client.query('UPDATE workshop_platform.objectives SET is_enabled=true,hint_enabled=$3,solution_enabled=$4,hint_content=$5,solution_content=$6 WHERE workshop_key=$1 AND objective_id=$2',[key,id,hintGate,solutionGate,JSON.stringify(target.hint_content),JSON.stringify(target.solution_content)]);
   const row=(await require('../../server/database/postgres/workshopConfigRepository').readConfig(client)).exercises[key].objectives[id];
   assert.equal(row.hintVisible,masterHint&&hintGate);assert.equal(row.solutionVisible,masterSolution&&solutionGate);
  }
  await client.query('UPDATE workshop_platform.objectives SET hint_content=NULL,solution_content=NULL,hint_enabled=true,solution_enabled=true WHERE workshop_key=$1 AND objective_id=$2',[key,id]);
  const absent=(await require('../../server/database/postgres/workshopConfigRepository').readConfig(client)).exercises[key].objectives[id];assert.equal(absent.hintVisible,false);assert.equal(absent.solutionVisible,false);
  await client.query('SAVEPOINT label_null');await assert.rejects(client.query('UPDATE workshop_platform.objectives SET label=NULL WHERE workshop_key=$1 AND objective_id=$2',[key,id]),e=>e.code==='23502');await client.query('ROLLBACK TO SAVEPOINT label_null');
 }finally{try{await client.query('ROLLBACK');}catch(e){discard=e;throw e;}}}finally{client.release(discard);}
 assert.deepEqual(await snapshot(migration),settled);
 return {version:'mcp-audit-seed-v1',freshDefaults:true,managedPriorThreeFields:true,instructorThreeFieldsPreserved:true,nullableContentPreserved:true,labelNullRejected:true,secondRunNoop:true,siblingCatalogPreserved:true,customProbeRolledBack:true,independentEffectiveGates:true,nullContentDenied:true,scope:'Canonical full seed upgrade/no-op; custom/null field reconciliation in rolled-back transaction. Rendered gates and learner evidence are separate.'};
}
module.exports={qualify};
