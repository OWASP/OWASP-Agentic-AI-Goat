'use strict';
const assert=require('node:assert/strict');
async function qualifyAuditCatalog({identity,migration}){
  const {seedWorkshopPlatform}=require('../../server/database/postgres/workshopPlatformSeed');
  const catalog=require('../../server/config/secureshopCurriculum');
  const key=catalog.WORKSHOP_KEY,pending='ss_audit_instruction_followed',pendingIds=new Set(catalog.PENDING_OBJECTIVE_IDS);
  await seedWorkshopPlatform(migration);
  const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(identity,{isSecureShopReady:()=>true});
  const rows=async()=>(await identity.query(`SELECT objective_id,label,is_enabled,hint_enabled,solution_enabled
    FROM workshop_platform.objectives WHERE workshop_key=$1 AND catalog_active ORDER BY ordinal`,[key])).rows;
  const canonicalIds=catalog.OBJECTIVES.map(objective=>objective.id).sort();
  const qualifiedIds=[...catalog.QUALIFIED_OBJECTIVE_IDS].sort();
  const objectiveIds=entries=>entries.map(row=>row.objective_id).sort();
  assert.deepEqual(objectiveIds(await rows()),canonicalIds,'active database catalog exactly matches canonical identities');
  assert.ok(qualifiedIds.includes('ss_audit_sql_extraction'));
  assert.ok(qualifiedIds.includes('ss_audit_instruction_followed'));
  for(const method of ['setObjectiveVisibility','setObjectiveHintVisibility','setObjectiveSolutionVisibility'])
    for(const pendingId of pendingIds)await assert.rejects(config[method](key,pendingId,true),{code:'OBJECTIVE_UNQUALIFIED'});
  const enabled=await config.setAllObjectiveVisibility(key,true);assert.equal(enabled.affectedCount,qualifiedIds.length);
  await config.setMasterHintVisibility(key,true);await config.setMasterSolutionVisibility(key,true);
  let current=await rows();
  assert.deepEqual(objectiveIds(current.filter(row=>row.is_enabled)),qualifiedIds,'bulk enable selects exactly qualified objectives');
  assert.ok(current.filter(row=>!pendingIds.has(row.objective_id)).every(row=>row.hint_enabled&&row.solution_enabled));
  assert.ok(current.filter(row=>pendingIds.has(row.objective_id)).every(row=>!row.is_enabled&&!row.hint_enabled&&!row.solution_enabled));
  const groups=catalog.projectExerciseGroups(current.filter(row=>row.is_enabled).map(row=>({id:row.objective_id,label:row.label})));
  assert.deepEqual(groups.flatMap(group=>group.objectives.map(objective=>objective.id)).sort(),qualifiedIds,'group projection preserves every enabled identity exactly once');
  assert.deepEqual(groups.map(group=>group.id).sort(),catalog.EXERCISES.filter(group=>group.objectiveIds.some(id=>qualifiedIds.includes(id))).map(group=>group.id).sort());
  assert.equal(groups.some(group=>group.id==='ss_audit_injection'),true);
  await migration.query(`UPDATE workshop_platform.objectives SET label='Instructor audit label'
    WHERE workshop_key=$1 AND objective_id=$2`,[key,pending]);
  await seedWorkshopPlatform(migration);await seedWorkshopPlatform(migration);
  current=await rows();assert.equal(current.find(row=>row.objective_id===pending).label,'Instructor audit label');
  assert.deepEqual(objectiveIds(current),canonicalIds,'reseed preserves canonical identities');
  assert.deepEqual(objectiveIds(current.filter(row=>row.is_enabled)),qualifiedIds,'reseed preserves instructor enablement');
  await config.setAllObjectiveVisibility(key,false);await config.setMasterHintVisibility(key,false);await config.setMasterSolutionVisibility(key,false);
  assert.ok((await rows()).every(row=>!row.is_enabled&&!row.hint_enabled&&!row.solution_enabled));
}
module.exports={qualifyAuditCatalog};
