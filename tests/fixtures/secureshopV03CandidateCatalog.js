'use strict';
const assert=require('node:assert/strict');
const{createHash}=require('node:crypto');
const OBJECTIVE='ss_listing_image_command_execution';
async function admitV03DisposableCandidate({migration,catalog,administratorContext,curriculum}={}){
 const checked=curriculum?.OBJECTIVES?.find(row=>row.id===OBJECTIVE);
 assert(['pending','native-browser-judge'].includes(checked?.qualification));assert.equal(checked.defaultEnabled,false);
 const productionQualified=checked.qualification==='native-browser-judge';
 assert.equal(curriculum.isQualifiedObjective(OBJECTIVE),productionQualified);
 const source=JSON.stringify({version:1,id:checked.id,label:checked.text,defaultEnabled:checked.defaultEnabled,qualification:checked.qualification});
 const sourceSha256=createHash('sha256').update(source).digest('hex');
 let objective=(await catalog.list(administratorContext)).objectives.find(row=>row.objectiveId===OBJECTIVE);
 assert.equal(objective?.qualification,checked.qualification);assert.equal(objective.enabled,false);
 if(!productionQualified){
  await assert.rejects(catalog.set(administratorContext,{objectiveId:OBJECTIVE,enabled:true,expectedRevision:objective.revision}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});
  const admitted=await migration.query(`UPDATE secureshop_auth.assessment_objectives SET qualification='native-browser-judge'
   WHERE objective_id=$1 AND qualification='pending' AND is_enabled=false AND catalog_active=true
    AND configuration_source='checked_in_default' AND source_sha256=$2 AND source_document=$3::jsonb
   RETURNING objective_id,qualification,is_enabled`,[OBJECTIVE,sourceSha256,source]);
  assert.equal(admitted.rowCount,1);assert.deepEqual(admitted.rows,[{objective_id:OBJECTIVE,qualification:'native-browser-judge',is_enabled:false}]);
  objective=(await catalog.list(administratorContext)).objectives.find(row=>row.objectiveId===OBJECTIVE);
  assert.equal(objective.qualification,'native-browser-judge');assert.equal(objective.enabled,false);
 }
 const enabled=await catalog.set(administratorContext,{objectiveId:OBJECTIVE,enabled:true,expectedRevision:objective.revision});
 assert.equal(enabled.enabled,true);assert.equal(enabled.qualification,'native-browser-judge');
 return Object.freeze({objectiveId:OBJECTIVE,fixtureLocalCandidateAdmission:!productionQualified,
  productionQualification:checked.qualification,productionDefaultEnabled:false});
}
module.exports={V03_OBJECTIVE:OBJECTIVE,admitV03DisposableCandidate};
