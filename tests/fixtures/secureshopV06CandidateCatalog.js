'use strict';
const assert=require('node:assert/strict');
const{createHash}=require('node:crypto');
const OBJECTIVE='ss_upload_extension_bypass';
async function admitDisposableCandidate({migration,catalog,administratorContext,curriculum,objectiveId=OBJECTIVE,pendingSourceSha256}={}){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const checked=curriculum?.OBJECTIVES?.find(row=>row.id===objectiveId);
 assert.ok(['pending','native-browser-judge'].includes(checked?.qualification));assert.equal(checked.defaultEnabled,false);
 if(pendingSourceSha256)assert.equal(createHash('sha256').update(JSON.stringify({version:1,id:checked.id,label:checked.text,defaultEnabled:false,qualification:'pending'})).digest('hex'),pendingSourceSha256);
 const fixtureLocalCandidateAdmission=checked.qualification==='pending';
 assert.equal(curriculum.isQualifiedObjective(objectiveId),!fixtureLocalCandidateAdmission);
 let objective=(await catalog.list(administratorContext)).objectives.find(row=>row.objectiveId===objectiveId);
 assert.equal(objective?.qualification,checked.qualification);assert.equal(objective.enabled,false);
 if(fixtureLocalCandidateAdmission){
  await assert.rejects(catalog.set(administratorContext,{objectiveId,enabled:true,
   expectedRevision:objective.revision}),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});
  const source=JSON.stringify({version:1,id:checked.id,label:checked.text,
   defaultEnabled:checked.defaultEnabled,qualification:checked.qualification});
  const sourceSha256=createHash('sha256').update(source).digest('hex');
  const admitted=await migration.query(`UPDATE secureshop_auth.assessment_objectives
   SET qualification='native-browser-judge' WHERE objective_id=$1 AND qualification='pending'
    AND is_enabled=false AND catalog_active=true AND configuration_source='checked_in_default'
    AND source_sha256=$2 AND source_document=$3::jsonb
   RETURNING objective_id,qualification,is_enabled`,[objectiveId,sourceSha256,source]);
  assert.equal(admitted.rowCount,1);assert.deepEqual(admitted.rows,[{objective_id:objectiveId,
   qualification:'native-browser-judge',is_enabled:false}]);
  objective=(await catalog.list(administratorContext)).objectives.find(row=>row.objectiveId===objectiveId);
 }
 assert.equal(objective.qualification,'native-browser-judge');assert.equal(objective.enabled,false);
 const enabled=await catalog.set(administratorContext,{objectiveId,enabled:true,
  expectedRevision:objective.revision});
 assert.equal(enabled.enabled,true);assert.equal(enabled.qualification,'native-browser-judge');
 return Object.freeze({objectiveId,fixtureLocalCandidateAdmission,
  productionQualification:checked.qualification,productionDefaultEnabled:false});
}
function admitV06DisposableCandidate(options){return admitDisposableCandidate(options);}
function admitV07DisposableCandidate(options){return admitDisposableCandidate({...options,objectiveId:'ss_upload_polyglot_server_execution',pendingSourceSha256:'00be7f7921bafa94f62a633575f39e63469369c30d935239a67f41540f238dd8'});}
module.exports={V06_OBJECTIVE:OBJECTIVE,admitV06DisposableCandidate,admitV07DisposableCandidate};
