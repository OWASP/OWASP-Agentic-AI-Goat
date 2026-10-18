'use strict';
const assert=require('node:assert/strict');const{test}=require('node:test');
const candidate=require('./fixtures/secureshopV03CandidateCatalog');
test('V03 candidate adapter uses current qualification without SQL and retains explicit historical pending admission',async()=>{
 for(const qualification of ['pending','native-browser-judge']){
  let enabled=false,revision=4,updates=0,denials=0;
  const objective=()=>({objectiveId:candidate.V03_OBJECTIVE,
   qualification:updates?'native-browser-judge':qualification,enabled,revision});
  const catalog={list:async()=>({objectives:[objective()]}),set:async(_ctx,input)=>{
   assert.equal(input.objectiveId,candidate.V03_OBJECTIVE);assert.equal(input.expectedRevision,revision);
   if(objective().qualification==='pending'){denials++;const error=Object.assign(Error('unqualified'),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});throw error;}
   enabled=input.enabled;revision++;return objective();}};
  const migration={query:async(sql,values)=>{updates++;assert.match(sql,/qualification='pending'.*is_enabled=false.*catalog_active=true.*configuration_source='checked_in_default'/s);assert.equal(values[0],candidate.V03_OBJECTIVE);assert.match(values[1],/^[a-f0-9]{64}$/);assert.equal(JSON.parse(values[2]).qualification,'pending');return{rowCount:1,rows:[{objective_id:candidate.V03_OBJECTIVE,qualification:'native-browser-judge',is_enabled:false}]};}};
  const curriculum={OBJECTIVES:[{id:candidate.V03_OBJECTIVE,text:'Owned V03 candidate',qualification,defaultEnabled:false}],isQualifiedObjective:()=>qualification==='native-browser-judge'};
  const receipt=await candidate.admitV03DisposableCandidate({migration,catalog,administratorContext:{},curriculum});
  assert.deepEqual(Object.keys(receipt).sort(),['fixtureLocalCandidateAdmission','objectiveId','productionDefaultEnabled','productionQualification']);
  assert.deepEqual(receipt,{objectiveId:candidate.V03_OBJECTIVE,fixtureLocalCandidateAdmission:qualification==='pending',productionQualification:qualification,productionDefaultEnabled:false});
  assert.equal(updates,qualification==='pending'?1:0);assert.equal(denials,qualification==='pending'?1:0);assert.equal(enabled,true);
 }
});
