'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {admitV01DisposableCandidate}=require('./fixtures/secureshopV01CandidateCatalog');
test('V01 candidate admission is confined to one disposable pending default row',async()=>{
 let qualified=false,enabled=false,revision=7,updates=0;
 const row=()=>({objectiveId:'ss_auth_bypass_jwt_none',qualification:qualified?'native-browser-judge':'pending',enabled,revision});
 const catalog={async list(){return{objectives:[row()]};},async set(_context,input){
  if(!qualified){const error=Error('pending');error.code='SHOP_OBJECTIVE_UNQUALIFIED';throw error;}
  assert.deepEqual(input,{objectiveId:'ss_auth_bypass_jwt_none',enabled:true,expectedRevision:revision});
  enabled=true;revision++;return row();}};
 const migration={async query(sql,args){updates++;assert.match(sql,/configuration_source='checked_in_default'/);
  assert.match(sql,/source_sha256=\$2 AND source_document=\$3::jsonb/);
  assert.equal(args[0],'ss_auth_bypass_jwt_none');assert.match(args[1],/^[a-f0-9]{64}$/);
  assert.deepEqual(JSON.parse(args[2]),{version:1,id:'ss_auth_bypass_jwt_none',label:'JWT lesson',
    defaultEnabled:false,qualification:'pending'});
  qualified=true;return{rowCount:1,rows:[{objective_id:'ss_auth_bypass_jwt_none',qualification:'native-browser-judge',is_enabled:false}]};}};
 const curriculum={OBJECTIVES:[{id:'ss_auth_bypass_jwt_none',text:'JWT lesson',qualification:'pending',defaultEnabled:false}],
  isQualifiedObjective:()=>false};
 assert.deepEqual(await admitV01DisposableCandidate({migration,catalog,administratorContext:{},curriculum}),{
  objectiveId:'ss_auth_bypass_jwt_none',fixtureLocalCandidateAdmission:true,
  productionQualification:'pending',productionDefaultEnabled:false});
 assert.equal(updates,1);assert.equal(enabled,true);
});
