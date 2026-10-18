'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const{V44_OBJECTIVE,admitV44DisposableCandidate}=require('./fixtures/secureshopV44CandidateCatalog');
test('V44 candidate admission is disposable, pending-only, default-disabled and exact-source bound',async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 let qualification='pending',enabled=false,revision=1,updates=0,denials=0;
 const row={id:V44_OBJECTIVE,text:'Synthetic traversal read',defaultEnabled:false,qualification:'pending'};
 const curriculum={OBJECTIVES:[row],isQualifiedObjective:id=>{assert.equal(id,V44_OBJECTIVE);return false;}};
 const catalog={list:async()=>({objectives:[{objectiveId:V44_OBJECTIVE,qualification,enabled,revision}]}),set:async(_ctx,input)=>{assert.equal(input.objectiveId,V44_OBJECTIVE);assert.equal(input.expectedRevision,revision);if(qualification==='pending'){denials++;throw Object.assign(Error('unqualified'),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});}enabled=input.enabled;revision++;return{enabled,qualification};}};
 const migration={query:async(sql,args)=>{updates++;assert.match(sql,/qualification='pending'/);assert.match(sql,/configuration_source='checked_in_default'/);assert.equal(args[0],V44_OBJECTIVE);const source=JSON.stringify({version:1,id:row.id,label:row.text,defaultEnabled:false,qualification:'pending'});assert.equal(args[2],source);assert.equal(args[1],require('node:crypto').createHash('sha256').update(source).digest('hex'));qualification='native-browser-judge';return{rowCount:1,rows:[{objective_id:V44_OBJECTIVE,qualification,is_enabled:false}]};}};
 try{assert.deepEqual(await admitV44DisposableCandidate({migration,catalog,administratorContext:{controlled:true},curriculum}),{objectiveId:V44_OBJECTIVE,fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false});assert.equal(updates,1);assert.equal(denials,1);assert.equal(enabled,true);}finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
test('V44 qualified catalog uses normal administrator enablement without a fixture SQL transition',async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 let enabled=false,revision=4,sets=0;
 const row={id:V44_OBJECTIVE,text:'Synthetic traversal read',defaultEnabled:false,qualification:'native-browser-judge'};
 const curriculum={OBJECTIVES:[row],isQualifiedObjective:id=>{assert.equal(id,V44_OBJECTIVE);return true;}};
 const catalog={list:async()=>({objectives:[{objectiveId:V44_OBJECTIVE,qualification:row.qualification,enabled,revision}]}),
  set:async(_ctx,input)=>{sets++;assert.deepEqual(input,{objectiveId:V44_OBJECTIVE,enabled:true,expectedRevision:revision});enabled=true;revision++;return{enabled,qualification:row.qualification};}};
 const migration={query:async()=>{throw Error('Qualified V44 catalog must not use fixture SQL admission');}};
 try{assert.deepEqual(await admitV44DisposableCandidate({migration,catalog,administratorContext:{controlled:true},curriculum}),
  {objectiveId:V44_OBJECTIVE,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
  assert.equal(sets,1);assert.equal(enabled,true);
 }finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
for(const [name,mutate] of [
 ['true checked-in default',({row})=>{row.defaultEnabled=true;}],
 ['unqualified curriculum projection',({state})=>{state.isQualified=false;}],
 ['catalog qualification drift',({state})=>{state.catalogQualification='pending';}],
])test(`V44 normal qualified admission rejects ${name}`,async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 const row={id:V44_OBJECTIVE,text:'Synthetic traversal read',defaultEnabled:false,qualification:'native-browser-judge'};
 const state={isQualified:true,catalogQualification:'native-browser-judge'};mutate({row,state});
 const curriculum={OBJECTIVES:[row],isQualifiedObjective:()=>state.isQualified};
 const catalog={list:async()=>({objectives:[{objectiveId:V44_OBJECTIVE,
  qualification:state.catalogQualification,enabled:false,revision:2}]}),set:async()=>{throw Error('Drifted catalog must fail before enablement');}};
 try{await assert.rejects(admitV44DisposableCandidate({migration:{query:async()=>{throw Error('No fixture SQL');}},
  catalog,administratorContext:{controlled:true},curriculum}),assert.AssertionError);
 }finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
