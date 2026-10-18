'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const{admitV09DisposableCandidate,installV09DisposableReadiness,initializeV09DisposableCandidate,V09_OBJECTIVE}=require('./secureshopV09CandidateCatalog');
test('V09 disposable wrapper changes only its release gate and restores exactly',async()=>{const original=async()=>Object.freeze({ss_mail_reply_redirect:true,[V09_OBJECTIVE]:false});const module={readMailObjectiveReadiness:original};let queries=0;const restore=installV09DisposableReadiness(module,{readEligibility:async(pool,scope,ids)=>{queries++;assert.equal(pool,'identity');assert.deepEqual(scope,{launchId:'l'});assert.deepEqual(ids,[V09_OBJECTIVE]);return[V09_OBJECTIVE];}});assert.deepEqual(await module.readMailObjectiveReadiness({identityPool:'identity',scope:{launchId:'l'},transportReady:true,judgeReady:true}),{ss_mail_reply_redirect:true,[V09_OBJECTIVE]:true});assert.deepEqual(await module.readMailObjectiveReadiness({identityPool:'identity',scope:{launchId:'l'},transportReady:false,judgeReady:true}),{ss_mail_reply_redirect:true,[V09_OBJECTIVE]:false});assert.equal(queries,2);restore();assert.equal(module.readMailObjectiveReadiness,original);restore();});

test('V09 initializes administrator authority before candidate admission and reuses an existing login',async()=>{const events=[];const created={context:{subject:'admin'}};const value=await initializeV09DisposableCandidate({existingAdministrator:null,loginAdministrator:async()=>{events.push('login');return created;},admitCandidate:async context=>{events.push('admit');assert.equal(context,created.context);return{objectiveId:V09_OBJECTIVE};}});assert.deepEqual(events,['login','admit']);assert.equal(value.administrator,created);events.length=0;const reused=await initializeV09DisposableCandidate({existingAdministrator:created,loginAdministrator:async()=>{throw new Error('must not relogin');},admitCandidate:async context=>{events.push('admit');assert.equal(context,created.context);return{objectiveId:V09_OBJECTIVE};}});assert.deepEqual(events,['admit']);assert.equal(reused.administrator,created);});


test('V09 candidate adapter uses production qualification without SQL promotion and keeps historical pending explicit',async()=>{
 for(const qualification of ['pending','native-browser-judge']){
  let enabled=false,revision=7,updates=0,denials=0;
  const current=()=>({objectiveId:V09_OBJECTIVE,qualification:updates?'native-browser-judge':qualification,enabled,revision});
  const catalog={list:async()=>({objectives:[current()]}),set:async(_context,input)=>{
   assert.equal(input.objectiveId,V09_OBJECTIVE);assert.equal(input.expectedRevision,revision);
   if(current().qualification==='pending'){denials++;const error=Error('unqualified');error.code='SHOP_OBJECTIVE_UNQUALIFIED';throw error;}
   enabled=input.enabled;revision++;return current();}};
  const migration={query:async(sql,args)=>{updates++;assert.match(sql,/qualification='pending'.*source_sha256=\$2.*source_document=\$3::jsonb/s);assert.equal(args[0],V09_OBJECTIVE);return{rowCount:1,rows:[{objective_id:V09_OBJECTIVE,qualification:'native-browser-judge',is_enabled:false}]};}};
  const curriculum={OBJECTIVES:[{id:V09_OBJECTIVE,text:'V09 mail HTML',qualification,defaultEnabled:false}],isQualifiedObjective:()=>qualification==='native-browser-judge'};
  const value=await admitV09DisposableCandidate({migration,catalog,administratorContext:{admin:true},curriculum});
  assert.deepEqual(value,{objectiveId:V09_OBJECTIVE,fixtureLocalCandidateAdmission:qualification==='pending',productionQualification:qualification,productionDefaultEnabled:false});
  assert.equal(updates,qualification==='pending'?1:0);assert.equal(denials,qualification==='pending'?1:0);assert.equal(enabled,true);
 }
});
