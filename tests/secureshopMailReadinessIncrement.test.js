'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {stageMailReadinessCandidate}=require('./fixtures/secureshopMailReadinessCandidate');
const {ownedModelList}=require('./fixtures/secureshopMailReadinessSupport');
test('readiness staging is idempotent and preserves current unrelated release flags without copying source',()=>{
 const {promoteKnownFlag}=require('./fixtures/secureshopMailReadinessCandidate');const prior=process.env.PG_TEST_DISPOSABLE;
 try{delete process.env.PG_TEST_DISPOSABLE;assert.throws(()=>stageMailReadinessCandidate('/never-read'));}finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
 for(const [file,before,after]of [['secureshopMailProduction.js','const PRODUCTION_QUALIFIED=false;','const PRODUCTION_QUALIFIED=true;'],['secureshopMailObjectiveReadiness.js','ss_mail_header_construction:false','ss_mail_header_construction:true']]){const current=fs.readFileSync(path.join('server/services',file),'utf8');assert.equal(promoteKnownFlag(current,before,after),current);const pending=current.replace(after,before);assert.equal(promoteKnownFlag(pending,before,after),current);assert.throws(()=>promoteKnownFlag(before+after,before,after));assert.throws(()=>promoteKnownFlag(after+after,before,after));}
 const {mailObjectiveReadiness,MAIL_OBJECTIVE_QUALIFICATION}=require('../server/services/secureshopMailObjectiveReadiness');assert.equal(MAIL_OBJECTIVE_QUALIFICATION.ss_mail_stored_browser_execution,true);assert(Object.values(mailObjectiveReadiness({transportReady:true,judgeReady:true,catalog:{}})).every(x=>x===false));assert(require('../server/config/secureshopCurriculum').OBJECTIVES.every(x=>x.defaultEnabled===false));
});
test('owned model-list listener exposes exact independent models and denies inference',async()=>{
 const server=await ownedModelList();try{assert.deepEqual((await(await fetch(server.origin+'/api/tags')).json()).models.map(r=>r.name),['owned-actor','owned-judge']);server.set({actor:false,judge:true});assert.deepEqual((await(await fetch(server.origin+'/api/tags')).json()).models.map(r=>r.name),['owned-judge']);assert.equal((await fetch(server.origin+'/api/chat',{method:'POST'})).status,503);assert.equal(server.counts().generation,1);}finally{await server.close();}
});
test('readiness increment preserves source-only orchestration contracts and no grading seed',()=>{
 const source=fs.readFileSync('tests/postgres/secureshopListingsFullApp.native.js','utf8'),browser=fs.readFileSync('tests/fixtures/secureshopMailReadinessBrowser.js','utf8'),support=fs.readFileSync('tests/fixtures/secureshopMailReadinessSupport.js','utf8');assert(source.includes('delete env.SS_BOUND_MAIL_ENABLED'));assert(source.includes('shouldInstallControlledProvider({mailReadinessMode,replyMode})'));const policy=require('./fixtures/secureshopMailReplyMountedContract').shouldInstallControlledProvider;assert.equal(policy({mailReadinessMode:true}),false);assert.equal(policy({replyMode:true}),false);assert.equal(policy({}),true);assert(source.includes('qualifyHeaderSeed({identity,migration})'));assert(browser.includes("click('Check pending mail')"));assert(browser.includes("click('Check saved headers')"));assert(!browser.includes('localStorage.setItem'));assert(support.includes('updateSolutionContent(key,id,customSolution)'));assert(support.includes('assert.deepEqual((await read()).filter'));assert(!support.includes('INSERT INTO workshop_platform.completions'));
});

test('read-only recovery capture binds exact original UUID and persisted successful DTO',()=>{const {decodeRecovery}=require('./fixtures/secureshopMailReadinessBrowser'),id=require('node:crypto').randomUUID(),expected={origin:'http://127.0.0.1:3001',requestId:id},event={request:{method:'GET',url:'http://127.0.0.1:3001/api/secureshop/email/operations/send/'+id},responseStatusCode:200},body={ok:true,status:'saved',requestId:id,email_id:3};assert.deepEqual(decodeRecovery(event,{body:JSON.stringify(body)},expected),body);for(const bad of [{...body,requestId:require('node:crypto').randomUUID()},{...body,email_id:0},{...body,status:'unconfirmed'}])assert.throws(()=>decodeRecovery(event,{body:JSON.stringify(bad)},expected));assert.throws(()=>decodeRecovery({...event,request:{...event.request,method:'POST'}},{body:JSON.stringify(body)},expected));});

test('readiness listener satisfies the real closed network guard contract',async()=>{
 const {validateNetworkConfiguration,networkGuardSource}=require('./fixtures/fullBackendBootControls');
 const listener=await ownedModelList();try{
  const database={host:'127.0.0.1',port:5432},service={name:'fixture_mail_model_list',host:'127.0.0.1',port:listener.port};
  const config={version:1,services:[{name:'agent_host',host:'127.0.0.1',port:8082},{name:'fixture_listings',host:'127.0.0.1',port:8095},service]};
  assert.deepEqual(validateNetworkConfiguration(database,config).services[2],service);assert.equal(typeof networkGuardSource(database,config),'string');
  for(const invalid of [{...service,name:'mail_model_list'},{...service,host:'192.0.2.1'},{...service,port:0}])assert.throws(()=>validateNetworkConfiguration(database,{version:1,services:[invalid]}));
  assert(fs.readFileSync('tests/postgres/secureshopListingsFullApp.native.js','utf8').includes("name:'fixture_mail_model_list',host:'127.0.0.1',port:modelList.port"));
 }finally{await listener.close();}
});
