'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const contract=require('../server/agent-runtime/dpiPolicyContract');
const view=require('../client/src/utils/dpiSelectedLesson');
test('selected lesson projection is closed, scoped and contains no policy material',()=>{
 for(const objectiveId of [...contract.TEXT_OBJECTIVES,'obfuscation'])for(const mode of objectiveId==='obfuscation'?['vuln','fixed']:['vuln']){
  const policy=contract.selectPolicy({objectiveId,mode}),value=contract.selectedLesson(policy);
  assert.deepEqual(view.readSelectedLesson(value),value);assert.equal(Object.keys(view.LESSONS).length,8);assert.equal(Object.keys(value).length,6);assert.equal(value.lessonKind,policy.lessonKind);
  assert.deepEqual(contract.admitSelectedLesson(value,objectiveId,mode),value);
  assert(view.describeSelectedLesson(value).includes(mode==='fixed'?'fixed mode':'vulnerable mode'));
  assert.throws(()=>contract.admitSelectedLesson(value,'other',mode));
  assert.throws(()=>contract.admitSelectedLesson(value,objectiveId,mode==='vuln'?'fixed':'vuln'));
  for(const change of [{extra:'x'},{systemPolicySha256:policy.systemPolicySha256},{lessonKind:'other'},{profile:'other'},{policyVersion:'other'},{version:'other'}])assert.equal(view.readSelectedLesson({...value,...change}),null);
 }
 assert.equal(view.readSelectedLesson(undefined),null);
 assert.throws(()=>contract.selectedLesson({...contract.selectPolicy({objectiveId:'interact',mode:'vuln'}),systemPolicySha256:'0'.repeat(64)}));
});
test('legacy graph without admitted policy does not synthesize a lesson',async()=>{
 const {runDpiGraph}=require('../server/agent-runtime/dpiGraph');
 const result=await runDpiGraph('hello',[],{},'interact',{SYSTEM_PROMPTS:contract.SYSTEM_PROMPTS,OBJECTIVE_IDS:{INTERACT:'interact',OBFUSCATION:'obfuscation'},filterRejectedExchanges:x=>x,buildMessages:system=>[{role:'system',content:system}],aiService:{async chatWithMessages(){return {provider:'mock',model:'fixture',mocked:true,response:'hello'};}},async evaluateDpiObjective(){return {verdict:'inconclusive'};}});
 assert.equal(Object.hasOwn(result,'selectedLesson'),false);
});
test('actual route forwards only selected lesson matching admitted objective and mode',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
 const filename=path.resolve(__dirname,'../server/routes/promptInjectionWorkshop.js');
 const router=()=>({handlers:{},use(){},get(){},post(p,fn){this.handlers[p]=fn;},all(){}});
 const progress={assertObjectiveEnabled:async()=>{},getProgress:async()=>({objectives:{}})};
 const mode={WORKSHOP_MODE_CATALOG:{direct_prompt_injection:{}}};
 const exports={};
 const context={module:{exports},exports,console:{log(){},warn(){},error(){}},process:{env:{PLATFORM_DATABASE_ENGINE:'postgres'}},require(id){
  if(id==='express')return {Router:router};
  if(id==='../agent-runtime/dpiPolicyContract')return contract;
  if(id==='../config/workshopCatalog')return {WORKSHOP_OBJECTIVES:{direct_prompt_injection:[]}};
  if(id==='../services/promptInjectionProgressService')return {createDefaultPromptInjectionProgressService:()=>progress};
  if(id==='../agent-runtime/runCoordinator')return {createRunCoordinator:()=>({})};
  if(id==='../services/workshopModeService')return mode;
  if(id==='../services/promptInjectionWorkshop'||id==='../services/multiProviderAIService'||id==='../utils/contextLogger'||id==='../services/promptInjectionStatusService')return {};
  throw Error('Unexpected route dependency '+id);
 }};
 vm.runInNewContext(fs.readFileSync(filename,'utf8'),context,{filename});
 const create=context.module.exports.createPromptInjectionWorkshopRouter;
 const selected=contract.selectedLesson(contract.selectPolicy({objectiveId:'obfuscation',mode:'fixed'}));
 async function invoke(value){
  const r=create({progressService:progress,legacyFixture:true,completionService:{beginAttempt:async()=>({mode:'fixed'})},logger:{error(){}},workshopService:{chat:async()=>({response:'controlled response',durableGrading:true,...(value?{selectedLesson:value}:{})})},runCoordinator:{run:async(_u,_o,work)=>work({check:async()=>{},trace:async()=>{}})}});
  let body,status=200;const res={status(n){status=n;return this;},json(v){body=v;return this;}};
  await r.handlers['/chat']({user:{id:7},body:{userMessage:'request',activeObjectiveId:'obfuscation'}},res);
  return {body,status};
 }
 const good=await invoke(selected);assert.equal(good.status,200);assert.deepEqual(good.body.selectedLesson,selected);
 assert.equal(Object.hasOwn((await invoke()).body,'selectedLesson'),false);
 for(const bad of [{...selected,mode:'vuln'},{...selected,objectiveId:'interact'},{...selected,extra:'private'}])assert.notEqual((await invoke(bad)).status,200);
});
test('server policy selection loads without frontend source in packaged deployment',()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const module={exports:{}};
 vm.runInNewContext(fs.readFileSync(require.resolve('../server/agent-runtime/dpiPolicyContract'),'utf8'),{module,require(id){assert(!id.includes('client/'));if(id==='node:crypto')return require(id);throw Error('Unexpected dependency '+id);}});
 for(const id of [...module.exports.TEXT_OBJECTIVES,'obfuscation']){
  const selected=module.exports.selectedLesson(module.exports.selectPolicy({objectiveId:id,mode:'vuln'}));
  assert.equal(view.readSelectedLesson(selected).lessonKind,selected.lessonKind);
 }
});
