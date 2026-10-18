'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const filename=path.resolve(__dirname,'../server/routes/promptInjectionWorkshop.js');
function routeFactory(){
 const progress={assertObjectiveEnabled:async()=>{},getProgress:async()=>({objectives:{}})};
 const context={module:{exports:{}},console:{log(){},warn(){},error(){}},process:{env:{PLATFORM_DATABASE_ENGINE:'postgres'}},require(id){
  if(id==='express')return {Router:()=>({handlers:{},use(){},get(){},post(p,f){this.handlers[p]=f;},all(){}})};
  if(id==='../config/workshopCatalog')return {WORKSHOP_OBJECTIVES:{direct_prompt_injection:[]}};
  if(id==='../services/promptInjectionProgressService')return {createDefaultPromptInjectionProgressService:()=>progress};
  if(id==='../agent-runtime/runCoordinator')return {createRunCoordinator:()=>({})};
  if(id==='../services/workshopModeService')return {WORKSHOP_MODE_CATALOG:{direct_prompt_injection:{}}};
  if(['../services/promptInjectionWorkshop','../services/multiProviderAIService','../utils/contextLogger','../services/promptInjectionStatusService'].includes(id))return {};
  throw Error('Unexpected dependency '+id);
 }};
 vm.runInNewContext(fs.readFileSync(filename,'utf8'),context,{filename});
 return async error=>{
  let progressWrites=0,status=200,body;
  const r=context.module.exports.createPromptInjectionWorkshopRouter({legacyFixture:true,progressService:{...progress,completeObjective:async()=>{progressWrites++;}},completionService:{beginAttempt:async()=>({})},logger:{error(){}},aiService:{getActiveProviderInfo:()=>({provider:'ollama',providerName:'Ollama'}),getOllamaBaseURL:()=> 'http://127.0.0.1:11434'},workshopService:{chat:async()=>{throw error;}},runCoordinator:{run:async(_u,_o,work)=>work({check:async()=>{},trace:async()=>{}})}});
  await r.handlers['/chat']({user:{id:7},body:{userMessage:'Explain S3',activeObjectiveId:'obfuscation'}},{status(n){status=n;return this;},json(v){body=v;return this;}});
  assert.equal(progressWrites,0);assert.equal(body.response,null);assert.equal(body.completedObjectiveId,null);return {status,body};
 };
}
test('DPI distinguishes slow inference, unreachable provider, and cancelled runs without credit',async()=>{
 const invoke=routeFactory();
 for(const error of [Object.assign(Error('The operation was aborted due to timeout'),{name:'TimeoutError'}),Object.assign(Error('request timed out'),{code:'ETIMEDOUT'}),Error('Provider timeout')]){
  const {status,body}=await invoke(error);assert.equal(status,504);assert.equal(body.code,'AI_PROVIDER_TIMEOUT');assert.match(body.error,/inference speed/);assert.doesNotMatch(body.error,/ollama serve|Ensure Ollama/);
 }
 const unavailable=await invoke(Error('connect ECONNREFUSED'));assert.equal(unavailable.status,503);assert.match(unavailable.body.error,/Ensure Ollama/);
 const cancelled=await invoke(Object.assign(Error('reset'),{name:'AbortError'}));assert.equal(cancelled.status,409);assert.equal(cancelled.body.code,'AGENT_RUN_CANCELLED');
 const failed=await invoke(Error('unexpected provider failure'));assert.equal(failed.status,500);
});
