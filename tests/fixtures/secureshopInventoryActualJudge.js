'use strict';
const assert=require('node:assert/strict');
const {createObjectiveJudge}=require('../../server/agent-runtime/objectiveJudge');
const {createLangChainProvider}=require('../../server/agent-runtime/providers/langchainProvider');
function createActualInventoryJudge({actual,record,maxCalls=4,signal}={}){
 assert.equal(typeof actual?.withJudgePhase,'function');assert.equal(typeof record,'function');
 assert.ok(Number.isInteger(maxCalls)&&maxCalls>0&&maxCalls<=4);
 const transport=createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://127.0.0.1:11434'});
 const calls=[];
 const model={async chat(messages,tools,options){
  assert.ok(calls.length<maxCalls,'Judge provider call budget exhausted');
  const call={index:calls.length+1,status:'pending'};calls.push(call);await record(structuredClone(calls));
  try{
   const response=await actual.withJudgePhase(()=>transport.chat(messages,tools,{...options,signal:AbortSignal.any([AbortSignal.timeout(60000),...(signal?[signal]:[]),...(options.signal?[options.signal]:[])])}));
   assert.equal(response.provider,'ollama');assert.equal(response.model,'llama3.1:8b');assert.equal(response.mocked,false);assert.notEqual(response.fallback,true);
   call.status='returned';call.response=response;await record(structuredClone(calls));return response;
  }catch(error){call.status='failed';call.error={name:error.name,code:error.code};await record(structuredClone(calls));throw error;}
 }};
 return{judge:createObjectiveJudge({model,timeoutMs:60000}),calls};
}
module.exports={createActualInventoryJudge};
