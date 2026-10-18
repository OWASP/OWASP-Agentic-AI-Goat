'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createObjectiveJudge,prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {createObjectiveCompletionService}=require('../server/services/objectiveCompletionService');
function input(){return{rubric:{family:'Owned',scenario:'scope',objectiveId:'effect',version:'scope-v1',mode:'vuln',criterionScoped:true,requiredFacts:[],criteria:[{id:'outcome',evidenceIds:['public_outcome'],allowedSources:['server_observation'],description:'The observed action succeeded.'}]},facts:{},evidence:[{id:'private_audit',source:'server_observation',content:'PRIVATE_AUDIT_SENTINEL'},{id:'public_outcome',source:'server_observation',content:'The action succeeded.'}]};}
test('criterion evidenceIds rejects missing, duplicate, wrong-source IDs and unsupported non-scoped combinations',()=>{
 for(const edit of [p=>p.rubric.criterionScoped=false,p=>p.rubric.criteria[0].evidenceIds=['missing'],p=>p.rubric.criteria[0].evidenceIds=['public_outcome','public_outcome'],p=>p.evidence[1].source='tool_result',p=>p.rubric.criteria[0].evidenceIds=[]]){const p=input();edit(p);assert.throws(()=>prepareJudgeInput(p));}
 const p=input();delete p.rubric.criteria[0].evidenceIds;assert.doesNotThrow(()=>prepareJudgeInput(p));
});
test('initial and canonical retained retry schema/prompt contain only scoped IDs, preserving full audit packet',async()=>{
 let calls=0,scope;const messages=[];
 const judge=createObjectiveJudge({model:{async chat(value,_tools,options){calls++;messages.push(JSON.stringify({value,format:options.format}));assert.ok(!messages.at(-1).includes('PRIVATE_AUDIT_SENTINEL'));assert.ok(!messages.at(-1).includes('private_audit'));if(calls===1)throw Error('controlled transport unavailable');return{provider:'controlled',model:'controlled',mocked:false,fallback:false,response:JSON.stringify({satisfied:true,evidenceRefs:['public_outcome'],citations:[]})};}}});
 const receipts={async beginEvaluation(value){scope=value;return{...value,verdict:null};},async recordVerdict({evaluationId,result}){return{...scope,evaluationId,verdict:result.verdict,result,disposition:result.verdict==='pass'?'awarded':'not_pass'};},async beginRetry(){return{receipt:{...scope,evaluationId:'child',verdict:null},packet:scope.recovery.packet};}};
 const service=createObjectiveCompletionService({receipts,progress:{async getGeneration(){return 1;}},judge});const execution={runId:'run',ownerKey:'owner',durableGeneration:'0',async check(){}};
 const attempt=await service.beginAttempt({userId:1,workshopKey:'scope_workshop',objectiveId:'effect',execution});
 const first=await service.evaluate({userId:1,workshopKey:'scope_workshop',evaluationId:'original',execution,attempt,...input()});assert.equal(first.judgment.verdict,'unavailable');assert.ok(scope.recovery.packet.includes('PRIVATE_AUDIT_SENTINEL'));
 const retry=await service.retry({userId:1,evaluationId:'original',execution});assert.equal(retry.judgment.verdict,'pass');assert.equal(calls,2);
});
test('out-of-scope evidence references and citations cannot pass even if they name retained audit records',async()=>{
 for(const wrong of [{satisfied:true,evidenceRefs:['private_audit'],citations:[]},{satisfied:true,evidenceRefs:['public_outcome'],citations:[{evidenceId:'private_audit',quote:'PRIVATE_AUDIT_SENTINEL'}]}]){
  const judge=createObjectiveJudge({model:{async chat(){return{provider:'controlled',model:'controlled',mocked:false,response:JSON.stringify(wrong)};}}});
  const result=await judge({...input(),execution:{async check(){}}});assert.equal(result.verdict,'unavailable');
 }
});
