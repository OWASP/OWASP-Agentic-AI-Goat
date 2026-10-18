'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');

function model(){return{provider:'fixture',async generateResponse(){return{response:'Controlled formatter output.',provider:'fixture',model:'controlled',mocked:true};}};}
function common(){return{async getHistory(){return[];},async saveMessage(){}};}

test('ARIA retained scripted service executes the raw SQL teaching effect once',async()=>{
 let calls=0,query;
 const store={...common(),async searchProducts(value){calls++;query=value;return{error:'controlled syntax error'};}};
 const agent=require('../server/services/ariaAgentService').createAgent({store,model:model(),runLedger:null,decisionMode:'scripted'});
 const result=await agent.invoke('1',"'",'vuln',{includeRunMetadata:true});
 assert.equal(calls,1);assert.equal(query,"'");assert.equal(result.toolUsed,'search_products');
 assert.equal(result.run.decisionSource,'scripted');assert.equal(result.run.responseSource,'fixture');
});

test('NOVA retained scripted service executes the raw operator teaching effect once',async()=>{
 let calls=0,query;
 const store={...common(),async searchPapers(value){calls++;query=value;return{error:'MongoServerError: unknown operator: $foo'};}};
 const agent=require('../server/services/novaAgentService').createAgent({store,model:model(),runLedger:null,decisionMode:'scripted'});
 const payload='{"$where":"test","$foo":"test"}';
 const result=await agent.invoke('2',payload,'vuln',{includeRunMetadata:true});
 assert.equal(calls,1);assert.equal(query,payload);assert.equal(result.toolUsed,'search_papers');
  assert.equal(result.run.decisionSource,'scripted');assert.equal(result.run.responseSource,'fixture');
 assert.equal(require('../server/services/sqlNoSqlObjectiveEvidence').hasObjectiveObservation({objectiveId:'nosqli_1',result:{toolResult:result.toolResult,toolInvocation:{params:{query}}}}),true);
});

test('controlled canonical denial carries the exact persisted evaluation scope',()=>{
 const runId='00000000-0000-4000-8000-000000000009',digest='a'.repeat(64);
 const row={family:'ARIA',scenario:'product_search',objective_id:'sqli_1',rubric_version:'aria_sql.v3',evidence_digest:digest,run_id:runId,mode:'vuln'};
 const result={family:'ARIA',scenario:'product_search',objectiveId:'sqli_1',rubricVersion:'aria_sql.v3',evidenceDigest:digest,runId,mode:'vuln',verdict:'fail',criteria:[],explanation:'Controlled required-fact denial.',provider:null,model:null,usage:null,attempts:0};
 assert.equal(require('../server/database/postgres/objectiveJudgmentRepository').resultValue(result,row).verdict,'fail');
});
