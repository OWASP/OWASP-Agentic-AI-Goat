'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {SensitiveInfoWorkshopAgent,createSensitiveInfoWorkshopStateStore}=require('../server/services/sensitiveInfoWorkshopAgent');
const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
function fixture({mock=false,stale=false}={}){
 let admitted,reads=0,judges=0;
 const resources=Object.fromEntries(['deleteDataset','createBackup','downloadBackup','listBackups','readLogOverlay','writeLogOverlay'].map(k=>[k,async()=>{throw Error('Unexpected resource operation');}]));
 resources.readDataset=async({execution,scope})=>{assert.equal(execution,admitted);assert.deepEqual(scope,{ownerId:31,generation:2});reads++;return{ownerId:31,generation:2,revision:4,records:[]};};
 const traversalManager={async read({execution}){assert.equal(execution,admitted);assert.equal(execution.ownerId,31);assert.equal(execution.durableGeneration,2);await execution.check();reads++;return{result:'Controlled fixture result',content:'controlled fixture bytes'};}};
 const store=createSensitiveInfoWorkshopStateStore({durableResources:resources,traversalManager});
 const judge=createObjectiveJudge({model:{generate:async prompt=>{judges++;const packet=JSON.parse(prompt.split('EVALUATION DATA (JSON):\n')[1].split('\nREPAIR:')[0]);assert.equal(packet.facts.real_response,false);return{provider:'controlled-judge',model:'unit',response:JSON.stringify({verdict:'pass',explanation:'Fixture claims success.',criteria:packet.rubric.criteria.map(c=>({id:c.id,satisfied:true,evidenceRefs:['response']}))})};}}});
 const completionService={async beginAttempt({execution}){admitted=execution;return{};},async evaluate(packet){assert.equal(packet.execution,admitted);const judgment=await judge(packet);assert.notEqual(judgment.verdict,'pass');return{judgment,completed:false};}};
 const model={provider:mock?'mock':'controlled',generateResponse:async()=>({response:'Controlled fixture explanation.'}),chatWithTools:async()=>({response:'Fixed response.'})};
 const agent=new SensitiveInfoWorkshopAgent({stateStore:store,decisionMode:mock?undefined:'scripted',model,completionService});
 const execution={ownerId:31,ownerKey:'31',runId:'scripted-run',durableGeneration:2,check:async()=>{if(stale)throw Object.assign(Error('stale owner'),{name:'AbortError'});},trace:async()=>{}};
 return{async run(message,objective){return agent.processMessage(message,[],'vulnerable',objective,31,store.getUserState(31),{execution});},reads:()=>reads,judges:()=>judges};
}
for(const mock of [false,true])for(const [message,objective,expected]of[['get account INVALID','error_leak','Dataset revision: 4'],['download ../../config/secrets.env','traversal_secrets','Controlled fixture result']]){
 test(`${mock?'mock':'scripted'} ${objective} forwards admitted execution to real tool and cannot award fixture credit`,async()=>{const f=fixture({mock}),r=await f.run(message,objective);assert.equal(f.reads(),1);assert.ok(f.judges()>0);assert.equal(r.toolCalls.length,1);assert.ok(r.toolCalls[0].result.includes(expected));assert.deepEqual(r.completedObjectiveIds,[]);assert.ok(r.judgments.every(j=>j.verdict!=='pass'));});
}
test('scripted and mock execution cancellation blocks resource entry',async()=>{for(const mock of [false,true])for(const [message,id]of[['get account INVALID','error_leak'],['download ../../config/secrets.env','traversal_secrets']]){const f=fixture({mock,stale:true});await assert.rejects(f.run(message,id),{name:'AbortError'});assert.equal(f.reads(),0);}});
