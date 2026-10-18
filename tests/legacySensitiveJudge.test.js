'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)(authDb|ctfDb|sensitiveInfoDb)(?:\.js)?$/.test(r))throw Error('Database initializer forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {CRITERIA,createLegacySensitiveGrader}=require('../server/agent-runtime/legacySensitiveJudge');
const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
function passingTransport(){return {generate:async prompt=>{const packet=JSON.parse(prompt.split('EVALUATION DATA (JSON):\n')[1].split('\nREPAIR:')[0]);return {provider:'injected',model:'fixture',response:JSON.stringify({verdict:'pass',explanation:'Observed fixture outcome.',criteria:packet.rubric.criteria.map(c=>({id:c.id,satisfied:true,evidenceRefs:['returned_content'],citations:[{evidenceId:'returned_content',quote:'safe synthetic tool output'}]}))})};}};}
test('All five legacy objectives require grounded observations even when model insists on passing',async()=>{
 assert.equal(Object.keys(CRITERIA).length,5);const records=[];
 const grade=createLegacySensitiveGrader({recordJudgment:async row=>records.push(row),judge:createObjectiveJudge({model:passingTransport()})});
 for(const objectiveId of Object.keys(CRITERIA))for(const observed of [true,false]){
  const result=await grade({userId:3,objectiveId,request:'fixture',result:{content:'safe synthetic tool output'},facts:{observed_effect:observed,known_flag:observed,protected_path:observed,real_model:observed},execution:{runId:randomUUID(),check:async()=>{}}});
  assert.equal(result.completed,observed,objectiveId);assert.equal(result.verdict,observed?'pass':'inconclusive');
 }
 assert.equal(records.length,10);assert.equal(records.filter(r=>r.completed).length,5);
});
test('Cancellation after judge prevents durable progress write; unauthenticated owners fail before judge',async()=>{
 let checks=0,writes=0;const grade=createLegacySensitiveGrader({recordJudgment:async()=>writes++,judge:async()=>({verdict:'pass'})});
 const args={userId:3,objectiveId:'path_traversal',request:'fixture',result:{},facts:{observed_effect:true,known_flag:true,protected_path:true},execution:{runId:randomUUID(),check:async()=>{if(++checks===2)throw Object.assign(Error('reset'),{name:'AbortError'});}}};
 await assert.rejects(grade(args),{name:'AbortError'});assert.equal(writes,0);await assert.rejects(grade({...args,userId:0}),/Authenticated/);
});
