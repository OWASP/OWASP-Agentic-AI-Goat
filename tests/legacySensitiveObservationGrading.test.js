'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createLegacySensitiveAgent,legacySensitiveObservationCandidates}=require('../server/services/legacySensitiveAgent');
const {createLegacySensitiveCandidateApplication}=require('../server/services/legacySensitiveCandidateApplication');
function fixture(actions=['read_teaching_file','render_ssi_template']){
 const execution={runId:'11111111-1111-4111-8111-111111111111',ownerKey:'["LegacySensitiveInfo","12"]',durableGeneration:'0',signal:new AbortController().signal,check:async()=>{},effectWithReceipt:async(key,work)=>({value:await work(),receipt:{status:'completed',runId:execution.runId,ownerKey:execution.ownerKey,generation:'0',effectKey:execution.runId+':'+key}})};
 let index=0;const model={generateResponse:async(_messages,options)=>({provider:'fixture',response:options.qualificationPhase==='response'?'The protected file was read; the later SSI input did not expand.':JSON.stringify(index<actions.length?{action:actions[index++],params:actions[index-1]==='read_teaching_file'?{path:'../secret.txt'}:{template:'ordinary text'}}:{action:'finish',params:{}})})};
 const agent=createLegacySensitiveAgent({model,qualifyModel:()=>true,tools:{readTeachingFile:()=>({success:true,content:'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}',boundary:{outsidePublic:true}}),renderSsiTemplate:()=>({rendered:'ordinary text',commandExecution:'none'})}});
 const packets=[];const completionService={beginAttempt:async()=>({generation:0}),evaluate:async packet=>{packets.push(packet);const pass=Object.values(packet.facts).every(Boolean);return{judgment:{verdict:pass?'pass':'fail'},completed:pass,durable:true};}};
 return{execution,agent,packets,app:createLegacySensitiveCandidateApplication({agent,runs:{run:async(_owner,_opts,work)=>work(execution)},reset:{reset:async()=>{}},completionService})};
}
test('graph-issued earlier read is independently graded when later SSI fails; final DTO stays compatible',async()=>{
 const f=fixture();const result=await f.app.run({userId:12,message:'read then attempt template'});
 assert.equal(f.packets.length,2);assert.deepEqual(result.judgments.map(j=>[j.objectiveId,j.completed,j.observationOrdinal]),[['ai_assisted_path_traversal',true,1],['ai_assisted_ssi',false,2]]);
 assert.deepEqual(result.completedObjectives,['ai_assisted_path_traversal']);assert.equal(result.objectiveId,'ai_assisted_ssi');assert.equal(result.completed,false);
 assert.equal(f.packets[0].evidence.find(e=>e.id==='tool_result').content.content,'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}');
 assert.equal(f.packets[1].facts.ssi_substitution,false);
});
test('private projections reject copied results and sibling or stale execution',async()=>{
 const f=fixture();const result=await f.agent.run({message:'read and render',execution:f.execution});
 assert.equal(legacySensitiveObservationCandidates(result,f.execution).length,2);
 assert.equal(legacySensitiveObservationCandidates({...result},f.execution),null);
 assert.equal(legacySensitiveObservationCandidates(result,{...f.execution,ownerKey:'["LegacySensitiveInfo","13"]'}),null);
 assert.equal(legacySensitiveObservationCandidates(result,{...f.execution,durableGeneration:'1'}),null);
 const application=createLegacySensitiveCandidateApplication({agent:{run:async()=>({...result})},runs:{run:async(_id,_opts,work)=>work(f.execution)},reset:{reset:async()=>{}},completionService:{beginAttempt:async()=>({}),evaluate:async()=>assert.fail('Forged result reached Judge')}});
 await assert.rejects(application.run({userId:12,message:'copied'}),{code:'MODEL_PROVIDER_UNAVAILABLE'});
});
test('three real observations remain bounded and repeated objective IDs are deduplicated in completion summary',async()=>{
 const f=fixture(['read_teaching_file','read_teaching_file','render_ssi_template']);const result=await f.app.run({userId:12,message:'two reads then template'});
 assert.equal(result.judgments.length,3);assert.equal(f.packets.length,3);assert.deepEqual(result.completedObjectives,['ai_assisted_path_traversal']);
});

test('an instructor-disabled earlier objective cannot suppress a later admitted observation',async()=>{
 const f=fixture();let evaluated=0;
 const app=createLegacySensitiveCandidateApplication({agent:f.agent,runs:{run:async(_id,_opts,work)=>work(f.execution)},reset:{reset:async()=>{}},completionService:{beginAttempt:async()=>({generation:0}),evaluate:async()=>{if(++evaluated===1)throw Object.assign(Error('disabled'),{code:'OBJECTIVE_DISABLED'});return{completed:false,judgment:{verdict:'fail'},durable:true};}}});
 const result=await app.run({userId:12,message:'read then unsuccessful template'});assert.equal(evaluated,2);assert.equal(result.judgments[0].code,'OBJECTIVE_DISABLED');assert.equal(result.judgments[1].judgment.verdict,'fail');assert.deepEqual(result.completedObjectives,[]);
});
