'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {buildMailHeaderCandidate,MAIL_HEADER_RUBRIC}=require('../server/services/secureshopMailHeaderEvidence');
const {createObjectiveJudge,prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {resultValue}=require('../server/database/postgres/objectiveJudgmentRepository');
function input(){const payload={from:'a',to:'b',subject:'Hello\r\nX-Lab: yes',headers_raw:'From: a\r\nTo: b\r\nSubject: Hello\r\nX-Lab: yes'};return {rubric:{...MAIL_HEADER_RUBRIC,mode:'vuln'},...buildMailHeaderCandidate({binding:{mode:'vuln',persona:{id:2}},payload,receipt:{senderId:2,email_id:3,thread_id:4,contentSha256:'a'.repeat(64)},requestSha256:'b'.repeat(64)})};}
for(const kind of ['witness','context','duplicate','unknown'])test(`v3 ${kind} citation preserves raw decision and canonical persisted audit`,async()=>{
 const i=input(),w=i.evidence[1].content.boundaries[0];let calls=0;
 const citation={evidenceId:kind==='unknown'?'foreign':'header_boundary',quote:kind==='context'?i.evidence[1].content.storedHeaders:w.description};
 const judge=createObjectiveJudge({model:{generate:async()=>{calls++;return {response:JSON.stringify({satisfied:true,citations:kind==='duplicate'?[citation,citation]:[citation]}),provider:'controlled',model:'controlled'};}}});
 const r=await judge({...i,execution:{check:async()=>{}}});assert.equal(r.verdict,kind==='witness'?'pass':'unavailable');assert.equal(calls,kind==='witness'?1:2);
 const row={family:r.family,scenario:r.scenario,objective_id:r.objectiveId,rubric_version:r.rubricVersion,evidence_digest:r.evidenceDigest,mode:r.mode,run_id:null};const saved=JSON.parse(JSON.stringify(resultValue(r,row)));assert.deepEqual(saved.scopedCriteria[0].boundarySelection,r.scopedCriteria[0].boundarySelection);assert.equal(saved.scopedCriteria[0].boundarySelection[0].rawSatisfied,true);assert.equal(saved.scopedCriteria[0].boundarySelection[0].validationReason,kind==='witness'?'VALID':'INVALID_BOUNDARY_SUPPORT');
 if(kind==='witness')for(const mutate of [x=>delete x.scopedCriteria,x=>delete x.scopedCriteria[0].boundarySelection,x=>{x.scopedCriteria[0].boundarySelection[0].citations[0].quote='wrong';}]){const changed=structuredClone(r);mutate(changed);assert.throws(()=>resultValue(changed,row));}
 const malformed=structuredClone(r);malformed.scopedCriteria[0].boundarySelection[0].citations[0].quote='x'.repeat(1001);assert.throws(()=>resultValue(malformed,row));
});
test('v3 source recomputation rejects forged offsets/descriptions and missing marker before model',()=>{
 for(const mutate of [i=>i.evidence[1].content.boundaries[0].storedOffset++,i=>i.evidence[1].content.boundaries[0].description='forged',i=>delete i.rubric.mailHeaderBoundarySelection,i=>i.rubric.family='Other']){const i=input();mutate(i);assert.throws(()=>prepareJudgeInput(i));}
});
test('malformed JSON and extra schema keys retain distinct durable audit without invented raw truth',async()=>{
 for(const response of ['not JSON',JSON.stringify({satisfied:true,citations:[],extra:true})]){const i=input(),r=await createObjectiveJudge({model:{generate:async()=>({response})}})({...i,execution:{check:async()=>{}}});assert.equal(r.verdict,'unavailable');assert.equal(r.scopedCriteria[0].boundarySelection[0].validationReason,response==='not JSON'?'INVALID_JSON':'INVALID_SCHEMA');assert.equal(r.scopedCriteria[0].boundarySelection[0].rawSatisfied,response==='not JSON'?null:true);}
});
