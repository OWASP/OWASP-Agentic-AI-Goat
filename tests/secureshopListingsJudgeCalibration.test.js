'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {captureCanonicalListingsPackets,calibrationCases}=require('./fixtures/secureshopListingsJudgeCalibration');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {GENERATED_BROWSER_RUBRIC}=require('../server/services/secureshopListingsAssessment');
function sample(){const record=require('./fixtures/secureshopListingsV1Packets.json').records.at(-1);return require('../server/services/secureshopListingsJudgeGuard').projectListingsCandidate({objectiveId:record.objectiveId,facts:record.packet.facts,evidence:record.packet.evidence});}
test('capture forwards exact private token, detaches packet and records only after canonical admission',async()=>{
 const rubric={...GENERATED_BROWSER_RUBRIC,mode:'vuln'},facts=Object.fromEntries(rubric.requiredFacts.map(key=>[key,true]));
 const prepared=prepareJudgeInput({rubric,facts,evidence:sample().evidence});
 const scope={workshopKey:'secureshop_agent_security',objectiveId:rubric.objectiveId,mode:'vuln',evaluationId:'evaluation',runId:'run',evidenceDigest:prepared.evidenceDigest,recovery:{packet:prepared.packet}};
 const token={},writes=[];let calls=0;
 const capture=captureCanonicalListingsPackets({receipts:Object.freeze({async beginEvaluation(actual,secret){assert.equal(actual,scope);assert.equal(secret,token);calls++;return{accepted:true};}}),record:async value=>writes.push(value)});
 assert.deepEqual(await capture.receipts.beginEvaluation(scope,token),{accepted:true});assert.equal(calls,1);assert.equal(writes.length,1);
 writes[0].packet.facts.qualified_model_generated_html=false;assert.equal(capture.snapshot()[0].packet.facts.qualified_model_generated_html,true);
 const corrupt={...scope,evidenceDigest:'0'.repeat(64)};await assert.rejects(capture.receipts.beginEvaluation(corrupt,token));assert.equal(calls,1);
 assert.throws(()=>calibrationCases(capture.snapshot()),/Exactly one fresh/);
});
test('failed canonical admission produces no recorded positive packet',async()=>{
 const rubric={...GENERATED_BROWSER_RUBRIC,mode:'vuln'},facts=Object.fromEntries(rubric.requiredFacts.map(key=>[key,true])),p=prepareJudgeInput({rubric,facts,evidence:sample().evidence});let records=0;
 const capture=captureCanonicalListingsPackets({receipts:{async beginEvaluation(){throw Error('admission denied');}},record:async()=>records++});
 await assert.rejects(capture.receipts.beginEvaluation({workshopKey:'secureshop_agent_security',objectiveId:rubric.objectiveId,mode:'vuln',evidenceDigest:p.evidenceDigest,recovery:{packet:p.packet}},{}),/admission denied/);
 assert.equal(records,0);assert.deepEqual(capture.snapshot(),[]);
});
