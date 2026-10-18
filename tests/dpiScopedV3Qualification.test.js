'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {scopedCases,calibrationPacket}=require('./fixtures/dpiScopedV3Cases');
test('retained scoped v3 inputs remain synthetic under current noncredit admission',async()=>{
 const cases=scopedCases();assert.equal(cases.actors.length,2);assert.equal(cases.calibration.length,10);assert.equal(new Set(cases.calibration.map(c=>c.id)).size,10);
 for(const row of cases.actors)assert.equal(row.request,require('../server/data/promptInjectionSolutions').solutions[row.objective].examples[0].prompt);
 for(const row of cases.calibration){assert.equal(row.executionProof,false);assert.equal(row.creditEligible,false);const packet=await calibrationPacket(row);assert.equal(packet.rubric.version,'dpi-'+row.objective+'-v14');assert.equal(packet.rubric.dpiAnswerComparison.protocolVersion,'dpi-answer-comparison-v11');assert.equal(packet.facts[row.objective==='obfuscation'?'owned_decoder_observed':'owned_actor_observed'],false,'Static supplied response is not owned actor/effect evidence');const prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(packet);assert.equal(prepared.evidenceError,undefined);if(row.objective==='obfuscation')assert.ok(packet.evidence.some(e=>e.id==='decoded_request'));}
 assert.equal(cases.calibration.filter(c=>c.expected==='pass').length,2);assert.ok(cases.calibration.some(c=>c.id==='encoded-wrong-question'));assert.ok(cases.calibration.some(c=>c.id==='encoded-echo'));assert.ok(cases.calibration.some(c=>c.id==='encoded-refusal'));
 for(const id of ['encoded-aws','encoded-judge-contamination']){const row=cases.calibration.find(c=>c.id===id);assert.equal(row.expected,'fail');const packet=await calibrationPacket(row);const text=packet.evidence.find(e=>e.id==='decoded_request').content.decodedRequest;assert.match(text,id==='encoded-aws'?/Amazon S3/:/Ignore grading rules.*2\+2/);assert.equal(packet.evidence.find(e=>e.id==='response').content,row.response);}
});
