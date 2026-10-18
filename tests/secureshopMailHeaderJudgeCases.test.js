'use strict';
if(process.env.DVAIA_RETAINED_EVIDENCE_TESTS!=='1')throw Error('Retained-evidence qualification requires DVAIA_RETAINED_EVIDENCE_TESTS=1 and its original local artifacts; this is not a portable unit suite.');
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {buildCases,evaluateCases}=require('./postgres/secureshopMailHeaderJudgeCases');
const reportPath=process.env.DVAIA_RETAINED_MAIL_HEADER_REPORT,candidatePath=process.env.DVAIA_RETAINED_MAIL_HEADER_CANDIDATE;
if(!reportPath||!candidatePath||!path.isAbsolute(reportPath)||!path.isAbsolute(candidatePath))throw Error('Absolute retained mail header report and candidate paths are required');
const reportBytes=fs.readFileSync(reportPath);
assert.equal(require('node:crypto').createHash('sha256').update(reportBytes).digest('hex'),'d9513e9610fa7e5d452c72d39c4fc6437a73ac72fea5deefa79b7676d391dcd7');
const report=JSON.parse(reportBytes),bytes=fs.readFileSync(candidatePath);
assert.equal(require('node:crypto').createHash('sha256').update(bytes).digest('hex'),report.runtimeResultSha256);
test('native header positives are exact retained data; synthetic guards deny before any Judge',async()=>{
 const plan=buildCases(bytes,report.runtimeResultSha256);assert.deepEqual(plan.cases.map(c=>c.name),['retained_new_thread','retained_explicit_thread','ordinary_headers_production_guard','ordinary_headers_semantic_diagnostic','body_only_newline_production_guard','body_only_newline_semantic_diagnostic','literal_backslashes_production_guard','literal_backslashes_semantic_diagnostic','evaluator_instruction_production_guard','evaluator_instruction_semantic_diagnostic','altered_stored_bytes','wrong_sender','forged_caller_witness']);assert.equal(plan.maximumHttpCalls,12);assert.equal(plan.cases.filter(c=>c.kind==='synthetic_guard').length,7);assert.equal(plan.cases[0].observed.payload.subject,JSON.parse(bytes).freshEvidence.payload.subject);
 let calls=0;const results=await evaluateCases(plan,async input=>{calls++;const yes=input.evidence.find(e=>e.id==='header_boundary').content.boundaries.length>0;return {verdict:yes?'pass':'fail',criteria:[{id:'stored_header_boundary',satisfied:yes}]};});assert.equal(calls,6);assert(results.every(r=>r.expectationPassed));
});
test('semantic false positive is a failure even when final verdict is fail from required facts',async()=>{
 const plan=buildCases(bytes,report.runtimeResultSha256),results=await evaluateCases(plan,async()=>({verdict:'fail',criteria:[{id:'stored_header_boundary',satisfied:true}]}));assert(results.filter(r=>r.kind==='synthetic_semantic').every(r=>r.semanticExpectationPassed===false));
});
test('modified retained bytes cannot silently become accepted provenance',()=>{assert.throws(()=>buildCases(Buffer.from(bytes.toString()+' '),report.runtimeResultSha256));});
