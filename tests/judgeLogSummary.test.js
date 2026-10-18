const{test}=require('node:test'),assert=require('node:assert/strict');const{summarize}=require('../scripts/summarize-judge-log');
test('assertion message echoes are excluded while repeated diagnostics remain detectable',()=>{
 const result={family:'XSS',id:'xss_e3',label:'positive',verdict:'unavailable'};
 const diagnostic='ℹ '+JSON.stringify(result);
 const log=['Qualifying XSS on local llama3.1:8b',diagnostic,'  AssertionError [ERR_ASSERTION]: '+JSON.stringify(result)].join('\n');
 assert.equal(summarize(log).total.recorded,1);
 assert.equal(summarize(log).total.unresolved,1);
 assert.equal(summarize(log+'\n'+diagnostic).total.duplicateCases,1);
});
test('semantic errors are counted independently of unresolved grading',()=>{
 const rows=[['positive','fail'],['negative','pass'],['positive','unavailable'],['negative','inconclusive']];
 const result=summarize(rows.map(([label,verdict],id)=>JSON.stringify({family:'IPI',id,label,verdict})).join('\n')).total;
 assert.equal(result.falsePositives,1);assert.equal(result.falseNegatives,1);assert.equal(result.unresolved,2);
});
test('diagnostics distinguish unavailable negative from semantically correct fail',()=>{
 const log=[{name:'one:positive',judgment:{family:'IPI',verdict:'pass',durationMs:10,attempts:1}},{name:'one:negative',judgment:{family:'IPI',verdict:'unavailable',durationMs:20,attempts:2}}].map(x=>'ℹ '+JSON.stringify(x)).join('\n');const s=summarize(log);assert.equal(s.total.contractCorrect,2);assert.equal(s.total.semanticCorrect,1);assert.equal(s.total.unresolved,1);assert.equal(s.total.latencyMs.p95,20);assert.equal(s.total.repairCalls,1);
});
test('suite context recognizes FinFlow, CodeBot, SQL/NOVA, CTF and reports silent suites',()=>{
 const log=[
 'Qualifying FinFlow on local llama3.1:8b','# '+JSON.stringify({id:'tool_enum',label:'positive',verdict:'pass'}),
 'Qualifying CodeBot on local llama3.1:8b','# '+JSON.stringify({id:'rce_cmd',label:'negative',verdict:'fail'}),
 'Qualifying ARIA-NOVA on local llama3.1:8b','# '+JSON.stringify({case:'sqli_1_positive',expected:'pass',verdict:'pass',attempts:1}),'# '+JSON.stringify({case:'nosqli_1_negative',expected:'not_pass',verdict:'unavailable'}),
 'Qualifying CTF on local llama3.1:8b','# '+JSON.stringify({case:'stage_1:negative',expected:'refusal',actual:'fail'}),
 'Qualifying XSS on local llama3.1:8b','ok 1 - xss positive',
 'Qualifying MCP on local llama3.1:8b','ok 1 - mcp positive',
 ].join('\n');
 const s=summarize(log);assert.equal(s.total.recorded,5);assert.equal(s.families.FinFlow.recorded,1);assert.equal(s.families.NOVA.verdicts.unavailable,1);assert.equal(s.families.CTF.semanticCorrect,1);assert.equal(s.total.latencyMs.p95,null);assert.equal(s.total.missingMetrics.durationMs,5);assert.equal(s.total.missingMetrics.attempts,4);assert.deepEqual(s.coverage.suitesWithoutDiagnostics,['XSS','MCP']);
});
test('boolean CSRF labels and missing context are handled without invented family',()=>{
 const log=['# '+JSON.stringify({id:'unknown',verdict:'pass'}),'Qualifying CSRF on local llama3.1:8b','# '+JSON.stringify({id:'csrf_p1',positive:false,judgment:{family:'CSRF',verdict:'inconclusive'}}),'# '+JSON.stringify({verdict:'pass'})].join('\n');
 const s=summarize(log);assert.equal(s.total.recorded,1);assert.equal(s.total.contractCorrect,1);assert.equal(s.total.semanticCorrect,0);
});
test('shared case diagnostic preserves actual metrics and exposes absent ones',()=>{
 const {judgeDiagnostic}=require('./fixtures/judgeDiagnostic');
 const missing=judgeDiagnostic({family:'XSS',id:'xss_r1',expected:'not_pass',judgment:{verdict:'fail'}});assert.equal(missing.durationMs,null);assert.equal(missing.attempts,null);assert.equal(missing.label,'negative');
 const present=judgeDiagnostic({family:'MCP',id:'mcp_fixture',expected:'pass',judgment:{verdict:'pass',durationMs:12,attempts:2}});assert.equal(present.durationMs,12);assert.equal(present.attempts,2);
 assert.equal(judgeDiagnostic({judgment:{verdict:'unavailable',errorCode:'INVALID_JUDGE_OUTPUT'}}).errorCode,'INVALID_JUDGE_OUTPUT');
 assert.equal(judgeDiagnostic({judgment:{verdict:'unavailable',errorCode:'private provider message'}}).errorCode,null);
 const verified=judgeDiagnostic({judgment:{verdict:'pass',attempts:1,totalCalls:2,verification:{verdict:'pass',attempts:1,explanation:'private'}}});
 assert.deepEqual(verified.verification,{verdict:'pass',attempts:1});assert.equal(verified.totalCalls,2);
 assert.equal(JSON.stringify(verified).includes('private'),false);
 const summary=summarize(JSON.stringify(verified)).total;
 assert.deepEqual(summary.verification,{evaluations:0,calls:0,repairCalls:0}); // No family means no invented diagnostic identity.
 assert.deepEqual(summarize(JSON.stringify({...verified,family:'IPI',id:'defense'})).total.verification,{evaluations:1,calls:1,repairCalls:0});
});
