'use strict';
const { test } = require('node:test'), assert = require('node:assert/strict');
const { catalogue, resolveIds, envelope, createDiagnostic, STAGES } = require('./fixtures/factoredJudgePrimitives');
const source = 'Assistant: preserve both actions and their conditions.';
function evidence(stage) { return stage === 'task_relation' ? { source, task: 'Trusted task' } : STAGES.indexOf(stage) < 3 ? { source } : { source, task: 'Trusted task', response: 'Completed answer', responseComplete: true, effects: null }; }
const answer = stage => stage === 'classification' ? '{"decision":"directive"}' : '{"unvalidated":true}';
test('full 8192-byte capacity and Unicode boundaries are lossless, immutable identity only', () => {
  for (const s of ['a'.repeat(8192), 'a'.repeat(127) + '🟠' + 'e\u0301\r\n'.repeat(100), '\"'.repeat(8192)]) {
    const c = catalogue(s); assert.equal(c.entries.map(x => x.text).join(''), s); assert(c.entries.length <= 64);
    for (const x of c.entries) { assert.equal(s.slice(x.utf16Start, x.utf16End), x.text); assert.equal(Buffer.from(s).subarray(x.utf8Start, x.utf8End).toString(), x.text); }
    assert.equal(c.exactOutputLiteralResolved, false); assert.equal(c.semanticCoverageVerified, false); assert(Object.isFrozen(c.entries[0]));
  }
  assert.throws(() => catalogue('a'.repeat(8193))); assert.throws(() => catalogue('\ud800'));
});
test('ID resolution rejects forged, duplicate, out-of-order IDs and does not infer nested logic or literals', () => {
  const s = 'a'.repeat(127) + 'IF A AND (B OR C), do X; unless Y. '.repeat(10);
  const r = resolveIds(s, ['S000','S001']); assert.equal(r.entries.length, 2); assert.equal(r.identityOnly,true);
  for (const ids of [['S999'],['S000','S000'],['S001','S000'],[]]) assert.throws(() => resolveIds(s,ids));
});
test('source stages reject task, response, labels and incomplete downstream response; expanded overflow denied without truncation', () => {
  for (const stage of STAGES.slice(0,3)) for (const extra of ['task','response','labels']) assert.throws(() => envelope(stage,{source,[extra]:'hidden'}));
  assert.throws(() => envelope('response',{...evidence('response'),responseComplete:false}));
  assert.throws(() => envelope('classification',{source:'\"'.repeat(8192)}),/Expanded/);
  assert.equal(envelope('classification',{source:'a'.repeat(8192)}).source.length,8192);
});
test('six transport invocations maximum, ordered trace and no semantic or credit authority', async () => {
  const d=createDiagnostic({source});let calls=0;
  for (const stage of STAGES) await d.run(stage,evidence(stage),async(req,opts)=>{calls++;assert.equal(req.source,source);assert(Object.isFrozen(req));assert(Number.isSafeInteger(opts.timeoutMs));return answer(stage);});
  const r=d.snapshot();assert.equal(calls,6);assert.equal(r.attempts,6);assert.equal(r.records.length,6);assert.equal(r.semanticAccepted,null);assert.equal(r.creditAuthorized,false);
  assert(r.records.every(x=>x.requestSha256&&x.responseSha256));assert.equal(r.physicallyPending,false);
  await assert.rejects(d.run('contrary',evidence('contrary'),()=>{throw Error('seventh');}));
});
test('negative branch still requires coverage and cannot jump to downstream; uncertainty terminates',async()=>{
 const d=createDiagnostic({source});await d.run('classification',{source},async()=>'{"decision":"no_directive"}');d.skipNegativeExtraction();
 await assert.rejects(d.run('task_relation',evidence('task_relation'),async()=>''));assert.equal(d.snapshot().attempts,1);
 await d.run('coverage',{source},async()=>'{}');assert.equal(d.snapshot().attempts,2);assert.equal(d.snapshot().semanticAccepted,null);
 const u=createDiagnostic({source});await u.run('classification',{source},async()=>'{"decision":"uncertain"}');await assert.rejects(u.run('extraction',{source},async()=>''));
});
test('invalid classification retains raw record, consumes one call and cannot retry',async()=>{
 const d=createDiagnostic({source});const r=await d.run('classification',{source},async()=>'{"decision":"directive","extra":1}');assert.equal(r.records[0].raw,'{"decision":"directive","extra":1}');assert.equal(r.records[0].status,'unavailable');await assert.rejects(d.run('classification',{source},async()=>answer('classification')));assert.equal(d.snapshot().attempts,1);
});
test('preabort and same-turn abort consume no transport attempts',async()=>{
 for(const pre of [true,false]){const c=new AbortController();if(pre)c.abort();const d=createDiagnostic({source,signal:c.signal});let calls=0;const p=d.run('classification',{source},()=>{calls++;return answer('classification');});if(!pre)c.abort();if(pre)await assert.rejects(p);else await p;assert.equal(calls,0);assert.equal(d.snapshot().attempts,0);}
});
test('noncooperative cancellation returns promptly but retains physical pending and bars reentry until settlement',async()=>{
 let release;const c=new AbortController(),d=createDiagnostic({source,signal:c.signal});const p=d.run('classification',{source},()=>new Promise(r=>release=r));await Promise.resolve();c.abort();const r=await p;assert.equal(r.physicallyPending,true);assert.equal(r.attempts,1);await assert.rejects(d.run('extraction',{source},async()=>''));release(answer('classification'));await new Promise(r=>setImmediate(r));assert.equal(d.snapshot().physicallyPending,false);
});
test('synchronous work crossing shared deadline is rejected without a fresh stage budget',async()=>{
 const d=createDiagnostic({source,timeoutMs:8});let passedSignal;const r=await d.run('classification',{source},async(_,{signal})=>{passedSignal=signal;const end=performance.now()+15;while(performance.now()<end){}return answer('classification');});assert.equal(r.records[0].status,'cancelled-or-deadline');assert.equal(passedSignal.aborted,true);await assert.rejects(d.run('extraction',{source},async()=>''));
});
test('source/task/response/effect bindings cannot change between stages',async()=>{
 const d=createDiagnostic({source});for(const stage of STAGES.slice(0,4))await d.run(stage,evidence(stage),async()=>answer(stage));
 await assert.rejects(d.run('response',{...evidence('response'),task:'changed'},async()=>''));
 await d.run('response',evidence('response'),async()=>'{}');
 for(const bad of [{source:'changed'},{response:'changed'},{effects:{forged:true}}])await assert.rejects(d.run('contrary',{...evidence('contrary'),...bad},async()=>''));assert.equal(d.snapshot().attempts,5);
});
test('elapsed time across completed stages consumes one shared deadline',async()=>{
 const d=createDiagnostic({source,timeoutMs:20});await d.run('classification',{source},async()=>answer('classification'));
 await new Promise(r=>setTimeout(r,25));let invoked=false;await assert.rejects(d.run('extraction',{source},async()=>{invoked=true;return '{}';}));assert.equal(invoked,false);assert.equal(d.snapshot().attempts,1);
});
test('slow classification parsing cannot report observed after deadline',async()=>{
 const original=JSON.parse,d=createDiagnostic({source,timeoutMs:8});
 JSON.parse=function(value,...rest){if(value===answer('classification')){const end=performance.now()+15;while(performance.now()<end){}}return original(value,...rest);};
 try{const r=await d.run('classification',{source},async()=>answer('classification'));assert.equal(r.records[0].status,'cancelled-or-deadline');assert.equal(r.creditAuthorized,false);}finally{JSON.parse=original;}
});
test('exported envelope rejects hidden evidence in prior metadata and forged order/status',()=>{
 for(const previous of [[{response:'hidden',labels:['pass']}],[{stage:'classification',requestSha256:'a'.repeat(64),responseSha256:'b'.repeat(64),status:'observed-unvalidated'}]])assert.throws(()=>envelope('classification',{source},previous));
 const valid={stage:'classification',requestSha256:'a'.repeat(64),responseSha256:'b'.repeat(64),status:'observed-unvalidated'};
 assert.equal(envelope('extraction',{source},[valid]).previous.length,1);
 for(const delta of [{labels:['pass']},{response:'hidden'},{stage:'response'},{status:'pass'},{requestSha256:'bad'}])assert.throws(()=>envelope('extraction',{source},[{...valid,...delta}]));
});

test('response catalogue supports full16384 bytes without widening default source limit',()=>{assert.throws(()=>catalogue('a'.repeat(8193)));const c=catalogue('a'.repeat(16384),16384);assert.equal(c.entries.length,128);assert.equal(c.entries.map(x=>x.text).join('').length,16384);assert.throws(()=>catalogue('a',32768));});
