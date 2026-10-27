'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { withGraphDiagnostics, workerDiagnostic } = require('../server/agent-runtime/workers/secureshopAuditWorker');
const { parseWorkerDiagnostic } = require('../server/services/secureshopAuditWorkerHost');
const secret = 'private log https://user:password@example.invalid/source';
const provider = { async chat() { return { genuine: true }; }, async finalResponse() { return { text: 'original' }; } };
async function failed(run, p = provider, signal = new AbortController().signal) {
  let caught;
  try { await withGraphDiagnostics({ provider: p, signal }, run); }
  catch (error) { caught = error; }
  assert.ok(caught); assert.equal(caught.message.includes(secret), false);
  const diagnostic = workerDiagnostic(caught);
  assert.equal(JSON.stringify(diagnostic).includes(secret), false);
  assert.deepEqual(parseWorkerDiagnostic(Buffer.from(JSON.stringify(diagnostic))), diagnostic);
  return diagnostic;
}
test('worker classifies its graph deadline separately from a provider exception', async () => {
  const controller = new AbortController();
  const deadline = await failed(async p => {
    await p.chat(); controller.abort(new DOMException('timed out', 'TimeoutError'));
    return p.finalResponse();
  }, { ...provider, async finalResponse() { throw Error(secret); } }, controller.signal);
  assert.deepEqual(deadline, { version: 1, code: 'AUDIT_WORKER_GRAPH_TIMEOUT', stage: 'graph', phase: 'final' });
  for (const [method, phase] of [['chat', 'decision'], ['finalResponse', 'final']]) {
    const rejected = await failed(async p => {
      // Supervisor may convert a rejected provider into an unavailable graph result.
      try { await p[method](); } catch { throw Error('graph evidence unavailable'); }
    }, { ...provider, async [method]() { throw Object.assign(Error(secret), { code: 'AUDIT_WORKER_GRAPH_TIMEOUT' }); } });
    assert.deepEqual(rejected, { version: 1, code: 'AUDIT_WORKER_PROVIDER_FAILED', stage: 'provider', phase });
  }
});
test('worker preserves successful values/calls and does not infer timeouts from exception strings', async () => {
  const calls = [];
  const result = await withGraphDiagnostics({ provider: {
    async chat(value) { calls.push(value); return value; },
    async finalResponse(value) { calls.push(value); return value; }
  }, signal: new AbortController().signal }, async p => {
    const first = await p.chat('selected'); assert.equal(first, 'selected'); return p.finalResponse('unchanged');
  });
  assert.equal(result, 'unchanged'); assert.deepEqual(calls, ['selected', 'unchanged']);
  const plain = await failed(async p => { await p.chat(); throw Object.assign(Error(secret), { name: 'TimeoutError' }); });
  assert.equal(plain.code, 'AUDIT_WORKER_GRAPH_FAILED');
  assert.deepEqual(workerDiagnostic(Error(secret)), { version: 1, code: 'AUDIT_WORKER_FAILED', stage: 'worker', phase: null });
});
test('unbounded worker shares one child-local graph budget across decisions and final response',async()=>{
  const seen=[],provider={async chat(input){seen.push(input.transportTimeoutMs);return 'decision';},
    async finalResponse(input){seen.push(input.transportTimeoutMs);return 'final';}};
  let remaining=170000;
  const result=await withGraphDiagnostics({provider,signal:new AbortController().signal,
    transportBudget:()=>remaining},async observed=>{
      await observed.chat({messages:[]});remaining=25000;
      return observed.finalResponse({messages:[]});
    });
  assert.equal(result,'final');assert.deepEqual(seen,[170000,25000]);
  let calls=0,caught;
  try{await withGraphDiagnostics({provider:{async finalResponse(){calls++;}},signal:new AbortController().signal,
    transportBudget:()=>{throw new DOMException('deadline','TimeoutError');}},
  async observed=>observed.finalResponse({messages:[]}));}catch(error){caught=error;}
  assert.equal(calls,0);assert.equal(workerDiagnostic(caught).phase,'final');
});
test('host rejects unknown, malformed, verbose, duplicated, or mismatched diagnostic frames', () => {
  const good = { version: 1, code: 'AUDIT_WORKER_PROVIDER_FAILED', stage: 'provider', phase: 'final' };
  for (const value of [null, [], {}, { ...good, code: 'PRIVATE_EXCEPTION' }, { ...good, stage: 'graph' },
    { ...good, phase: null }, { ...good, message: secret }, { ...good, version: 2 }, { ...good, phase: secret }]) {
    assert.equal(parseWorkerDiagnostic(Buffer.from(JSON.stringify(value))), null);
  }
  assert.equal(parseWorkerDiagnostic(Buffer.from(JSON.stringify(good) + '\n' + JSON.stringify(good))), null);
  assert.equal(parseWorkerDiagnostic(Buffer.from('x'.repeat(513))), null);
  assert.equal(parseWorkerDiagnostic(Buffer.from(secret)), null);
});
test('actual host nonzero child exit propagates only the closed diagnostic and preserves host cancellation priority', async t => {
  const { EventEmitter } = require('node:events');
  const { PassThrough, Writable } = require('node:stream');
  let frame = JSON.stringify({ version: 1, code: 'AUDIT_WORKER_GRAPH_TIMEOUT', stage: 'graph', phase: 'final' }),childInput,spawns=0;
  t.mock.method(require('node:child_process'), 'spawn', () => {
    spawns++;
    const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    child.kill = () => { queueMicrotask(() => child.emit('close', null, 'SIGTERM')); return true; };
    child.stdin = new Writable({ write(v, _e, cb) { childInput=JSON.parse(v.toString('utf8'));cb(); }, final(cb) {
      cb(); if (frame !== null) queueMicrotask(() => { child.stderr.write(frame); child.emit('close', 1, null); });
    } }); return child;
  });
  const filename = require.resolve('../server/services/secureshopAuditWorkerHost'), previous = require.cache[filename];
  delete require.cache[filename]; const host = require(filename).runSecureShopAuditWorker; require.cache[filename] = previous;
  const input = { spool: { directory: '/unused', manifest: {} }, baseUrl: 'http://127.0.0.1:1', model: 'controlled', checkCurrent: async () => {} };
  await assert.rejects(host(input), { code: 'AUDIT_WORKER_GRAPH_TIMEOUT', stage: 'graph', phase: 'final' });
  let fakeTime=1000;
  await assert.rejects(host({...input,taskRequestVersion:2,timeoutMs:185000,
    now:()=>fakeTime,checkCurrent:async()=>{fakeTime+=5000;}}),
    {code:'AUDIT_WORKER_GRAPH_TIMEOUT'});
  assert.equal(childInput.graphTimeoutMs,170000);
  assert.equal(Object.hasOwn(childInput,'auditDeadline'),false);
  const before=spawns;
  await assert.rejects(host({...input,taskRequestVersion:2,timeoutMs:20000,
    now:()=>fakeTime,checkCurrent:async()=>{fakeTime+=1;}}),{code:'AUDIT_WORKER_TIMEOUT'});
  assert.equal(spawns,before,'exhausted budget must fail before child spawn');
  await assert.rejects(host({...input,taskRequestVersion:2,timeoutMs:190001}),/Owned audit worker request/);
  await assert.rejects(host({...input,taskRequestVersion:1,timeoutMs:120001}),/Owned audit worker request/);
  frame = secret;
  await assert.rejects(host(input), error => error.code === 'AUDIT_WORKER_FAILED' && !JSON.stringify(error).includes(secret));
  frame = null;
  await assert.rejects(host({ ...input, timeoutMs: 1 }), { code: 'AUDIT_WORKER_TIMEOUT' });
});

test('actual worker executes selected immutable focus and preserves full oversized source through canonical evidence',async t=>{
 // Controlled provider only: proves composition/effects, never real-model credit.
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto');
 const hash=value=>createHash('sha256').update(value).digest('hex'),root=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-audit-focus-control-'));
 t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const runId=randomUUID(),requestId=randomUUID(),nonce=randomUUID(),action='audit_unbounded_requested';
 const rows=Array.from({length:130},(_,i)=>({id:'agents:'+randomUUID(),store:'agents',
  ts:`2026-10-16T00:00:00.${String(999999-i).padStart(6,'0')}Z`,actor:'admin',action:i?'synthetic_history':action,
  target:i?'owned-history':runId,params_json:JSON.stringify(i?{padding:'x'.repeat(1100)}:{requestId,requestedCount:5000,nonce}),
  outcome:'completed',source_kind:'audit',source_id:String(i)}));
 const spool=await require('../server/services/secureshopAuditObservationSpool').spoolAuditObservation({root,
  rows:(async function*(){yield*rows;})(),scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:2,platformSessionId:3},
  runId,requestedCount:5000,checkCurrent:async()=>{}});
 const log=await fs.readFile(spool.paths.log,'utf8');assert(Buffer.byteLength(log)>131072);
 const Provider=require('../server/services/secureshop/providers/ollamaProvider').OllamaProvider;let decisions=0,finals=0;
 t.mock.method(Provider.prototype,'chat',async input=>{
  decisions++;assert.deepEqual(input.tools[0].inputSchema.required,['limit','focus_action']);
  return {provider:'ollama',model:'llama3.1:8b',mocked:false,stop_reason:'tool_use',
   tool_uses:[{id:'selected-focus',name:'audit.summarize_anomalies',args:{focus_action:action,limit:5000}}]};
 });
 t.mock.method(Provider.prototype,'finalResponse',async input=>{
  finals++;assert.equal(input.max_tokens,256);
  const observed=JSON.parse(input.messages.find(m=>m.role==='tool').content);
  assert.equal(observed.version,3);assert.equal(observed.log_text,log);assert.equal(observed.row_count,130);
  assert.equal(observed.focus.matches.length,1);assert.equal(observed.focus.matches[0].lineIndex,0);
  assert.equal(observed.focus.matches[0].text,log.split('\n')[0]);
  return {provider:'ollama',model:'llama3.1:8b',mocked:false,responseMode:'structured_final',stop_reason:'end_turn',
   text:`The audit recorded ${action} for run ${runId}, requestId ${requestId}, nonce ${nonce}.`};
 });
 const result=await require('../server/agent-runtime/workers/secureshopAuditWorker').execute({directory:spool.directory,
  manifest:spool.manifest,baseUrl:'http://127.0.0.1:1',model:'llama3.1:8b',persona:{id:3,role:'admin'},taskRequestVersion:2,graphTimeoutMs:180000});
 assert.equal(decisions,1);assert.equal(finals,1);assert.equal(result.objectiveCredit,false);
 const artifacts={...result.artifacts,log:{bytes:Buffer.byteLength(log),sha256:hash(log)},
  sources:{bytes:(await fs.stat(spool.paths.sources)).size,sha256:spool.manifest.sourcesSha256}};
 const evidence={...result,requestedCount:5000,artifacts,async*readArtifact(name){
  yield await fs.readFile(name==='log'?spool.paths.log:name==='sources'?spool.paths.sources:path.join(spool.directory,name+'.json'));
 }};
 const verified=await require('../server/services/secureshopAuditVerifiedEvidence').consumeSecureShopAuditEvidence(evidence,{qualifyModel:()=>true,check:async()=>{}});
 assert.equal(verified.observationVersion,3);assert.equal(verified.focusAction,action);assert.equal(verified.objectiveCredit,false);
 const witness=log.split('\n')[0],prepared=await require('../server/services/secureshopAuditUnboundedEvidence').prepareSecureShopAuditUnboundedJudgePacket(evidence,
  {qualifyModel:()=>true,check:async()=>{},boundedWitness:{version:1,line:witness,sha256:hash(witness)}});
 assert.equal(prepared.packet.rubric.version,'secureshop-audit-unbounded-observation-v3');
 assert.equal(prepared.packet.evidence[0].content,witness);assert.equal(prepared.packet.evidence[1].content,result.summary);
});
