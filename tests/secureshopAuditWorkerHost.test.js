'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { runSecureShopAuditWorker } = require('../server/services/secureshopAuditWorkerHost');
const { spoolAuditObservation } = require('../server/services/secureshopAuditObservationSpool');
const scope = { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001', generation: 2, platformOwnerId: 7, platformSessionId: 8 };
async function fixture(t,{runId='owned-test'}={}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-audit-worker-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const spool = await spoolAuditObservation({ root, scope, runId, requestedCount: 1, checkCurrent: async () => {},
    rows: (async function *() {})() });
  return { spool, baseUrl: 'http://127.0.0.1:1', model: 'llama3.1:8b', persona: { id: 3, role: 'admin' }, checkCurrent: async () => {} };
}
test('actual child rejects altered source and leaks neither raw logs nor exception details', async t => {
  const input = await fixture(t); await fs.writeFile(input.spool.paths.log, 'private changed source');
  await assert.rejects(runSecureShopAuditWorker(input), error => {
    assert.equal(error.code, 'AUDIT_WORKER_FAILED'); assert.equal(error.message.includes('private'), false); return true;
  });
  assert.equal((await fs.readdir(input.spool.directory)).includes('traces.json'), false);
});
test('aborted authority prevents spawn, and wall deadline closes the actual child', async t => {
  const input = await fixture(t); const ctrl = new AbortController(); ctrl.abort();
  await assert.rejects(runSecureShopAuditWorker({ ...input, signal: ctrl.signal }), { name: 'AbortError' });
  await assert.rejects(runSecureShopAuditWorker({ ...input, timeoutMs: 1 }), { code: 'AUDIT_WORKER_TIMEOUT' });
});
test('reset cancellation closes an actual unbounded worker while its provider request is pending', { timeout: 10000 }, async t => {
  const http = require('node:http');
  const input = await fixture(t);
  let admitted;
  const providerRequest = new Promise(resolve => { admitted = resolve; });
  const server = http.createServer((_req, _res) => admitted());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const ctrl = new AbortController();
  const reason = Object.assign(new Error('Owned reset fence'), { code: 'CONTROLLED_RESET' });
  t.after(async () => {
    ctrl.abort(reason);
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const pending = runSecureShopAuditWorker({ ...input,
    baseUrl: `http://127.0.0.1:${server.address().port}`, signal: ctrl.signal,
    taskRequestVersion:2,timeoutMs:22000 });
  const rejection = assert.rejects(pending, { code: 'CONTROLLED_RESET' });
  await providerRequest;
  ctrl.abort(reason);
  await rejection; // Host settles only after its actual child emits close.
  assert.equal((await fs.readdir(input.spool.directory)).includes('traces.json'), false);
});
test('legacy transport retains 16KiB limit and invalid policy never reaches child execution',async t=>{
 const input=await fixture(t);
 for(const taskRequestVersion of [0,3,'2',true,null])await assert.rejects(runSecureShopAuditWorker({...input,taskRequestVersion}),/Owned audit worker request/);
 await assert.rejects(runSecureShopAuditWorker({...input,model:'m'.repeat(17000)}),{code:'AUDIT_WORKER_INPUT_LIMIT'});
 const policy=require('../server/services/secureshopPromptPolicySnapshot').buildPolicySnapshot({policyVersion:'1',role:'admin',policies:[]});
 await assert.rejects(runSecureShopAuditWorker({...input,promptPolicySnapshot:policy,model:'m'.repeat(2*1024*1024)}),{code:'AUDIT_WORKER_INPUT_LIMIT'});
 const {execute}=require('../server/agent-runtime/workers/secureshopAuditWorker');
 await assert.rejects(execute({promptPolicySnapshot:{forged:true}}),/Invalid prompt policy snapshot/);
 await assert.rejects(execute({taskRequestVersion:3}),/Invalid audit summary task request/);
});

test('worker forwards only a validated context setting and preserves absent defaults', async t => {
  const originalContext = process.env.OLLAMA_CONTEXT_WINDOW;
  const originalSecret = process.env.AUDIT_TEST_PRIVATE_ENV;
  t.after(() => {
    if (originalContext === undefined) delete process.env.OLLAMA_CONTEXT_WINDOW;
    else process.env.OLLAMA_CONTEXT_WINDOW = originalContext;
    if (originalSecret === undefined) delete process.env.AUDIT_TEST_PRIVATE_ENV;
    else process.env.AUDIT_TEST_PRIVATE_ENV = originalSecret;
  });
  process.env.AUDIT_TEST_PRIVATE_ENV = 'must-not-reach-worker';
  const inputs = [], { EventEmitter } = require('node:events');
  const { PassThrough, Writable } = require('node:stream');
  t.mock.method(require('node:child_process'), 'spawn', (_exec, _args, options) => {
    inputs.push(options);
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough();
    child.kill = () => true;
    child.stdin = new Writable({ write(_chunk, _encoding, callback) { callback(); },
      final(callback) { callback(); queueMicrotask(() => child.emit('close', 1, null)); } });
    return child;
  });
  const filename = require.resolve('../server/services/secureshopAuditWorkerHost');
  const cached = require.cache[filename];
  delete require.cache[filename];
  const isolated = require(filename).runSecureShopAuditWorker;
  require.cache[filename] = cached;
  const input = await fixture(t);
  for (const configured of [undefined, '', '65536', '8192']) {
    if (configured === undefined) delete process.env.OLLAMA_CONTEXT_WINDOW;
    else process.env.OLLAMA_CONTEXT_WINDOW = configured;
    await assert.rejects(isolated(input), { code: 'AUDIT_WORKER_FAILED' });
    assert.deepEqual(inputs.at(-1).env, { PATH: path.dirname(process.execPath), LANG: 'C.UTF-8',
      ...(configured ? { OLLAMA_CONTEXT_WINDOW: configured } : {}) });
  }
  const before = inputs.length;
  for (const configured of ['0', '-1', '01', ' 65536', '65536 ', '1.5', '1e5', '１２', '9007199254740992']) {
    process.env.OLLAMA_CONTEXT_WINDOW = configured;
    await assert.rejects(isolated(input), { name: 'RangeError' });
  }
  assert.equal(inputs.length, before, 'invalid context never spawns a worker');
});

test('actual child sends the configured context on its original provider request', { timeout: 10000 }, async t => {
  const originalContext = process.env.OLLAMA_CONTEXT_WINDOW;
  process.env.OLLAMA_CONTEXT_WINDOW = '65536';
  t.after(() => {
    if (originalContext === undefined) delete process.env.OLLAMA_CONTEXT_WINDOW;
    else process.env.OLLAMA_CONTEXT_WINDOW = originalContext;
  });
  const input = await fixture(t), http = require('node:http');
  let observe;
  const observed = new Promise(resolve => { observe = resolve; });
  const server = http.createServer((req, _res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => observe({ path: req.url, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const controller = new AbortController();
  const reason = Object.assign(new Error('Controlled request observed'), { code: 'CONTROLLED_CONTEXT_OBSERVED' });
  t.after(async () => {
    controller.abort(reason); server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const pending = runSecureShopAuditWorker({ ...input,
    baseUrl: `http://127.0.0.1:${server.address().port}`, signal: controller.signal, timeoutMs: 8000 });
  const rejected = assert.rejects(pending, { code: 'CONTROLLED_CONTEXT_OBSERVED' });
  const request = await observed;
  assert.equal(request.path, '/api/chat');
  assert.equal(request.body.options.num_ctx, 65536);
  controller.abort(reason);
  await rejected;
});

test('actual host binds parent-issued optional focus admission to the exact persisted child call', {timeout:10000},async t=>{
 const http=require('node:http'),{randomUUID}=require('node:crypto'),runId=randomUUID(),input=await fixture(t,{runId});
 const prior=process.env.OLLAMA_CONTEXT_WINDOW;process.env.OLLAMA_CONTEXT_WINDOW='32768';
 t.after(()=>{if(prior===undefined)delete process.env.OLLAMA_CONTEXT_WINDOW;else process.env.OLLAMA_CONTEXT_WINDOW=prior;});
 const observed=[];let decisions=0;
 const server=http.createServer((req,res)=>{const chunks=[];req.on('data',c=>chunks.push(c));req.on('end',()=>{
  const body=JSON.parse(Buffer.concat(chunks));assert.equal(req.url,'/api/chat');
  const final=body.options.num_predict===256;observed.push(body);
  const response=final?{answer:'No matching events were present in the original empty snapshot.'}
   :{tool_calls:[{agent:'audit',tool:'summarize_anomalies',args:{focus_action:'listing_update',limit:1}}]};
  res.writeHead(200,{'content-type':'application/x-ndjson'});res.end(JSON.stringify({model:'llama3.1:8b',
   message:{role:'assistant',content:JSON.stringify(response)},done:true,done_reason:'stop',prompt_eval_count:300,eval_count:30})+'\n');
 });});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
 const result=await runSecureShopAuditWorker({...input,taskRequestVersion:2,baseUrl:`http://127.0.0.1:${server.address().port}`,admitTool:async request=>{
  decisions++;assert.deepEqual(request.args,{focus_action:'listing_update',limit:1});assert(Object.isFrozen(request.args));
  return {admissionId:randomUUID(),runId,invocationId:request.invocationId,toolKey:'audit.summarize_anomalies',policyVersion:'1',registrySha256:'a'.repeat(64),enforcement:true,allowed:true,action:'dispatch',policyViolation:null};
 }});
 assert.equal(decisions,1);assert.equal(observed.length,2);assert.equal(result.objectiveCredit,false);
 const messages=JSON.parse(await fs.readFile(path.join(input.spool.directory,'messages.json'),'utf8'));
 const observation=JSON.parse(messages.find(m=>m.role==='tool').content);assert.equal(observation.version,3);
 assert.equal(observation.log_text,'');assert.deepEqual(observation.focus.matches,[]);
});
