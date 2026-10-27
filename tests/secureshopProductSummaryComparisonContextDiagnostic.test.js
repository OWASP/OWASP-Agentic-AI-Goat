'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const d = require('./postgres/secureshopProductSummaryComparisonContextDiagnostic');
const capability = require('./postgres/secureshopProductSummarySameSchemaCapabilityDiagnostic');
const retained = require('./postgres/secureshopProductSummaryRetainedDiagnostic');

// Generic controls deliberately use labelled controlled strings. They do not
// pretend to be genuine captures and require no ignored/private evidence.
const schema = { anyOf: [{ type: 'object' }, { type: 'object' }] };
const options = { temperature: 0, num_ctx: 32768, max_tokens: 900, num_predict: 900, timeout: 90000 };
function controlledCases() {
  return d.INPUTS.map((input, i) => ({ id: input.id, expected: i === 0, answer: 'controlled answer ' + i,
    comparison: { version: 1, originalTask: { kind: 'server_original_request', text: 'controlled task ' + i },
      productId: i + 1, untrustedObservedToolResult: { mcp: { content: [{ type: 'text', text: JSON.stringify({ description: 'controlled source ' + i }) }] }, sha256: 'controlled' } },
    requests: [0, 1].map(j => ({ method: 'chat', input: [
      { role: 'system', content: 'unchanged criterion ' + j + '\n' + d.ANCHOR + '\nThe reference is NOT citable.\nOUTPUT JSON SCHEMA:\n' + JSON.stringify(schema) },
      { role: 'user', content: JSON.stringify({ nonCitableServerReference: { evidenceId: 'product_summary_comparison', content: {} }, citableObservedEvidence: [] }) },
    ], tools: [], schema, options })) }));
}
const model = async () => ({ identityMatched: true, localSocketRetired: true });
test('stable read bounds bytes even when regular file grows after initial stat', () => {
  const directory=fs.mkdtempSync(path.join(d.ROOT,'tasks/qualification/v16-read-growth-'));
  const file=path.join(directory,'controlled.txt');fs.writeFileSync(file,'four',{mode:0o600});
  const original=fs.readSync;let injected=false,totalRequested=0;
  fs.readSync=function(fd,buffer,offset,length,position) {
    totalRequested+=length;
    if(!injected){injected=true;fs.appendFileSync(file,'controlled appended bytes');}
    return original.call(fs,fd,buffer,offset,length,position);
  };
  try {assert.throws(()=>d.read(path.relative(d.ROOT,file),4,true),/grew/);}
  finally {fs.readSync=original;}
  assert.equal(totalRequested,5,'Only pre-size plus one-byte growth probe may be requested');
});
function qwenResult(request, changes = {}) {
  const selected = d.candidate('qwen3-v1');
  const result = controlledResult(request);
  const sent = { ...JSON.parse(result.physical.raw), model: selected.model, think: false, ...changes };
  const raw = JSON.stringify(sent);
  const response = JSON.stringify({ model: selected.model, message: { content: result.text }, done: true }) + '\n';
  return { ...result, adapterModel: selected.model,
    physical: { raw, sha256: d.sha(raw), bytes: Buffer.byteLength(raw) },
    physicalResponse: { text: response, sha256: d.sha(response), complete: true, truncated: false } };
}
function controlledResult(request, text = JSON.stringify({ satisfied: false, citations: [] })) {
  const raw = JSON.stringify({ model: capability.MODEL, stream: true, messages: request.input, format: request.schema,
    options: { num_ctx: 32768, num_predict: 900, temperature: 0 } });
  const response = JSON.stringify({ model: capability.MODEL, message: { content: text }, done: true }) + '\n';
  return { text, returned: capability.boundedReturnedText(text),
    physical: { raw, sha256: d.sha(raw), bytes: Buffer.byteLength(raw) },
    physicalResponse: { text: response, sha256: d.sha(response), complete: true, truncated: false },
    httpStatus: 200, adapterTerminalDone: true, responseBodyConsumed: true, adapterModel: capability.MODEL };
}

test('explicit version, inert plan grammar and original bounds; no private captures needed', () => {
  assert.deepEqual(d.parseArgs(['--plan', '--version', d.VERSION]), { run: false, expected: undefined });
  assert.equal(d.parseArgs(['--run', '--version', d.VERSION, '--expected-plan-sha256', 'a'.repeat(64)]).run, true);
  for (const args of [[], ['--run'], ['--plan', '--version', 'other'], ['--run', '--version', d.VERSION, '--expected-plan-sha256', 'bad']])
    assert.throws(() => d.parseArgs(args));
  assert.equal(d.LIMITS.physicalCalls, 4); assert.equal(d.LIMITS.callMs, 90000); assert.equal(d.LIMITS.workMs, 450000);
});

test('closed candidate identity preserves original default and rejects implicit transport', async () => {
  assert.deepEqual(d.candidate(), { model: capability.MODEL, digest: retained.MODEL_DIGEST });
  assert.throws(() => d.candidate('qwen3:latest'));
  await assert.rejects(d.execute({ cases: controlledCases(), candidateId: 'qwen3-v1' }));
});

test('Qwen candidate keeps all four original requests and genuine-pair shape, never awards credit', async () => {
  const cases = controlledCases(), before = structuredClone(cases), requests = [];
  const state = await d.execute({ cases, candidateId: 'qwen3-v1',
    probe: async () => ({ identityMatched: true, localSocketRetired: true, ...d.candidate('qwen3-v1') }),
    call: async request => { requests.push(request); return qwenResult(request); } });
  assert.deepEqual(cases, before);
  assert.deepEqual(requests, cases.flatMap(c => [0, 1].map(i => d.requestFor(c, i))));
  assert.equal(state.calls.length, 4); assert.equal(state.errors.length, 0);
  assert.deepEqual(state.calls.map(c => c.expectedMet), [false, false, true, true]);
  assert.equal(state.actorCalls, 0); assert.equal(state.canonicalJudgeCalls, 0);
  assert.equal(state.qualificationCredit, false);
});

test('Qwen candidate denies wrong digest before inference and wrong model/thinking wire', async () => {
  let dispatched = 0;
  const wrong = await d.execute({ cases: controlledCases(), candidateId: 'qwen3-v1',
    probe: async () => ({ identityMatched: true, localSocketRetired: true, ...d.candidate('qwen3-v1'), digest: '0'.repeat(64) }),
    call: async () => { dispatched++; throw Error('must not dispatch'); } });
  assert.equal(dispatched, 0); assert(wrong.errors.length > 0);
  for (const changes of [{ model: capability.MODEL }, { think: true }, { options: { num_ctx: 8192 } }]) {
    const state = await d.execute({ cases: controlledCases(), candidateId: 'qwen3-v1',
      probe: async () => ({ identityMatched: true, localSocketRetired: true, ...d.candidate('qwen3-v1') }),
      call: async request => qwenResult(request, changes) });
    assert(state.errors.length > 0); assert.equal(state.calls.length, 1);
  }
});

test('only exact generic anchor changes, each case keeps its own complete context and answer', () => {
  for (const c of controlledCases()) for (const i of [0, 1]) {
    const r = d.requestFor(c, i), original = c.requests[i];
    assert.equal(r.input[0].content.replace(d.REPLACEMENT, d.ANCHOR), original.input[0].content);
    assert.deepEqual(r.options, original.options); assert.deepEqual(r.schema, original.schema); assert.deepEqual(r.tools, original.tools);
    const body = JSON.parse(r.input[1].content);
    assert.deepEqual(body.nonCitableServerReference.content, c.comparison);
    assert.equal(body.citableObservedEvidence[0].content, c.answer);
    assert(!JSON.stringify(r).includes('expected'));
  }
  assert.throws(() => d.changedInstructions('unknown'));
  assert.throws(() => d.changedInstructions(d.ANCHOR + d.ANCHOR));
});

test('absence-only skip helper checks ALL present inputs, even beside a missing file', () => {
  const inputs = [{ path: 'one', sha256: d.sha('one') }, { path: 'two', sha256: d.sha('two') }];
  const missing = () => { throw Object.assign(Error('absent'), { code: 'ENOENT' }); };
  assert.deepEqual(d.missingCaptures(inputs, missing), ['one', 'two']);
  assert.deepEqual(d.missingCaptures(inputs, p => p === 'one' ? Buffer.from('one') : missing()), ['two']);
  assert.throws(() => d.missingCaptures(inputs, p => p === 'one' ? missing() : Buffer.from('corrupt')));
  assert.throws(() => d.missingCaptures(inputs, () => { throw Object.assign(Error('denied'), { code: 'EACCES' }); }));
});

test('unchanged quote parser rejects reference-only, invented quotes, extra fields and invalid branches', () => {
  for (const value of [
    { satisfied: true, citations: [] },
    { satisfied: true, citations: [{ evidenceId: 'product_summary_comparison', quote: 'answer' }] },
    { satisfied: true, citations: [{ evidenceId: 'product_summary_response', quote: 'absent' }] },
    { satisfied: false, citations: [{ evidenceId: 'product_summary_response', quote: 'answer' }] },
    { satisfied: false, citations: [], explanation: 'extra' },
  ]) assert.throws(() => retained.parseAnswer(JSON.stringify(value), 'answer', schema));
  assert.equal(retained.parseAnswer('{"satisfied":false,"citations":[]}', 'answer', schema).satisfied, false);
});

test('four controlled completed calls preserve unexpected false decisions without credit or forced verdict', async () => {
  let calls = 0, probes = 0;
  const state = await d.execute({ cases: controlledCases(), probe: async () => { probes++; return model(); },
    call: async request => { calls++; return controlledResult(request); } });
  assert.equal(calls, 4); assert.equal(probes, 2); assert.equal(state.status, 'diagnostic-complete');
  assert.deepEqual(state.calls.map(c => c.expectedMet), [false, false, true, true]);
  assert.equal(state.qualificationCredit, false); assert.equal(state.assessmentAuthority, null);
  assert.equal(state.canonicalJudgeCalls, 0); assert.equal(state.actorCalls, 0);
});

test('physically complete invalid output remains invalid, next genuine-case slot is not erased', async () => {
  let calls = 0;
  const state = await d.execute({ cases: controlledCases(), probe: model,
    call: async request => controlledResult(request, ++calls === 1 ? '{bad' : '{"satisfied":false,"citations":[]}') });
  assert.equal(calls, 4); assert.equal(state.calls[0].state, 'invalid');
  assert.equal(state.calls[0].returned.text, '{bad'); assert.equal(state.calls[3].state, 'parsed');
  assert.equal(state.status, 'diagnostic-incomplete');
});

test('unknown physical completion stops further dispatch and retains partial evidence, no retry', async () => {
  let calls = 0;
  const state = await d.execute({ cases: controlledCases(), probe: model, call: async () => {
    calls++; throw Object.assign(Error('private error text'), { capabilityTransport: { physicalRequests: 1, adapterTerminalDone: false } });
  } });
  assert.equal(calls, 1); assert.equal(state.remoteCompletionUnverified, true);
  assert.equal(state.calls[0].transport.physicalRequests, 1);
  assert(!JSON.stringify(state.errors).includes('private error text'));
});

test('dispatch rechecks original aggregate endpoint after durable preparation and after return', async () => {
  let time = 100, calls = 0;
  const state = await d.execute({ cases: controlledCases(), probe: model, now: () => time,
    persist: s => { if (s.calls.length) time = 450101; }, call: async r => { calls++; return controlledResult(r); } });
  assert.equal(calls, 0); assert.equal(state.calls[0].state, 'not-dispatched');
  time = 100;
  const late = await d.execute({ cases: controlledCases(), probe: model, now: () => time,
    call: async r => { calls++; time = 450101; return controlledResult(r); } });
  assert.equal(calls, 1); assert.equal(late.status, 'diagnostic-incomplete');
  assert.equal(late.calls[0].physicalResponse.complete, true);
});

test('abort and persistence failure before dispatch never call the provider', async () => {
  const abort = new AbortController(); let calls = 0;
  const state = await d.execute({ cases: controlledCases(), probe: model, signal: abort.signal,
    persist: s => { if (s.calls.length) abort.abort(Error('stop')); }, call: async r => { calls++; return controlledResult(r); } });
  assert.equal(calls, 0); assert.equal(state.calls[0].state, 'not-dispatched');
  let failed = false;
  const io = await d.execute({ cases: controlledCases(), probe: model,
    persist: s => { if (!failed && s.calls.length) { failed = true; throw Error('fsync'); } },
    call: async r => { calls++; return controlledResult(r); } });
  assert.equal(calls, 0); assert.equal(io.status, 'diagnostic-incomplete');
});

test('real production adapter and physical parser execute offline with one controlled fetch', async () => {
  const request = d.requestFor(controlledCases()[0], 0); let sends = 0;
  const text = '{"satisfied":false,"citations":[]}';
  const before = d.captureSources();
  const r = await capability.invokeAdapter({ messages: request.input }, { schema: request.schema, options: request.options }, {
    signal: AbortSignal.timeout(5000), fetchImpl: async (_url, init) => {
      sends++; const body = JSON.parse(init.body);
      assert.deepEqual(body.messages, request.input); assert.deepEqual(body.format, request.schema);
      return new Response(JSON.stringify({ model: capability.MODEL, message: { role: 'assistant', content: text },
        done: true, done_reason: 'stop' }) + '\n', { status: 200, headers: { 'content-type': 'application/x-ndjson' } });
    } });
  assert.equal(sends, 1); assert.equal(r.text, text); assert.equal(r.physicalResponse.complete, true);
  assert.equal(r.adapterTerminalDone, true); assert.equal(r.responseBodyConsumed, true);
  assert.equal(d.verifyClosure(before), true, 'First actual adapter invocation must not escape the admitted loaded closure');
});

test('source drift and post-model failure cannot leave a successful terminal claim', async () => {
  let probes = 0, verifies = 0;
  const state = await d.execute({ cases: controlledCases(), probe: async () => ++probes === 1
    ? model() : { identityMatched: false, localSocketRetired: true },
    verify: () => { if (++verifies > 1) throw Error('drift'); return true; },
    call: async request => controlledResult(request) });
  assert.equal(state.calls.length, 4); assert.equal(state.status, 'diagnostic-incomplete');
  assert.deepEqual(state.errors.map(e => e.phase), ['model-after', 'source']);
  assert.equal(state.sourceUnchanged, false);
});

test('actual production adapter cancellation and HTTP failure do not retry or fallback', async () => {
  const request = d.requestFor(controlledCases()[0], 0), contract = { schema: request.schema, options: request.options };
  let sends = 0; const abort = new AbortController(); abort.abort(Error('controlled abort'));
  await assert.rejects(capability.invokeAdapter({ messages: request.input }, contract, {
    signal: abort.signal, fetchImpl: async () => { sends++; throw Error('must not dispatch'); } }));
  assert.equal(sends, 0);
  await assert.rejects(capability.invokeAdapter({ messages: request.input }, contract, {
    signal: AbortSignal.timeout(5000), fetchImpl: async () => {
      sends++; return new Response('{"error":"controlled failure"}', { status: 503, headers: { 'content-type': 'application/json' } });
    } }));
  assert.equal(sends, 1);
});

test('permanent persistence failure is thrown, never returned as successful evidence', async () => {
  let calls = 0;
  await assert.rejects(d.execute({ cases: controlledCases(), probe: model,
    persist: () => { throw Error('controlled disk unavailable'); },
    call: async request => { calls++; return controlledResult(request); } }), /controlled disk unavailable/);
  assert.equal(calls, 0);
});

test('bounded stable reads reject symlink, changed hash and private mode mismatch', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v16-context-control-'));
  const file = path.join(dir, 'capture'), alias = path.join(dir, 'alias');
  try {
    fs.writeFileSync(file, 'one', { mode: 0o600 });
    assert.equal(d.read(path.relative(d.ROOT, file), 3, true).toString(), 'one');
    assert.throws(() => d.read(path.relative(d.ROOT, file), 2, true));
    fs.symlinkSync(file, alias); assert.throws(() => d.read(path.relative(d.ROOT, alias), 3, true));
    fs.chmodSync(file, 0o644); assert.throws(() => d.read(path.relative(d.ROOT, file), 3, true));
  } finally { if (fs.existsSync(alias)) fs.unlinkSync(alias); fs.unlinkSync(file); fs.rmdirSync(dir); }
});

test('loaded source closure includes actual installed bytes and rejects hash/set tampering', () => {
  const closure = d.captureSources(); assert(Object.keys(closure.pins).some(p => p.startsWith('node_modules/@langchain/ollama/')));
  assert(Object.keys(closure.pins).some(p => p.endsWith('ComparisonContextDiagnostic.test.js')));
  assert.equal(d.verifyClosure(closure), true);
  const changed = structuredClone(closure); changed.pins['package.json'] = '0'.repeat(64);
  assert.throws(() => d.verifyClosure(changed));
  const extra = structuredClone(closure); extra.loaded.push('controlled-extra.js'); assert.throws(() => d.verifyClosure(extra));
});

test('exact genuine captures admit unchanged rubric and distinct original source contexts', t => {
  const absent = d.missingCaptures();
  if (absent.length) { t.skip('Exact private V16 captures absent: ' + absent.join(', ')); return; }
  // Historical default admission deliberately remains stale rather than
  // silently reauthorizing old Llama runs against changed source bytes.
  assert.throws(() => d.admission());
  assert.equal(d.SOURCE_PINS['server/agent-runtime/objectiveJudge.js'],
    '186b7169cbc7161bca4a4c64f88790b3a40da3e512a7c1c9331a3928c1ed46a1');
  const cases = d.admission('qwen3-v1'); assert.equal(cases.length, 2);
  assert.equal(cases[0].retainedAssessment.body.judgment.verdict, 'fail');
  assert.equal(cases[1].retainedAssessment.body.modelEvaluated, false);
  assert.equal(cases[1].benignProof.assessmentAuthority, null);
  assert.deepEqual(cases[0].rubric, cases[1].rubric);
  assert.notDeepEqual(cases[0].comparison.untrustedObservedToolResult, cases[1].comparison.untrustedObservedToolResult);
  for (const c of cases) for (const i of [0, 1]) {
    const r = d.requestFor(c, i); assert.deepEqual(r.schema, c.requests[i].schema);
    assert.equal(r.input[0].content.replace(d.REPLACEMENT, d.ANCHOR), c.requests[i].input[0].content);
    assert.deepEqual(JSON.parse(r.input[1].content).nonCitableServerReference.content, c.comparison);
  }
});

test('exclusive durable claim consumes version/input pair once, even under a different fresh plan', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v16-claim-control-'));
  fs.chmodSync(dir, 0o700);
  let file;
  try {
    const operations = [];
    const io = { ...fs, writeFileSync: (...args) => { operations.push('write'); return fs.writeFileSync(...args); },
      fsyncSync: fd => { operations.push(fs.fstatSync(fd).isDirectory() ? 'directory-fsync' : 'file-fsync'); return fs.fsyncSync(fd); },
      closeSync: fd => { operations.push('close'); return fs.closeSync(fd); } };
    file = d.claimRun(dir, 'a'.repeat(64), io);
    assert.deepEqual(operations, ['write', 'file-fsync', 'close', 'directory-fsync', 'close']);
    assert.deepEqual(JSON.parse(fs.readFileSync(file)), { version: d.VERSION, inputs: d.INPUTS, planSha256: 'a'.repeat(64) });
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.throws(() => d.claimRun(dir, 'a'.repeat(64)), { code: 'EEXIST' });
    assert.throws(() => d.claimRun(dir, 'b'.repeat(64)), { code: 'EEXIST' });
  } finally { if (file) fs.unlinkSync(file); fs.rmdirSync(dir); }
});

test('failed claim fsync is never reset, and preexisting symlink is never followed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v16-claim-fault-control-'));
  fs.chmodSync(dir, 0o700);
  try {
    assert.throws(() => d.claimRun(dir, 'a'.repeat(64), { ...fs, fsyncSync: () => { throw Error('controlled fsync failure'); } }), /fsync failure/);
    assert.throws(() => d.claimRun(dir, 'a'.repeat(64)), { code: 'EEXIST' });
    const [name] = fs.readdirSync(dir), file = path.join(dir, name);
    // Only this disposable controlled claim is removed, never actual evidence.
    fs.unlinkSync(file); fs.symlinkSync('missing-controlled-target', file);
    assert.throws(() => d.claimRun(dir, 'a'.repeat(64)), { code: 'EEXIST' });
    assert.equal(fs.existsSync(path.join(dir, 'missing-controlled-target')), false);
  } finally { for (const name of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, name)); fs.rmdirSync(dir); }
});

test('nonsettling generation reaches bounded durable debt terminal; late completion cannot mutate it', async () => {
  let finish, calls = 0, probes = 0, capturedSignal;
  const delays = [], snapshots = [];
  const timers = { setTimeout: (fn, ms) => { delays.push(ms); return setTimeout(fn, 3); }, clearTimeout };
  const state = await d.execute({ cases: controlledCases(), timers, probe: async () => { probes++; return model(); },
    persist: value => snapshots.push(JSON.stringify(value)), call: (request, signal) => {
      calls++; capturedSignal = signal; return new Promise(resolve => { finish = () => resolve(controlledResult(request)); });
    } });
  assert.equal(calls, 1); assert.equal(probes, 2); assert.equal(capturedSignal.aborted, true);
  assert.equal(state.localRetirementUnproven, true); assert.equal(state.remoteCompletionUnverified, true);
  assert.deepEqual(state.pendingLocalWork, ['generation']); assert.equal(state.calls[0].state, 'failed');
  assert.equal(state.status, 'diagnostic-incomplete'); assert.equal(state.qualificationCredit, false);
  assert(delays.some(ms => ms > 80000 && ms <= 90000));
  assert(delays.filter(ms => ms <= 10000).length >= 3);
  const terminal = JSON.stringify(state); assert.equal(snapshots.at(-1), terminal);
  finish(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(JSON.stringify(state), terminal); assert.equal(calls, 1);
});

test('external abort and stalled postflight share one existing postflight endpoint, no extra calls', async () => {
  const controller = new AbortController(); let calls = 0, probes = 0, time = 100;
  const delays = [];
  const timers = { setTimeout: (fn, ms) => { delays.push(ms); return setTimeout(fn, 3); }, clearTimeout };
  const state = await d.execute({ cases: controlledCases(), timers, now: () => time, signal: controller.signal,
    probe: () => ++probes === 1 ? model() : new Promise(() => {}), call: () => {
      calls++; time = 1000; controller.abort(Error('controlled abort')); return new Promise(() => {});
    } });
  assert.equal(calls, 1); assert.equal(probes, 2);
  assert.deepEqual(state.pendingLocalWork, ['generation', 'model-after']);
  assert.equal(state.localRetirementUnproven, true); assert.equal(state.remoteCompletionUnverified, true);
  assert.deepEqual(delays.slice(-2), [10000, 10000], 'Caller join and probe race concurrently against the SAME endpoint');
});

test('caller rejection after abort is not proof of remote generation retirement', async () => {
  const controller = new AbortController(); let calls = 0;
  const state = await d.execute({ cases: controlledCases(), signal: controller.signal, probe: model,
    call: async () => { calls++; controller.abort(Error('controlled stop')); throw Object.assign(Error('caller aborted'), {
      capabilityTransport: { physicalRequests: 1, adapterTerminalDone: false, diagnostic: 'controlled bounded evidence' },
    }); } });
  assert.equal(calls, 1); assert.equal(state.localRetirementUnproven, false);
  assert.equal(state.remoteCompletionUnverified, true); assert.equal(state.status, 'diagnostic-incomplete');
  assert.equal(state.calls[0].lateTransport.physicalRequests, 1);
});
