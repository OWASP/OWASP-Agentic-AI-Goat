'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const diagnostic = require('./secureshopProductSummarySameSchemaCapabilityDiagnostic');
const { loadRetained } = require('./secureshopProductSummaryRetainedDiagnostic');

const ROOT = path.resolve(__dirname, '../..');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const identity = () => ({ identityMatched: true, localSocketRetired: true,
  status: 200, termination: 'complete' });
function response(text) {
  return new Response(JSON.stringify({ model: diagnostic.MODEL,
    message: { role: 'assistant', content: text }, done: true, done_reason: 'stop',
    prompt_eval_count: 20, eval_count: 10 }) + '\n',
  { status: 200, headers: { 'content-type': 'application/x-ndjson' } });
}
function fakeResult(scenario) {
  const quote = 'Polaris lantern is rechargeable';
  return { text: JSON.stringify({ satisfied: scenario.expected,
    citations: scenario.expected ? [{ evidenceId: 'product_summary_response', quote }] : [] }),
    physical: { raw: '{}', sha256: sha('{}'), bytes: 2 }, httpStatus: 200,
    physicalResponse: { text: 'controlled', sha256: sha('controlled'), bytes: 10,
      complete: true, stopped: null, truncated: false },
    adapterTerminalDone: true, responseBodyConsumed: true,
    adapterModel: diagnostic.MODEL };
}

test('inert plan and exact retained anyOf schema/options stay separate from failed actor and Judge', async () => {
  const source = diagnostic.contract();
  const retained = loadRetained();
  assert.deepEqual(source.schema, retained.requests[0].schema);
  assert.deepEqual(source.schema, retained.requests[1].schema);
  assert.deepEqual(source.options, retained.requests[0].options);
  assert.equal(source.schemaSha256, sha(JSON.stringify(retained.requests[0].schema)));
  const cases = diagnostic.benignCases(source);
  assert.deepEqual(cases.map(item => item.expected), [true, false]);
  assert(cases.every(item => !JSON.stringify(item).includes(retained.retainedResponse)));
  assert(cases.every(item => item.messages[0].content.endsWith(JSON.stringify(source.schema))));
  const output = [], originalWrite = process.stdout.write;
  process.stdout.write = value => { output.push(value); return true; };
  try { await diagnostic.main(['--plan']); } finally { process.stdout.write = originalWrite; }
  assert.equal(output.length, 1);
  assert.equal(JSON.parse(output[0]).nativeStarted, false);
  assert.equal(JSON.parse(output[0]).maxCalls, 2);
  assert.equal(JSON.parse(output[0]).qualificationCredit, false);
});

test('actual production adapter SDK path sends one exact streamed physical request per benign case', async () => {
  const source = diagnostic.contract(), cases = diagnostic.benignCases(source);
  for (const scenario of cases) {
    let dispatches = 0, actualWire = null;
    const result = await diagnostic.invokeAdapter(scenario, source, {
      origin: 'http://127.0.0.1:11434', signal: AbortSignal.timeout(5000),
      fetchImpl: async (url, init) => {
        dispatches++;
        assert.equal(String(url), 'http://127.0.0.1:11434/api/chat');
        actualWire = JSON.parse(init.body);
        return response(fakeResult(scenario).text);
      },
    });
    assert.equal(dispatches, 1);
    assert.equal(result.httpStatus, 200);
    assert.equal(result.adapterTerminalDone, true);
    assert.equal(result.responseBodyConsumed, true);
    assert.equal(result.physicalResponse.complete, true);
    assert.match(result.physicalResponse.text, /"done":true/);
    assert.equal(result.text, fakeResult(scenario).text);
    assert.equal(result.physical.sha256, sha(result.physical.raw));
    assert.deepEqual(actualWire.messages, scenario.messages);
    assert.deepEqual(actualWire.format, source.schema);
    assert.equal(actualWire.stream, true);
    assert.deepEqual([actualWire.options.temperature, actualWire.options.num_ctx,
      actualWire.options.num_predict], [0, 32768, 900]);
    assert(!Object.hasOwn(actualWire.options, 'max_tokens'));
  }
  assert.equal(diagnostic.sourcePins().adapter.sha256,
    'cb35f9be11b96cf2c50657f67c133bcc47bde2f42a3ab8986d689a8d2b94813a');
});

test('physical request rejects dropped evidence, wrong format/model, nonstream and additional tools', () => {
  const source = diagnostic.contract(), scenario = diagnostic.benignCases(source)[0];
  const base = { model: diagnostic.MODEL, stream: true, messages: scenario.messages,
    format: source.schema, options: { temperature: 0, num_ctx: 32768, num_predict: 900 } };
  assert.equal(diagnostic.validatePhysicalRequest(JSON.stringify(base), scenario, source.schema).bytes,
    Buffer.byteLength(JSON.stringify(base)));
  for (const modified of [
    { ...base, model: 'wrong-model' }, { ...base, stream: false },
    { ...base, messages: [scenario.messages[0]] }, { ...base, format: { type: 'object' } },
    { ...base, tools: [{ type: 'function' }] },
    { ...base, options: { ...base.options, num_predict: 42 } },
  ]) assert.throws(() => diagnostic.validatePhysicalRequest(JSON.stringify(modified), scenario, source.schema));
});

test('two controlled branch outcomes keep grammar enforcement unproven and zero credit', async () => {
  const calls = [], report = await diagnostic.runCapability({
    inspectModel: async () => identity(),
    beforeCall: row => calls.push(row),
    invoke: async scenario => fakeResult(scenario),
  });
  assert.equal(report.failed, false);
  assert.equal(report.callCount, 2);
  assert.equal(calls.length, 2);
  assert.deepEqual(report.cases.map(row => row.expectedMet), [true, true]);
  assert.equal(report.grammarEnforcementProven, false);
  assert.equal(report.adapterDecoderLocalized, false);
  assert.equal(report.qualificationCredit, false);
  assert.equal(report.actorCalls, 0);
  assert.equal(report.canonicalJudgeCalls, 0);
  assert.equal(report.adapterSourceUnchanged, true);
  assert.equal(report.cases[0].returned.text, fakeResult(casesFromReport(report)[0]).text);
});

function casesFromReport(report) {
  const cases = diagnostic.benignCases();
  assert.equal(report.cases.length, cases.length);
  return cases;
}

test('schema-invalid returned answer is retained bounded before parser rejects it', async () => {
  const error = await diagnostic.runCapability({ inspectModel: async () => identity(),
    invoke: async scenario => ({ ...fakeResult(scenario), text: '{not-json' })
  }).then(() => { throw Error('expected failure'); }, value => value);
  assert.equal(error.capabilityReport.callCount, 1);
  assert.equal(error.capabilityReport.cases[0].returned.text, '{not-json');
  assert.equal(error.capabilityReport.cases[0].returned.sha256, sha('{not-json'));
  assert.equal(error.capabilityReport.cases[0].state, 'failed');
});

test('returned text and physical stream evidence are byte-bounded without changing full hashes', async () => {
  const oversized = 'x'.repeat(32 * 1024 + 3);
  const returned = diagnostic.boundedReturnedText(oversized);
  assert.equal(returned.bytes, Buffer.byteLength(oversized));
  assert.equal(returned.sha256, sha(oversized));
  assert.equal(Buffer.byteLength(returned.text), 32 * 1024);
  assert.equal(returned.truncated, true);
  const observer = diagnostic.observePhysicalResponse(new Response('y'.repeat(1024 * 1024 + 1)));
  await observer.finished;
  assert.equal(observer.snapshot().bytes, 1024 * 1024);
  assert.equal(observer.snapshot().truncated, true);
  assert.equal(observer.snapshot().complete, false);
});

test('partial physical response and adapter failure remain bounded private evidence', async () => {
  const source = diagnostic.contract(), scenario = diagnostic.benignCases(source)[0];
  const error = await diagnostic.invokeAdapter(scenario, source, {
    signal: AbortSignal.timeout(5000),
    fetchImpl: async () => new Response('not-ndjson', { status: 503 }),
  }).then(() => { throw Error('expected adapter failure'); }, value => value);
  assert.equal(error.capabilityTransport.httpStatus, 503);
  assert.equal(error.capabilityTransport.physicalRequests, 1);
  assert.equal(error.capabilityTransport.physicalResponse.text, 'not-ndjson');
  assert.equal(error.capabilityTransport.physicalResponse.sha256, sha('not-ndjson'));
  assert.equal(error.capabilityTransport.physicalResponse.complete, true);
});

test('physical observer waits for delayed terminal body and cancellation is explicit', async () => {
  let release, cancelled = 0;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode('first')); release = () => controller.close(); },
    cancel() { cancelled++; },
  });
  const observer = diagnostic.observePhysicalResponse(new Response(body));
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(observer.snapshot().complete, false);
  assert.equal(observer.snapshot().text, 'first');
  release();
  await observer.finished;
  assert.equal(observer.snapshot().complete, true);
  assert.equal(cancelled, 0);
  let hold;
  const pending = diagnostic.observePhysicalResponse(new Response(new ReadableStream({
    start(controller) { hold = controller; controller.enqueue(new TextEncoder().encode('partial')); },
    cancel() { cancelled++; },
  })));
  await new Promise(resolve => setTimeout(resolve, 10));
  pending.stop('adapter_error');
  assert.equal(pending.snapshot().complete, false);
  assert.equal(pending.snapshot().stopped, 'adapter_error');
  await pending.finished;
  // Cancelling a clone branch need not cancel the original HTTP branch.
  assert.equal(cancelled, 0);
  void hold;
});

test('installed adapter waits for delayed terminal HTTP body before claiming completion', async () => {
  const source = diagnostic.contract(), scenario = diagnostic.benignCases(source)[0];
  let release, responded = false;
  const terminal = JSON.stringify({ model: diagnostic.MODEL,
    message: { role: 'assistant', content: fakeResult(scenario).text }, done: true,
    done_reason: 'stop', prompt_eval_count: 20, eval_count: 10 }) + '\n';
  const pending = diagnostic.invokeAdapter(scenario, source, {
    signal: AbortSignal.timeout(5000),
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(terminal));
        release = () => controller.close();
      },
    }), { status: 200, headers: { 'content-type': 'application/x-ndjson' } }),
  }).then(value => { responded = true; return value; });
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(responded, false);
  release();
  const result = await pending;
  assert.equal(result.adapterTerminalDone, true);
  assert.equal(result.physicalResponse.complete, true);
  assert.equal(result.responseBodyConsumed, true);
});

test('adapter abort during an unfinished streamed response retains partial bytes without socket-retirement claim',
  { timeout: 4000 }, async () => {
    const source = diagnostic.contract(), scenario = diagnostic.benignCases(source)[0];
    const controller = new AbortController();
    let entered;
    const enteredPromise = new Promise(resolve => { entered = resolve; });
    const frame = JSON.stringify({ model: diagnostic.MODEL,
      message: { role: 'assistant', content: 'partial' }, done: false }) + '\n';
    const pending = diagnostic.invokeAdapter(scenario, source, {
      signal: controller.signal,
      fetchImpl: async (_url, init) => new Response(new ReadableStream({
        start(stream) {
          stream.enqueue(new TextEncoder().encode(frame));
          init.signal.addEventListener('abort', () => stream.error(init.signal.reason), { once: true });
          entered();
        },
      }), { status: 200, headers: { 'content-type': 'application/x-ndjson' } }),
    });
    await enteredPromise;
    controller.abort(Object.assign(Error('CONTROLLED_ABORT'), { code: 'CONTROLLED_ABORT' }));
    const error = await pending.then(() => { throw Error('expected abort'); }, value => value);
    assert.equal(error.capabilityTransport.physicalRequests, 1);
    assert.equal(error.capabilityTransport.httpStatus, 200);
    assert.equal(error.capabilityTransport.adapterTerminalDone, false);
    assert.equal(error.capabilityTransport.generationSocketRetirementProven, false);
    assert.equal(error.capabilityTransport.physicalResponse.complete, false);
    assert(error.capabilityTransport.physicalResponse.bytes <= 1024 * 1024);
  });

test('a false result for the true branch remains diagnostic nonpass without a third call', async () => {
  let calls = 0;
  const report = await diagnostic.runCapability({ inspectModel: async () => identity(),
    invoke: async scenario => {
      calls++;
      return { ...fakeResult(scenario), text: '{"satisfied":false,"citations":[]}' };
    } });
  assert.equal(calls, 2);
  assert.equal(report.callCount, 2);
  assert.deepEqual(report.cases.map(row => row.expectedMet), [false, true]);
  assert.equal(report.qualificationCredit, false);
});

test('in-flight adapter abort closes the single controlled request and restores fetch', async () => {
  const source = diagnostic.contract(), scenario = diagnostic.benignCases(source)[0];
  const originalFetch = global.fetch, controller = new AbortController();
  let enteredResolve, calls = 0;
  const entered = new Promise(resolve => { enteredResolve = resolve; });
  const pending = diagnostic.invokeAdapter(scenario, source, {
    signal: controller.signal, fetchImpl: async (_url, init) => {
      calls++; enteredResolve();
      return new Promise((_resolve, reject) => {
        const abort = () => reject(init.signal.reason || Error('ABORTED'));
        init.signal.addEventListener('abort', abort, { once: true });
        if (init.signal.aborted) abort();
      });
    },
  });
  let timer;
  try {
    await Promise.race([entered, new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(Error('controlled adapter never dispatched')), 2000);
    })]);
  } finally { clearTimeout(timer); }
  controller.abort(Object.assign(Error('CONTROLLED_ABORT'), { code: 'CONTROLLED_ABORT' }));
  await assert.rejects(pending);
  assert.equal(calls, 1);
  assert.equal(global.fetch, originalFetch);
});

test('failure retains completed first call, caps second attempt and records postflight', async () => {
  let count = 0, probes = 0;
  const error = await diagnostic.runCapability({
    inspectModel: async () => { probes++; return identity(); },
    invoke: async scenario => {
      if (++count === 2) throw Object.assign(Error('private failed adapter body'), {
        code: 'ADAPTER_FAILED', capabilityTransport: { physicalRequests: 1,
          httpStatus: 503, adapterTerminalDone: false, responseBodyConsumed: false },
      });
      return fakeResult(scenario);
    },
  }).then(() => { throw Error('expected failure'); }, error => error);
  const report = error.capabilityReport;
  assert.equal(count, 2); assert.equal(probes, 2);
  assert.equal(report.callCount, 2);
  assert.equal(report.cases[0].state, 'parsed');
  assert.equal(report.cases[1].state, 'failed');
  assert.equal(report.cases[1].transport.httpStatus, 503);
  assert.equal(report.cases[1].transport.adapterTerminalDone, false);
  assert.equal(report.failure.code, 'ADAPTER_FAILED');
  assert.deepEqual(report.postModel, identity());
  assert(!JSON.stringify(report).includes('private failed adapter body'));
});

test('wrong pre-model identity dispatches zero calls', async () => {
  let count = 0;
  const report = await diagnostic.runCapability({ inspectModel: async () => ({
    identityMatched: false, localSocketRetired: true }), invoke: async () => { count++; } });
  assert.equal(count, 0); assert.equal(report.callCount, 0);
  assert.equal(report.failed, true); assert.equal(report.failure.code, 'MODEL_IDENTITY_UNVERIFIED');
});

test('private exclusive output prevents duplicate calls and retains sanitized failure journal', async () => {
  const run = fs.mkdtempSync(path.join(ROOT, 'tasks/qualification/run-v16-schema-unit-'));
  fs.chmodSync(run, 0o700);
  const output = path.join(run, diagnostic.OUTPUT), journal = path.join(run, diagnostic.JOURNAL);
  let calls = 0;
  try {
    await assert.rejects(diagnostic.main(['--run', '--output', output], {
      diagnostic: async ({ beforeCall }) => {
        await beforeCall({ id: 'true-branch-exact-quote', inputSha256: 'a'.repeat(64) });
        calls++;
        throw Error('private tool source must not persist');
      },
    }), /private tool source/);
    await assert.rejects(diagnostic.main(['--run', '--output', output], {
      diagnostic: async () => { calls++; },
    }), error => error.code === 'EEXIST');
    assert.equal(calls, 1);
    const content = fs.readFileSync(output, 'utf8');
    assert.equal(JSON.parse(content).qualificationCredit, false);
    assert(!content.includes('private tool source'));
    assert.deepEqual(fs.readFileSync(journal, 'utf8').trim().split('\n').map(JSON.parse)
      .map(event => event.event), ['started', 'call_reserved', 'failed']);
  } finally { fs.unlinkSync(output); fs.unlinkSync(journal); fs.rmdirSync(run); }
});

test('lexical run symlink is rejected before realpath or output creation', () => {
  const parent = path.join(ROOT, 'tasks/qualification');
  const actual = fs.mkdtempSync(path.join(parent, 'run-v16-actual-'));
  const alias = path.join(parent, `run-v16-alias-${process.pid}-${Date.now()}`);
  fs.chmodSync(actual, 0o700);
  fs.symlinkSync(actual, alias);
  try {
    assert.throws(() => diagnostic.admittedOutput(path.join(alias, diagnostic.OUTPUT)));
    assert.equal(fs.existsSync(path.join(actual, diagnostic.OUTPUT)), false);
  } finally { fs.unlinkSync(alias); fs.rmdirSync(actual); }
});

test('lexical qualification ancestor symlink is rejected before output creation', () => {
  const parent = path.join(ROOT, 'tasks/qualification');
  const run = fs.mkdtempSync(path.join(parent, 'run-v16-ancestor-unit-'));
  fs.chmodSync(run, 0o700);
  const original = fs.lstatSync;
  try {
    fs.lstatSync = (name, ...args) => {
      const stat = original(name, ...args);
      if (name !== parent) return stat;
      return new Proxy(stat, { get(target, key) {
        if (key === 'isSymbolicLink') return () => true;
        return Reflect.get(target, key);
      } });
    };
    assert.throws(() => diagnostic.admittedOutput(path.join(run, diagnostic.OUTPUT)));
  } finally { fs.lstatSync = original; fs.rmdirSync(run); }
});
