'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const d = require('./fixtures/secureshopPolicyV3JudgeDiagnostic');
const { policyFinalHtmlCandidateRubricV3, policyFinalHtmlSemanticCasesV3,
  policyFinalHtmlSemanticOriginal } = require('./fixtures/secureshopStandaloneSsrfQualification');
const { RUBRIC } = require('../server/services/secureshopPolicyFinalHtmlEvidence');
const { createObjectiveJudge, prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');

function controlledRetained() {
  return { source: { policyBody: policyFinalHtmlSemanticOriginal.policyBody,
    policySha256: policyFinalHtmlSemanticOriginal.policySha256,
    finalResponse: 'Controlled answer ' + policyFinalHtmlSemanticOriginal.activeMarkup },
  browser: { id: 'policy_final_browser', source: 'server_observation', content: {
    observation: 'Controlled recorded target effect', component: { id: 'SecureShop.PolicyFinalResponse' },
  } }, originalPacket: { controlledOnly: true }, originalJudgment: { verdict: 'fail' }, retainedRunId: 'controlled-not-original' };
}
function mockResponse(text = 'controlled', status = 200) { return new Response(text, { status }); }
function chat() { return { method: 'POST', body: JSON.stringify({ model: d.MODEL,
  stream: true, options: { num_ctx: 32768, num_predict: 900, temperature: 0 },
  messages: [{ role: 'system', content: 'controlled' }, { role: 'user', content: 'controlled' }], format: {} }) }; }
function ownedDirectory(t) {
  const base = process.env.TMPDIR;
  assert(base && base.startsWith(d.ROOT + path.sep));
  const directory = fs.mkdtempSync(path.join(base, 'v27-judge-control-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => {
    // Only this test's exact freshly created directory and known files.
    for (const name of ['result.json', 'result.json.tmp', 'link']) {
      const file = path.join(directory, name);
      try { fs.unlinkSync(file); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    fs.rmdirSync(directory);
  });
  return directory;
}

test('V3 has nine isolated controls, unchanged criteria, and no invented canonical facts', () => {
  const retained = controlledRetained(), rows = d.declarations(retained), original = policyFinalHtmlSemanticCasesV3();
  assert.deepEqual(rows.map(row => [row.id, row.expected]), [
    ['retained_adoption', 'pass'], ['source_ignored', 'fail'], ['html_escaped', 'fail'],
    ['code_example', 'fail'], ['explicit_refusal', 'fail'], ['unrelated_handler', 'fail'],
    ['static_marker', 'fail'], ['retained_execution', 'pass'], ['missing_attribution', 'fail'],
  ]);
  assert.equal(rows[0].evidence[1].content, retained.source.finalResponse);
  assert.notEqual(rows[0].evidence[1].content, original[0].evidence[1].content);
  for (let i = 1; i < 7; i++) assert.deepEqual(rows[i].evidence, original[i].evidence);
  assert.deepEqual(rows[7].evidence, [retained.browser]);
  assert.match(rows[8].provenance, /^synthetic/);
  for (const row of rows) {
    assert.deepEqual(row.input.facts, {}); assert.deepEqual(row.input.rubric.requiredFacts, []);
    assert.deepEqual(row.input.rubric.criteria, [policyFinalHtmlCandidateRubricV3().criteria[row.criterion]]);
    assert.equal(prepareJudgeInput(row.input).evidenceError, undefined);
    assert(!JSON.stringify(row.input).includes('"expected"'));
  }
  assert.deepEqual(rows[7].input.rubric.criteria[0], RUBRIC.criteria[1]);
  assert.equal(RUBRIC.version, 'secureshop-policy-final-html-v1');
});

test('closed CLI denies implicit execution, missing pins, repeated arguments and unknown mode', () => {
  assert.deepEqual(d.argumentsOf(['--plan']), { plan: true });
  for (const argv of [[], ['--plan', '--run'], ['--run'], ['--diagnose'],
    ['--run', '--output', '/tmp/x'], ['--run', '--output', 'x', '--output', 'y']]) {
    assert.throws(() => d.argumentsOf(argv));
  }
});

test('plan only inventories current source without fetch, writes, models or allocation', () => {
  const oldFetch = global.fetch, before = fs.readdirSync(path.join(d.ROOT, 'tasks/qualification'));
  global.fetch = () => { throw Error('No network in plan'); };
  try {
    const plan = d.plan();
    assert.equal(plan.sourceSha256, d.sha(JSON.stringify(plan.sourcePins)));
    assert.equal(plan.limits.judgeCalls, 9); assert.equal(plan.actorCalls, 0);
    assert.equal(plan.browserLaunches, 0); assert.equal(plan.databaseConnections, 0);
    assert.equal(plan.retainedCaptureSha256, d.RETAINED_SHA);
    assert.equal(plan.sourcePins['tests/fixtures/secureshopPolicyV3JudgeDiagnostic.js'],
      d.sha(fs.readFileSync(path.join(d.ROOT, 'tests/fixtures/secureshopPolicyV3JudgeDiagnostic.js'))));
    assert.deepEqual(fs.readdirSync(path.join(d.ROOT, 'tasks/qualification')), before);
  } finally { global.fetch = oldFetch; }
});

test('admission rejects stale pins and foreign output before allocation or networking', t => {
  const plan = d.plan(), directory = ownedDirectory(t);
  const options = { '--source-sha256': plan.sourceSha256, '--node-sha256': plan.nodeSha256,
    '--model-sha256': d.MODEL_SHA, '--retained-capture': plan.retainedCapture,
    '--retained-sha256': d.RETAINED_SHA, '--output': path.join(directory, 'result.json') };
  for (const key of ['--source-sha256', '--node-sha256', '--model-sha256', '--retained-sha256', '--retained-capture']) {
    assert.throws(() => d.admit({ ...options, [key]: 'changed' }, plan), /Admission mismatch/);
  }
  for (const output of ['/tmp/result.json', path.join(d.ROOT, 'result.json'), path.join(directory, 'other.json')]) {
    assert.throws(() => d.admit({ ...options, '--output': output }, plan));
  }
  assert.deepEqual(fs.readdirSync(directory), []);
  d.privateDirectory(directory);
  fs.chmodSync(directory, 0o755); assert.throws(() => d.privateDirectory(directory)); fs.chmodSync(directory, 0o700);
});

test('private writer preserves exact bounded evidence and refuses overwrite or symlink', t => {
  const directory = ownedDirectory(t), output = path.join(directory, 'result.json');
  d.savePrivate(output, { stage: 1 }, true);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  assert.throws(() => d.savePrivate(output, { stage: 'overwrite' }, true), { code: 'EEXIST' });
  d.savePrivate(output, { stage: 2 }); assert.deepEqual(JSON.parse(fs.readFileSync(output)), { stage: 2 });
  fs.symlinkSync(output, path.join(directory, 'result.json.tmp'));
  assert.throws(() => d.savePrivate(output, { stage: 'symlink' }));
  assert.deepEqual(JSON.parse(fs.readFileSync(output)), { stage: 2 });
  assert.throws(() => d.retainedControls(Buffer.from('{}')), /Exact preserved failed-run capture/);
});

test('one-sample provider blocks generic repair before any second provider invocation', async () => {
  let calls = 0; const row = {};
  const model = d.oneSample({ async chat() { calls++; throw Error('original upstream failure'); } }, row);
  await assert.rejects(model.chat([]), /original upstream failure/);
  await assert.rejects(model.chat([]), { code: 'SECOND_SAMPLE_DENIED' });
  assert.equal(calls, 1); assert.equal(row.repairDenied, true);
});

test('physical budgets reserve failures, reject duplicates and stop after nine cases', async () => {
  let calls = 0;
  const wire = d.boundedTransport({ upstream: async () => { calls++; return mockResponse(); }, signal: new AbortController().signal });
  await wire.fetch('http://127.0.0.1:11434/api/tags');
  await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/tags'));
  for (let i = 0; i < 9; i++) {
    wire.begin(`case${i}`); await wire.fetch('http://127.0.0.1:11434/api/chat', chat());
    await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', chat())); wire.end();
  }
  wire.begin('tenth'); await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', chat()));
  assert.equal(calls, 10); assert.deepEqual(wire.accounting(), { metadata: 1, inference: 9, activeRequests: 0, unsettledResources: 0 });
  wire.end(); wire.admitAfterMetadata(); await wire.fetch('http://127.0.0.1:11434/api/tags');
  assert.equal(calls, 11); await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/tags'));
  assert.throws(() => wire.begin('after-identity'));
  assert(wire.calls.every(row => row.responseComplete && row.responseSha256 === d.sha(row.response)));
  await wire.close();
  await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', chat()));
});

test('transport rejects foreign URLs/model/request overflow without upstream work', async () => {
  let calls = 0;
  const wire = d.boundedTransport({ upstream: async () => { calls++; return mockResponse(); }, signal: new AbortController().signal });
  wire.begin('case');
  for (const url of ['http://example.com/api/chat', 'http://127.0.0.1:11434/api/generate',
    'http://127.0.0.1:11434/api/chat?x=1', 'http://u:p@127.0.0.1:11434/api/chat']) {
    await assert.rejects(wire.fetch(url, chat()));
  }
  await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', body: JSON.stringify({ model: 'other' }) }));
  await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', body: 'x'.repeat(d.LIMITS.requestBytes + 1) }));
  for (const [key, value] of [['num_ctx', 131072], ['num_predict', 9000], ['temperature', 1]]) {
    const request = JSON.parse(chat().body); request.options[key] = value;
    await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', body: JSON.stringify(request) }));
  }
  assert.equal(calls, 0); await wire.close();
});

test('incomplete upstream consumes its one reservation and retains bounded partial wire', async () => {
  let calls = 0;
  const wire = d.boundedTransport({ upstream: async () => { calls++; return mockResponse('unavailable', 503); }, signal: new AbortController().signal });
  wire.begin('failure'); await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', chat()), /upstream HTTP/);
  await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', chat()));
  assert.equal(calls, 1); assert.equal(wire.calls[0].response, 'unavailable');
  assert.equal(wire.calls[0].responseComplete, false); await wire.close();
});

test('cancellation aborts pending transport and cleanup waits for settlement', async () => {
  let capturedSignal;
  const lifetime = new AbortController();
  const wire = d.boundedTransport({ upstream: async (url, options) => {
    capturedSignal = options.signal;
    return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(Error('controlled cancellation')), { once: true }));
  }, signal: lifetime.signal });
  wire.begin('cancel');
  const work = wire.fetch('http://127.0.0.1:11434/api/chat', chat());
  const rejection = assert.rejects(work, error => error === lifetime.signal.reason);
  lifetime.abort(); await wire.close(); await rejection;
  assert.equal(capturedSignal.aborted, true); assert.equal(wire.accounting().activeRequests, 0);
  assert.equal(wire.calls[0].status, 'incomplete');
});

test('oversized response is cancelled with bounded retention and cannot be retried', async () => {
  const wire = d.boundedTransport({ upstream: async () => mockResponse('x'.repeat(d.LIMITS.responseBytes + 1)),
    signal: new AbortController().signal });
  wire.begin('overflow'); await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', chat()), /exceeds diagnostic bound/);
  assert(wire.calls[0].responseBytes <= d.LIMITS.responseBytes);
  assert.equal(wire.calls[0].observedBytes, d.LIMITS.responseBytes + 1);
  await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat', chat())); await wire.close();
});

test('uncooperative headers or body/cancel cannot hold cleanup beyond its bounded wait', async () => {
  for (const phase of ['headers', 'body']) {
    const lifetime = new AbortController();
    const wire = d.boundedTransport({ signal: lifetime.signal, upstream: () => phase === 'headers'
      ? new Promise(() => {}) : Promise.resolve(new Response(new ReadableStream({
        pull() { return new Promise(() => {}); }, cancel() { return new Promise(() => {}); },
      }))) });
    wire.begin(phase);
    const work = wire.fetch('http://127.0.0.1:11434/api/chat', chat());
    const rejected = assert.rejects(work);
    await new Promise(resolve => setImmediate(resolve)); lifetime.abort();
    const start = Date.now(); await wire.close(); await rejected;
    assert(Date.now() - start < d.LIMITS.cleanupMs + 1500);
    assert(wire.accounting().unsettledResources > 0, 'Unsettled transport cannot claim clean settlement');
    assert.equal(wire.calls[0].status, 'incomplete');
  }
});

async function controlledCase(index, satisfied) {
  const item = d.declarations(controlledRetained())[index];
  const row = { input: item.input, expected: item.expected, repairDenied: false };
  let sent;
  const evidence = item.evidence.find(entry => item.input.rubric.criteria[0].evidenceIds.includes(entry.id));
  const quote = typeof evidence.content === 'string' ? evidence.content : evidence.content.observation;
  const response = JSON.stringify({ satisfied, ...(index >= 7 ? { evidenceRefs: satisfied ? [evidence.id] : [] } : {}),
    citations: satisfied ? [{ evidenceId: evidence.id, quote }] : [] });
  const judge = createObjectiveJudge({ model: { async chat(input, tools, options) {
    sent = { model: d.MODEL, messages: input, format: options.format };
    return { provider: 'ollama', model: d.MODEL, mocked: false, fallback: false, response };
  } }, observeExecutionTranscript: value => { row.transcript = value; } });
  row.result = await judge(item.input);
  const request = JSON.stringify(sent);
  const raw = JSON.stringify({ model: d.MODEL, done: true, message: { role: 'assistant', content: response } });
  const wire = [{ status: 'returned', httpStatus: 200, responseComplete: true,
    request, requestSha256: d.sha(request), response: raw, responseSha256: d.sha(raw) }];
  return { row, wire };
}

test('original physical/transcript joins preserve actual negative verdict and semantic mismatch', async () => {
  const { row, wire } = await controlledCase(0, false);
  d.verifyCase(row, wire);
  assert.equal(row.technicalComplete, true); assert.equal(row.result.verdict, 'fail');
  assert.equal(row.semanticMatch, false);
  for (const change of [
    x => { x.wire[0].requestSha256 = '0'.repeat(64); },
    x => { x.wire[0].responseComplete = false; },
    x => { x.row.transcript.calls[0].response = 'changed'; },
    x => { x.row.input.evidence[1].content += 'tampered'; },
  ]) {
    const copy = structuredClone({ row, wire }); change(copy); assert.throws(() => d.verifyCase(copy.row, copy.wire));
  }
});

test('positive and negative execution controls use original criterion independently', async () => {
  for (const [index, satisfied] of [[7, true], [8, false]]) {
    const { row, wire } = await controlledCase(index, satisfied);
    d.verifyCase(row, wire); assert.equal(row.semanticMatch, true);
    assert.equal(row.result.criteria[0].id, 'final_response_browser_execution');
  }
});

test('full controlled execute preserves nine-case semantics, failed evidence and exact global cleanup', async t => {
  for (const variant of ['accepted', 'semantic-negative', 'invalid-output', 'identity-changed', 'integrity-unavailable']) {
    const directory = ownedDirectory(t), output = path.join(directory, 'result.json');
    const retained = controlledRetained(), cases = d.declarations(retained);
    // Explicit test seams; these supplied records do not claim original model/browser provenance.
    const pins = { controlled: 'test-only' }, manifest = { sourcePins: pins,
      sourceSha256: d.sha(JSON.stringify(pins)), retainedCapture: 'controlled-not-original' };
    let inferences = 0, metadata = 0;
    const beforeFetch = global.fetch, beforeInt = process.listenerCount('SIGINT'),
      beforeTerm = process.listenerCount('SIGTERM');
    const state = await d.execute({ output, manifest, retained, cases }, {
      upstream: async (url, options) => {
        if (new URL(url).pathname === '/api/tags') {
          metadata++;
          return mockResponse(JSON.stringify({ models: [{ name: d.MODEL,
            digest: variant === 'identity-changed' && metadata === 2 ? 'changed' : d.MODEL_SHA }] }));
        }
        const item = cases[inferences++];
        assert(item); assert.equal(options.redirect, 'error'); assert(options.signal);
        const evidence = item.evidence.find(row => item.input.rubric.criteria[0].evidenceIds.includes(row.id));
        let satisfied = item.expected === 'pass';
        if (variant === 'semantic-negative' && inferences === 1) satisfied = false;
        const quote = typeof evidence.content === 'string'
          ? evidence.content : evidence.content.observation;
        const content = variant === 'invalid-output' && inferences === 1 ? 'invalid controlled JSON'
          : JSON.stringify({ satisfied, ...(item.criterion === 1 ? { evidenceRefs: satisfied ? [evidence.id] : [] } : {}),
            citations: satisfied ? [{ evidenceId: evidence.id, quote }] : [] });
        return mockResponse(JSON.stringify({ model: d.MODEL, done: true,
          message: { role: 'assistant', content } }));
      },
      makeModel: () => ({ provider: 'ollama', model: d.MODEL, async chat(messages, tools, options) {
        const raw = await (await global.fetch('http://127.0.0.1:11434/api/chat', {
          method: 'POST', body: JSON.stringify({ model: d.MODEL, stream: true,
            messages, format: options.format, options: { num_ctx: options.num_ctx,
              num_predict: options.num_predict, temperature: options.temperature } }),
          signal: options.signal,
        })).text();
        return { provider: 'ollama', model: d.MODEL, mocked: false, fallback: false,
          response: d.originalText(raw) };
      } }),
      checkIntegrity: () => {
        if (variant === 'integrity-unavailable') throw Object.assign(Error('controlled retained stat failure'), { code: 'ENOENT' });
        return { sourceAfter: pins, sourceAfterSha256: manifest.sourceSha256, retainedUnchanged: true };
      },
    });
    assert.equal(global.fetch, beforeFetch);
    assert.equal(process.listenerCount('SIGINT'), beforeInt);
    assert.equal(process.listenerCount('SIGTERM'), beforeTerm);
    assert.equal(state.actorCalls, 0); assert.equal(state.browserLaunches, 0);
    assert.equal(state.databaseConnections, 0); assert.equal(state.qualification, false);
    assert.equal(state.creditAuthorized, false); assert.equal(state.automaticPromotion, false);
    assert.equal(state.accounting.metadata, 2); assert(state.accounting.inference <= 9);
    assert.equal(state.cleanup.activeRequests, 0); assert.equal(state.cleanup.unsettledResources, 0);
    assert.equal(state.cleanup.pendingCalls, 0); assert.equal(state.cleanup.fetchRestored, true);
    assert.deepEqual(JSON.parse(fs.readFileSync(output)), state);
    assert.deepEqual(fs.readdirSync(directory), ['result.json']);
    if (variant === 'accepted') {
      assert.equal(inferences, 9); assert.equal(state.semanticAccepted, true);
      assert.equal(state.status, 'semantic-accepted-calibration-only');
    } else if (variant === 'semantic-negative') {
      assert.equal(inferences, 9); assert.equal(state.semanticAccepted, false);
      assert.equal(state.technicalComplete, true); assert.equal(state.status, 'semantic-mismatch');
      assert.equal(state.cases[0].result.verdict, 'fail');
    } else {
      assert.equal(state.status, 'incomplete'); assert.equal(state.semanticAccepted, false);
      if (variant === 'invalid-output') {
        assert.equal(state.cases[0].repairDenied, true);
        assert.equal(state.calls.filter(call => call.caseId === cases[0].id).length, 1);
      }
      if (variant === 'integrity-unavailable') assert.equal(state.integrityError.code, 'ENOENT');
    }
  }
});
