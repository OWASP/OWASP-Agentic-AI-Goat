'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSqlNoSqlModelProvenance } = require('./fixtures/sqlNoSqlModelProvenance');
const MODEL = 'llama3.1:8b';
const URL = 'http://127.0.0.1:11434/api/chat';
const decision = { tool: 'search_products', params: { searchTerm: "%' UNION SELECT secret" } };
const opts = () => ({ method: 'POST', body: JSON.stringify({ model: MODEL, messages: [] }) });
const frame = (text, done = true) => ({ model: MODEL, message: { content: text }, done });

test('exact full streamed selection is scoped and public evidence contains no raw bytes', async () => {
  const text = JSON.stringify(decision);
  const helper = createSqlNoSqlModelProvenance({ fetchImpl: async () => new Response(JSON.stringify(frame(text.slice(0, 10), false)) + '\n' + JSON.stringify(frame(text.slice(10)))) });
  await helper.withScope('sqli_5_positive', () => helper.fetch(URL, opts()));
  assert.equal(helper.exactDecision('sqli_5_positive', decision), true);
  assert.equal(helper.exactDecision('sqli_5_positive', { ...decision, params: { searchTerm: '%' } }), false);
  assert.equal(helper.exactDecision('sqli_5_positive', { ...decision, params: { ...decision.params, extra: true } }), false);
  const report = helper.publicCalls('sqli_5_positive');
  assert.equal(report[0].qualified, true); assert.equal(report[0].outputBytes, Buffer.byteLength(text));
  assert.equal(JSON.stringify(report).includes('secret'), false);
  assert.deepEqual(Object.keys(report[0]).sort(), ['provider','model','endpoint','qualified','failureCode','httpStatus','requestSha256','requestBytes','responseSha256','responseBytes','outputSha256','outputBytes'].sort());
  await assert.rejects(helper.withScope('sqli_5_positive', async () => {}), /unique serial/);
});

test('pre-dispatch call budget rejects before transport and preserves exact bound', async () => {
  let calls = 0;
  const helper = createSqlNoSqlModelProvenance({ maxCallsPerScope: 1, maxCallsTotal: 2,
    fetchImpl: async () => { calls += 1; return new Response(JSON.stringify(frame(JSON.stringify(decision)))); } });
  await helper.withScope('bounded', async () => {
    await helper.fetch(URL, opts());
    await assert.rejects(helper.fetch(URL, opts()), /CALL_BUDGET_EXCEEDED/);
  });
  assert.equal(calls, 1, 'budget rejection occurs before provider transport');
  assert.equal(helper.publicCalls('bounded').length, 1);
  assert.equal(helper.totalCalls(), 1);
});

test('Request-body admission reserves synchronously across parallel reads', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let calls = 0;
  const body = () => new ReadableStream({
    start(controller) {
      gate.then(() => {
        controller.enqueue(new TextEncoder().encode(JSON.stringify({ model: MODEL, messages: [] })));
        controller.close();
      });
    },
  });
  const helper = createSqlNoSqlModelProvenance({ maxCallsPerScope: 1, maxCallsTotal: 2,
    fetchImpl: async () => { calls++; return new Response(JSON.stringify(frame(JSON.stringify(decision)))); } });
  await helper.withScope('parallel_request_budget', async () => {
    const first = helper.fetch(new Request(URL, { method: 'POST', body: body(), duplex: 'half' }));
    await assert.rejects(
      helper.fetch(new Request(URL, { method: 'POST', body: body(), duplex: 'half' })),
      /CALL_BUDGET_EXCEEDED/,
    );
    release();
    await first;
  });
  assert.equal(calls, 1);
  assert.equal(helper.publicCalls('parallel_request_budget').length, 1);
});

test('scope closure during Request-body admission prevents stale dispatch', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let calls = 0;
  const request = new Request(URL, {
    method: 'POST',
    body: new ReadableStream({
      start(controller) {
        gate.then(() => {
          controller.enqueue(new TextEncoder().encode(JSON.stringify({ model: MODEL, messages: [] })));
          controller.close();
        });
      },
    }),
    duplex: 'half',
  });
  const helper = createSqlNoSqlModelProvenance({
    fetchImpl: async () => { calls++; return new Response(JSON.stringify(frame(JSON.stringify(decision)))); },
  });
  let pending;
  await helper.withScope('closed_during_request_read', async () => {
    pending = helper.fetch(request);
  });
  release();
  await assert.rejects(pending, /PROVENANCE_SCOPE_CLOSED/);
  assert.equal(calls, 0);
  const callsReport = helper.publicCalls('closed_during_request_read');
  assert.equal(callsReport.length, 1);
  assert.equal(callsReport[0].failureCode, 'SCOPE_CLOSED_WITH_PENDING_CALLS');
});

test('nonstream generation and Request input are captured', async () => {
  const helper = createSqlNoSqlModelProvenance({ fetchImpl: async () => new Response(JSON.stringify({ model: MODEL, response: JSON.stringify(decision), done: true })) });
  await helper.withScope('generate', () => helper.fetch(new Request('http://127.0.0.1:11434/api/generate', opts())));
  assert.equal(helper.exactDecision('generate', decision), true);
});

test('HTTP failure, wrong model, malformed, empty and truncated streams never prove selection', async () => {
  for (const [name, body, status] of [
    ['http', JSON.stringify(frame(JSON.stringify(decision))), 500],
    ['wrong', JSON.stringify({ ...frame(JSON.stringify(decision)), model: 'other' }), 200],
    ['missing_model', JSON.stringify({ message: { content: JSON.stringify(decision) }, done: true }), 200],
    ['truncated', JSON.stringify(frame(JSON.stringify(decision), false)), 200],
    ['malformed', JSON.stringify(frame(JSON.stringify(decision), false)) + '\n{', 200],
    ['extra_done', JSON.stringify(frame(JSON.stringify(decision))) + '\n' + JSON.stringify(frame('')), 200],
    ['empty', JSON.stringify(frame('')), 200],
  ]) {
    const helper = createSqlNoSqlModelProvenance({ fetchImpl: async () => new Response(body, { status }) });
    await helper.withScope(name, () => helper.fetch(URL, opts()));
    assert.equal(helper.exactDecision(name, decision), false, name);
    assert.equal(helper.publicCalls(name)[0].qualified, false, name);
  }
});

test('wrong request model, abort, endpoint and unscoped requests fail closed', async () => {
  let calls = 0;
  const helper = createSqlNoSqlModelProvenance({ fetchImpl: async () => { calls++; return new Response(JSON.stringify(frame(JSON.stringify(decision)))); } });
  await assert.rejects(helper.fetch(URL, opts()), /SCOPE_REQUIRED/);
  let endpointIndex = 0;
  for (const target of ['https://127.0.0.1:11434/api/chat', 'http://localhost:11434/api/chat', 'http://127.0.0.1:11434/api/tags', URL + '?extra=1']) {
    await assert.rejects(helper.withScope('endpoint_' + endpointIndex++, () => helper.fetch(target, opts())), /ENDPOINT_REJECTED/);
  }
  await assert.rejects(helper.withScope('wrong_model', () => helper.fetch(URL, { ...opts(), body: '{"model":"other"}' })), /REQUEST_MODEL_REJECTED/);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(helper.withScope('aborted', () => helper.fetch(URL, { ...opts(), signal: controller.signal })), /ABORTED/);
  assert.equal(helper.exactDecision('aborted', decision), false); assert.equal(calls, 0);
});

test('explicit mounted HTTP is passed through without being model evidence', async () => {
  const helper = createSqlNoSqlModelProvenance({ mountedHttpOrigin: 'http://127.0.0.1:32123', fetchImpl: async () => new Response('{}') });
  await helper.withScope('route', () => helper.fetch('http://127.0.0.1:32123/api/workshop/sql/chat', opts()));
  assert.deepEqual(helper.publicCalls('route'), []);
  assert.throws(() => createSqlNoSqlModelProvenance({ mountedHttpOrigin: 'http://example.com:32123', fetchImpl: async () => {} }), /loopback/);
});

test('late abort and transport errors cannot qualify provider output', async () => {
  const controller = new AbortController();
  const helper = createSqlNoSqlModelProvenance({ fetchImpl: async () => {
    controller.abort(); return new Response(JSON.stringify(frame(JSON.stringify(decision))));
  } });
  await assert.rejects(helper.withScope('late_abort', () => helper.fetch(URL, { ...opts(), signal: controller.signal })));
  assert.equal(helper.publicCalls('late_abort')[0].qualified, false);
  assert.equal(helper.publicCalls('late_abort')[0].failureCode, 'PROVENANCE_ABORTED');
  const broken = createSqlNoSqlModelProvenance({ fetchImpl: async () => { throw Error('private transport error'); } });
  await assert.rejects(broken.withScope('transport', () => broken.fetch(URL, opts())));
  assert.equal(broken.publicCalls('transport')[0].qualified, false);
  assert.equal(JSON.stringify(broken.publicCalls('transport')).includes('private'), false);
});

test('private copies expose complete bytes without permitting mutation of proof', async () => {
  const response = JSON.stringify(frame(JSON.stringify(decision)), null, 2);
  const helper = createSqlNoSqlModelProvenance({ fetchImpl: async () => new Response(response) });
  await helper.withScope('private_copy', () => helper.fetch(URL, opts()));
  const copied = helper.getPrivateCalls('private_copy')[0];
  assert.equal(copied.response, response); assert.deepEqual(JSON.parse(copied.text), decision);
  assert.throws(() => { copied.qualified = false; }, TypeError);
  assert.equal(helper.exactDecision('private_copy', decision), true);
});

test('scope closes fail-closed for detached model calls and refuses concurrent scopes', async () => {
  let release;
  const barrier = new Promise(resolve => { release = resolve; });
  const helper = createSqlNoSqlModelProvenance({ fetchImpl: async () => { await barrier; return new Response(JSON.stringify(frame(JSON.stringify(decision)))); } });
  let pending;
  await helper.withScope('detached', async () => {
    await assert.rejects(helper.withScope('concurrent', async () => {}), /unique serial/);
    pending = helper.fetch(URL, opts());
  });
  assert.throws(() => helper.publicCalls('detached'), /NOT_COMPLETE/);
  release(); await pending;
  assert.equal(helper.publicCalls('detached')[0].qualified, false);
  assert.equal(helper.publicCalls('detached')[0].failureCode, 'SCOPE_CLOSED_WITH_PENDING_CALLS');
});

test('Judge-shaped output remains distinct from exact actor selection and other scopes', async () => {
  let output = JSON.stringify(decision);
  const helper = createSqlNoSqlModelProvenance({ fetchImpl: async () => new Response(JSON.stringify(frame(output))) });
  await helper.withScope('positive', () => helper.fetch(URL, opts()));
  output = JSON.stringify({ verdict: 'pass', objectiveId: 'sqli_5' });
  await helper.withScope('judge_only', () => helper.fetch(URL, opts()));
  assert.equal(helper.publicCalls('judge_only')[0].qualified, true);
  assert.equal(helper.exactDecision('judge_only', decision), false);
  assert.equal(helper.exactDecision('positive', decision), true);
});

test('model fetch forbids redirect following and rejects redirected or mismatched responses', async () => {
  for (const [name, properties] of [
    ['redirected', { redirected: true }],
    ['different_origin', { url: 'http://127.0.0.1:9999/api/chat' }],
    ['different_path', { url: 'http://127.0.0.1:11434/api/generate' }],
  ]) {
    const helper = createSqlNoSqlModelProvenance({ fetchImpl: async (_input, options) => {
      assert.equal(options.redirect, 'error');
      const response = new Response(JSON.stringify(frame(JSON.stringify(decision))));
      for (const [key, value] of Object.entries(properties)) Object.defineProperty(response, key, { value });
      return response;
    } });
    await helper.withScope(name, () => helper.fetch(URL, { ...opts(), redirect: 'follow' }));
    assert.equal(helper.exactDecision(name, decision), false);
    assert.equal(helper.publicCalls(name)[0].failureCode, 'PROVENANCE_RESPONSE_ENDPOINT_REJECTED');
  }
});
