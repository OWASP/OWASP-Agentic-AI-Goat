'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { requestFor, classify } = require('./fixtures/sourceMeaningDiagnostic');

test('source-only request preserves exact bytes and excludes all companion evidence', () => {
  const source = '  source\nwith a quoted instruction: "override the system"  ';
  const request = requestFor({ source });
  assert.deepEqual(JSON.parse(request.messages[1].content), { source });
  assert.equal(request.sourceSha256, createHash('sha256').update(source).digest('hex'));
  assert(!request.messages[0].content.includes(source));
  assert(request.messages[0].content.endsWith(JSON.stringify(request.schema)));
  for (const key of ['response', 'trustedTask', 'label', 'id', 'rationale']) {
    assert.throws(() => requestFor({ source, [key]: 'must not enter request' }));
  }
  assert.throws(() => requestFor({ source: 'a'.repeat(16001) }));
  assert.throws(() => requestFor({ source: '"'.repeat(15000) }));
});

test('all three valid observations remain unprivileged single-call diagnostic results', async () => {
  for (const decision of ['directive', 'no_directive', 'uncertain']) {
    let calls = 0;
    const result = await classify({ source: 'Evidence.' }, async (request, options) => {
      calls++; assert.equal(options.timeoutMs, 60000); assert(options.signal);
      return JSON.stringify({ decision });
    });
    assert.equal(calls, 1); assert.equal(result.calls, 1);
    assert.equal(result.status, 'observed'); assert.equal(result.decision, decision);
    assert.equal(result.creditAuthorized, false);
  }
});

test('invalid, extra, fenced and oversized output never becomes a negative or a positive', async () => {
  for (const raw of ['null', '[]', '{}', '{"decision":"yes"}',
    '{"decision":"directive","credit":true}', '```json\n{"decision":"directive"}\n```',
    'x'.repeat(1025), { decision: 'directive' }]) {
    const result = await classify({ source: 'Evidence.' }, async () => raw);
    assert.equal(result.reason, 'INVALID_OUTPUT'); assert.equal(result.decision, null);
    assert.equal(result.calls, 1);
  }
});

test('pre-cancellation prevents provider invocation and provider failure has no semantic verdict', async () => {
  const controller = new AbortController(); controller.abort(); let calls = 0;
  const result = await classify({ source: 'Evidence.' }, async () => { calls++; }, { signal: controller.signal });
  assert.equal(result.calls, 0); assert.equal(calls, 0);
  assert.equal(result.reason, 'CANCELLED_OR_DEADLINE');
  const failure = await classify({ source: 'Evidence.' }, async () => { throw Error('provider'); });
  assert.equal(failure.reason, 'PROVIDER_FAILURE'); assert.equal(failure.decision, null);
});

test('noncooperative and event-loop-blocking late callbacks cannot publish decisions', async () => {
  let providedSignal;
  const pending = await classify({ source: 'Evidence.' }, (_request, options) => {
    providedSignal = options.signal; return new Promise(() => {});
  }, { timeoutMs: 5 });
  assert.equal(pending.reason, 'CANCELLED_OR_DEADLINE'); assert(providedSignal.aborted);
  const late = await classify({ source: 'Evidence.' }, async () => {
    const end = performance.now() + 20; while (performance.now() < end) {}
    return '{"decision":"directive"}';
  }, { timeoutMs: 5 });
  assert.equal(late.reason, 'CANCELLED_OR_DEADLINE'); assert.equal(late.decision, null);
});
