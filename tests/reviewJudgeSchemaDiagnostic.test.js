'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const diagnostic = require('./fixtures/reviewJudgeSchemaDiagnostic');

function controlledProvider() {
  const requests = [];
  return Object.freeze({ requests, async chat(messages, tools, options) {
    requests.push({ messages, tools, options });
    return { provider: 'controlled', model: 'schema-diagnostic-fixture',
      response: JSON.stringify({ satisfied: false, evidenceRefs: [], citations: [] }),
      metadata: { eval_count: 1 } };
  } });
}

test('schema diagnostic matrix is exactly two cases by two criteria by two arms by two repeats', async () => {
  const provider = controlledProvider();
  const output = await diagnostic.runSchemaDiagnostic({ provider });
  assert.equal(output.cells.length, 8);
  assert.equal(provider.requests.length, 16);
  assert.deepEqual([...new Set(output.cells.map(row => row.caseId))], diagnostic.CASE_IDS);
  assert.deepEqual([...new Set(output.cells.map(row => row.arm))], diagnostic.ARMS);
  assert.deepEqual([...new Set(output.cells.map(row => row.repeat))], [1, 2]);
  assert.ok(output.cells.every(row => row.calls.length === 2));
});

test('flat arm changes only format while production messages and model options stay identical', async () => {
  const provider = controlledProvider();
  await diagnostic.runSchemaDiagnostic({ provider });
  for (let index = 0; index < provider.requests.length; index += 4) {
    for (let criterion = 0; criterion < 2; criterion += 1) {
      const current = provider.requests[index + criterion];
      const flat = provider.requests[index + 2 + criterion];
      assert.deepEqual(current.messages, flat.messages);
      assert.deepEqual(current.tools, flat.tools);
      assert.deepEqual({ ...current.options, format: undefined },
        { ...flat.options, format: undefined });
      assert.deepEqual(current.options.format.anyOf.map(branch =>
        branch.properties.satisfied.const), [true, false]);
      assert.equal(flat.options.format.type, 'object');
      assert.deepEqual(flat.options.format.properties.satisfied, { type: 'boolean' });
      assert.equal(Object.hasOwn(flat.options.format, 'anyOf'), false);
    }
  }
});

test('diagnostic retains every bounded raw response before semantic comparison', async () => {
  const provider = controlledProvider();
  const recorded = [];
  await diagnostic.runSchemaDiagnostic({ provider,
    recordCell: async cell => recorded.push(cell) });
  assert.equal(recorded.length, diagnostic.EXPECTED_CELLS);
  assert.ok(recorded.every(cell => cell.calls.every(call =>
    call.rawResponse === '{"satisfied":false,"evidenceRefs":[],"citations":[]}'
      && /^[0-9a-f]{64}$/.test(call.rawResponseSha256)
      && /^[0-9a-f]{64}$/.test(call.diagnosticRequestSha256)
      && call.rawResponseBytes > 0 && call.parsedResponse.satisfied === false)));
});

test('a repair attempt is blocked before an extra provider call', async () => {
  let calls = 0;
  const provider = Object.freeze({ async chat() {
    calls += 1;
    return { provider: 'controlled', model: 'schema-diagnostic-fixture',
      response: '{"invalid":true}', metadata: { eval_count: 1 } };
  } });
  await assert.rejects(diagnostic.runSchemaDiagnostic({ provider }), /call missing/);
  assert.ok(calls <= diagnostic.MAX_PROVIDER_CALLS);
});
