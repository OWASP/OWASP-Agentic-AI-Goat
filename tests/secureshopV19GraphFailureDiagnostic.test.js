'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createV19GraphFailureDiagnostic, errorChain } = require('./fixtures/secureshopV19GraphFailureDiagnostic');

test('V19 diagnostic forwards success and restores the exact factory', async () => {
  const graph = Object.freeze({ purpose: 'test', async run(value) { return value; } });
  const original = () => graph, module = { createBoundFileSummaryGraph: original }, records = [];
  const diagnostic = createV19GraphFailureDiagnostic({ graphModule: module, workspace: '/workspace', record: value => records.push(value) });
  const wrapped = module.createBoundFileSummaryGraph({});
  assert.notEqual(wrapped, graph); assert.deepEqual(await wrapped.run({ ok: true }), { ok: true });
  assert.deepEqual(records, []); assert.deepEqual(diagnostic.state(), { restored: false, factoryCalls: 1, failures: 0, captureFailure: null });
  assert.deepEqual(diagnostic.restore(), { factoryCalls: 1, failures: 0, captureFailure: null });
  assert.equal(module.createBoundFileSummaryGraph, original);
  assert.deepEqual(diagnostic.restore(), { factoryCalls: 1, failures: 0, captureFailure: null });
});

test('V19 diagnostic records bounded projected failure and rethrows identical error', async () => {
  const cause = Object.assign(new Error('/workspace/private token=abc'), { code: '23505', constraint: 'owned_row_key' });
  const failure = Object.assign(new TypeError('Failed 123e4567-e89b-42d3-a456-426614174000'), { code: 'FILE_SUMMARY_AUTHORITY', cause });
  const original = () => Object.freeze({ async run() { throw failure; } });
  const module = { createBoundFileSummaryGraph: original }, records = [];
  const diagnostic = createV19GraphFailureDiagnostic({ graphModule: module, workspace: '/workspace', record: value => records.push(value) });
  const wrapped = module.createBoundFileSummaryGraph({});
  await assert.rejects(wrapped.run({}), error => error === failure);
  assert.equal(records.length, 1); assert.deepEqual(Object.keys(records[0]).sort(),
    ['chain', 'errorCode', 'errorName', 'failureCategory', 'phase', 'version']);
  assert.equal(records[0].phase, 'route'); assert.equal(records[0].errorCode, 'UNCLASSIFIED');
  assert.equal(records[0].chain[0].code, 'FILE_SUMMARY_AUTHORITY');
  assert.equal(records[0].chain[0].message, 'Failed [uuid]');
  assert.equal(records[0].chain[1].message.includes('/workspace'), false);
  assert.equal(records[0].chain[1].message.includes('abc'), false);
  assert.ok(Buffer.byteLength(JSON.stringify(records[0])) < 8192);
  assert.deepEqual(diagnostic.restore(), { factoryCalls: 1, failures: 1, captureFailure: null });
});

test('V19 diagnostic never masks the original when private capture fails', async () => {
  const failure = Object.assign(new Error('original graph failure'), { code: 'FILE_SUMMARY_AUTHORITY' });
  const capture = Object.assign(new Error('private evidence write failed'), { code: 'EVIDENCE_WRITE_FAILED' });
  const original = () => Object.freeze({ async run() { throw failure; } });
  const module = { createBoundFileSummaryGraph: original };
  const diagnostic = createV19GraphFailureDiagnostic({ graphModule: module, workspace: '/workspace',
    record() { throw capture; } });
  await assert.rejects(module.createBoundFileSummaryGraph({}).run({}), error => error === failure);
  const state = diagnostic.state();
  assert.equal(state.failures, 1); assert.equal(state.captureFailure.chain[0].code, 'EVIDENCE_WRITE_FAILED');
  assert.equal(state.captureFailure.chain[0].message, 'private evidence write failed');
  diagnostic.restore();
});

test('V19 diagnostic rejects ambiguous reuse and bounds cause chains', async () => {
  const original = () => Object.freeze({ async run() {} }), module = { createBoundFileSummaryGraph: original };
  const diagnostic = createV19GraphFailureDiagnostic({ graphModule: module, workspace: '/workspace', record() {} });
  module.createBoundFileSummaryGraph({}); assert.throws(() => module.createBoundFileSummaryGraph({}), /factory unavailable/);
  diagnostic.restore();
  let error = null; for (let index = 0; index < 9; index++) error = Object.assign(new Error(`error-${index}`), { cause: error });
  assert.equal(errorChain(error, '/workspace').length, 4);
});
