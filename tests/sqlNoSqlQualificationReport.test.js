'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { OBJECTIVE_IDS, createSqlNoSqlQualificationReport: create } = require('./fixtures/sqlNoSqlQualificationReport');
const call = () => ({ provider: 'ollama', model: 'llama3.1:8b', endpoint: '/api/chat', qualified: true, failureCode: null,
  httpStatus: 200, requestSha256: 'a'.repeat(64), requestBytes: 20, responseSha256: 'b'.repeat(64), responseBytes: 40, outputSha256: 'c'.repeat(64), outputBytes: 10 });

test('all twenty selected objectives remain represented; pending or failed cannot qualify', () => {
  const report = create({ selectedIds: [...OBJECTIVE_IDS].reverse() });
  assert.deepEqual(report.snapshot().selectedIds, OBJECTIVE_IDS);
  assert.equal(report.snapshot().scope, 'aria_nova_objective_cases');
  assert.equal(report.snapshot().partial, false); assert.equal(report.snapshot().cases.length, 20);
  for (const id of OBJECTIVE_IDS.slice(0,-1)) report.finalize(id, { status: 'pass', durationMs: 3 });
  assert.equal(report.snapshot().qualification, 'incomplete');
  assert.equal(report.snapshot().cases.at(-1).status, 'pending');
  report.finalize(OBJECTIVE_IDS.at(-1), { status: 'fail', durationMs: 9, failureStage: 'negative_judge', failureCode: 'ASSERTION_FAILED' });
  assert.equal(report.snapshot().qualification, 'incomplete');
  assert.throws(() => report.finalize(OBJECTIVE_IDS.at(-1), { status: 'pass', durationMs: 1 }), /pending/);
});

test('all-pass complete selection qualifies; an all-pass subset is explicitly partial', () => {
  for (const ids of [OBJECTIVE_IDS, ['sqli_1']]) {
    const report = create({ selectedIds: ids });
    for (const id of ids) report.finalize(id, { status: 'pass', durationMs: 0, calls: [call()] });
    assert.equal(report.snapshot().partial, ids.length !== 20);
    assert.equal(report.snapshot().qualification, ids.length === 20 ? 'qualified' : 'incomplete');
    assert.throws(() => { report.snapshot().cases[0].calls[0].model = 'other'; }, TypeError);
  }
});

test('unknown/duplicate IDs, skipped states, raw diagnostics and malformed provenance rejected', () => {
  for (const ids of [[], ['unknown'], ['sqli_1','sqli_1']]) assert.throws(() => create({ selectedIds: ids }));
  const report = create({ selectedIds: ['sqli_1'] });
  assert.throws(() => report.finalize('sqli_2', { status: 'pass', durationMs: 1 }));
  for (const result of [
    { status: 'skipped', durationMs: 0 }, { status: 'pass', durationMs: -1 },
    { status: 'pass', durationMs: 0, message: 'private' },
    { status: 'fail', durationMs: 1, failureStage: 'private', failureCode: 'EXECUTION_FAILED' },
    { status: 'fail', durationMs: 1, failureStage: 'positive', failureCode: 'private' },
    { status: 'pass', durationMs: 0, failureStage: 'positive' },
    ...[{ raw: 'private' }, { requestSha256: 'short' }, { requestBytes: true }, { outputBytes: 0 }, { model: 'other' }, { failureCode: 'private' }, { httpStatus: 500 }]
      .map(patch => ({ status: 'pass', durationMs: 1, calls: [{ ...call(), ...patch }] })),
  ]) assert.throws(() => report.finalize('sqli_1', result));
  assert.equal(report.snapshot().cases[0].status, 'pending');
});
