'use strict';

// This is an opt-in, offline binder regression over a retained owned capture.
// It rearranges saved effect/support responses in memory to exercise the
// source-only branch; it is not evidence of a second actual model run.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { bindAuditContinuation } = require('./fixtures/secureshopMailRenderedQualification');

const evidence = process.env.AUDIT_RETAINED_CONTINUATION_EVIDENCE;
test('source-only continuation binder joins recovered effect and support to the original packet',
  { skip: !evidence && 'Requires an explicitly supplied retained owned capture' }, async () => {
    const retained = JSON.parse(fs.readFileSync(path.join(evidence, 'audit-instruction-captures.json')));
    const wire = JSON.parse(fs.readFileSync(path.join(evidence, 'wire.json')));
    assert.deepEqual(retained.cases.map(row => row.name), ['benign', 'injected']);
    const original = wire.calls.filter(row => row.caseId === 'injected' && row.role === 'judge');
    const recovered = wire.calls.filter(row => row.caseId === 'recovery' && row.role === 'judge');
    assert.equal(original.length, 3);
    assert.equal(recovered.length, 1);
    assert.equal(original[1].status, 'returned');
    assert.equal(original[2].status, 'incomplete');
    const effect = original[1], interrupted = original[2];
    const effectPosition = wire.calls.findIndex(row => row.index === effect.index);
    const interruptedPosition = wire.calls.findIndex(row => row.index === interrupted.index);
    wire.calls[effectPosition] = {
      ...interrupted, index: effect.index,
      request: effect.request, requestSha256: effect.requestSha256,
    };
    wire.calls[interruptedPosition] = {
      ...effect, index: interrupted.index, caseId: 'recovery',
    };
    wire.originalFailure.index = effect.index;
    wire.phaseCounts.injected.judge = 2;
    wire.phaseCounts.recovery.judge = 2;
    retained.recovery.effectCheckpointSha256 = null;
    retained.recovery.after.checkpoints = retained.recovery.after.checkpoints.filter(row =>
      row.evaluation_id !== retained.recovery.parentEvaluationId || row.stage !== 'effect');
    const child = retained.recovery.after.judgments.find(row =>
      row.evaluation_id === retained.recovery.retry.body.judgment.evaluationId);
    assert(child);
    child.result_json.auditContinuation.checkpoints =
      child.result_json.auditContinuation.checkpoints.filter(row => row.stage !== 'effect');
    child.result_json.comparisonStages.find(row => row.stage === 'effect').attempts = 1;
    const bound = await bindAuditContinuation(retained, wire);
    assert.equal(bound.genuineCredit, 1);
    const forged = structuredClone(wire);
    forged.calls.find(row => row.caseId === 'recovery' && row.role === 'judge').request = '{}';
    await assert.rejects(bindAuditContinuation(retained, forged));
  });
