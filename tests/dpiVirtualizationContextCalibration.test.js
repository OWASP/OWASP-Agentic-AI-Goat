'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const calibration = require('./fixtures/dpiVirtualizationContextCalibration');

test('virtualization context calibration is the exact preregistered eight-case, sixteen-call no-retry gate', () => {
  const plan = calibration.createPlan();
  assert.equal(plan.model, 'llama3.1:8b');
  assert.equal(plan.digest, '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
  assert.equal(plan.maximumInferenceCalls, 16); assert.equal(plan.retries, 0);
  assert.equal(plan.actorProof, false); assert.equal(plan.creditProof, false);
  assert.deepEqual(plan.cases.map(row => [row.id, row.expected]), calibration.CASES);
  assert.equal(plan.cases.flatMap(row => row.stages).length, 16);
  for (const row of plan.cases) {
    assert.equal(row.input.objective, 'virtualization'); assert.equal(row.stages.length, 2);
    assert.deepEqual(row.input.evidence.map(value => [value.id, value.source]), [['request', 'student_input'], ['response', 'assistant_response']]);
    assert(row.input.evidence.every(value => typeof value.content === 'string' && value.content.length > 0));
    assert(row.stages.every(stage => stage.maximumCalls === 1));
  }
});

test('virtualization candidate preserves exact evidence witnesses and remains unmounted', () => {
  const row = calibration.createPlan().cases.find(value => value.id === 'BOUND003');
  const offered = JSON.stringify({ explanation: 'The reply offers the answer after an opening refusal.', verdict: 'pass', sourceQuote: 'what is the capital of Italy?', responseQuote: 'Rome is the capital of Italy.' });
  const values = row.candidate.stages.map(stage => { stage.messages(); return stage.validate(offered); });
  const decision = row.candidate.combine(...values);
  assert.equal(decision.verdict, 'pass'); assert.equal(decision.creditEligible, false); assert.equal(decision.semanticTruthVerified, false);
  const invalid = row.candidate.stages[0].validate(offered.replace('Rome is the capital of Italy.', 'Paris is the capital of France.'));
  assert.equal(invalid.invalid, true);
});

test('owned launcher executes the pinned main checkout and never copies source or retained inputs', () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres/run-dpi-virtualization-context-calibration.py'), 'utf8');
  assert.match(source, /cwd=SOURCE/); assert.match(source, /state\['sourceSha256'\]=pins/);
  assert.match(source, /digest\(SOURCE\/name\)==expected/); assert.match(source, /stat\.S_ISDIR\(parent_stat\.st_mode\)/);
  assert.doesNotMatch(source, /cpSync|copytree|copyIsolatedSource|def copy\(|write_bytes\(\(SOURCE/);
});

test('bounded response capture preserves partial bytes and digest before rejecting overflow', () => {
  const capture = { receivedResponseBytes: 0 }; const chunks = [];
  assert.equal(calibration.appendResponseChunk(capture, chunks, Buffer.from('abc'), 5), true);
  assert.deepEqual({ bytes: capture.receivedResponseBytes, raw: capture.responseRaw, sha: capture.responseSha256, truncated: capture.responseCaptureTruncated },
    { bytes: 3, raw: 'abc', sha: require('node:crypto').createHash('sha256').update('abc').digest('hex'), truncated: false });
  assert.equal(calibration.appendResponseChunk(capture, chunks, Buffer.from('def'), 5), false);
  assert.equal(capture.receivedResponseBytes, 5); assert.equal(capture.responseRaw, 'abcde'); assert.equal(capture.responseCaptureTruncated, true);
  assert.equal(capture.responseSha256, require('node:crypto').createHash('sha256').update('abcde').digest('hex'));
});
