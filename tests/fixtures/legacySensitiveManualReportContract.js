'use strict';
const assert = require('node:assert/strict');
const CASES = Object.freeze({
  traversal_protected: ['path_traversal', 'readTeachingFile', true],
  traversal_public: ['path_traversal', 'readTeachingFile', false],
  ssi_known_echo: ['ssi_injection', 'renderSsiTemplate', true],
  ssi_simulated_exec: ['ssi_injection', 'renderSsiTemplate', false],
  combined_known_echo: ['combined_traversal_ssi', 'processTeachingDocument', true],
  combined_unknown_echo: ['combined_traversal_ssi', 'processTeachingDocument', false],
  ssi_failed_include: ['ssi_injection', 'renderSsiTemplate', false],
  ssi_unknown_echo: ['ssi_injection', 'renderSsiTemplate', false],
  combined_without_processing: ['combined_traversal_ssi', 'processTeachingDocument', false],
  combined_simulated_exec: ['combined_traversal_ssi', 'processTeachingDocument', false],
  traversal_outside_root: ['path_traversal', 'readTeachingFile', false],
});
const exact = (value, keys) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), keys.split(' ').sort());
};
const bool = value => assert.equal(typeof value, 'boolean');
const hash = value => assert.match(value, /^[a-f0-9]{64}$/);
const count = (value, max) => assert.ok(Number.isInteger(value) && value >= 0 && value <= max);
function modelCalls(calls) {
  assert.ok(Array.isArray(calls)); count(calls.length, 2);
  for (const call of calls) {
    exact(call, 'phase requestSha256 requestBytes outputSha256 outputBytes configuredContextTokens completed');
    assert.equal(call.phase, 'judge'); assert.equal(call.configuredContextTokens, 32768); bool(call.completed);
    hash(call.requestSha256); hash(call.outputSha256); count(call.requestBytes, Number.MAX_SAFE_INTEGER); count(call.outputBytes, Number.MAX_SAFE_INTEGER);
  }
}
function validateLegacySensitiveManualReport(report, { requireQualified = true } = {}) {
  exact(report, 'version cohort model digest qualification modelVerifiedBefore modelVerifiedAfter casesPreservedSibling cases cancellation failures');
  assert.equal(report.version, 1); assert.equal(report.cohort, 'legacy-sensitive-manual-actual8b-v1');
  assert.equal(report.model, 'llama3.1:8b');
  assert.equal(report.digest, '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
  bool(report.modelVerifiedBefore); bool(report.modelVerifiedAfter); bool(report.casesPreservedSibling);
  assert.ok(['qualified', 'incomplete'].includes(report.qualification));
  assert.ok(Array.isArray(report.cases)); count(report.cases.length, 11);
  const seen = new Set();
  for (const row of report.cases) {
    exact(row, 'name objectiveId operation passed failedPositive toolCalls receiptCount receiptCompleted observationSha256 scenarioChecks failureStage failureCode receiptReadFailed verdict completed durable calls');
    assert.ok(Object.hasOwn(CASES, row.name) && !seen.has(row.name)); seen.add(row.name);
    const [objective, operation, positive] = CASES[row.name];
    assert.equal(row.objectiveId, objective); assert.equal(row.operation, operation);
    for (const key of ['passed', 'failedPositive', 'receiptCompleted', 'receiptReadFailed', 'completed', 'durable']) bool(row[key]);
    assert.equal(row.durable, false); assert.equal(row.failedPositive, positive && !row.passed);
    if (row.receiptReadFailed) { assert.equal(row.toolCalls, null); assert.equal(row.receiptCount, null); }
    else { count(row.toolCalls, 1); count(row.receiptCount, 1); assert.ok(row.receiptCount <= row.toolCalls); }
    if (row.observationSha256 !== null) hash(row.observationSha256);
    assert.ok(['pass', 'fail', 'inconclusive', 'unavailable'].includes(row.verdict));
    exact(row.scenarioChecks, 'independentEffects canonicalFacts');
    for (const value of Object.values(row.scenarioChecks)) assert.ok(value === null || typeof value === 'boolean');
    modelCalls(row.calls);
    if (row.passed) {
      assert.equal(row.failureStage, null); assert.equal(row.failureCode, null); assert.equal(row.receiptReadFailed, false);
      assert.equal(row.receiptCompleted, true); assert.equal(row.toolCalls, 1); assert.equal(row.receiptCount, 1); hash(row.observationSha256);
      assert.equal(row.verdict, positive ? 'pass' : 'fail'); assert.equal(row.completed, positive);
      assert.ok(row.calls.length > 0 && row.calls.every(call => call.completed && call.requestBytes > 0 && call.outputBytes > 0));
    } else {
      assert.ok(['admission', 'tool', 'receipt_validation', 'scenario_validation', 'judge', 'judge_validation', 'run_completion'].includes(row.failureStage));
      assert.ok(['23514', 'ERR_ASSERTION', 'EFFECT_RECEIPT_INVALID', 'GRAPH_EFFECT_REPLAY_BLOCKED', 'ABORTED', 'UNCLASSIFIED'].includes(row.failureCode));
    }
    if (['admission', 'tool', 'receipt_validation', 'scenario_validation'].includes(row.failureStage)) assert.equal(row.calls.length, 0);
    const beforeScenario = !row.passed && ['admission', 'tool', 'receipt_validation'].includes(row.failureStage);
    if (beforeScenario) assert.ok(Object.values(row.scenarioChecks).every(value => value === null));
    else assert.ok(Object.values(row.scenarioChecks).every(value => typeof value === 'boolean'));
    if (row.passed || ['judge', 'judge_validation', 'run_completion'].includes(row.failureStage)) {
      assert.ok(Object.values(row.scenarioChecks).every(value => value === true));
    }
  }
  exact(report.cancellation, 'passed actorCalls judgeCalls calls'); bool(report.cancellation.passed);
  assert.equal(report.cancellation.actorCalls, 0); modelCalls(report.cancellation.calls);
  assert.equal(report.cancellation.judgeCalls, report.cancellation.calls.length);
  if (report.cancellation.passed) assert.equal(report.cancellation.calls.length, 0);
  assert.ok(Array.isArray(report.failures)); assert.equal(new Set(report.failures).size, report.failures.length);
  for (const failure of report.failures) assert.ok(Object.hasOwn(CASES, failure) || ['sibling_case_isolation', 'reset_cancellation', 'qualification_infrastructure', 'model_provenance', 'pool_cleanup'].includes(failure));
  for (const row of report.cases) assert.equal(report.failures.includes(row.name), !row.passed);
  if (report.qualification === 'qualified') {
    assert.equal(seen.size, 11); assert.ok(report.cases.every(row => row.passed));
    assert.equal(report.modelVerifiedBefore, true); assert.equal(report.modelVerifiedAfter, true);
    assert.equal(report.casesPreservedSibling, true); assert.equal(report.cancellation.passed, true); assert.deepEqual(report.failures, []);
  } else assert.ok(report.failures.length > 0);
  if (requireQualified) assert.equal(report.qualification, 'qualified');
  return report;
}
module.exports = { CASES, validateLegacySensitiveManualReport };
