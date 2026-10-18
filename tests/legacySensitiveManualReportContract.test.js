'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { CASES, validateLegacySensitiveManualReport: validate } = require('./fixtures/legacySensitiveManualReportContract');
function qualified() {
  return { version: 1, cohort: 'legacy-sensitive-manual-actual8b-v1', model: 'llama3.1:8b',
    digest: '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
    qualification: 'qualified', modelVerifiedBefore: true, modelVerifiedAfter: true, casesPreservedSibling: true,
    cases: Object.entries(CASES).map(([name, [objectiveId, operation, positive]]) => ({
      name, objectiveId, operation, passed: true, failedPositive: false, toolCalls: 1, receiptCount: 1,
      receiptCompleted: true, observationSha256: 'a'.repeat(64), scenarioChecks: { independentEffects: true, canonicalFacts: true },
      failureStage: null, failureCode: null, receiptReadFailed: false, verdict: positive ? 'pass' : 'fail', completed: positive, durable: false,
      calls: [{ phase: 'judge', requestSha256: 'b'.repeat(64), requestBytes: 1, outputSha256: 'c'.repeat(64), outputBytes: 1, configuredContextTokens: 32768, completed: true }],
    })), cancellation: { passed: true, actorCalls: 0, judgeCalls: 0, calls: [] }, failures: [] };
}
// These invented report bytes test validation only and are never qualification.
test('strict manual report contract accepts complete shape and rejects false proof', () => {
  validate(qualified());
  const mutations = [
    r => r.cases.pop(), r => r.cases.push(r.cases[0]), r => r.cases[1].name = r.cases[0].name,
    r => r.cases[0].calls[0].phase = 'actor', r => r.cases[0].calls = [],
    r => r.cases[0].calls[0].configuredContextTokens = 8192,
    r => r.cases[0].calls[0].completed = false, r => r.cases[0].calls[0].outputBytes = 0, r => r.cases[0].calls[0].requestBytes = 0,
    r => r.cases[0].receiptCompleted = false, r => r.cases[0].receiptCount = 0,
    r => r.cases[0].observationSha256 = null, r => r.cases[0].durable = true,
    r => r.cases[0].scenarioChecks.independentEffects = false,
    r => r.cases[3].verdict = 'pass', r => r.cases[0].response = 'private',
    r => r.cases[0].calls[0].request = 'private', r => r.modelVerifiedAfter = false,
    r => r.casesPreservedSibling = false, r => r.cancellation.actorCalls = 1,
    r => { r.cancellation.calls = r.cases[0].calls; r.cancellation.judgeCalls = 1; },
  ];
  for (const mutate of mutations) { const report = qualified(); mutate(report); assert.throws(() => validate(report)); }
});

test('incomplete report preserves bounded failure and does not qualify', () => {
  const report = qualified(); report.qualification = 'incomplete'; report.cases = [];
  report.modelVerifiedBefore = false; report.modelVerifiedAfter = false; report.casesPreservedSibling = false;
  report.cancellation.passed = false; report.failures = ['qualification_infrastructure', 'model_provenance'];
  validate(report, { requireQualified: false }); assert.throws(() => validate(report));
});

test('pre-Judge failed reports cannot contain model calls', () => {
  for (const failureStage of ['admission', 'tool', 'receipt_validation', 'scenario_validation']) {
    const report = qualified(); report.qualification = 'incomplete';
    const row = report.cases[0]; row.passed = false; row.failedPositive = true;
    row.failureStage = failureStage; row.failureCode = 'ERR_ASSERTION';
    report.failures = [row.name];
    if (failureStage !== 'scenario_validation') row.scenarioChecks = { independentEffects: null, canonicalFacts: null };
    assert.throws(() => validate(report, { requireQualified: false }));
    row.calls = []; validate(report, { requireQualified: false });
  }
});
