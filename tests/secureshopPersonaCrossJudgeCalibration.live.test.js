'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createLangChainProvider }
  = require('../server/agent-runtime/providers/langchainProvider');
const calibration = require('./fixtures/secureshopPersonaCrossJudgeCalibration');

const LIVE = process.env.RUN_LIVE_SECURESHOP_PERSONA_CROSS_CALIBRATION === '1';

function modelUrl() {
  assert.equal(process.env.JUDGE_PROVIDER, 'ollama');
  assert.equal(process.env.JUDGE_MODEL, calibration.MODEL);
  const value = new URL(process.env.OLLAMA_BASE_URL);
  assert.equal(value.protocol, 'http:');
  assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.port, /^[1-9][0-9]{1,4}$/);
  assert.equal(value.username, ''); assert.equal(value.password, '');
  assert.equal(value.pathname, '/'); assert.equal(value.search, ''); assert.equal(value.hash, '');
  return value.toString().replace(/\/$/, '');
}

function diagnostic(result) {
  return { caseId: result.caseId, trial: result.trial, kind: result.kind,
    expectedSatisfied: result.expectedSatisfied,
    packetSha256: result.packetSha256, policySha256: result.policySha256,
    bodySha256: result.bodySha256, resultSha256: result.resultSha256,
    attempts: result.attempts, invalidAttempts: result.invalidAttempts,
    persistedResult: result.persistedResult };
}

test('local llama3.1:8b preserves the historical cross-persona v1 diagnostic', {
  skip: !LIVE, timeout: 900000,
}, async t => {
  const provider = createLangChainProvider({ provider: 'ollama', model: calibration.MODEL,
    baseURL: modelUrl() });
  let providerCalls = 0;
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(
    new Error('Persona cross calibration deadline exceeded')), 840000);
  deadline.unref?.();
  try {
    const output = await calibration.runCalibration({
      async classify({ messages, format, options }) {
        controller.signal.throwIfAborted();
        providerCalls += 1;
        assert.ok(providerCalls <= calibration.MAX_PROVIDER_CALLS);
        assert.equal(options.format, format);
        assert.equal(options.max_tokens, 900);
        assert.equal(options.num_predict, 900);
        return provider.chat(messages, [], options);
      },
      async recordAttempt(attempt) {
        t.diagnostic(JSON.stringify({ scope: 'secureshop_persona_cross_attempt', attempt }));
      },
      async recordResult(result) {
        t.diagnostic(JSON.stringify({ scope: 'secureshop_persona_cross_result',
          result: diagnostic(result) }));
      },
      qualification: true,
      assertExpected: false,
      signal: controller.signal,
    });
    assert.equal(output.results.length, calibration.EXPECTED_RESULTS);
    assert.equal(providerCalls, output.providerAttempts);
    assert.ok(providerCalls >= calibration.EXPECTED_PROVIDER_CALLS
      && providerCalls <= calibration.MAX_PROVIDER_CALLS);
    const semanticMismatches = output.results.map(result => {
      const calibrationCase = calibration.cases().find(item => item.definition.id === result.caseId);
      return calibration.semanticMismatch(calibrationCase, result);
    }).filter(Boolean);
    const repaired = providerCalls !== calibration.EXPECTED_PROVIDER_CALLS;
    const status = semanticMismatches.length ? 'semantic_calibration_failed'
      : repaired ? 'semantic_results_with_repairs_unqualified' : 'semantic_calibration_passed';
    t.diagnostic(JSON.stringify({ scope: 'secureshop_persona_cross_calibration_summary',
      status, qualification: !semanticMismatches.length && !repaired,
      objectiveId: 'ss_cross_persona_effect', provider: 'ollama', model: calibration.MODEL,
      cases: calibration.SEMANTIC_CASES, trials: calibration.TRIALS_PER_CASE,
      results: calibration.EXPECTED_RESULTS, providerCalls,
      maximumProviderCalls: calibration.MAX_PROVIDER_CALLS,
      objectiveCreditAttempted: false, mountedWorkflowQualified: false,
      semanticMismatches,
      results: output.results.map(diagnostic) }));
    assert.deepEqual(semanticMismatches, [], 'Cross-persona semantic calibration mismatches');
    assert.equal(providerCalls, calibration.EXPECTED_PROVIDER_CALLS,
      'Cross-persona semantic calibration required a schema repair');
  } finally {
    clearTimeout(deadline);
  }
});
