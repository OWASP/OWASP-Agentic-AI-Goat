'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
const calibration = require('./fixtures/secureshopReviewModerationComparisonCalibration');

const LIVE = process.env.RUN_LIVE_SECURESHOP_REVIEW_MODERATION_COMPARISON_CALIBRATION === '1';

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

test('local llama3.1:8b classifies authentic review moderation premises', {
  skip: !LIVE, timeout: 900000,
}, async t => {
  const provider = createLangChainProvider({ provider: 'ollama', model: calibration.MODEL,
    baseURL: modelUrl() });
  let providerCalls = 0;
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(
    new Error('Review moderation comparison calibration deadline exceeded')), 840000);
  deadline.unref?.();
  try {
    const attempts = [];
    const output = await calibration.runCalibration({
      async classify({ messages, format, maxOutput, options }) {
        controller.signal.throwIfAborted();
        providerCalls += 1;
        assert.ok(providerCalls <= calibration.MAX_PROVIDER_CALLS);
        assert.ok(Number.isSafeInteger(maxOutput) && maxOutput >= 900);
        assert.equal(options.format, format);
        assert.equal(options.max_tokens, maxOutput);
        assert.equal(options.num_predict, maxOutput);
        return provider.chat(messages, [], options);
      },
      async recordAttempt(attempt) {
        attempts.push(attempt);
        t.diagnostic(JSON.stringify({ qualification: false, attempt }));
      },
      async recordResult(result) {
        t.diagnostic(JSON.stringify({ qualification: false, caseId: result.caseId,
          kind: result.kind, trial: result.trial, expectedCriteria: result.expectedCriteria,
          packetSha256: result.packetSha256, resultSha256: result.resultSha256,
          attempts: result.attempts, canonicalInvalids: result.canonicalInvalids,
          judgment: result.judgment }));
      },
      signal: controller.signal,
    });
    assert.equal(output.results.length, 30);
    assert.equal(output.providerAttempts, calibration.EXPECTED_PROVIDER_CALLS);
    assert.equal(attempts.length, calibration.EXPECTED_PROVIDER_CALLS);
    assert.equal(providerCalls, calibration.EXPECTED_PROVIDER_CALLS);
    t.diagnostic(JSON.stringify({
      scope: 'review_moderation_comparison_calibration_summary',
      status: 'comparison_calibration_qualified',
      qualification: true,
      judgeVersion: output.results[0].judgment.judgeVersion,
      cases: calibration.CASES_PER_TRIAL,
      trials: calibration.TRIALS_PER_CASE,
      results: output.results.length,
      providerCalls,
      maximumProviderCalls: calibration.MAX_PROVIDER_CALLS,
      objectiveCreditAttempted: false,
      mountedWorkflowQualified: false,
    }));
  } finally {
    clearTimeout(deadline);
  }
});
