'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
const calibration = require('./fixtures/secureshopPersonaInboxJudgeCalibration');

const LIVE = process.env.RUN_LIVE_SECURESHOP_PERSONA_JUDGE_CALIBRATION === '1';
const MODEL = 'llama3.1:8b';

function configuredModelUrl() {
  assert.equal(process.env.JUDGE_PROVIDER, 'ollama', 'Calibration requires explicit JUDGE_PROVIDER=ollama');
  assert.equal(process.env.JUDGE_MODEL, MODEL, `Calibration requires explicit JUDGE_MODEL=${MODEL}`);
  assert.ok(process.env.OLLAMA_BASE_URL, 'Calibration requires explicit OLLAMA_BASE_URL');
  const url = new URL(process.env.OLLAMA_BASE_URL);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.port, /^[1-9][0-9]{1,4}$/);
  assert.equal(url.username, ''); assert.equal(url.password, '');
  assert.equal(url.pathname, '/'); assert.equal(url.search, ''); assert.equal(url.hash, '');
  return url.toString().replace(/\/$/, '');
}

function diagnostic(item) {
  const judgment = item.judgment;
  return Object.freeze({ variant: item.variant, caseId: item.caseId, trial: item.trial, kind: item.kind,
    expected: item.expected, modelCalled: item.modelCalled, gateAdmitted:item.gateAdmitted,
    verdict: judgment?.verdict??null,
    packetSha256:item.packetSha256,resultSha256:item.resultSha256,
    provider: judgment?.provider??null, model: judgment?.model??null, attempts: judgment?.attempts??0,
    explanation: judgment?.explanation??null, criteria: judgment?.criteria??[] });
}

test('local llama3.1:8b corroborates repeated v4 authority-valid advisory packets', {
  skip: !LIVE,
  timeout: 600000,
}, async t => {
  const baseURL = configuredModelUrl();
  const provider = createLangChainProvider({ provider: 'ollama', model: MODEL,
    baseURL });
  let providerCalls = 0;
  const model = Object.freeze({
    async chat(...args) {
      providerCalls += 1;
      assert.ok(providerCalls <= calibration.MAX_PROVIDER_CALLS,
        'Calibration exceeded the canonical two-attempt bound');
      return provider.chat(...args);
    },
  });
  const judge = createObjectiveJudge({ model, timeoutMs: 60000 });
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(new Error('Persona advisory calibration deadline exceeded')), 540000);
  deadline.unref?.();
  let run = 0;
  try {
    const output = await calibration.runCalibration({
      async evaluate(packet, metadata) {
        run += 1;
        const judgment = await judge({ ...packet, execution: Object.freeze({ ownerId: 'synthetic-calibration',
          runId: `persona-advisory-calibration-${metadata.trial}-${run}`, signal: controller.signal,
          async check() { controller.signal.throwIfAborted(); }, async emit() {} }) });
        return judgment;
      },
      async recordResult(item){t.diagnostic(JSON.stringify(diagnostic(item)));},
    });
    t.diagnostic(JSON.stringify({ scope: 'secureshop_persona_advisory_calibration_summary',
      provider: 'ollama', model: MODEL, judgeCases: output.judgeCases, providerCalls,
      maximumProviderCalls: calibration.MAX_PROVIDER_CALLS,
      cases: output.results.map(item => ({ variant: item.variant, caseId: item.caseId,
        trial:item.trial,expected: item.expected,modelCalled:item.modelCalled,gateAdmitted:item.gateAdmitted,
        verdict:item.judgment?.verdict??null,attempts:item.judgment?.attempts??0 })) }));
    assert.equal(output.judgeCases, calibration.MAX_JUDGE_CASES);
    assert.ok(providerCalls >= calibration.MAX_JUDGE_CASES);
    assert.ok(providerCalls <= calibration.MAX_PROVIDER_CALLS);
    assert.equal(providerCalls, output.results.filter(item => item.modelCalled)
      .reduce((count, item) => count + item.judgment.attempts, 0));
    for (const item of output.results.filter(item=>item.modelCalled)) {
      assert.equal(item.judgment.provider, 'ollama', `${item.variant}/${item.caseId}`);
      assert.equal(item.judgment.model, MODEL, `${item.variant}/${item.caseId}`);
      assert.ok(Number.isInteger(item.judgment.attempts) && item.judgment.attempts >= 1
        && item.judgment.attempts <= 2, `${item.variant}/${item.caseId}`);
      assert.ok(['pass', 'fail', 'inconclusive'].includes(item.judgment.verdict),
        `${item.variant}/${item.caseId} did not produce a terminal semantic verdict`);
      assert.equal(item.variant,calibration.CANDIDATE);
      assert.equal(item.expected,'pass');
      assert.equal(item.judgment.verdict, 'pass', `${item.caseId}/trial${item.trial}`);
    }
    assert.equal(output.results.filter(item=>!item.modelCalled).length,18);
    assert.ok(output.results.filter(item=>!item.modelCalled)
      .every(item=>item.expected==='not_pass'&&item.gateAdmitted===false&&item.judgment===null));
    t.diagnostic(JSON.stringify({ qualification: 'positive_semantic_corroboration_and_authority_gate_controls_only',
      objectiveId: 'ss_acl_advisory_effect', provider: 'ollama', model: MODEL,
      toolsExecuted: 0, databaseWrites: 0, creditsAttempted: 0,
      judgeCases: output.judgeCases, providerCalls, maximumProviderCalls: calibration.MAX_PROVIDER_CALLS,
      results: output.results.map(diagnostic) }));
  } finally {
    clearTimeout(deadline);
  }
});
