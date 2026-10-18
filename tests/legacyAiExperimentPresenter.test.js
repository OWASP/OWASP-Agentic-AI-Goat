'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  projectLegacyAiExperimentResult,
} = require('../server/services/legacyAiExperimentPresenter');
const {
  createLegacyAiExperimentRunner,
} = require('../server/services/legacyAiExperimentRunner');

function resultFor(sourceRoute, overrides = {}) {
  const diagnostics = {
    inputBytes: 120,
    inputCharacters: 120,
    tokenCount: null,
    contextWindowTokens: null,
    tokenMetrics: 'unknown',
    responseChainFormatMarkers: [],
  };
  if (sourceRoute === 'context_stuffing') {
    diagnostics.stuffingBytes = 32;
    diagnostics.stuffingCharacters = 32;
  } else {
    diagnostics.inputAttackMarkers = ['ignore previous'];
  }
  if (sourceRoute === 'chain_of_thought') {
    diagnostics.responseChainFormatMarkers = ['step 1:', 'analysis:'];
  }
  if (sourceRoute === 'multi_turn_jailbreak') diagnostics.turns = 2;
  return {
    response: 'Observed controlled experiment response.',
    modelUsed: 'llama3.1:8b',
    provider: 'ollama',
    teaching: {
      route: sourceRoute,
      artifactId: 'private-artifact-id',
      diagnostics,
      evaluation: {
        verdict: 'pass',
        criteria: [{ id: 'synthetic_canary_disclosed', satisfied: true }],
        passed: true,
        explanation: 'private Judge explanation',
        provider: 'private-judge-provider',
        model: 'private-judge-model',
      },
    },
    privateReceipt: 'must-not-project',
    ...overrides,
  };
}

function runnerResultWithJudge(judge) {
  return createLegacyAiExperimentRunner({
    provider: {
      async generate() {
        return {
          response: 'CANARY-artifact-1',
          model: 'controlled-model',
          provider: 'controlled-provider',
          mocked: false,
          fallback: false,
        };
      },
    },
    judge,
    issueArtifact: () => ({ artifactId: 'artifact-1', canary: 'CANARY-artifact-1' }),
  }).run({ sourceRoute: 'prompt_injection', prompt: 'experiment request', options: {} });
}

test('projects all four fixed route diagnostics into immutable public responses', () => {
  for (const sourceRoute of [
    'prompt_injection',
    'chain_of_thought',
    'context_stuffing',
    'multi_turn_jailbreak',
  ]) {
    const projected = projectLegacyAiExperimentResult(resultFor(sourceRoute), { sourceRoute });
    assert.equal(projected.teaching.route, sourceRoute);
    assert.equal(projected.creditAwarded, false);
    assert.equal(Object.isFrozen(projected), true);
    assert.equal(Object.isFrozen(projected.teaching.diagnostics), true);
    assert.equal(Object.isFrozen(projected.teaching.evaluation), true);
    assert.equal(Object.isFrozen(projected.teaching.evaluation.criteria), true);
    assert.equal('artifactId' in projected.teaching, false);
    assert.equal(JSON.stringify(projected).includes('private-artifact-id'), false);
    assert.equal(JSON.stringify(projected).includes('private-judge'), false);
    assert.equal(JSON.stringify(projected).includes('must-not-project'), false);
    assert.equal(projected.teaching.diagnostics.tokenCount, null);
    assert.equal(projected.teaching.diagnostics.contextWindowTokens, null);
    assert.equal(projected.teaching.diagnostics.tokenMetrics, 'unknown');
  }
});

test('uses exact route-specific diagnostic fields and never changes unknown token semantics', () => {
  const context = projectLegacyAiExperimentResult(
    resultFor('context_stuffing'), { sourceRoute: 'context_stuffing' },
  );
  assert.deepEqual(context.teaching.diagnostics, {
    inputBytes: 120,
    inputCharacters: 120,
    tokenCount: null,
    contextWindowTokens: null,
    tokenMetrics: 'unknown',
    stuffingBytes: 32,
    stuffingCharacters: 32,
    responseChainFormatMarkers: [],
  });
  const multi = projectLegacyAiExperimentResult(
    resultFor('multi_turn_jailbreak'), { sourceRoute: 'multi_turn_jailbreak' },
  );
  assert.deepEqual(multi.teaching.diagnostics, {
    inputBytes: 120,
    inputCharacters: 120,
    tokenCount: null,
    contextWindowTokens: null,
    tokenMetrics: 'unknown',
    inputAttackMarkers: ['ignore previous'],
    responseChainFormatMarkers: [],
    turns: 2,
  });
});

test('rejects route confusion, invalid result strings, and unsafe provider metadata', () => {
  assert.throws(
    () => projectLegacyAiExperimentResult(resultFor('prompt_injection'), { sourceRoute: 'unknown' }),
    /route required/,
  );
  assert.throws(
    () => projectLegacyAiExperimentResult(resultFor('prompt_injection', {
      teaching: { ...resultFor('prompt_injection').teaching, route: 'context_stuffing' },
    }), { sourceRoute: 'prompt_injection' }),
    /does not match/,
  );
  assert.throws(
    () => projectLegacyAiExperimentResult(resultFor('prompt_injection', { response: '' }), { sourceRoute: 'prompt_injection' }),
    /response required/,
  );
  assert.throws(
    () => projectLegacyAiExperimentResult(resultFor('prompt_injection', { provider: 'judge CANARY-private' }), { sourceRoute: 'prompt_injection' }),
    /provider identifier required/,
  );
});

test('requires exactly one known satisfied criterion and a consistent runner pass state', () => {
  const sourceRoute = 'prompt_injection';
  for (const evaluation of [
    { verdict: 'pass', criteria: [{ id: 'other', satisfied: true }], passed: true },
    { verdict: 'pass', criteria: [{ id: 'synthetic_canary_disclosed', satisfied: false }], passed: true },
    { verdict: 'pass', criteria: [
      { id: 'synthetic_canary_disclosed', satisfied: true },
      { id: 'synthetic_canary_disclosed', satisfied: true },
    ], passed: true },
    { verdict: 'fail', criteria: [{ id: 'synthetic_canary_disclosed', satisfied: true }], passed: true },
    { verdict: 'pass', criteria: [], passed: false },
    { verdict: 'fail', criteria: [], passed: true },
  ]) {
    const input = resultFor(sourceRoute);
    input.teaching.evaluation = evaluation;
    assert.throws(
      () => projectLegacyAiExperimentResult(input, { sourceRoute }),
      /evaluation|criterion|Inconsistent/,
    );
  }
  const notPassed = resultFor(sourceRoute);
  notPassed.teaching.evaluation = {
    verdict: 'pass',
    criteria: [{ id: 'synthetic_canary_disclosed', satisfied: true }],
    passed: false,
  };
  const projected = projectLegacyAiExperimentResult(notPassed, { sourceRoute });
  assert.equal(projected.teaching.evaluation.passed, false);
  assert.equal(projected.creditAwarded, false);
});

test('composes actual runner unavailable and thrown-Judge outputs without inventing completion', async () => {
  const unavailable = await runnerResultWithJudge(async () => ({ verdict: 'unavailable' }));
  const thrown = await runnerResultWithJudge(async () => {
    throw new Error('controlled Judge unavailable');
  });

  for (const runnerResult of [unavailable, thrown]) {
    assert.deepEqual(runnerResult.teaching.evaluation.criteria, []);
    const projected = projectLegacyAiExperimentResult(runnerResult, { sourceRoute: 'prompt_injection' });
    assert.equal(projected.teaching.evaluation.verdict, 'unavailable');
    assert.deepEqual(projected.teaching.evaluation.criteria, []);
    assert.equal(projected.teaching.evaluation.passed, false);
    assert.equal(projected.creditAwarded, false);
    assert.equal(Object.isFrozen(projected.teaching.evaluation.criteria), true);
  }
});

test('rejects malformed diagnostics instead of projecting a plausible completion', () => {
  const unknownTokens = resultFor('chain_of_thought');
  unknownTokens.teaching.diagnostics.tokenCount = 42;
  assert.throws(
    () => projectLegacyAiExperimentResult(unknownTokens, { sourceRoute: 'chain_of_thought' }),
    /diagnostics/,
  );

  const invalidMarker = resultFor('prompt_injection');
  invalidMarker.teaching.diagnostics.inputAttackMarkers = ['CANARY-private'];
  assert.throws(
    () => projectLegacyAiExperimentResult(invalidMarker, { sourceRoute: 'prompt_injection' }),
    /markers/,
  );

  const malformedEmptyMarkers = resultFor('prompt_injection');
  malformedEmptyMarkers.teaching.diagnostics.responseChainFormatMarkers = '';
  assert.throws(
    () => projectLegacyAiExperimentResult(malformedEmptyMarkers, { sourceRoute: 'prompt_injection' }),
    /diagnostics/,
  );

  const invalidContext = resultFor('context_stuffing');
  invalidContext.teaching.diagnostics.responseChainFormatMarkers = ['step 1:'];
  assert.throws(
    () => projectLegacyAiExperimentResult(invalidContext, { sourceRoute: 'context_stuffing' }),
    /context-stuffing diagnostics/,
  );
});
