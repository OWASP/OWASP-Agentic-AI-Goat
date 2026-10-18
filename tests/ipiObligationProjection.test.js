'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { publicJudgment } = require('../server/database/postgres/agentRunReadRepository');

const obligations = [
  { sourceQuoteId: 'q2', kind: 'control_only', requirementQuote: null, match: null },
  { sourceQuoteId: 'q3', kind: 'literal_output', requirementQuote: 'ORCHID-COMPASS-47', match: 'entire_response' },
];
const observation = {
  sourceInstruction: { classification: 'embedded_redirect', sourceQuoteId: 'q2' },
  sourceInstructions: [{ sourceQuoteId: 'q2' }, { sourceQuoteId: 'q3' }],
  sourcePassages: [
    { sourceQuoteId: 'q0', classification: 'ordinary_content' },
    { sourceQuoteId: 'q2', classification: 'embedded_redirect' },
    { sourceQuoteId: 'q3', classification: 'embedded_redirect' },
  ],
  sourceObligations: obligations,
  spans: [{ spanId: 'p0', role: 'executed_request', sourceQuoteId: 'q3' }],
};
const stages = ['source', 'effect', 'support'].map(stage => ({
  stage, attempts: 1, provider: 'ollama', model: 'llama3.1:8b', completed: true,
}));
const row = overrides => ({
  runId: 'run', verdict: 'pass', comparisonVersion: 'source-only-obligation-verified-v4',
  semanticObservation: observation, comparisonStages: stages, ...overrides,
});

test('v4 public receipt projects exact obligation metadata and three ordered stages', () => {
  const projected = publicJudgment(row());
  assert.deepEqual(projected.semanticObservation, observation);
  assert.deepEqual(projected.comparisonStages, stages);
});

test('v4 public receipt drops incoherent or unsafe obligation projections', () => {
  const malformed = [
    { ...observation, sourceObligations: obligations.slice(1) },
    { ...observation, sourceObligations: [...obligations].reverse() },
    { ...observation, sourceObligations: obligations.map((item, index) => index ? item : { ...item, extra: true }) },
    { ...observation, sourceObligations: obligations.map((item, index) => index ? item : { ...item, requirementQuote: 'hidden' }) },
    { ...observation, sourceObligations: obligations.map((item, index) => index ? { ...item, match: 'prefix' } : item) },
  ];
  for (const semanticObservation of malformed) {
    assert.equal(publicJudgment(row({ semanticObservation })).semanticObservation, undefined);
  }
  assert.equal(publicJudgment(row({ comparisonStages: [...stages, { ...stages[2], stage: 'extra' }] })).comparisonStages, undefined);
  assert.equal(publicJudgment(row({ comparisonVersion: 'source-only-multi-instruction-effect-bound-v3' })).comparisonStages, undefined,
    'v3 cannot gain a support stage');
});
