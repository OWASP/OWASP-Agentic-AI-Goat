'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const express = require('express');
const {
  createCtfReceiptAdapter, createLegacySensitiveReceiptAdapter, createXssEmailReceiptAdapter, createLazyFamilyReceiptAdapters,
  publicJudgment,
} = require('../server/database/postgres/agentRunReadRepository');
const { createAgentRunsRouter } = require('../server/routes/agentRuns');

const RUN = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const DIGEST = 'a'.repeat(64);

test('public Judge projection keeps bounded citations tied to visible criterion references only', () => {
  const projected = publicJudgment({ source: 'canonical', runId: RUN, verdict: 'fail', disposition: 'not_pass',
    explanation: 'x'.repeat(5000), criteria: [{ id: 'criterion_1', satisfied: false, evidenceRefs: ['response', { secret: 'drop' }] },
      { id: 'criterion_2', satisfied: true, evidenceRefs: ['tool_result'], citations: [{ evidenceId: 'tool_result', quote: 'Synthetic visible evidence.' }] }],
    provider: 'provider', model: 'model', usage: { inputTokens: 10, outputTokens: 20, totalTokens: 30, secret: 99 },
    result: { prompt: 'drop' } });
  assert.equal(projected.explanation.length, 1000);
  assert.deepEqual(projected.criteria, [
    { id: 'criterion_1', satisfied: false, evidenceRefs: ['response'] },
    { id: 'criterion_2', satisfied: true, evidenceRefs: ['tool_result'], citations: [{ evidenceId: 'tool_result', quote: 'Synthetic visible evidence.' }] },
  ]);
  assert.deepEqual(projected.usage, { inputTokens: 10, outputTokens: 20, totalTokens: 30 });
  assert.equal(projected.result, undefined);
});

test('public Judge projection omits malformed, foreign, oversized, and unsatisfied citations without truncating quotes', () => {
  const projected = publicJudgment({ runId: RUN, criteria: [
    { id: 'malformed', satisfied: true, evidenceRefs: ['tool'], citations: [{ evidenceId: 'tool', quote: '' }] },
    { id: 'foreign', satisfied: true, evidenceRefs: ['tool'], citations: [{ evidenceId: 'other', quote: 'foreign quote' }] },
    { id: 'empty_ref', satisfied: true, evidenceRefs: ['tool'], citations: [{ evidenceId: '', quote: 'empty ref' }] },
    { id: 'oversized', satisfied: true, evidenceRefs: ['tool'], citations: [{ evidenceId: 'tool', quote: 'x'.repeat(1001) }] },
    { id: 'truncated_ref', satisfied: true, evidenceRefs: ['x'.repeat(101)], citations: [{ evidenceId: `${'x'.repeat(99)}…`, quote: 'must not bind to a display truncation' }] },
    { id: 'unsatisfied', satisfied: false, evidenceRefs: ['tool'], citations: [{ evidenceId: 'tool', quote: 'must not appear' }] },
    { id: 'legacy', satisfied: true, evidenceRefs: ['tool'] },
  ] });
  assert.deepEqual(projected.criteria, [
    { id: 'malformed', satisfied: true, evidenceRefs: ['tool'] },
    { id: 'foreign', satisfied: true, evidenceRefs: ['tool'] },
    { id: 'empty_ref', satisfied: true, evidenceRefs: ['tool'] },
    { id: 'oversized', satisfied: true, evidenceRefs: ['tool'] },
    { id: 'truncated_ref', satisfied: true, evidenceRefs: [`${'x'.repeat(99)}…`] },
    { id: 'unsatisfied', satisfied: false, evidenceRefs: ['tool'] },
    { id: 'legacy', satisfied: true, evidenceRefs: ['tool'] },
  ]);
});

function poolWith(rows) {
  const calls = [];
  return { calls, query: async (sql, params) => { calls.push({ sql, params }); return { rows }; } };
}

test('CTF receipt adapter scopes by authoritative owner and strips attempt metadata', async () => {
  const pool = poolWith([{ runId: RUN, stageDigest: DIGEST, verdict: 'pass', accepted: 1, stageNumber: 2, stageName: 'Secrets', createdAt: '2026-09-12T00:00:00.000Z' }]);
  const receipts = await createCtfReceiptAdapter(pool)({ runId: RUN, ownerId: '7' });
  assert.deepEqual(pool.calls[0].params, [7, RUN]);
  assert.deepEqual(receipts[0], {
    source: 'ctf', receiptId: `ctf:${RUN}`, evaluationId: null, runId: RUN, workshopKey: 'ctf', objectiveId: 'stage_2',
    family: 'CTF', scenario: 'Secrets', rubricVersion: null, evidenceDigest: null, configDigest: DIGEST, explanation: null,
    criteria: null, judgeProvider: null, judgeModel: null, usage: null, generation: undefined,
    mode: null, canonicalMode: null, verdict: 'pass', disposition: 'accepted', createdAt: '2026-09-12T00:00:00.000Z',
    evaluatedAt: null, errorCode: null, childEvaluationId: null,
  });
  assert.equal(receipts[0].payload, undefined);
});

test('legacy sensitive adapter joins current generation and preserves only bounded judge metadata', async () => {
  const pool = poolWith([{ runId: RUN, generation: 4, challengeType: 'path_traversal', success: 1,
    judgment: { verdict: 'pass', rubricVersion: 'ssi-v1', evidenceDigest: DIGEST, flag_found: 'secret' }, createdAt: '2026-09-12T00:00:00.000Z' }]);
  const receipts = await createLegacySensitiveReceiptAdapter(pool)({ runId: RUN, ownerId: '7' });
  assert.deepEqual(pool.calls[0].params, [7, RUN]);
  assert.equal(receipts[0].source, 'legacy_sensitive');
  assert.equal(receipts[0].family, 'LegacySensitiveInfo');
  assert.equal(receipts[0].evidenceDigest, DIGEST);
  assert.equal(receipts[0].flag_found, undefined);
  assert.equal(receipts[0].disposition, 'accepted');
  assert.match(pool.calls[0].sql, /owner_state/);
});

test('XSS email adapter uses run and owner together and excludes template content', async () => {
  const pool = poolWith([{ receiptId: 12, runId: RUN, level: 4, verdict: 'fail', judgeVersion: 'j1', rubricVersion: 'xss-v1',
    evidenceDigest: DIGEST, errorCode: null, browserExecuted: 0, browserReason: 'not executed', createdAt: '2026-09-12T00:00:00.000Z', html_content: '<script>' }]);
  const receipts = await createXssEmailReceiptAdapter(pool)({ runId: RUN, ownerId: '7' });
  assert.deepEqual(pool.calls[0].params, ['7', RUN]);
  assert.equal(receipts[0].source, 'xss_email');
  assert.equal(receipts[0].objectiveId, 'level_4');
  assert.equal(receipts[0].browserExecuted, false);
  assert.equal(receipts[0].browserReason, 'not executed');
  assert.equal(receipts[0].html_content, undefined);
});

test('run detail passes authoritative admin run owner to selected family adapter', async () => {
  const seen = [];
  const repository = {
    events: async () => ({ run: { runId: RUN, family: 'CTF', ownerId: '71', status: 'completed' }, events: [], nextCursor: null }),
    judgments: async () => [],
  };
  const app = express();
  app.use('/runs', createAgentRunsRouter({ repository, admin: true,
    authenticateToken: (req, res, next) => { req.user = { id: 7 }; next(); },
    requirePermission: () => (req, res, next) => next(), getGraphDefinition: () => null,
    receiptAdapters: { CTF: async ({ ownerId, runId }) => { seen.push([ownerId, runId]); return []; } },
  }));
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/runs/${RUN}`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.deepEqual(seen, [['71', RUN]]);
    assert.deepEqual(body.receiptSources, [{ source: 'canonical', status: 'available', count: 0 }, { source: 'CTF', status: 'available', count: 0 }]);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('separate receipt failure is explicit and does not hide authoritative run detail', async () => {
  const repository = { events: async () => ({ run: { runId: RUN, family: 'XSS_EMAIL', status: 'completed' }, events: [], nextCursor: null }), judgments: async () => [] };
  const app = express();
  app.use('/runs', createAgentRunsRouter({ repository, authenticateToken: (req, res, next) => { req.user = { id: 7 }; next(); },
    getGraphDefinition: () => null, receiptAdapters: { XSS_EMAIL: async () => { throw new Error('database password leaked'); } } }));
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/runs/${RUN}`);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.deepEqual(body.receiptSources[1], { source: 'XSS_EMAIL', status: 'unavailable', code: 'FAMILY_RECEIPT_UNAVAILABLE' });
    assert.doesNotMatch(JSON.stringify(body), /password|database/i);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('family pools are lazy and only the selected namespace is opened', async () => {
  const opened = [];
  const rows = [{ runId: RUN, verdict: 'fail', accepted: 0, stageNumber: 1, stageName: 'Guardian' }];
  const adapters = createLazyFamilyReceiptAdapters({ poolFactory: (_env, key) => {
    opened.push(key);
    return poolWith(rows);
  } });
  assert.deepEqual(opened, []);
  await adapters.CTF({ runId: RUN, ownerId: 7 });
  assert.deepEqual(opened, ['CTF_DATABASE_URL']);
});


test('public Judge projection exposes only typed semantic observation identifiers', () => {
  const semanticObservation = { sourceInstruction: { classification: 'embedded_redirect', sourceQuoteId: 'q1' },
    spans: [{ spanId: 'p0', role: 'executed_request', sourceQuoteId: 'q1' }] };
  assert.deepEqual(publicJudgment({ runId: RUN, semanticObservation }).semanticObservation, semanticObservation);
  for (const malformed of [
    { ...semanticObservation, spans: [{ spanId: '', role: 'executed_request', sourceQuoteId: 'q1' }] },
    { ...semanticObservation, spans: [{ spanId: 'raw response text', role: 'executed_request', sourceQuoteId: 'q1' }] },
    { ...semanticObservation, spans: [{ spanId: 'p0', role: 'executed_request', sourceQuoteId: 'raw source text' }] },
    { sourceInstruction: { classification: 'other', sourceQuoteId: null }, spans: [] },
    { sourceInstruction: semanticObservation.sourceInstruction, spans: Array.from({ length: 65 }, (_, i) => ({ spanId: `p${i}`, role: 'neutral_text', sourceQuoteId: null })) },
  ]) assert.equal(publicJudgment({ runId: RUN, semanticObservation: malformed }).semanticObservation, undefined);
});

test('PostgreSQL run receipt query selects semantic observation without stored packet content', async () => {
  const source = require('node:fs').readFileSync(require.resolve('../server/database/postgres/agentRunReadRepository'), 'utf8');
  assert.match(source, /result_json->'semanticObservation' AS "semanticObservation"/);
  assert.doesNotMatch(source, /SELECT[^;]+result_json\s+AS/is);
});
