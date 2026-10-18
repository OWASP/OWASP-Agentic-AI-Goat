'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { traceData } = require('../server/agent-runtime/runTraceStore');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');

test('comparison stage projection admits only the three categorical Judge phases', () => {
  for (const comparisonStage of ['source', 'effect', 'support']) {
    assert.deepEqual(traceData({ comparisonStage }), { comparisonStage });
  }
  for (const comparisonStage of ['SOURCE', 'final', '', 1, null, { private: true }]) {
    assert.deepEqual(traceData({ comparisonStage, rawResponse: 'private', prompt: 'private' }), {});
  }
});

test('reference comparison validation projection admits only fixed safe categories', () => {
  for (const validationCode of ['DPI_REFERENCE_JSON_SYNTAX','DPI_REFERENCE_SCHEMA_SHAPE',
    'DPI_REFERENCE_ID_COVERAGE','DPI_REFERENCE_EXACT_GROUNDING']) {
    assert.deepEqual(traceData({ validationCode, rawResponse:'PRIVATE', prompt:'PRIVATE' }), { validationCode });
  }
  assert.deepEqual(traceData({ validationCode:'DPI_REFERENCE_PRIVATE_TEXT', rawResponse:'PRIVATE' }), {});
});

test('reviewer profile projection admits only the exact known categorical triple', () => {
  const digest = 'a'.repeat(64);
  const exact = {
    reviewerProfileId: 'ctf-stage5-learner-claimed-telemetry',
    reviewerProfileVersion: 'structured-artifact-v1',
    reviewerPolicyDigest: digest,
  };
  assert.deepEqual(traceData(exact), exact);
  for (const candidate of [
    { ...exact, reviewerProfileId: 'other' },
    { ...exact, reviewerProfileVersion: 'structured-artifact-v2' },
    { ...exact, reviewerPolicyDigest: 'A'.repeat(64) },
    { ...exact, reviewerPolicyDigest: 'a'.repeat(63) },
    { reviewerProfileId: exact.reviewerProfileId },
  ]) assert.deepEqual(traceData(candidate), {});
});

test('Stage 6 reviewer profile and structural veto survive the durable trace projection without protected text', async () => {
  const profile = {
    reviewerProfileId: 'ctf-stage6-learner-claimed-rotation-handoff',
    reviewerProfileVersion: 'rotation-handoff-v1',
    reviewerPolicyDigest: 'ec4d475c82c25daf344f51b7b375da33142c4bdbf7816e097a6c294e5086812a',
  };
  assert.deepEqual(traceData({ ...profile, decisionSource: 'model', verdict: 'SAFE',
    rawResponse: 'PRIVATE_SECRET', prompt: 'PRIVATE_SECRET' }),
  { ...profile, decisionSource: 'model', verdict: 'SAFE' });
  const veto = { ...profile, decisionSource: 'model', verdict: 'LEAKED',
    modelVerdict: 'SAFE', policyShapeRejected: true };
  assert.deepEqual(traceData({ ...veto, rawResponse: 'PRIVATE_SECRET' }), veto);
  for (const altered of [
    { ...veto, reviewerPolicyDigest: '0'.repeat(64) },
    { ...veto, reviewerProfileVersion: 'rotation-handoff-v2' },
    { ...veto, modelVerdict: 'LEAKED' },
    { ...veto, policyShapeRejected: false },
    { ...veto, verdict: 'SAFE' },
    { ...veto, reviewerProfileId: 'ctf-stage5-learner-claimed-telemetry',
      reviewerProfileVersion: 'structured-artifact-v1' },
  ]) {
    const projected = traceData(altered);
    assert.equal(Object.hasOwn(projected, 'modelVerdict'), false);
    assert.equal(Object.hasOwn(projected, 'policyShapeRejected'), false);
  }
  const recorded = [];
  const ledger = { begin: async () => ({ durableGeneration: '1' }), assertCurrent: async () => {},
    recordEvent: async (_context, event) => recorded.push(event), finish: async () => {} };
  const coordinator = createRunCoordinator({ family: 'CTF', ledger });
  await coordinator.run('7', {}, async execution => execution.trace({
    node: 'ctf_output_reviewer', type: 'decision', data: { ...veto, protectedValue: 'PRIVATE_SECRET' },
  }));
  assert.equal(recorded.length, 1);
  assert.deepEqual(recorded[0].data, veto);
});

test('coordinator preserves source authority and stage identity under the durable event contract', async () => {
  const recorded = [];
  const ledger = {
    begin: async () => ({ durableGeneration: '4' }),
    assertCurrent: async () => {},
    recordEvent: async (_context, event) => recorded.push(event),
    finish: async () => {},
  };
  const coordinator = createRunCoordinator({ family: 'DPI', ledger });
  await coordinator.run('7', {}, async execution => {
    await execution.trace({
      node: 'judge_compare_source_validate',
      type: 'verdict',
      data: {
        comparisonStage: 'source',
        evidenceSummary: 'trusted_server_reference_v1',
        rawResponse: 'PRIVATE_MODEL_OUTPUT',
      },
    });
    await execution.trace({
      node: 'judge_compare_effect_model',
      type: 'end',
      data: { comparisonStage: 'effect', provider: 'ollama', model: 'llama3.1:8b' },
    });
  });

  assert.deepEqual(recorded, [
    {
      node: 'judge_compare_source_validate',
      type: 'decision',
      data: { comparisonStage: 'source', evidenceSummary: 'trusted_server_reference_v1' },
    },
    {
      node: 'judge_compare_effect_model',
      type: 'node_end',
      data: { comparisonStage: 'effect', provider: 'ollama', model: 'llama3.1:8b' },
    },
  ]);
  assert.equal(JSON.stringify(recorded).includes('PRIVATE_MODEL_OUTPUT'), false);
});

test('production DPI reference Judge survives coordinator and trace projection without protected bytes', async () => {
  const calibration = require('./fixtures/dpiSystemPromptV3JudgeCalibration');
  const item = (await calibration.cases()).find(row => row.definition.id === 'invented_configuration');
  const recorded = [];
  const ledger = {
    begin: async () => ({ durableGeneration: '5' }),
    assertCurrent: async () => {},
    recordEvent: async (_context, event) => recorded.push(event),
    finish: async () => {},
  };
  const model = { chat: async messages => {
    const input = JSON.parse(messages[1].content);
    return {
      response: JSON.stringify({
        passages: Object.fromEntries(input.response_passages.map(row => [row.id, {
          relation: 'invented', refs: [],
        }])),
        explanation: 'Controlled negative comparison.',
      }),
      provider: 'controlled', model: 'controlled', mocked: false, fallback: false,
    };
  } };
  const judge = require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({ model });
  const coordinator = createRunCoordinator({ family: 'DPI', ledger });
  const result = await coordinator.run('8', {}, execution => judge({
    ...item.packet,
    execution: { ...execution, ownerId: '8', emit: execution.trace },
  }));

  assert.equal(result.verdict, 'fail');
  assert.ok(recorded.some(event => event.node === 'judge_compare_source_validate'
    && event.type === 'decision'
    && event.data.evidenceSummary === 'trusted_server_reference_v1'));
  assert.ok(recorded.some(event => event.node === 'judge_compare_effect_model'
    && event.type === 'node_end'
    && event.data.comparisonStage === 'effect'));
  const serialized = JSON.stringify(recorded);
  assert.equal(serialized.includes(item.packet.evidence.find(row => row.id === 'protected_reference').content.protectedConfiguration), false);
  assert.equal(serialized.includes(item.packet.evidence.find(row => row.id === 'response').content), false);
});

test('identity migration admits only the same bounded comparison stage enum', () => {
  const sql = fs.readFileSync(path.join(__dirname,
    '../db/postgres/identity-migrations/0067_graph_observability_metadata.sql'), 'utf8');
  assert.match(sql, /events_metadata_keys_check/);
  assert.match(sql, /'comparisonStage'/);
  assert.match(sql, /IN \('source','effect','support'\)/);
  assert.match(sql, /events_reviewer_profile_check/);
  assert.match(sql, /ctf-stage5-learner-claimed-telemetry/);
  assert.match(sql, /structured-artifact-v1/);
  const allowedKeys = sql.match(/metadata - ARRAY\[([^\]]+)\]/)?.[1] || '';
  assert.doesNotMatch(allowedKeys, /rawResponse|prompt|citation|evidenceDigest/);
});
