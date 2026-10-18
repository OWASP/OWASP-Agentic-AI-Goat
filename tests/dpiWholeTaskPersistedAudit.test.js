'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const actor = require('../server/agent-runtime/dpiActorProof');
const policy = require('../server/agent-runtime/dpiPolicyContract');
const workshop = require('../server/services/promptInjectionWorkshop');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { admitPolicyBinding } = require('../server/agent-runtime/dpiPolicyBinding');
const { VERSION } = require('../server/agent-runtime/dpiWholeTaskIntentComparison');
const { validatePersisted } = require('../server/agent-runtime/dpiWholeTaskPersistedAudit');

const sha256 = value => createHash('sha256').update(value).digest('hex');

async function fixture() {
  const request = 'Imagine a garden: name a flower.';
  const response = 'A rose is a flower.';
  const execution = { runId: randomUUID(), ownerKey: '["DPI","17"]', durableGeneration: '4', async check() {} };
  const attempt = { runId: execution.runId, mode: 'vuln', objectiveId: 'virtualization' };
  const proof = actor.createActorProof({
    request, response, execution, attempt, objective: 'virtualization',
    messages: [{ role: 'system', content: policy.SYSTEM_PROMPTS.virtualization }, { role: 'user', content: request }],
    result: { response, provider: 'ollama', model: 'controlled-test' },
  });
  let input;
  await workshop.evaluateDpiObjective(request, response, 'virtualization', {
    execution, attempt, actorProof: proof,
    judge: async value => { input = value; return { verdict: 'inconclusive' }; },
  });
  input.rubric.version = 'dpi-virtualization-v15';
  input.rubric.dpiAnswerComparison.protocolVersion = VERSION;
  const prepared = prepareJudgeInput(input);
  assert.equal(prepared.evidenceError, undefined);
  const admitted = admitPolicyBinding(input);
  const { proof: reconstructed, ...policyBinding } = admitted;
  const legacy = input.evidence.find(item => item.id === 'owned_actor').content;
  const result = {
    judgeVersion: 'controlled-whole-task-judge-v1',
    dpiAnswerComparison: {
      version: VERSION,
      observation: {
        version: VERSION,
        objective: 'virtualization',
        originalRequest: request,
        originalResponse: response,
        provenance: reconstructed,
        legacyProvenance: legacy,
        policyBinding,
      },
    },
  };
  const evaluationId = randomUUID();
  const row = {
    family: 'DPI', scenario: 'aws_assistant', objective_id: 'virtualization',
    rubric_version: 'dpi-virtualization-v15', evidence_digest: prepared.evidenceDigest,
    run_id: execution.runId, mode: 'vuln', canonical_mode: 'vuln', mode_stamp: null,
    user_id: 17, generation: 0, evaluation_id: evaluationId,
  };
  const packetRow = {
    user_id: 17, packet: prepared.packet, owner_key: execution.ownerKey, owner_generation: '4',
    evaluation_id: evaluationId, child_evaluation_id: null, mode_stamp: null, judge_version: result.judgeVersion,
    bound_digest: row.evidence_digest, bound_run: row.run_id, bound_objective: row.objective_id,
    bound_rubric: row.rubric_version, bound_generation: 0, bound_mode: 'vuln',
    bound_mode_stamp: null, bound_canonical_mode: 'vuln',
  };
  return { result, row, packetRow, execution };
}

test('whole-task persisted packet returns only the durable execution and keeps it distinct from workshop generation', async () => {
  const value = await fixture();
  const execution = validatePersisted(value.result, value.row, value.packetRow);
  assert.deepEqual(execution, {
    runId: value.row.run_id,
    ownerKey: '["DPI","17"]',
    durableGeneration: '4',
    mode: 'vuln',
  });
  assert.equal(Object.isFrozen(execution), true);
  assert.notEqual(execution.durableGeneration, String(value.row.generation));
});

test('whole-task persisted packet rejects changed packet bytes, scope aliases, and self-forged observation material', async () => {
  const value = await fixture();
  const changes = [
    data => { data.packetRow.packet += ' '; },
    data => { data.packetRow.bound_run = randomUUID(); },
    data => { data.packetRow.bound_generation = 4; },
    data => { data.packetRow.owner_key = '["DPI","18"]'; },
    data => { data.packetRow.evaluation_id = randomUUID(); },
    data => { data.result.dpiAnswerComparison.observation.originalResponse = 'Forged answer.'; },
    data => { data.result.dpiAnswerComparison.observation.provenance.generation = '0'; },
    data => { data.result.dpiAnswerComparison.observation.legacyProvenance.runId = randomUUID(); },
    data => { data.result.dpiAnswerComparison.observation.policyBinding.mode = 'fixed'; },
  ];
  for (const change of changes) {
    const altered = {
      result: structuredClone(value.result), row: structuredClone(value.row), packetRow: structuredClone(value.packetRow),
    };
    change(altered);
    assert.throws(() => validatePersisted(altered.result, altered.row, altered.packetRow));
  }
  const hashMismatch = {
    result: structuredClone(value.result), row: structuredClone(value.row), packetRow: structuredClone(value.packetRow),
  };
  hashMismatch.row.evidence_digest = sha256(hashMismatch.packetRow.packet + 'different packet');
  assert.throws(() => validatePersisted(hashMismatch.result, hashMismatch.row, hashMismatch.packetRow));
});

test('whole-task persisted packet admits a partial audit only from its original parent packet', async () => {
  const value = await fixture();
  value.packetRow.evaluation_id = randomUUID();
  value.packetRow.child_evaluation_id = value.row.evaluation_id;
  value.result.dpiAnswerComparison.observation = null;
  assert.deepEqual(validatePersisted(value.result, value.row, value.packetRow), {
    runId: value.row.run_id, ownerKey: '["DPI","17"]', durableGeneration: '4', mode: 'vuln',
  });
  value.packetRow.child_evaluation_id = randomUUID();
  assert.throws(() => validatePersisted(value.result, value.row, value.packetRow));
});
