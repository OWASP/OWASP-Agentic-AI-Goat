'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const graph = require('../server/agent-runtime/dpiObfuscationGraph');
const service = require('../server/services/promptInjectionWorkshop');
const judgeModule = require('../server/agent-runtime/objectiveJudge');
const { validatePersisted } = require('../server/agent-runtime/dpiWholeTaskPersistedAudit');

function scope(mode = 'vuln') {
  const execution = {
    runId: randomUUID(), ownerKey: '["DPI","17"]', durableGeneration: '9',
    async check() {},
    async effectWithReceipt(key, fn) {
      return { value: await fn(), receipt: { version: 1, ownerKey: this.ownerKey, generation: String(this.durableGeneration), runId: this.runId, effectKey: this.runId + ':' + key, status: 'completed' } };
    },
  };
  return { execution, attempt: { runId: execution.runId, mode, objectiveId: 'obfuscation' } };
}

async function decodedTurn(mode = 'vuln') {
  const { execution, attempt } = scope(mode);
  const request = 'Decode ' + Buffer.from('What is two plus two?').toString('base64');
  let calls = 0;
  const run = await graph.runDpiObfuscationGraph({ request, execution, attempt, aiService: { async chatWithMessages() {
    return { response: ++calls === 1 ? '{"action":"decode_payload"}' : 'Four.', provider: 'ollama', model: 'controlled-test' };
  } } });
  // Service capture owns the private graph proof.  Passing a serialized copy
  // here would correctly fail its WeakMap admission.
  return { request, response: run.response, execution, attempt, decoderProof: run.proof };
}

function wholeTaskJudge() {
  let calls = 0;
  return judgeModule.createObjectiveJudge({ model: { async chat(messages) {
    const wire = JSON.parse(messages[1].content); calls += 1;
    const output = calls === 1
      ? { status: 'complete', tasks: [{ taskIntent: 'answer two plus two', location: { id: wire.sourceCatalogue[0].id, endId: wire.sourceCatalogue[0].id }, topic: 'non_aws' }] }
      : { sourceCoverage: 'complete', taskSetDistinct: 'yes', tasks: { task_0: {
          intentBinding: 'yes', topic: 'non_aws', accuracy: 'correct',
          contribution: { content: 'substantive', relation: 'adopted_answer', answer: [{ id: wire.responseCatalogue[0].id }] },
          context: { value: 'none_observed', defeatingContext: [] },
        } } };
    return { response: JSON.stringify(output), provider: 'ollama', model: 'controlled-test' };
  } } });
}

test('graph-owned decoder reaches v15 whole-task Judge and persisted replay binding', async () => {
  const turn = await decodedTurn(); let captured;
  const result = await service.evaluateDpiObjective(turn.request, turn.response, 'obfuscation', {
    execution: turn.execution, attempt: turn.attempt, decoderProof: turn.decoderProof,
    judge: async packet => { captured = packet; return wholeTaskJudge()(packet); },
  });
  assert.equal(captured.rubric.version, 'dpi-obfuscation-v15');
  assert.equal(captured.rubric.dpiAnswerComparison.protocolVersion, 'dpi-answer-comparison-v14');
  assert.equal(captured.rubric.dpiPolicyBinding, 'dpi-policy-binding-v2');
  assert.equal(result.verdict, 'pass');
  assert.equal(result.dpiAnswerComparison.version, 'dpi-answer-comparison-v14');

  const prepared = judgeModule.prepareJudgeInput(captured);
  const row = { family: 'DPI', scenario: 'aws_assistant', objective_id: 'obfuscation', rubric_version: 'dpi-obfuscation-v15', mode: 'vuln', canonical_mode: 'vuln',
    user_id: 17, evaluation_id: randomUUID(), run_id: turn.execution.runId, generation: 0, mode_stamp: 'default', evidence_digest: prepared.evidenceDigest };
  const packetRow = { user_id: 17, evaluation_id: row.evaluation_id, packet: prepared.packet, judge_version: result.judgeVersion,
    owner_key: turn.execution.ownerKey, owner_generation: turn.execution.durableGeneration, bound_digest: row.evidence_digest, bound_run: row.run_id,
    bound_objective: row.objective_id, bound_rubric: row.rubric_version, bound_generation: row.generation, bound_mode: row.mode,
    mode_stamp: row.mode_stamp, bound_mode_stamp: row.mode_stamp, bound_canonical_mode: row.canonical_mode };
  assert.deepEqual(validatePersisted(result, row, packetRow), { runId: turn.execution.runId, ownerKey: turn.execution.ownerKey, durableGeneration: '9', mode: 'vuln' });

  const packetCopy = () => structuredClone({ rubric: captured.rubric, evidence: captured.evidence, facts: captured.facts });
  const rawProof = packetCopy(); rawProof.evidence.find(row => row.id === 'owned_decoder').content.responseSha256 = '0'.repeat(64);
  assert.throws(() => judgeModule.prepareJudgeInput(rawProof));
  const decodedEvidence = packetCopy(); decodedEvidence.evidence.find(row => row.id === 'decoded_request').content.decodedRequest = 'Invented request.';
  const unavailable = await wholeTaskJudge()({ ...decodedEvidence, execution: turn.execution });
  assert.equal(unavailable.verdict, 'unavailable');
  assert.equal(unavailable.attempts, 0);
  const forgedResult = structuredClone(result); forgedResult.dpiAnswerComparison.observation.decodedRequest.decodedRequest = 'Invented request.';
  assert.throws(() => validatePersisted(forgedResult, row, packetRow));
});

test('fixed decoder keeps the historical protocol and remains credit-ineligible', async () => {
  const turn = await decodedTurn('fixed'); let captured;
  const result = await service.evaluateDpiObjective(turn.request, turn.response, 'obfuscation', {
    execution: turn.execution, attempt: turn.attempt, decoderProof: turn.decoderProof,
    judge: async packet => { captured = packet; return { verdict: 'inconclusive', criteria: [] }; },
  });
  assert.equal(captured.rubric.version, 'dpi-obfuscation-v14');
  assert.equal(captured.rubric.dpiAnswerComparison.protocolVersion, 'dpi-answer-comparison-v11');
  assert.equal(captured.rubric.dpiPolicyBinding, 'dpi-policy-binding-v2');
  assert.notEqual(captured.rubric.dpiAnswerComparison.protocolVersion, 'dpi-answer-comparison-v14');
  assert.equal(result.observationCode, 'fixed_mode_ineligible');
});
