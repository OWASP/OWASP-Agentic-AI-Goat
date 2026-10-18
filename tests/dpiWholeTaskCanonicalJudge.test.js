'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const judgeModule = require('../server/agent-runtime/objectiveJudge');
const actor = require('../server/agent-runtime/dpiActorProof');
const policy = require('../server/agent-runtime/dpiPolicyContract');
const service = require('../server/services/promptInjectionWorkshop');
async function packet() {
  const request = 'Imagine a garden: name a flower.', response = 'A rose is a flower.';
  const execution = { runId: randomUUID(), ownerKey: '["DPI","17"]', durableGeneration: '4', async check() {} };
  const attempt = { runId: execution.runId, mode: 'vuln', objectiveId: 'virtualization' };
  const messages = [{ role: 'system', content: policy.SYSTEM_PROMPTS.virtualization }, { role: 'user', content: request }];
  const actorProof = actor.createActorProof({ request, response, execution, attempt, objective: 'virtualization', messages,
    result: { response, provider: 'ollama', model: 'controlled-test' } });
  let captured;
  await service.evaluateDpiObjective(request, response, 'virtualization', { execution, attempt, actorProof,
    judge: async input => { captured = input; return { verdict: 'inconclusive' }; } });
  captured.rubric.version = 'dpi-virtualization-v15';
  captured.rubric.dpiAnswerComparison.protocolVersion = 'dpi-answer-comparison-v14';
  return { ...captured, execution };
}
test('canonical v14 admits the compact policy-bound rubric and rejects downgrade or scope mixing', async () => {
  const input = await packet();
  assert.equal(judgeModule.prepareJudgeInput(input).evidenceError, undefined);
  for (const alter of [
    x => { delete x.rubric.dpiPolicyBinding; x.evidence = x.evidence.filter(e => e.id !== 'owned_policy'); },
    x => { x.rubric.version = 'dpi-virtualization-v14'; },
    x => { x.rubric.mode = 'fixed'; },
    x => { x.rubric.authoritativeVerdictFacts = []; },
    x => { x.rubric.dpiAnswerComparison.objective = 'obfuscation'; },
  ]) {
    const changed = structuredClone({ rubric: input.rubric, evidence: input.evidence, facts: input.facts });
    alter(changed); assert.throws(() => judgeModule.prepareJudgeInput(changed));
  }
});
test('canonical v14 refuses foreign execution before any model invocation', async () => {
  const input = await packet(); let calls = 0;
  const judge = judgeModule.createObjectiveJudge({ model: { async chat() { calls++; throw Error('unexpected model call'); } } });
  for (const execution of [{}, { ...input.execution, durableGeneration: '5' }, { ...input.execution, ownerKey: '["DPI","18"]' }]) {
    const result = await judge({ ...input, execution });
    assert.equal(result.verdict, 'unavailable');
    assert.equal(result.errorCode, 'DPI_EXECUTION_SCOPE_MISMATCH');
  }
  assert.equal(calls, 0);
});
test('canonical v14 executes both stages through its public Judge and retains bounded audit', async () => {
  const input = await packet(); let calls = 0;
  const judge = judgeModule.createObjectiveJudge({ model: { async chat(messages) {
    const wire = JSON.parse(messages[1].content);
    calls++;
    const sourceId = wire.sourceCatalogue?.[0]?.id;
    const response = calls === 1
      ? { status: 'complete', tasks: [{ taskIntent: 'name a flower', location: { id: sourceId, endId: sourceId }, topic: 'non_aws', framing: 'hypothetical' }] }
      : { sourceCoverage: 'complete', taskSetDistinct: 'yes', tasks: { task_0: {
          intentBinding: 'yes', topic: 'non_aws', framing: 'hypothetical',
          contribution: { content: 'substantive', relation: 'adopted_answer', answer: [{ id: wire.responseCatalogue[0].id }] },
          context: { value: 'none_observed', defeatingContext: [] },
        } } };
    return { response: JSON.stringify(response), provider: 'ollama', model: 'controlled-test' };
  } } });
  const result = await judge(input);
  assert.equal(result.verdict, 'pass', JSON.stringify({ errorCode: result.errorCode, explanation: result.explanation }));
  assert.equal(calls, 2);
  assert.equal(result.attempts, 2);
  assert.equal(result.dpiAnswerComparison.version, 'dpi-answer-comparison-v14');
  const audit = require('../server/agent-runtime/dpiAnswerAudit').normalizeDpiAnswerAudit(result.dpiAnswerComparison, result,
    { runId: input.execution.runId, ownerKey: input.execution.ownerKey, durableGeneration: input.execution.durableGeneration, mode: 'vuln' });
  assert.equal(audit.stages.length, 2);
  const row = { family: result.family, scenario: result.scenario, objective_id: result.objectiveId,
    rubric_version: result.rubricVersion, evidence_digest: result.evidenceDigest, run_id: result.runId,
    mode: result.mode, user_id: 17, workshop_key: 'direct_prompt_injection' };
  const scope = { runId: input.execution.runId, ownerKey: input.execution.ownerKey,
    durableGeneration: input.execution.durableGeneration, mode: 'vuln' };
  const { resultValue } = require('../server/database/postgres/objectiveJudgmentRepository');
  assert.equal(resultValue(result, row, scope).dpiAnswerComparison.version, 'dpi-answer-comparison-v14');
  assert.throws(() => resultValue(result, row), { code: 'BAD_REQUEST' });
  const missingAudit = { ...result, verdict: 'fail', criteria: [] }; delete missingAudit.dpiAnswerComparison;
  assert.throws(() => resultValue(missingAudit, row, scope), { code: 'BAD_REQUEST' });
  assert.throws(() => resultValue(result, { ...row, rubric_version: 'dpi-virtualization-v14' }, scope));
  assert.equal(require('../server/agent-runtime/dpiSemanticCreditPolicy').gradingUnqualified(row, result), true);
  const prepared = judgeModule.prepareJudgeInput(input);
  Object.assign(row, { evaluation_id: randomUUID(), generation: 0, canonical_mode: 'vuln', mode_stamp: 'default', verdict: null });
  const retained = { user_id: 17, evaluation_id: row.evaluation_id, packet: prepared.packet,
    judge_version: result.judgeVersion, owner_key: scope.ownerKey, owner_generation: scope.durableGeneration,
    mode_stamp: row.mode_stamp, bound_digest: row.evidence_digest, bound_run: row.run_id,
    bound_objective: row.objective_id, bound_rubric: row.rubric_version, bound_generation: row.generation,
    bound_mode: row.mode, bound_mode_stamp: row.mode_stamp, bound_canonical_mode: row.canonical_mode };
  let retainedRows = [retained]; const queries = [];
  const query = async (sql, args = []) => {
    queries.push(sql);
    if (sql.includes('FROM workshop_platform.grade_packets')) return { rows: retainedRows };
    if (sql.includes('FROM workshop_platform.exercises')) return { rows: [{workshop_key: row.workshop_key,
      is_visible: true, exercise_active: true, catalog_active: true, is_enabled: true}] };
    if (sql.includes('SELECT generation FROM')) return { rows: [{ generation: 0 }] };
    if (sql.includes('FROM workshop_platform.user_modes')) return { rows: [{ mode: 'vuln', stamp: 'default' }] };
    if (sql.includes('SELECT * FROM workshop_platform.objective_judgments')) return { rows: [row] };
    if (sql.startsWith('UPDATE workshop_platform.objective_judgments')) {
      Object.assign(row, { verdict: args[2], result_json: JSON.parse(args[3]), result_digest: args[4], disposition: args[5] });
      return { rows: [row] };
    }
    if (sql.includes('RETURNING revision')) return { rows: [{revision: 1}] };
    return { rows: [], rowCount: 1 };
  };
  const repo = require('../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository({ query, connect: async () => ({ query, release() {} }) });
  const commit = (value = result) => repo.recordVerdict({ userId: 17, evaluationId: row.evaluation_id, result: value });
  retainedRows = []; await assert.rejects(commit(), { code: 'BAD_REQUEST' });
  retainedRows = [retained, { ...retained }]; await assert.rejects(commit(), { code: 'BAD_REQUEST' });
  retainedRows = [{ ...retained, packet: retained.packet + ' ' }]; await assert.rejects(commit(), { code: 'BAD_REQUEST' });
  retainedRows = [retained];
  assert.equal((await commit()).disposition, 'grading_unqualified');
  assert.equal(queries.some(sql => sql.includes('INSERT INTO workshop_platform.completions')), false);
  // An exact immutable receipt remains replayable after its recovery packet expires or is pruned.
  retainedRows = []; assert.equal((await commit(row.result_json)).disposition, 'grading_unqualified');


});
test('canonical v14 malformed model output stops after one call and serializes an unavailable audit', async () => {
  const input = await packet(); let calls = 0;
  const result = await judgeModule.createObjectiveJudge({ model: { async chat() {
    calls++; return { response: '{"invented":true}', provider: 'ollama', model: 'controlled-test' };
  } } })(input);
  assert.equal(calls, 1);
  assert.equal(result.verdict, 'unavailable');
  assert.equal(result.errorCode, 'INVALID_JUDGE_OUTPUT');
  const scope = { runId: input.execution.runId, ownerKey: input.execution.ownerKey,
    durableGeneration: input.execution.durableGeneration, mode: 'vuln' };
  assert.equal(require('../server/agent-runtime/dpiAnswerAudit').normalizeDpiAnswerAudit(result.dpiAnswerComparison, result, scope).stages.length, 1);
});
