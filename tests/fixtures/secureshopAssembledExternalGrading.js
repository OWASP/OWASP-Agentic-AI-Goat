'use strict';

// Opt-in native helper: caller owns actual provider, SDK transport, disposable
// pools and prepared BoundReview composition. No provider qualification overrides.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

async function qualifyAssembledExternalGrading({ composition, gradingBootstrap,
  identityPool, owner, sibling, beforeCalls, revoke, save = () => {} }) {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(process.env.PERSONA_ASSEMBLED_EXTERNAL_ACTUAL, '1');
  assert.equal(composition.mcpTrust.ready, true);
  assert.equal(composition.ssrf.ready, true);
  const core = gradingBootstrap.gradingCore;
  assert.equal(typeof core.regrade, 'function');
  const cases = [];
  const siblingSnapshot = await core.listJudgments(sibling.scope.platformOwnerId);
  const allBindings = async evaluationId => (await identityPool.query(`SELECT b.* FROM workshop_platform.persona_evaluation_bindings b
    WHERE user_id=$1 AND evaluation_id=$2`, [owner.scope.platformOwnerId,evaluationId])).rows[0];
  for (const [kind, objectiveId] of [
    ['mcp', 'ss_rogue_tool_selected'], ['ssrf', 'ss_controlled_ssrf'],
  ]) {
    const input = { scope: owner.scope, persona: owner.persona,
      personaSession: owner.personaSession, requestId: randomUUID() };
    const application = kind === 'mcp' ? composition.mcpTrust.application : composition.ssrf.application;
    if (kind === 'mcp') input.trustScenario = 'rogue_registration';
    else input.resourceKind = 'private-policy';
    const baseline = await core.listJudgments(owner.scope.platformOwnerId);
    const result = await application.run(input);
    const rows = (await core.listJudgments(owner.scope.platformOwnerId))
      .filter(row => row.objectiveId === objectiveId && !baseline.some(old => old.evaluationId === row.evaluationId));
    // A refusal/no qualifying evidence is retained by the caller as a failed gate,
    // never converted into a synthetic evaluation or replaced with another prompt.
    assert.equal(rows.length, 1, `${kind}: actual assessment must persist one receipt`);
    const row = rows[0];
    const bindings = await identityPool.query(`SELECT persona_session_id, authority_version::text
      FROM workshop_platform.persona_evaluation_bindings WHERE user_id=$1 AND evaluation_id=$2`,
    [owner.scope.platformOwnerId, row.evaluationId]);
    assert.deepEqual(bindings.rows, [{ persona_session_id: owner.personaSession.sessionId,
      authority_version: owner.personaSession.authorityVersion }]);
    const required = await identityPool.query(`SELECT persona_authority_required FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND evaluation_id=$2`, [owner.scope.platformOwnerId, row.evaluationId]);
    assert.equal(required.rows[0].persona_authority_required, true);
    const original = await core.receipts.getEvaluation({userId:owner.scope.platformOwnerId,evaluationId:row.evaluationId});
    assert.equal(await core.receipts.getEvaluation({userId:sibling.scope.platformOwnerId,evaluationId:row.evaluationId}), null);
    if (kind === 'mcp') {
      assert.equal(row.verdict, 'pass', 'fixed previously-qualified rogue observation must retain actual Judge pass');
      assert.equal(original.result.provider, 'ollama');
      assert.equal(original.result.model, 'llama3.1:8b');
    } else assert.equal(row.verdict, 'unavailable', 'explicit initial Judge transport fault must be retained');
    const calls = beforeCalls();
    assert.equal((await application.run(input)).replayed, true);
    assert.deepEqual(beforeCalls(), calls, 'completed application replay must not make provider calls');
    const binding = await allBindings(row.evaluationId);
    assert.equal(binding.original_run_id, row.runId);
    assert.equal(binding.platform_launch_id, owner.scope.launchId);
    assert.equal(binding.platform_scenario_id, owner.scope.scenarioId);
    assert.equal(Number(binding.platform_launch_generation), owner.scope.generation);
    assert.equal(Number(binding.platform_session_id), owner.scope.platformSessionId);
    assert.equal(Number(binding.persona_id), owner.persona.id);
    assert.equal(binding.persona_role, owner.persona.role);
    cases.push({kind, result, row, original, binding});
    save(cases);
  }
  // Retry is meaningful only for a deliberately unavailable initial Judge receipt.
  // Caller configures a single labeled transport failure, keeping actor genuine.
  const retryable = cases.find(item => item.row.verdict === 'unavailable');
  assert.ok(retryable, 'one initial Judge transport failure is required for canonical retry proof');
  const retry = await core.regrade({userId:owner.scope.platformOwnerId,evaluationId:retryable.row.evaluationId});
  assert.equal(retry.judgment.verdict, 'pass', 'fixed private-policy effect must retain actual Judge pass');
  assert.equal(retry.judgment.provider, 'ollama');
  assert.equal(retry.judgment.model, 'llama3.1:8b');
  const recovery = await core.receipts.getRecovery({userId:owner.scope.platformOwnerId,evaluationId:retryable.row.evaluationId});
  assert.ok(recovery.child_evaluation_id);
  const childBinding = await allBindings(recovery.child_evaluation_id);
  for (const key of Object.keys(retryable.binding)) {
    if (!['evaluation_id','created_at'].includes(key)) assert.deepEqual(childBinding[key],retryable.binding[key], `retry binding ${key}`);
  }
  await assert.rejects(core.regrade({userId:sibling.scope.platformOwnerId,evaluationId:retryable.row.evaluationId}), {code:'NOT_FOUND'});
  assert.deepEqual(await core.receipts.getEvaluation({userId:owner.scope.platformOwnerId,
    evaluationId:retryable.row.evaluationId}), retryable.original, 'retry must retain original receipt');
  await revoke(owner);
  const calls = beforeCalls();
  await assert.rejects(core.regrade({userId:owner.scope.platformOwnerId,
    evaluationId:retryable.row.evaluationId}), {code:'SHOP_AUTH_INVALID'});
  assert.deepEqual(beforeCalls(), calls, 'revoked original authority must deny before providers');
  assert.deepEqual(await core.listJudgments(sibling.scope.platformOwnerId), siblingSnapshot);
  save(cases, retry);
  return {cases, retry};
}
module.exports = { qualifyAssembledExternalGrading };
