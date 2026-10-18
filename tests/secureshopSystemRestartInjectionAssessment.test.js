'use strict';

// Controlled stores exercise the real assessment and canonical completion
// machinery. No executor, browser, database or configured model is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { fixture: sourceFixture } = require('./secureshopSystemRestartInjectionEvidence.test');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createLaunchScope } = require('../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const implementation = require('../server/services/secureshopSystemRestartInjectionAssessment');
const OBJECTIVE = 'ss_system_restart_command_injection';
const hash = value => createHash('sha256').update(value).digest('hex');

function fixture({ original: suppliedOriginal, readSource: protectedReader } = {}) {
  const original = suppliedOriginal || sourceFixture(), a = original.input;
  const scope = createLaunchScope(a.binding), persona = { id: a.binding.shopUserId, role: 'admin' };
  const session = { ...a.personaSession };
  const source = { turn: a.turn, traces: a.traces, operation: a.operation,
    run: a.run, preparationEffect: a.preparationEffect, sourceBinding: original.sourceBinding, fullReceipt:a.fullReceipt };
  const envelope = JSON.parse(a.turn.taskMetadata.roleChat.systemRestartInjectionOrigin.sourceEnvelope);
  const scene = createSceneBinding({ ...scope, targetId: envelope.targetId }, {
    sceneId: envelope.sceneId, sceneGeneration: envelope.sceneGeneration, grantId: original.sourceBinding.grant_id,
    execution: scope, withLease: work => work(),
  });
  const assessmentSession = randomUUID(), assessmentRun = randomUUID();
  const owner = JSON.stringify(['SecureShopBoundConversation', assessmentSession]);
  const publication = { mode: 'vuln', generation: 1, modeStamp: 'a'.repeat(64) };
  const adminMode = { ...a.systemExecution, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1' };
  let currentScene = scene, enabled = true, active = true, sourceError = null;
  let journalRow = null, canonicalRow = null, packet = null, onJudge = () => {}, afterAdmission = () => {}, completeError = null, judgePass = false;
  const calls = { source: 0, judge: 0, claim: 0, complete: 0, verdict: 0, acquire: 0, effects: 0, uncertain: 0 };
  const check = async () => { if (!active) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); };
  const identityPool = { async query(sql, params) {
    if (sql.includes('identity.secureshop_authority_owners')) return { rows: [{ realm: 'platform', shop_tenant_id: null }] };
    if (sql.includes('workshop_platform.objectives')) return { rows: enabled ? [{ objective_id: OBJECTIVE }] : [] };
    if (sql.includes('FROM secureshop_auth.execution_authority_state')) {
      if (sql.includes('j.run_id=$5')) {
        assert.match(sql, /NOT EXISTS[\s\S]*retry\.child_id=j\.evaluation_id/);
        assert.match(sql, /current_tenant_id[\s\S]*current_principal_id[\s\S]*current_membership_version[\s\S]*live_owner_generation/);
        assert.deepEqual(params, [scope.platformSessionId, scope.platformOwnerId, persona.id,
          OBJECTIVE, canonicalRow.run_id, canonicalRow.owner_key, canonicalRow.packet, canonicalRow.evidence_digest]);
      }
      return { rows: canonicalRow ? [canonicalRow] : [] };
    }
    throw Error('Unexpected controlled identity query: ' + sql);
  } };
  const journal = {
    async claim(input) {
      calls.claim++;
      if (journalRow) return { status: journalRow.status, result: journalRow.result_json, claimId: 'controlled-claim' };
      const request = createTurnRequest(input);
      journalRow = { session_id: input.sessionId, request_id: input.requestId,
        request_hash: request.hash, request_version: request.version, status: 'started', result_json: null };
      return { status: 'claimed', claimId: 'controlled-claim' };
    },
    async complete(input) {
      await check(); if (completeError) throw completeError;
      calls.complete++; journalRow.status = 'completed'; journalRow.result_json = structuredClone(input.result);
    },
    async markUncertain() { calls.uncertain++; if (journalRow?.status !== 'completed') journalRow.status = 'uncertain'; },
  };
  const conversationRepository = {
    async getBoundSession(id) {
      return id === assessmentSession ? { id, state: 'active', purpose: 'persona_inbox', binding: a.binding }
        : id === a.sessionId ? { id, state: 'active', purpose: 'secureshop_admin_assistant', binding: a.binding } : null;
    },
    async acquireBoundSession() { calls.acquire++; return { id: assessmentSession, state: 'active' }; },
  };
  const tenantId = randomUUID(), principalId = randomUUID();
  const service = implementation.createSystemRestartInjectionAssessment({ identityPool,
    agentsPool: { async query(sql) {
      assert.match(sql, /secureshop_agents\.turn_requests/);
      return { rows: journalRow ? [journalRow] : [] };
    } }, launches: { assertCurrent: check }, conversationRepository, journal,
    coordinator: { async run(_id, options, work) {
      const admitted = await options.admit(); if (admitted.skip) return admitted.value;
      await afterAdmission();
      return work({ runId: assessmentRun, ownerKey: owner, durableGeneration: '0', check,
        async effectWithReceipt() { calls.effects++; throw Error('Assessment cannot execute diagnostic'); } });
    } },
    personaAuthority: { capture: input => ({ binding: { ...createLaunchScope(input.scope),
      personaId: input.personaId, role: input.role, sessionId: input.sessionId,
      authorityVersion: input.authorityVersion }, assertRemoteAdmission: check }) },
    personaBindings: { capture: async () => ({ controlled: true }) },
    scenes: { readRetained: async () => currentScene },
    modeAuthority: { async capture(_scope, feature) {
      const current = () => feature === 'system_restart' ? a.systemExecution : adminMode;
      const snapshot = structuredClone(current());
      return { snapshot, async assertCurrent() { await check(); assert.deepEqual(current(), snapshot); } };
    }, assertToken: value => value },
    publicationModes: { getEvaluationScope: async () => publication },
    progress: { getGeneration: async () => publication.generation, getEvaluationScope: async () => publication },
    receipts: {
      async beginEvaluation(input) {
        const rubric = JSON.parse(input.recovery.packet).rubric;
        canonicalRow = { tenant_id: tenantId, principal_id: principalId, evaluation_id: input.evaluationId,
          shop_user_id: persona.id, workshop_key: 'secureshop_agent_security', objective_id: OBJECTIVE,
          family: rubric.family, scenario: rubric.scenario, rubric_version: rubric.version,
          mode: publication.mode, generation: publication.generation, mode_stamp: publication.modeStamp,
          owner_key: owner, owner_generation: '0', live_owner_generation: '0',
          current_tenant_id: tenantId, current_principal_id: principalId, current_membership_version: '1',
          run_id: assessmentRun, execution_json: { tenantId, principalId, membershipVersion: '1', scope,
            personaSessionId: session.sessionId, personaAuthorityVersion: session.authorityVersion,
            role: 'admin', runId: assessmentRun }, packet: input.recovery.packet,
          evidence_digest: hash(input.recovery.packet), child_id: null };
        return { verdict: null };
      },
      async recordVerdict({ result }) {
        calls.verdict++; const serialized = JSON.stringify(result);
        Object.assign(canonicalRow, { verdict: result.verdict, disposition: 'not_pass',
          result_json: result, result_serialized: serialized, result_digest: hash(serialized) });
        return { verdict: result.verdict, disposition: 'not_pass', result };
      },
    },
    qualifyModel: a.qualifyModel,
    async readSource(input) {
      calls.source++; await check();
      assert.equal(input.sessionId, a.sessionId); assert.equal(input.requestId, a.requestId);
      assert.equal(input.proposalId, undefined);
      if (sourceError) throw sourceError;
      return protectedReader ? protectedReader(input) : structuredClone(source);
    },
    async judge(input) {
      calls.judge++; packet = prepareJudgeInput(input).packet; await onJudge();
      if (judgePass) return { verdict: 'pass', explanation: 'Controlled positive verdict is not registered model provenance',
        criteria: [{ id: 'additional_command_executed', satisfied: true,
          evidenceRefs: ['system_restart_command', 'system_restart_execution'],
          citations: [{ evidenceId: 'system_restart_command', quote: input.evidence[1].content.command },
            { evidenceId: 'system_restart_execution', quote: input.evidence[2].content.stdout }] }] };
      return { verdict: 'fail', explanation: 'Controlled negative Judge; no credit', criteria: [] };
    },
  });
  const input = { scope, persona, personaSession: session, sessionId: a.sessionId,
    requestId: a.requestId };
  return { service, input, source, original, calls, publication,
    get journalRow() { return journalRow; }, get canonicalRow() { return canonicalRow; }, get packet() { return packet; },
    revoke() { active = false; }, disable() { enabled = false; },
    setScene(value) { currentScene = value; }, sourceError(error) { sourceError = error; },
    onJudge(fn) { onJudge = fn; }, afterAdmission(fn) { afterAdmission = fn; }, onCompleteError(error) { completeError = error; },
    controlledPositiveJudge() { judgePass = true; } };
}

module.exports = { fixture };
if (require.main === module) {
test('V04 assessment and GET recovery never dispatch diagnostics or regrade terminal evidence', async () => {
  const f = fixture();
  assert.deepEqual(await f.service.readOutcome(f.input), { completed: false, status: 'unconfirmed', modelEvaluated: false });
  const result = await f.service.runAttempt(f.input);
  assert.equal(result.completed, false); assert.equal(result.judgment.verdict, 'fail');
  assert.equal(f.calls.judge, 1); assert.equal(f.calls.verdict, 1); assert.equal(f.calls.effects, 0);
  assert.deepEqual(await f.service.readOutcome(f.input), { ...result, replayed: true });
  assert.deepEqual(await f.service.runAttempt(f.input), { ...result, replayed: true });
  assert.equal(f.calls.judge, 1); assert.equal(f.calls.complete, 1); assert.equal(f.calls.effects, 0);
});

test('V04 fixed, disabled and unconfirmed source cannot claim a grading turn', async () => {
  for (const change of [f => { f.original.input.systemExecution.mode = 'fixed'; },
    f => { f.publication.mode = 'fixed'; }, f => f.disable(),
    f => { f.source.operation.state = 'unknown'; }]) {
    const f = fixture(); change(f);
    assert.deepEqual(await f.service.runAttempt(f.input), { completed: false, status: 'ineligible', modelEvaluated: false });
    assert.equal(f.calls.judge, 0); assert.equal(f.calls.claim, 0); assert.equal(f.calls.effects, 0);
  }
});

test('V04 original source read outage propagates before admission and permits an explicit retry', async () => {
  const f = fixture(); f.sourceError(Object.assign(Error('database offline'), { code: '57P01' }));
  await assert.rejects(f.service.runAttempt(f.input), { code: '57P01' });
  assert.equal(f.calls.claim, 0); assert.equal(f.calls.judge, 0);
  f.sourceError(null); const result = await f.service.runAttempt(f.input);
  assert.equal(result.completed, false); assert.equal(f.calls.judge, 1); assert.equal(f.calls.effects, 0);
});

test('V04 foreign owner and session cannot read original evidence or admit assessment', async () => {
  for (const mutate of [f => { f.input.scope = { ...f.input.scope, platformOwnerId: 999 }; },
    f => { f.input.sessionId = randomUUID(); }, f => { f.input.persona.role = 'customer'; }]) {
    const f = fixture(); mutate(f);
    await assert.rejects(f.service.runAttempt(f.input));
    await assert.rejects(f.service.readOutcome(f.input));
    assert.equal(f.calls.source, 0); assert.equal(f.calls.claim, 0); assert.equal(f.calls.judge, 0);
  }
});

test('V04 revocation, scene reset, source change and disable during Judge block verdict publication', async () => {
  for (const change of [f => f.revoke(), f => f.setScene(null), f => f.disable(),
    f => { f.source.turn.text = 'changed original response'; },
    f => { f.source.sourceBinding.grant_id = randomUUID(); },
    f => { f.original.input.systemExecution.modeStamp = 'changed'; },
    f => { f.publication.modeStamp = 'changed'; }]) {
    const f = fixture(); f.onJudge(() => change(f));
    await assert.rejects(f.service.runAttempt(f.input));
    assert.equal(f.calls.judge, 1); assert.equal(f.calls.verdict, 0); assert.equal(f.calls.complete, 0);
    assert.equal(f.calls.effects, 0);
  }
});

test('V04 original scene, grant and product target mismatches deny before any grading claim', async () => {
  for (const mutate of [f => { f.source.sourceBinding.scene_id = randomUUID(); },
    f => { f.source.sourceBinding.scene_generation++; },
    f => { f.source.sourceBinding.grant_id = randomUUID(); },
    f => { f.source.sourceBinding.target_id = randomUUID(); }]) {
    const f = fixture(); mutate(f);
    await assert.rejects(f.service.runAttempt(f.input));
    assert.equal(f.calls.judge, 0); assert.equal(f.calls.claim, 0); assert.equal(f.calls.effects, 0);
  }
});

test('V04 controlled positive Judge response cannot establish genuine grading provenance or credit', async () => {
  const f = fixture(); f.controlledPositiveJudge();
  const result = await f.service.runAttempt(f.input);
  assert.equal(f.calls.judge, 1);
  assert.equal(result.judgment.verdict, 'pass');
  assert.equal(result.completed, false, 'a coherent positive test double is not the configured canonical Judge');
  assert.equal(f.calls.effects, 0);
});

test('V04 saved canonical packet, session, run, mode and result tampering fail without new work', async () => {
  for (const change of [r => { r.execution_json.personaSessionId = randomUUID(); },
    r => { r.run_id = randomUUID(); }, r => { r.packet += ' '; },
    r => { r.mode_stamp = 'changed'; }, r => { r.rubric_version = 'unknown'; },
    r => { r.result_digest = '0'.repeat(64); }]) {
    const f = fixture(); await f.service.runAttempt(f.input); change(f.canonicalRow);
    await assert.rejects(f.service.readOutcome(f.input));
    assert.equal(f.calls.judge, 1); assert.equal(f.calls.complete, 1); assert.equal(f.calls.effects, 0);
  }
});

test('V04 uncertain assessment journal publication cannot automatically replay Judge or source effect', async () => {
  const f = fixture(); f.onCompleteError(Error('controlled lost journal acknowledgement'));
  await assert.rejects(f.service.runAttempt(f.input));
  assert.equal(f.journalRow.status, 'uncertain');
  await assert.rejects(f.service.runAttempt(f.input), { code: 'TURN_RECOVERY_REQUIRED' });
  assert.equal(f.calls.judge, 1); assert.equal(f.calls.effects, 0);
});

test('V04 retained canonical parent survives uncertain journal while returned guard rejects source or grant drift', async () => {
  for (const mutate of [f => { f.source.turn.text = 'changed original response'; },
    f => { f.source.sourceBinding.grant_id = randomUUID(); }]) {
    const f = fixture();
    f.onCompleteError(Error('controlled lost journal acknowledgement'));
    await assert.rejects(f.service.runAttempt(f.input));
    assert.equal(f.journalRow.status, 'uncertain');
    assert.equal(f.canonicalRow.packet, f.packet, 'the original canonical parent remains persisted');
    const guard = await f.service.assertRetainedPacket({ ...f.input, packet: f.packet });
    await guard.assertCurrent();
    const before = { judge: f.calls.judge, effects: f.calls.effects,
      claim: f.calls.claim, complete: f.calls.complete, verdict: f.calls.verdict };
    assert.deepEqual(before, { judge: 1, effects: 0, claim: 1, complete: 0, verdict: 1 });
    mutate(f);
    await assert.rejects(guard.assertCurrent());
    assert.deepEqual({ judge: f.calls.judge, effects: f.calls.effects,
      claim: f.calls.claim, complete: f.calls.complete, verdict: f.calls.verdict }, before);
    assert.equal(f.journalRow.status, 'uncertain');
  }
});


test('V04 eligibility revoked after admission preserves the closed ineligible result without Judge work', async () => {
  const f = fixture(); f.afterAdmission(() => f.disable());
  assert.deepEqual(await f.service.runAttempt(f.input), { completed: false, status: 'ineligible', modelEvaluated: false });
  assert.equal(f.calls.claim, 1); assert.equal(f.calls.judge, 0);
  assert.equal(f.calls.verdict, 0); assert.equal(f.calls.effects, 0);
});
}
