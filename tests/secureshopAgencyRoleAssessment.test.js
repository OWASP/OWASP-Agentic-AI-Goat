'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { assessmentRequestId, createAgencyRoleAssessment } = require('../server/services/secureshopAgencyRoleAssessment');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { fixture } = require('./secureshopAgencyRoleEvidence.test');

test('rendered Judge recorder detaches the canonical packet from a live execution fence', () => {
  const { v29JudgeRequestRecord } = require('./postgres/secureshopCustomerCheckoutRendered.integration.test');
  const runId = randomUUID(), check = async () => {};
  const input = {
    rubric: { family: 'SecureShop', scenario: 'agency_role', objectiveId: 'ss_customer_role_escalation',
      version: 'recorder-v1', mode: 'vuln', criteria: [{ id: 'effect', description: 'Observed owned effect',
        allowedSources: ['server_observation'] }] },
    facts: {}, evidence: [{ id: 'effect', source: 'server_observation', content: { changed: true } }],
    execution: Object.freeze({ runId, ownerKey: 'bound-role', durableGeneration: 1,
      signal: new AbortController().signal, check })
  };
  const recorded = v29JudgeRequestRecord(input);
  assert.equal(recorded.execution.runId, runId);
  assert.deepEqual(JSON.parse(recorded.packet).evidence, input.evidence);
  assert.equal(recorded.execution.check, undefined);
  assert.match(recorded.evidenceDigest, /^[a-f0-9]{64}$/);
});

test('assessment identity is stable for its original customer request and rejects foreign identifiers', () => {
  const sessionId = randomUUID(), requestId = randomUUID();
  assert.equal(assessmentRequestId(sessionId, requestId), assessmentRequestId(sessionId, requestId));
  assert.notEqual(assessmentRequestId(sessionId, requestId), assessmentRequestId(randomUUID(), requestId));
  assert.throws(() => assessmentRequestId('foreign', requestId));
});

test('assessment requires complete canonical lifecycle dependencies', () => {
  assert.throws(() => createAgencyRoleAssessment(), /Agency role assessment dependencies required/);
});

test('readOutcome uses the admitted customer-chat purpose and leaves an absent assessment unconfirmed', async () => {
  const source = fixture(), scope = source.binding, receipt = source.row.result_json.taskMetadata.agencyRole.receipt;
  const target = createSceneBinding({ ...scope, targetId: receipt.scene.targetId }, {
    sceneId: receipt.scene.sceneId, sceneGeneration: receipt.scene.sceneGeneration, grantId: receipt.scene.grantId,
    execution: scope, withLease: async work => work()
  });
  const calls = [];
  const mode = { snapshot: receipt.modeExecution, assertCurrent: async () => {} };
  const service = createAgencyRoleAssessment({
    identityPool: { query: async sql => ({ rows: sql.includes('SELECT o.objective_id')
      ? [{ objective_id: 'ss_customer_role_escalation' }] : [{ realm: 'platform', shop_tenant_id: null }] }) },
    agentsPool: { query: async () => ({ rows: [] }) },
    launches: { assertCurrent: async () => {} },
    conversationRepository: {
      getBoundSession: async id => { calls.push(id); return { id, state: 'active',
        purpose: 'secureshop_customer_chat', binding: scope }; },
      acquireBoundSession: async () => { throw Error('unexpected write'); },
      activateBoundSession: async () => false
    },
    coordinator: { run: async () => { throw Error('unexpected run'); } },
    journal: { claim: async () => {}, complete: async () => {}, markUncertain: async () => {} },
    personaAuthority: { capture: () => ({ binding: { ...scope, personaId: scope.shopUserId,
      role: 'customer', sessionId: source.personaSession.sessionId,
      authorityVersion: source.personaSession.authorityVersion }, assertRemoteAdmission: async () => {} }) },
    personaBindings: { capture: async () => ({}) },
    scenes: { readRetained: async () => target },
    modeAuthority: { capture: async () => mode, assertToken: value => value },
    sourceReader: { read: async () => { const { binding, personaSession, qualifyModel, ...raw } = source; return raw; } },
    receipts: { beginEvaluation: async () => {}, recordVerdict: async () => {} },
    progress: { getGeneration: async () => 1 },
    publicationModes: { getEvaluationScope: async () => ({ generation: 1, mode: 'vuln', modeStamp: 'publication' }) },
    judge: async () => ({ verdict: 'fail' }), qualifyModel: identity => identity.provider === 'controlled-native'
  });
  const value = await service.readOutcome({ scope, persona: { id: scope.shopUserId, role: 'customer' },
    personaSession: source.personaSession, sessionId: source.row.session_id, requestId: source.row.request_id });
  assert.deepEqual(value, { completed: false, status: 'unconfirmed', modelEvaluated: false });
  assert.ok(calls.length >= 1);
});

function lifecycleFixture({ modelOutcome = null } = {}) {
  const source = fixture();
  const scope = source.binding;
  const receipt = source.row.result_json.taskMetadata.agencyRole.receipt;
  const target = createSceneBinding({ ...scope, targetId: receipt.scene.targetId }, {
    sceneId: receipt.scene.sceneId, sceneGeneration: receipt.scene.sceneGeneration, grantId: receipt.scene.grantId,
    execution: scope, withLease: async work => work()
  });
  const assessmentSessions = new Map();
  const calls = { source: 0, judge: 0, model: 0, claim: 0, complete: 0, verdict: 0, acquire: 0, uncertain: 0 };
  const publication = { generation: 1, mode: 'vuln', modeStamp: 'controlled-publication' };
  let enabled = true, active = true, currentMode = structuredClone(receipt.modeExecution);
  let journalRow = null, canonicalRow = null, packet = null;
  const check = async () => {
    if (!active) throw Object.assign(new Error('revoked'), { code: 'SHOP_AUTH_INVALID' });
  };
  const conversationRepository = {
    async getBoundSession(id) {
      if (id === source.row.session_id) return { id, state: 'active', purpose: 'secureshop_customer_chat', binding: scope };
      return assessmentSessions.get(id) || null;
    },
    async acquireBoundSession({ id, binding, purpose }) {
      calls.acquire++;
      const row = { id, state: 'active', purpose, binding };
      assessmentSessions.set(id, row);
      return row;
    },
    async activateBoundSession() { return true; }
  };
  const identityPool = {
    async query(sql) {
      if (sql.includes('identity.secureshop_authority_owners')) return { rows: [{ realm: 'platform', shop_tenant_id: null }] };
      if (sql.includes('workshop_platform.objectives')) return { rows: enabled ? [{ objective_id: 'ss_customer_role_escalation' }] : [] };
      if (sql.includes('FROM secureshop_auth.execution_authority_state')) return { rows: canonicalRow ? [canonicalRow] : [] };
      throw Error(`Unexpected SQL: ${sql}`);
    }
  };
  const journal = {
    async claim(input) {
      calls.claim++;
      if (journalRow) return { status: journalRow.status, result: journalRow.result_json, claimId: randomUUID() };
      const request = require('../server/services/secureshopTurnRequest').createTurnRequest(input);
      journalRow = { session_id: input.sessionId, request_id: input.requestId,
        request_hash: request.hash, request_version: request.version, status: 'started', result_json: null };
      return { status: 'claimed', claimId: randomUUID() };
    },
    async complete(input) {
      await check(); calls.complete++;
      journalRow.status = 'completed'; journalRow.result_json = structuredClone(input.result);
    },
    async markUncertain() { calls.uncertain++; if (journalRow?.status !== 'completed') journalRow.status = 'uncertain'; }
  };
  const service = createAgencyRoleAssessment({
    identityPool,
    agentsPool: { query: async () => ({ rows: journalRow ? [journalRow] : [] }) },
    launches: { assertCurrent: check },
    conversationRepository,
    coordinator: {
      async run(sessionId, options, work) {
        const admitted = await options.admit();
        if (admitted.skip) return admitted.value;
        return work({ runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', sessionId]),
          durableGeneration: '0', check, signal: undefined });
      }
    },
    journal,
    personaAuthority: {
      capture: input => ({ binding: { launchId: input.scope.launchId, scenarioId: input.scope.scenarioId,
        generation: input.scope.generation, platformOwnerId: input.scope.platformOwnerId,
        platformSessionId: input.scope.platformSessionId, personaId: input.personaId, role: input.role,
        sessionId: input.sessionId, authorityVersion: input.authorityVersion }, assertRemoteAdmission: check })
    },
    personaBindings: { capture: async () => ({ controlled: true }) },
    scenes: { readRetained: async () => target },
    modeAuthority: {
      capture: async () => {
        const snapshot = structuredClone(currentMode);
        return { snapshot, assertCurrent: async () => assert.deepEqual(currentMode, snapshot) };
      },
      assertToken: value => value
    },
    sourceReader: {
      read: async () => {
        calls.source++;
        const { binding, personaSession, qualifyModel, ...raw } = source;
        return structuredClone(raw);
      }
    },
    receipts: {
      async beginEvaluation(input) {
        packet = input.recovery.packet;
        const rubric = JSON.parse(packet).rubric;
        const runId = input.runId;
        const ownerKey = input.recovery.ownerKey;
        const tenantId = randomUUID(), principalId = randomUUID();
        canonicalRow = {
          tenant_id: tenantId, principal_id: principalId, evaluation_id: input.evaluationId,
          shop_user_id: scope.shopUserId, workshop_key: 'secureshop_agent_security', objective_id: rubric.objectiveId,
          family: rubric.family, scenario: rubric.scenario, rubric_version: rubric.version, mode: publication.mode,
          generation: publication.generation, mode_stamp: publication.modeStamp, owner_key: ownerKey,
          owner_generation: '0', live_owner_generation: '0', current_tenant_id: tenantId,
          current_principal_id: principalId, current_membership_version: '1', run_id: runId,
          execution_json: { tenantId, principalId, membershipVersion: '1', scope: {
            launchId: scope.launchId, scenarioId: scope.scenarioId, generation: scope.generation,
            platformOwnerId: scope.platformOwnerId, platformSessionId: scope.platformSessionId
          }, personaSessionId: source.personaSession.sessionId,
          personaAuthorityVersion: source.personaSession.authorityVersion, role: 'customer', runId },
          packet, evidence_digest: input.evidenceDigest, child_id: null, verdict: null
        };
        return { verdict: null };
      },
      async recordVerdict({ result }) {
        calls.verdict++;
        const serialized = JSON.stringify(result);
        Object.assign(canonicalRow, { verdict: result.verdict, disposition: 'not_pass', result_json: result,
          result_serialized: serialized, result_digest: require('node:crypto').createHash('sha256').update(serialized).digest('hex') });
        return { verdict: result.verdict, disposition: 'not_pass', result };
      }
    },
    progress: { getGeneration: async () => publication.generation,
      getEvaluationScope: async () => ({ ...publication }) },
    publicationModes: { getEvaluationScope: async () => ({ ...publication }) },
    judge: async input => {
      calls.judge++; assert.equal(input.rubric.objectiveId, 'ss_customer_role_escalation');
      if(modelOutcome){
        const actual=require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{async chat(){
          calls.model++;
          return {provider:'controlled',model:'agency-role-composition-control',mocked:false,
            response:JSON.stringify({outcome:modelOutcome,
              reason:'The original transition and continuation were independently classified under the complete criterion.',
              selectedRefs:['selection_record','effect_record']})};
        }}});
        return actual(input);
      }
      return { verdict: 'fail', criteria: [], explanation: 'Controlled negative Judge; no credit.' };
    },
    qualifyModel: identity => identity.provider === 'controlled-native' && identity.model === 'teaching-model'
  });
  const input = { scope, persona: { id: scope.shopUserId, role: 'customer' }, personaSession: source.personaSession,
    sessionId: source.row.session_id, requestId: source.row.request_id };
  return {
    service, input, calls, source,
    get journalRow() { return journalRow; }, get canonicalRow() { return canonicalRow; }, get packet() { return packet; },
    disable() { enabled = false; }, revoke() { active = false; }, fixed() { currentMode = { ...currentMode, mode: 'fixed' }; }
  };
}

test('runAttempt persists one controlled canonical verdict and terminal reads replay without a new Judge', async () => {
  const f = lifecycleFixture();
  const initial = await f.service.readOutcome(f.input);
  assert.deepEqual(initial, { completed: false, status: 'unconfirmed', modelEvaluated: false });
  const result = await f.service.runAttempt(f.input);
  assert.equal(result.completed, false);
  assert.equal(result.judgment.verdict, 'fail');
  assert.equal(f.calls.judge, 1);
  assert.equal(f.calls.verdict, 1);
  assert.equal(f.calls.complete, 1);
  assert.ok(f.packet);

  const saved = await f.service.readOutcome(f.input);
  assert.equal(saved.replayed, true);
  assert.equal(saved.judgment.verdict, 'fail');
  const replay = await f.service.runAttempt(f.input);
  assert.equal(replay.replayed, true);
  assert.equal(replay.judgment.verdict, 'fail');
  assert.equal(f.calls.judge, 1);
  assert.equal(f.calls.verdict, 1);
  assert.equal(f.calls.complete, 1);
});

test('prospective v5 negative and insufficient outcomes persist without progress or a second model call',async()=>{
  for(const [modelOutcome,expected] of [
    ['criterion_not_established','fail'],['insufficient_evidence','unavailable']
  ]){
    const f=lifecycleFixture({modelOutcome});
    const first=await f.service.runAttempt(f.input);
    assert.equal(first.completed,false);
    assert.equal(first.judgment.verdict,expected);
    assert.equal(f.calls.model,1);
    const stored=f.canonicalRow.result_json;
    assert.equal(stored.scopedCriteria[0].groundedObservation.referenceSelection.outcome,modelOutcome);
    if(expected==='unavailable')assert.equal(stored.errorCode,'SEMANTIC_COVERAGE_UNAVAILABLE');
    const saved=await f.service.readOutcome(f.input);
    assert.equal(saved.replayed,true);assert.equal(saved.completed,false);
    assert.equal(saved.judgment.verdict,expected);
    const replay=await f.service.runAttempt(f.input);
    assert.equal(replay.replayed,true);assert.equal(replay.judgment.verdict,expected);
    assert.equal(f.calls.model,1);assert.equal(f.calls.verdict,1);assert.equal(f.calls.complete,1);
  }
});

test('historical v2, v3 and v4 saved outcomes retain their exact packets without a new Judge', async () => {
  const evidence = require('../server/services/secureshopAgencyRoleEvidence');
  for(const [version,rubric] of [
    [evidence.PREVIOUS_VERSION,evidence.RUBRIC_V2],
    [evidence.HISTORICAL_V3,evidence.RUBRIC_V3],
    [evidence.HISTORICAL_V4,evidence.RUBRIC_V4]
  ]){
    const f = lifecycleFixture();
    await f.service.runAttempt(f.input);
    const candidate = evidence.buildAgencyRoleCandidate(f.source,{ evidenceVersion:version });
    assert.ok(candidate);
    const historical = require('../server/agent-runtime/objectiveJudge').prepareJudgeInput({rubric,...candidate});
    assert.equal(historical.evidenceError, undefined);
    const original = historical.packet;
    f.canonicalRow.rubric_version = version;
    f.canonicalRow.packet = historical.packet;
    f.canonicalRow.evidence_digest = historical.evidenceDigest;
    const saved = await f.service.readOutcome(f.input);
    assert.equal(saved.replayed, true);
    assert.equal(saved.judgment.verdict, 'fail');
    assert.equal(f.calls.judge, 1);
    assert.equal(f.canonicalRow.packet, original);
    const relabeled = structuredClone(f.canonicalRow);
    Object.assign(f.canonicalRow, { rubric_version: evidence.RUBRIC.version });
    await assert.rejects(f.service.readOutcome(f.input));
    Object.assign(f.canonicalRow, relabeled);
  }
});

test('assessment preserves pending, revocation, and source authority fences before grading', async () => {
  const pending = lifecycleFixture();
  await pending.service.runAttempt(pending.input);
  pending.journalRow.status = 'started';
  assert.deepEqual(await pending.service.readOutcome(pending.input), { completed: false, status: 'pending', modelEvaluated: false });
  assert.equal(pending.calls.judge, 1);

  for (const change of [f => f.disable(), f => f.fixed()]) {
    const f = lifecycleFixture();
    change(f);
    assert.deepEqual(await f.service.runAttempt(f.input), { completed: false, status: 'ineligible', modelEvaluated: false });
    assert.equal(f.calls.judge, 0);
    assert.equal(f.calls.claim, 0);
  }

  const foreignRequest = lifecycleFixture();
  const wrongRequest = { ...foreignRequest.input, requestId: randomUUID() };
  assert.deepEqual(await foreignRequest.service.runAttempt(wrongRequest), { completed: false, status: 'ineligible', modelEvaluated: false });
  assert.equal(foreignRequest.calls.judge, 0);
  assert.equal(foreignRequest.calls.claim, 0);

  const foreignSession = lifecycleFixture();
  await assert.rejects(foreignSession.service.runAttempt({ ...foreignSession.input, sessionId: randomUUID() }),
    { code: 'CONVERSATION_UNAVAILABLE' });
  assert.equal(foreignSession.calls.source, 0);
  assert.equal(foreignSession.calls.claim, 0);

  const revoked = lifecycleFixture();
  revoked.revoke();
  await assert.rejects(revoked.service.readOutcome(revoked.input), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(revoked.calls.judge, 0);
});
