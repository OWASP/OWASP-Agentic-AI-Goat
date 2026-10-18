'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { createRequire } = require('node:module');
const { randomUUID, createHash } = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { ticketSource } = require('../server/services/secureshopTicketAgentConfirmation');
const Ticket = require('../server/services/secureshopTicketContract');
const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');

const file = path.resolve('server/services/secureshopTicketBrowserAssessment.js');
const realRequire = createRequire(file);
const SHA = value => createHash('sha256').update(value).digest('hex');

function fixture({ mode = 'vuln', enabled = true } = {}) {
  const originalScope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 8, platformSessionId: 9 };
  const adminScope = { ...originalScope, platformSessionId: 12 };
  const targetId = randomUUID(), sceneId = randomUUID(), grantId = randomUUID();
  const retainedScene = createSceneBinding({ ...adminScope, targetId },
    { sceneId, sceneGeneration: 1, grantId, execution: adminScope,
      withLease: async work => work() });
  const customerScene = createSceneBinding({ ...originalScope, targetId },
    { sceneId, sceneGeneration: 1, grantId: randomUUID(), execution: originalScope,
      withLease: async work => work() });
  const admin = { id: 20, role: 'admin' }, adminSession = {
    sessionId: randomUUID(), authorityVersion: '2' };
  const origin = { turnSessionId: randomUUID(), turnRequestId: randomUUID(),
    toolKey: Ticket.TOOL, invocationStep: 1, callId: 'selected-call' };
  const body = '<img src=x onerror=alert(1)>', subject = 'Support';
  const message = JSON.stringify({ subject, body });
  const proposal = Ticket.prepare({ subject, body, message, sourceOrigin: origin });
  const source = ticketSource({ scope: originalScope, persona: { id: 10, role: 'customer' },
    personaSession: { sessionId: randomUUID(), authorityVersion: '3' },
    retainedScene: customerScene }, { origin, proposal, runId: randomUUID() });
  const result = { version: 1, kind: 'support_ticket', ticketId: '4',
    operationId: proposal.proposalId, requestId: origin.turnRequestId,
    runId: source.turn.runId, proposalId: proposal.proposalId, status: 'open',
    subjectSha256: proposal.subjectSha256, bodySha256: proposal.bodySha256,
    receiptSha256: 'a'.repeat(64) };
  const capability = { version: 1, featureId: 'support_tickets',
    policyVersion: 'owned-ticket-render-v1', effectiveMode: mode,
    scope: { kind: 'launch_feature', id: 'support_tickets' } };
  const component = { id: 'SecureShop.AdminTicketBody', sourceSha256: 'a'.repeat(64),
    artifactSha256: 'b'.repeat(64) };
  const state = { enabled, mode, browser: 0, judgment: 0, reads: 0,
    checks: 0, currentScene: retainedScene,
    ticket: { source, proposal, result, requestSha256: 'c'.repeat(64),
      receipt: { sha256: result.receiptSha256 },
      consumer: { admin: { shopUserId: admin.id,
        personaSessionId: adminSession.sessionId,
        authorityVersion: adminSession.authorityVersion } },
      detail: { modeCapability: capability }, subject, body } };
  const token = { snapshot: { featureId: 'support_tickets',
    policyVersion: 'owned-ticket-render-v1', mode },
  async assertCurrent() { if (state.revoked) throw Error('revoked'); } };
  const originalRead = { message, turn: { status: 'completed',
    request_hash: 'c'.repeat(64) }, traces: [] };
  state.originalRead = originalRead;
  state.selected = { runId: source.turn.runId, requestSha256: 'c'.repeat(64),
    message, proposal, traceEventIds: [randomUUID()],
    decisionEventId: randomUUID(), callEventId: randomUUID(),
    resultEventId: randomUUID(), terminalEventId: randomUUID() };
  const candidate = { facts: { original_customer_model_prepared: true },
    evidence: [{ id: 'ticket_browser', source: 'server_observation',
      content: { bodySha256: proposal.bodySha256 } }] };
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, exports: module.exports, Buffer, JSON, Object, structuredClone,
    require(name) {
      if (name === './secureshopAssessmentEligibility') return {
        readSecureShopAssessmentEligibility: async () => state.enabled
          ? ['ss_ticket_stored_browser_execution'] : [],
      };
      if (name === './secureshopFeatureModeAuthority') return {
        captureFeatureMode: async () => token,
      };
      if (name === './secureshopTicketBrowserOriginalReader') return {
        createTicketBrowserOriginalReader: () => async () => state.originalRead,
      };
      if (name === './secureshopTicketAgentProposal') return {
        originalSelection: () => state.selected,
      };
      if (name === './secureshopTicketBrowserEvidence') return {
        OBJECTIVE: 'ss_ticket_stored_browser_execution',
        RUBRIC: realRequire('./secureshopTicketBrowserEvidence').RUBRIC,
        rubricForSelection: realRequire('./secureshopTicketBrowserEvidence').rubricForSelection,
        buildTicketBrowserCandidate: input => {
          state.candidateInput = input;
          return state.badCandidate ? null : candidate;
        },
      };
      if (name === './secureshopBoundConversation') return {
        createBoundConversationService: () => ({ create: async () => ({ id: randomUUID() }),
          assertOwned: async () => {} }),
      };
      if (name === './secureshopBoundTurns') return {
        createBoundTurns: () => ({ run: async (_id, _binding, _actor, options, work) => {
          const admission = await options.admit();
          if (admission.skip) return { result: admission.value, replayed: true };
          const runId = randomUUID();
          return { result: await work({ identity: { runId, ownerKey: 'ticket-admin-owner',
            durableGeneration: 1 }, signal: options.signal,
          async check() { if (state.revoked) throw Error('revoked'); },
          async effectWithReceipt(node, fn) {
            const value = await fn();
            return { value, receipt: { version: 1, status: 'completed',
              runId, ownerKey: 'ticket-admin-owner', generation: 1,
              effectKey: `${options.idempotencyKey}:${node}` } };
          } }), replayed: false };
        } }),
      };
      if (name === './secureshopTurnAdmission') return {
        createTurnAdmission: () => ({ prepare: async () => ({ status: 'claimed' }),
          execute: async (_claim, _boundary, work) => work(), abandon: async () => {} }),
      };
      if (name === './secureshopAssessmentPersonaCapture') return {
        createAssessmentPersonaCapture: () => ({ options: {}, prepare: () => ({}),
          bind: () => {} }),
      };
      if (name === './secureshopAssessmentPublicationScope') return {
        captureAssessmentPublicationScope: async () => ({ binding: {
          mode: state.mode, generation: 0, modeStamp: 'current-mode-stamp' },
          assertCurrent: async () => {} }),
      };
      if (name === './secureshopObjectiveCompletionService') return {
        createObjectiveCompletionService: options => ({
          beginAttempt: async () => ({ mode: state.mode }),
          evaluate: async input => { state.judgment++;
            state.judgeRubric = input.rubric;
            const prepared = realRequire('../agent-runtime/objectiveJudge')
              .prepareJudgeInput(input);
            const snapshot = JSON.parse(prepared.packet);
            if (state.tamperJudge) snapshot.evidence[0].content.bodySha256 = 'f'.repeat(64);
            await options.judge({ ...snapshot, execution: input.execution });
            return { completed: false, judgment: { verdict: 'fail' } };
          },
        }),
      };
      return realRequire(name);
    },
  });
  const service = module.exports.createTicketBrowserAssessment({
    identityPool: { query: async sql => ({ rows: sql.includes('graph_runtime.effects')
      ? state.graphRows || [] : sql.includes('assessment_judgments')
        ? state.judgmentRows || [] : state.enabled ? [{}] : [] }) },
    launches: { assertCurrent: async () => { state.checks++;
      if (state.revoked) throw Error('revoked'); } },
    conversationRepository: { getBoundSession() {}, getMessages() {},
      getTraceEvents() {}, acquireBoundSession() {} },
    coordinator: { run() {} }, journal: { readBoundRequest() {},
      readTicketBrowserAssessment: async ({ requestId }) =>
        state.journalRow?.request_id === requestId ? state.journalRow : null },
    bindingRepository: { read() {} },
    personaAuthority: { capture: async input => ({ binding: {
      ...input.scope, personaId: input.personaId, role: input.role,
      sessionId: input.sessionId, authorityVersion: input.authorityVersion },
    assertRemoteAdmission: async () => { if (state.revoked) throw Error('revoked'); } }) },
    personaBindings: { capture() {} },
    scenes: { readRetained: async () => state.currentScene },
    modeAuthority: { capture() {}, assertToken() {} },
    ticketRepository: { readForAssessment: async () => {
      state.reads++; return state.ticket;
    } }, receipts: {}, progress: {}, publicationModes: { getEvaluationScope() {} },
    judge: async () => ({ verdict: 'fail' }), qualifyModel: () => true,
    browserQualification: { readComponent: () => component,
      qualifyTicket: async input => { state.browser++;
        if (state.revokeDuring) state.revoked = true;
        if (state.switchSceneDuring) state.currentScene = createSceneBinding({ ...adminScope,
          targetId: randomUUID() }, { sceneId: randomUUID(), sceneGeneration: 1,
          grantId: randomUUID(), execution: adminScope, withLease: async work => work() });
        return { component, renderedSourceSha256: SHA(input.html),
          executed: true, targetEventExecuted: true, targetEffectObserved: true,
          syntheticCookieOnly: true, finalCookieIsSyntheticOnly: true,
          markers: ['observed'], blockedRequests: [] };
      } },
  });
  return { service, state, adminScope, admin, adminSession, component };
}

function retainedPacket(f) {
  const { OBJECTIVE, RUBRIC, RUBRIC_V2 } = realRequire('./secureshopTicketBrowserEvidence');
  const { prepareJudgeInput } = realRequire('../agent-runtime/objectiveJudge');
  const t = f.state.ticket, selected = f.state.selected;
  const receipt = { version: 1, status: 'completed', runId: randomUUID(),
    ownerKey: 'ticket-admin-owner', generation: 1,
    effectKey: `${randomUUID()}:ticket-browser:4` };
  f.state.graphRows = [{ ...receipt }];
  const v2 = f.state.selected.sourceVersion === 2;
  const content = { version: v2 ? 2 : 1, objectiveId: OBJECTIVE,
    originalCustomer: { source: t.source, requestSha256: selected.requestSha256,
      modelRunId: selected.runId, message: selected.message,
      proposal: selected.proposal, traceEventIds: selected.traceEventIds,
      decisionEventId: selected.decisionEventId,
      callEventId: selected.callEventId, resultEventId: selected.resultEventId,
      terminalEventId: selected.terminalEventId,
      ...(v2 ? { sourceVersion: 2, requestRef: selected.requestRef } : {}) },
    ticket: { result: t.result, receiptSha256: t.receipt.sha256,
      subjectSha256: t.result.subjectSha256, bodySha256: t.result.bodySha256,
      body: t.body },
    currentAdmin: { consumer: t.consumer, ticketId: '4',
      modeCapability: t.detail.modeCapability },
    component: f.component,
    browser: { renderedSourceSha256: SHA(t.body), targetEventExecuted: true,
      targetEffectObserved: true, syntheticCookieOnly: true,
      finalCookieIsSyntheticOnly: true, markers: ['observed'], blockedRequests: [] },
    effectReceipt: receipt };
  const rubric = v2 ? RUBRIC_V2 : RUBRIC;
  return prepareJudgeInput({ rubric: { ...rubric, mode: 'vuln' },
    facts: Object.fromEntries(rubric.requiredFacts.map(key => [key, true])),
    evidence: [{ id: 'ticket_browser', source: 'server_observation', content }] });
}

function selectV2(f) {
  f.state.selected.sourceVersion = 2;
  f.state.originalRead.turn.result_json = { taskMetadata: { customerChat: {
    envelopeSha256: 'e'.repeat(64),
  } } };
  f.state.selected.requestRef = Ticket.requestRef({
    requestHash: f.state.originalRead.turn.request_hash,
    envelopeSha256: f.state.originalRead.turn.result_json.taskMetadata.customerChat.envelopeSha256,
  });
}

test('admin assessment reads original ticket and browser under its own Judge', async () => {
  const f = fixture();
  const result = await f.service.runAttempt({ scope: f.adminScope, persona: f.admin,
    personaSession: f.adminSession, ticketId: '4', requestId: randomUUID() });
  assert.equal(result.completed, false);
  assert.equal(result.judgment.verdict, 'fail');
  assert.equal(f.state.browser, 1);
  assert.equal(f.state.judgment, 1);
  assert.equal(f.state.reads, 2);
  assert.equal(f.state.candidateInput.ticketRead, f.state.ticket);
});

test('v2 fresh assessment sends the reference rubric to the same canonical Judge', async () => {
  const f = fixture(); selectV2(f);
  const result = await f.service.runAttempt({ scope: f.adminScope, persona: f.admin,
    personaSession: f.adminSession, ticketId: '4', requestId: randomUUID() });
  assert.equal(result.judgment.verdict, 'fail');
  assert.equal(f.state.judgeRubric.version, 'secureshop-ticket-browser-v2');
  assert.equal(f.state.browser, 1);
  assert.equal(f.state.judgment, 1);
});

test('disabled or fixed policy never opens ticket browser or Judge', async () => {
  for (const options of [{ enabled: false }, { mode: 'fixed' }]) {
    const f = fixture(options);
    const result = await f.service.runAttempt({ scope: f.adminScope, persona: f.admin,
      personaSession: f.adminSession, ticketId: '4', requestId: randomUUID() });
    assert.equal(result.status, 'ineligible');
    assert.equal(f.state.browser, 0);
    assert.equal(f.state.judgment, 0);
  }
});

test('changed ticket, revoked admin, switched scene and altered Judge packet never credit', async () => {
  for (const kind of ['changed', 'revoked', 'switchScene', 'badCandidate', 'tamperJudge']) {
    const f = fixture();
    if (kind === 'badCandidate') f.state.badCandidate = true;
    if (kind === 'tamperJudge') f.state.tamperJudge = true;
    if (kind === 'revoked') f.state.revokeDuring = true;
    if (kind === 'switchScene') f.state.switchSceneDuring = true;
    if (kind === 'changed') {
      const original = f.state.ticket;
      let reads = 0;
      Object.defineProperty(f.state, 'ticket', { get() { reads++;
        return reads === 1 ? original : { ...original, body: 'changed' };
      } });
    }
    const pending = f.service.runAttempt({ scope: f.adminScope,
      persona: f.admin, personaSession: f.adminSession,
      ticketId: '4', requestId: randomUUID() });
    if (kind === 'badCandidate') {
      const result = await pending;
      assert.equal(result.status, 'ineligible');
    } else await assert.rejects(pending);
    assert.equal(f.state.judgment, kind === 'tamperJudge' ? 1 : 0);
  }
});

test('retained retry guard rechecks the current admin, source and completed browser effect', async () => {
  const f = fixture();
  const packet = retainedPacket(f);
  assert.ok(!packet.evidenceError);
  const input = { packet: packet.packet, scope: f.adminScope,
    persona: f.admin, personaSession: f.adminSession };
  const guard = await f.service.assertRetainedPacket(input);
  await guard.assertCurrent();
  assert.equal(f.state.browser, 0);
  assert.equal(f.state.judgment, 0);
  f.state.ticket = { ...f.state.ticket, body: 'changed' };
  await assert.rejects(guard.assertCurrent());
});

test('v2 retained packet revalidates selected reference and never reruns browser or actor', async () => {
  const f = fixture(); selectV2(f);
  const packet = retainedPacket(f);
  assert.ok(!packet.evidenceError);
  assert.equal(JSON.parse(packet.packet).rubric.version, 'secureshop-ticket-browser-v2');
  const input = { packet: packet.packet, scope: f.adminScope,
    persona: f.admin, personaSession: f.adminSession };
  const guard = await f.service.assertRetainedPacket(input);
  await guard.assertCurrent();
  assert.equal(f.state.browser, 0);
  assert.equal(f.state.judgment, 0);
  f.state.selected.requestRef = randomUUID();
  await assert.rejects(guard.assertCurrent());
});

test('v1 and v2 rubric or proof cannot be mixed at retained retry', async () => {
  const f = fixture(); selectV2(f);
  const v2 = JSON.parse(retainedPacket(f).packet);
  const { RUBRIC } = realRequire('./secureshopTicketBrowserEvidence');
  const wrongRubric = structuredClone(v2);
  wrongRubric.rubric = { ...RUBRIC, mode: 'vuln' };
  await assert.rejects(f.service.assertRetainedPacket({ packet: wrongRubric,
    scope: f.adminScope, persona: f.admin, personaSession: f.adminSession }));
  const wrongProof = structuredClone(v2);
  wrongProof.evidence[0].content.version = 1;
  await assert.rejects(f.service.assertRetainedPacket({ packet: wrongProof,
    scope: f.adminScope, persona: f.admin, personaSession: f.adminSession }));
});

test('v1 and v2 saved assessment GET read exact canonical rows without browser or Judge replay', async () => {
  for (const version of [1, 2]) {
  const f = fixture();
  if (version === 2) selectV2(f);
  const requestId = randomUUID(), sessionId = randomUUID(), evaluationId = randomUUID();
  const packet = retainedPacket(f);
  const binding = createConversationBinding(f.adminScope, f.admin);
  const message = JSON.stringify(['ss_ticket_stored_browser_execution', '4',
    f.state.ticket.result.operationId, f.state.ticket.result.receiptSha256,
    f.state.ticket.consumer, f.adminSession,
    { featureId: 'support_tickets', policyVersion: 'owned-ticket-render-v1',
      mode: 'vuln' },
    { mode: 'vuln', generation: 0, modeStamp: 'current-mode-stamp' }]);
  const request = createTurnRequest({ sessionId, requestId, binding, message });
  const projected = { verdict: 'fail', evaluationId, canRetry: false };
  f.state.journalRow = { session_id: sessionId, request_id: requestId,
    request_hash: request.hash, request_version: request.version,
    status: 'completed', result_json: { completed: false, judgment: projected } };
  f.state.judgmentRows = [{ evaluation_id: evaluationId,
    result_digest: SHA(JSON.stringify({ verdict: 'fail' })),
    result_json: { verdict: 'fail' }, verdict: 'fail', disposition: 'not_pass',
    packet: packet.packet, evidence_digest: packet.evidenceDigest,
    workshop_key: 'secureshop_agent_security',
    objective_id: 'ss_ticket_stored_browser_execution', shop_user_id: f.admin.id,
    family: 'SecureShop', scenario: 'bound_ticket_browser',
    rubric_version: `secureshop-ticket-browser-v${version}`, mode: 'vuln',
    generation: 0, mode_stamp: 'current-mode-stamp',
    owner_key: JSON.stringify(['SecureShopBoundConversation', sessionId]),
    owner_generation: 1, live_owner_generation: '1',
    run_id: randomUUID(), current_tenant_id: 'tenant',
    current_principal_id: 'principal', current_membership_version: '1',
    execution_json: null }];
  const row = f.state.judgmentRows[0];
  row.execution_json = { tenantId: row.current_tenant_id,
    principalId: row.current_principal_id,
    membershipVersion: row.current_membership_version, scope: f.adminScope,
    personaSessionId: f.adminSession.sessionId,
    personaAuthorityVersion: f.adminSession.authorityVersion,
    role: 'admin', runId: row.run_id };
  const input = { scope: f.adminScope, persona: f.admin,
    personaSession: f.adminSession, ticketId: '4', requestId };
  const result = await f.service.readOutcome(input);
  assert.deepEqual(JSON.parse(JSON.stringify(result)),
    { completed: false, judgment: projected, replayed: true });
  assert.equal(f.state.browser, 0);
  assert.equal(f.state.judgment, 0);
  assert.equal((await f.service.readOutcome({ ...input, requestId: randomUUID() })).status,
    'unconfirmed');
  const childId = randomUUID();
  row.child_id = childId;
  row.child_row = { ...row, evaluation_id: childId,
    packet: '{}', execution_json: { ...row.execution_json, runId: randomUUID() } };
  await assert.rejects(f.service.readOutcome(input));
  delete row.child_id;
  delete row.child_row;
  f.state.ticket = { ...f.state.ticket, consumer: {
    admin: { ...f.state.ticket.consumer.admin, shopUserId: 99 } } };
  await assert.rejects(f.service.readOutcome(input));
  assert.equal(f.state.browser, 0);
  assert.equal(f.state.judgment, 0);
  }
});
