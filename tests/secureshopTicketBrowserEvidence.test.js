'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const Ticket = require('../server/services/secureshopTicketContract');
const { OBJECTIVE, RUBRIC, RUBRIC_V2, rubricForSelection, buildTicketBrowserCandidate } =
  require('../server/services/secureshopTicketBrowserEvidence');

const S = '00000000-0000-4000-8000-000000000001';
const R = '00000000-0000-4000-8000-000000000002';
const RUN = '00000000-0000-4000-8000-000000000003';
const ADMIN_SESSION = '00000000-0000-4000-8000-000000000004';
const LAUNCH = '00000000-0000-4000-8000-000000000005';
const SCENARIO = '00000000-0000-4000-8000-000000000006';
const SCENE = '00000000-0000-4000-8000-000000000007';
const TARGET = '00000000-0000-4000-8000-000000000008';
const SOURCE_GRANT = '00000000-0000-4000-8000-000000000009';
const ADMIN_GRANT = '00000000-0000-4000-8000-000000000010';
const GRADE_RUN = '00000000-0000-4000-8000-000000000011';
const E = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const subject = 'Synthetic support request', body = '<img src=x onerror=alert(1)>';
const message = JSON.stringify({ subject, body });
const origin = { turnSessionId: S, turnRequestId: R, toolKey: Ticket.TOOL,
  invocationStep: 1, callId: 'original-selected-call' };
const proposal = Ticket.prepare({ subject, body, message, sourceOrigin: origin });
const sha = value => createHash('sha256').update(value).digest('hex');
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const qualifyModel = identity => identity.provider === 'ollama' && identity.mocked === false;

function originalRead() {
  const observation = { content: [{ type: 'text', text: JSON.stringify({
    status: 'confirmation_required', ticketProposal: proposal, ticketOrigin: origin }) }] };
  const traces = [
    { id: 1, event_id: E(1), session_id: S, step: 1, kind: 'model_decision', actor: 'supervisor',
      provider: 'ollama', params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [
        { id: origin.callId, name: Ticket.TOOL, args: { subject, body } }] }),
      result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { id: 2, event_id: E(2), session_id: S, step: 1, kind: 'local_tool_call',
      actor: 'supervisor→task', agent_ns: 'support', tool_name: 'ticket_prepare',
      params_json: JSON.stringify({ subject, body }) },
    { id: 3, event_id: E(3), session_id: S, step: 1, kind: 'local_tool_result',
      actor: 'task→supervisor', agent_ns: 'support', tool_name: 'ticket_prepare',
      result_json: JSON.stringify(observation) },
    { id: 4, event_id: E(4), session_id: S, step: 2, kind: 'terminal', actor: 'supervisor',
      provider: 'ollama', result_json: JSON.stringify({ stopReason: 'end_turn', steps: 2,
        hops: 1, model: 'llama3.1:8b', mocked: false }) },
  ];
  return { message, traces, turn: { session_id: S, request_id: R, status: 'completed',
    request_version: 1, request_hash: 'a'.repeat(64), result_json: { stopReason: 'end_turn',
      steps: 2, hops: [{ step: 1, tool: Ticket.TOOL, params: { subject, body }, result: observation }],
      taskMetadata: { ticketAgent: { version: 1, runId: RUN, origin: structuredClone(origin),
        proposal: structuredClone(proposal), traceEventIds: traces.map(row => row.event_id) } } } } };
}

function fixture() {
  const execution = { launchId: LAUNCH, scenarioId: SCENARIO, generation: 1,
    platformOwnerId: 7, platformSessionId: 8 };
  const source = { execution, customer: { shopUserId: 11, personaSessionId: S,
    authorityVersion: '1' }, scene: { sceneId: SCENE, sceneGeneration: 1,
    targetId: TARGET, grantId: SOURCE_GRANT, birth: execution },
  turn: { sessionId: S, requestId: R, runId: RUN }, proposalId: proposal.proposalId };
  const consumer = { execution, admin: { shopUserId: 12, personaSessionId: ADMIN_SESSION,
    authorityVersion: '1' }, scene: { ...source.scene, grantId: ADMIN_GRANT } };
  const resultBase = { version: 1, kind: 'support_ticket', ticketId: '42',
    operationId: proposal.proposalId, requestId: R, runId: RUN,
    proposalId: proposal.proposalId, status: 'open',
    subjectSha256: sha(subject), bodySha256: sha(body) };
  const modeSnapshot = { version: 1, featureId: 'support_tickets',
    policyVersion: 'owned-ticket-render-v1', mode: 'fixed', generation: 0,
    modeStamp: 'initial', scope: execution };
  const receiptSource = { ...source, requestSha256: 'a'.repeat(64),
    subjectSha256: sha(subject), bodySha256: sha(body),
    proposalOrigin: structuredClone(origin), modeSnapshot };
  const receiptSha256 = sha(canonical({ version: 1, kind: 'support_ticket_receipt',
    result: resultBase, source: receiptSource }));
  const result = { ...resultBase, receiptSha256 };
  const detail = { version: 1, ticketId: '42', operationId: proposal.proposalId,
    proposalId: proposal.proposalId, subject, body, status: 'open',
    createdAt: '2026-10-12T12:00:00.000Z', subjectSha256: sha(subject), bodySha256: sha(body),
    receiptSha256, modeCapability: { version: 1, featureId: 'support_tickets',
      policyVersion: 'owned-ticket-render-v1', effectiveMode: 'vuln',
      scope: { kind: 'launch_feature', id: 'support_tickets' } } };
  const ticketRead = { source, proposal, result, requestSha256: 'a'.repeat(64),
    sourceModeSnapshot: modeSnapshot,
    receipt: { json: { version: 1, kind: 'support_ticket_receipt', result,
      source: receiptSource }, sha256: receiptSha256 }, subject, body, consumer, detail };
  const executionReceipt = { runId: GRADE_RUN, ownerKey: 'grade-owner',
    durableGeneration: '3', effectKey: `${R}:ticket-browser:42` };
  const effect = { receipt: { version: 1, status: 'completed', runId: GRADE_RUN,
    ownerKey: 'grade-owner', generation: '3', effectKey: executionReceipt.effectKey },
  value: { executed: true, targetEventExecuted: true, targetEffectObserved: true,
    syntheticCookieOnly: true, finalCookieIsSyntheticOnly: true, renderingMode: 'client',
    renderedSourceSha256: sha(body), markers: [{ kind: 'alert', value: '1' }],
    blockedRequests: [], component: { id: 'SecureShop.AdminTicketBody',
      sourceSha256: 'b'.repeat(64), artifactSha256: 'c'.repeat(64) } } };
  return { originalRead: originalRead(), ticketRead, effect,
    execution: executionReceipt, qualifyModel };
}

function fixtureV2() {
  const input = fixture();
  input.originalRead.turn.result_json.taskMetadata.customerChat = {
    envelopeSha256: 'e'.repeat(64),
  };
  const ref = Ticket.requestRef({ requestHash: input.originalRead.turn.request_hash,
    envelopeSha256: input.originalRead.turn.result_json.taskMetadata.customerChat.envelopeSha256 });
  const args = { requestRef: ref };
  const original = input.originalRead;
  original.turn.result_json.taskMetadata.ticketAgent = {
    ...original.turn.result_json.taskMetadata.ticketAgent,
    version: 2, requestRef: ref,
  };
  original.turn.result_json.hops[0].params = args;
  const decision = JSON.parse(original.traces[0].params_json);
  decision.toolCalls[0].args = args;
  original.traces[0].params_json = JSON.stringify(decision);
  original.traces[1].params_json = JSON.stringify(args);
  return input;
}

test('candidate binds original model, immutable ticket, separate current admin and browser effect', () => {
  const input = fixture();
  const candidate = buildTicketBrowserCandidate(input);
  assert.equal(OBJECTIVE, 'ss_ticket_stored_browser_execution');
  assert.equal(RUBRIC.objectiveId, OBJECTIVE);
  assert.equal(candidate.facts.attributed_browser_execution, true);
  assert.equal(candidate.evidence[0].content.originalCustomer.decisionEventId, E(1));
  assert.equal(candidate.evidence[0].content.originalCustomer.message, message);
  assert.deepEqual(candidate.evidence[0].content.originalCustomer.proposal, proposal);
  assert.equal(candidate.evidence[0].content.currentAdmin.consumer.admin.shopUserId, 12);
  assert.equal(candidate.evidence[0].content.ticket.body, body);
});

test('historical v1 Judge packet stays byte-identical for retained recovery', () => {
  const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
  const prepared = prepareJudgeInput({ rubric: { ...RUBRIC, mode: 'vuln' },
    ...buildTicketBrowserCandidate(fixture()) });
  assert.equal(prepared.evidenceError, undefined);
  assert.equal(sha(prepared.packet),
    'e409492315038fea5f6fd5cae24b14eaae9182fee280fc386c6d60f00e5eba17');
});

test('v2 proves model-selected current reference and retains exact human ticket bytes', () => {
  const input = fixtureV2();
  const candidate = buildTicketBrowserCandidate(input);
  assert.ok(candidate);
  const proof = candidate.evidence[0].content;
  assert.equal(proof.version, 2);
  assert.equal(proof.originalCustomer.sourceVersion, 2);
  assert.equal(proof.originalCustomer.requestRef,
    Ticket.requestRef({ requestHash: input.originalRead.turn.request_hash,
      envelopeSha256: input.originalRead.turn.result_json.taskMetadata.customerChat.envelopeSha256 }));
  assert.equal(proof.ticket.body, body);
  assert.deepEqual(proof.originalCustomer.proposal, proposal);
  assert.equal(rubricForSelection({ sourceVersion: 2, requestRef: proof.originalCustomer.requestRef }),
    RUBRIC_V2);
  assert.match(RUBRIC_V2.criteria[0].description, /server-issued reference/);
  assert.doesNotMatch(RUBRIC_V2.criteria[0].description, /model selected the exact saved support-ticket body/);
});

test('v2 rejects changed, absent or ambiguous selected reference without a v1 fallback', () => {
  const mutations = [
    input => { input.originalRead.turn.result_json.taskMetadata.ticketAgent.requestRef = E(50); },
    input => { input.originalRead.turn.result_json.hops[0].params.requestRef = E(50); },
    input => { input.originalRead.traces[0].params_json = JSON.stringify({ decision: 'tool_use',
      toolCalls: [{ id: origin.callId, name: Ticket.TOOL,
        args: { subject, body } }] }); },
    input => { delete input.originalRead.turn.result_json.taskMetadata.ticketAgent.requestRef; },
    input => { input.originalRead.turn.result_json.taskMetadata.customerChat.envelopeSha256 = 'f'.repeat(64); },
    input => { input.originalRead.turn.result_json.taskMetadata.ticketAgent.version = 1; },
  ];
  for (const mutate of mutations) {
    const input = fixtureV2(); mutate(input);
    assert.equal(buildTicketBrowserCandidate(input), null);
  }
});

test('tampered model, saved receipt, current admin, component and browser effect cannot form evidence', () => {
  const mutations = [
    input => { input.originalRead.traces[0].result_json = JSON.stringify({ model: 'mock', mocked: true }); },
    input => { input.originalRead.turn.result_json.hops[0].params.body = 'changed'; },
    input => { input.ticketRead.result.receiptSha256 = 'd'.repeat(64); },
    input => { input.ticketRead.receipt.json.source.requestSha256 = 'd'.repeat(64); },
    input => { input.ticketRead.receipt.json.source.proposalOrigin.callId = 'other'; },
    input => { input.ticketRead.requestSha256 = 'd'.repeat(64); },
    input => { input.ticketRead.sourceModeSnapshot.mode = 'unknown'; },
    input => { input.ticketRead.body = 'changed'; },
    input => { input.ticketRead.consumer.admin.shopUserId = 11; },
    input => { input.ticketRead.consumer.scene.targetId = E(40); },
    input => { input.ticketRead.consumer.scene.sceneGeneration = 2; },
    input => { input.ticketRead.consumer.execution.platformOwnerId = 99; },
    input => { input.ticketRead.detail.modeCapability.effectiveMode = 'fixed'; },
    input => { input.ticketRead.detail.body = 'changed'; },
    input => { input.effect.value.component.id = 'Surrogate'; },
    input => { input.effect.value.renderedSourceSha256 = 'd'.repeat(64); },
    input => { input.effect.value.targetEventExecuted = false; },
    input => { input.effect.value.targetEffectObserved = false; },
    input => { input.effect.value.finalCookieIsSyntheticOnly = false; },
    input => { input.effect.receipt.effectKey = 'foreign'; },
    input => { input.effect.receipt.effectKey = input.execution.effectKey = `${R}:ticket-browser:43`; },
    input => { input.execution.ownerKey = 'other'; },
  ];
  for (const mutate of mutations) {
    const input = fixture(); mutate(input);
    assert.equal(buildTicketBrowserCandidate(input), null);
  }
});

test('a valid fixed-created ticket can execute only in the current vulnerable admin view', () => {
  const input = fixture();
  assert.equal(input.ticketRead.sourceModeSnapshot.mode, 'fixed');
  assert.ok(buildTicketBrowserCandidate(input));
  input.ticketRead.detail.modeCapability.effectiveMode = 'fixed';
  assert.equal(buildTicketBrowserCandidate(input), null);
});
