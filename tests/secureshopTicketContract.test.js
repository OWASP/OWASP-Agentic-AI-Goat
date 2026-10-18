'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const Ticket = require('../server/services/secureshopTicketContract');

test('request reference binds both protected turn and full scene/persona envelope digests', () => {
  const binding = { requestHash: 'a'.repeat(64), envelopeSha256: 'c'.repeat(64) };
  const first = Ticket.requestRef(binding);
  assert.match(first, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(first, Ticket.requestRef(binding));
  assert.notEqual(first, Ticket.requestRef({ ...binding, requestHash: 'b'.repeat(64) }));
  assert.notEqual(first, Ticket.requestRef({ ...binding, envelopeSha256: 'd'.repeat(64) }));
  assert.throws(() => Ticket.requestRef('not-a-turn-hash'), { code: 'TICKET_CONTRACT_INVALID' });
});

const id = () => randomUUID();
const sha = text => createHash('sha256').update(text).digest('hex');
const original = { turnSessionId: id(), turnRequestId: id(), toolKey: Ticket.TOOL,
  invocationStep: 1, callId: 'provider-call-1' };
const subject = 'Need help with an order';
const body = '  <img src=x onerror="fetch(\'/owned-canary\')">  ';
const message = JSON.stringify({ subject, body });
const prepared = Ticket.prepare({ subject, body, message, sourceOrigin: original });
const birth = { launchId: id(), scenarioId: id(), generation: 1,
  platformOwnerId: 7, platformSessionId: 11 };
const customerExecution = { launchId: birth.launchId, scenarioId: birth.scenarioId,
  generation: 1, platformOwnerId: 7, platformSessionId: 11 };
const common = { sceneId: id(), sceneGeneration: 1, targetId: id(), birth };
const source = { execution: customerExecution,
  customer: { shopUserId: 21, personaSessionId: id(), authorityVersion: '1' },
  scene: { ...common, grantId: id() },
  turn: { sessionId: original.turnSessionId, requestId: original.turnRequestId, runId: id() },
  proposalId: prepared.proposalId };
const admin = { execution: { launchId: id(), scenarioId: id(), generation: 2,
  platformOwnerId: 7, platformSessionId: 12 },
admin: { shopUserId: 23, personaSessionId: id(), authorityVersion: '2' },
scene: { ...common, grantId: id() } };
const result = { version: 1, kind: 'support_ticket', ticketId: '37',
  operationId: prepared.proposalId, requestId: original.turnRequestId,
  runId: source.turn.runId, proposalId: prepared.proposalId, status: 'open',
  subjectSha256: sha(subject), bodySha256: sha(body), receiptSha256: 'a'.repeat(64) };
const mode = effectiveMode => ({ version: 1, featureId: 'support_tickets',
  policyVersion: 'owned-ticket-render-v1', effectiveMode,
  scope: { kind: 'launch_feature', id: 'support_tickets' } });

test('repository-facing ticket mode validator is exported and rejects stale or foreign capabilities', () => {
  for (const effectiveMode of ['vuln', 'fixed'])
    assert.deepEqual(Ticket.modeCapability(mode(effectiveMode)), mode(effectiveMode));
  for (const candidate of [
    { ...mode('vuln'), featureId: 'customer_chat' },
    { ...mode('vuln'), policyVersion: 'old-policy' },
    { ...mode('vuln'), scope: { kind: 'launch_feature', id: 'customer_chat' } },
    { ...mode('vuln'), privateToken: 'must-not-project' },
  ]) assert.throws(() => Ticket.modeCapability(candidate), { code: 'TICKET_CONTRACT_INVALID' });
});

test('ticket prepare preserves exact human JSON fields and creates no effect claim', () => {
  assert.deepEqual(Ticket.humanRequest(message), { subject, body });
  assert.deepEqual(Ticket.selected({ subject, body }, message), { subject, body });
  assert.equal(prepared.subject, subject);
  assert.equal(prepared.body, body);
  assert.equal(prepared.subjectSha256, sha(subject));
  assert.equal(prepared.bodySha256, sha(body));
  assert.equal(prepared.proposalId, Ticket.operationId(original));
  assert.deepEqual(Ticket.proposal(prepared, { message, sourceOrigin: original }), prepared);
  assert.deepEqual(Ticket.proposal({ ...prepared, origin: {
    callId: original.callId, invocationStep: original.invocationStep,
    toolKey: original.toolKey, turnRequestId: original.turnRequestId,
    turnSessionId: original.turnSessionId } }, { message, sourceOrigin: original }), prepared,
  'JSONB key order must not change protected origin identity');
  assert.deepEqual(Ticket.projectProposal(prepared, { message, sourceOrigin: original }), {
    version: 1, kind: Ticket.TOOL, status: 'confirmation_required',
    proposalId: prepared.proposalId, subject, body,
    subjectSha256: sha(subject), bodySha256: sha(body) });
  for (const candidate of [
    JSON.stringify({ body, subject }),
    `${message} extra`,
    ` ${message}`,
    `{"subject":${JSON.stringify(subject)},"subject":${JSON.stringify(subject)},"body":${JSON.stringify(body)}}`,
    JSON.stringify({ subject, body, customerId: 21 }),
  ]) assert.throws(() => Ticket.humanRequest(candidate), { code: 'TICKET_CONTRACT_INVALID' });
  for (const value of [body.trim(), `${body} `, body.replace('owned-canary', 'other')]) {
    assert.throws(() => Ticket.prepare({ subject, body: value, message, sourceOrigin: original }),
      { code: 'TICKET_CONTRACT_INVALID' });
  }
  assert.throws(() => Ticket.prepare({ subject: 'changed', body, message, sourceOrigin: original }),
    { code: 'TICKET_CONTRACT_INVALID' });
  for (const badBody of ['a\0b', '\ud800', ' '.repeat(4097)]) {
    assert.throws(() => Ticket.humanRequest(JSON.stringify({ subject, body: badBody })),
      { code: 'TICKET_CONTRACT_INVALID' });
  }
  assert.throws(() => Ticket.proposal({ ...prepared, bodySha256: 'b'.repeat(64) },
    { message, sourceOrigin: original }), { code: 'TICKET_CONTRACT_INVALID' });
  assert.throws(() => Ticket.origin({ ...original, invocationStep: 0 }),
    { code: 'TICKET_CONTRACT_INVALID' });
});

test('confirmation accepts only protected turn IDs and deterministic proposal ID', () => {
  const request = { sessionId: original.turnSessionId, requestId: original.turnRequestId,
    proposalId: prepared.proposalId };
  assert.deepEqual(Ticket.confirmation(request, { sourceOrigin: original }), request);
  for (const mutation of [
    { ...request, body }, { ...request, proposalId: id() },
    { ...request, requestId: id() }, { ...request, sessionId: id() },
  ]) assert.throws(() => Ticket.confirmation(mutation, { sourceOrigin: original }),
    { code: 'TICKET_CONTRACT_INVALID' });
  assert.notEqual(Ticket.operationId({ ...original, callId: 'other-call' }), prepared.proposalId);
});

test('customer source and current admin consumer stay distinct with exact scene and birth', () => {
  assert.deepEqual(Ticket.source(source), source);
  assert.deepEqual(Ticket.consumer(admin, source), admin);
  for (const changed of [
    { ...admin, execution: { ...admin.execution, platformOwnerId: 8 } },
    { ...admin, scene: { ...admin.scene, sceneId: id() } },
    { ...admin, scene: { ...admin.scene, sceneGeneration: 2 } },
    { ...admin, scene: { ...admin.scene, targetId: id() } },
    { ...admin, scene: { ...admin.scene, birth: { ...birth, launchId: id() } } },
    { ...admin, admin: { ...admin.admin, shopUserId: source.customer.shopUserId } },
  ]) assert.throws(() => Ticket.consumer(changed, source), { code: 'TICKET_CONTRACT_INVALID' });
  assert.throws(() => Ticket.source({ ...source,
    scene: { ...source.scene, birth: { ...birth, generation: 0 } } }),
  { code: 'TICKET_CONTRACT_INVALID' }, 'invalid retained birth is rejected');
  assert.notEqual(admin.execution.launchId, source.execution.launchId);
  assert.notEqual(admin.scene.grantId, source.scene.grantId);
});

test('saved result and admin list/detail expose only closed fields with current mode', () => {
  const options = { source, ticketProposal: prepared };
  assert.deepEqual(Ticket.publicResult(result), result);
  assert.deepEqual(Ticket.result(result, options), result);
  assert.throws(() => Ticket.result({ ...result, runId: id() }, options),
    { code: 'TICKET_CONTRACT_INVALID' }, 'no replacement graph run ID');
  assert.throws(() => Ticket.result(result, { ...options,
    source: { ...source, turn: { ...source.turn, runId: id() } } }),
  { code: 'TICKET_CONTRACT_INVALID' }, 'result cannot borrow a different source run ID');
  assert.throws(() => Ticket.result(result, { source,
    ticketProposal: { ...prepared, origin: { ...original, turnRequestId: id() } } }),
  { code: 'TICKET_CONTRACT_INVALID' });
  assert.deepEqual(Ticket.publicSaved({ status: 'unconfirmed' }), { status: 'unconfirmed' });
  assert.deepEqual(Ticket.publicSaved({ status: 'completed', result }),
    { status: 'completed', result });
  assert.deepEqual(Ticket.saved({ status: 'unconfirmed' }, options), { status: 'unconfirmed' });
  assert.deepEqual(Ticket.saved({ status: 'completed', result }, options),
    { status: 'completed', result });
  assert.throws(() => Ticket.saved({ status: 'completed', result, source }, options),
    { code: 'TICKET_CONTRACT_INVALID' });
  assert.throws(() => Ticket.result({ ...result, body }, options),
    { code: 'TICKET_CONTRACT_INVALID' });
  const createdAt = '2026-10-12T20:00:00.000Z';
  const list = { version: 1, tickets: [{ ticketId: result.ticketId, subject,
    status: 'open', createdAt }], nextCursor: null };
  assert.deepEqual(Ticket.adminList(list), list);
  assert.throws(() => Ticket.adminList({ ...list, tickets: [{ ...list.tickets[0], body }] }),
    { code: 'TICKET_CONTRACT_INVALID' });
  for (const effectiveMode of ['vuln', 'fixed']) {
    const detail = { version: 1, ticketId: result.ticketId, operationId: result.operationId,
      proposalId: result.proposalId, subject, body, status: 'open', createdAt,
      subjectSha256: result.subjectSha256, bodySha256: result.bodySha256,
      receiptSha256: result.receiptSha256, modeCapability: mode(effectiveMode) };
    assert.deepEqual(Ticket.publicAdminDetail(detail), detail);
    assert.deepEqual(Ticket.adminDetail(detail, { source, consumer: admin }), detail);
    assert.throws(() => Ticket.publicAdminDetail({ ...detail, source }),
      { code: 'TICKET_CONTRACT_INVALID' });
    assert.throws(() => Ticket.adminDetail({ ...detail, body: `${body}x` },
      { source, consumer: admin }), { code: 'TICKET_CONTRACT_INVALID' });
    assert.throws(() => Ticket.adminDetail({ ...detail, modeCapability: mode('unknown') },
      { source, consumer: admin }), { code: 'TICKET_CONTRACT_INVALID' });
    assert.throws(() => Ticket.adminDetail({ ...detail, source },
      { source, consumer: admin }), { code: 'TICKET_CONTRACT_INVALID' });
  }
});
