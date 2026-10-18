'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const Ticket = require('../server/services/secureshopTicketContract');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createSecureShopTicketRepository } = require('../server/database/postgres/secureshopTicketRepository');

const id = () => randomUUID();
const sha = value => createHash('sha256').update(value).digest('hex');
const clone = value => structuredClone(value);

function fixture() {
  const birth = { launchId: id(), scenarioId: id(), generation: 1, platformOwnerId: 7, platformSessionId: 11 };
  const targetId = id(), sceneId = id();
  const customerExecution = { ...birth };
  const adminExecution = { launchId: id(), scenarioId: id(), generation: 2, platformOwnerId: 7, platformSessionId: 12 };
  const customerGrantId = id(), adminGrantId = id();
  const customerScene = createSceneBinding({ ...birth, targetId }, { sceneId, sceneGeneration: 1,
    grantId: customerGrantId, execution: customerExecution, withLease: work => work() });
  const adminScene = createSceneBinding({ ...birth, targetId }, { sceneId, sceneGeneration: 1,
    grantId: adminGrantId, execution: adminExecution, withLease: work => work() });
  const customerPersona = { id: 21, role: 'customer' };
  const customerSession = { sessionId: id(), authorityVersion: '1' };
  const adminPersona = { id: 22, role: 'admin' };
  const adminSession = { sessionId: id(), authorityVersion: '2' };
  const origin = { turnSessionId: id(), turnRequestId: id(), toolKey: Ticket.TOOL, invocationStep: 1, callId: 'ticket-call-1' };
  const message = JSON.stringify({ subject: 'Need order support', body: 'Exact customer body <owned-canary>' });
  const proposal = Ticket.prepare({ subject: 'Need order support', body: 'Exact customer body <owned-canary>', message, sourceOrigin: origin });
  const source = { execution: customerExecution,
    customer: { shopUserId: customerPersona.id, personaSessionId: customerSession.sessionId, authorityVersion: customerSession.authorityVersion },
    scene: { sceneId, sceneGeneration: 1, targetId, grantId: customerGrantId, birth },
    turn: { sessionId: origin.turnSessionId, requestId: origin.turnRequestId, runId: id() }, proposalId: proposal.proposalId };
  const scopeToken = scope => Object.freeze({ snapshot: Object.freeze({ version: 1, featureId: 'support_tickets',
    policyVersion: 'owned-ticket-render-v1', mode: 'vuln', generation: 3, modeStamp: 'stamp-3', scope }),
  async assertCurrent() {}, async assertCurrentAtEffect() {} });
  const customerMode = scopeToken(customerExecution), adminMode = scopeToken(adminExecution);
  return { birth, targetId, sceneId, customerScene, adminScene, customerPersona, customerSession, adminPersona, adminSession,
    origin, message, proposal, source, customerMode, adminMode, customerExecution, adminExecution };
}

function memoryPool() {
  const tickets = new Map(), receipts = new Map(), queries = [];
  let nextTicket = 1;
  const merged = row => ({ ...row, request_sha256: Buffer.from(row.request_sha256),
    subject_sha256: Buffer.from(row.subject_sha256), body_sha256: Buffer.from(row.body_sha256),
    source_mode_snapshot: clone(row.source_mode_snapshot), receipt_operation_id: row.operation_id,
    receipt_ticket_id: row.ticket_id, receipt_target_id: row.target_id,
    receipt_json: clone(receipts.get(row.operation_id).receipt_json),
    receipt_sha256: Buffer.from(receipts.get(row.operation_id).receipt_sha256), created_at_utc: row.created_at });
  const client = {
    async query(text, values = []) {
      queries.push({ text, values: clone(values) });
      if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(text) || text.startsWith("SELECT set_config") || text.startsWith('SELECT pg_advisory')) return { rows: [], rowCount: 0 };
      if (text.includes('assert_scene_execution_grant')) return { rows: [{ allowed: true }], rowCount: 1 };
      if (text.includes('FROM secureshop_review.product_targets') && text.includes('FOR SHARE')) return { rows: [{ lifecycle: 'active' }], rowCount: 1 };
      if (text.includes('WHERE t.operation_id=$1')) {
        const row = tickets.get(values[0]);
        return { rows: row ? [merged(row)] : [], rowCount: row ? 1 : 0 };
      }
      if (text.startsWith('INSERT INTO secureshop_review.product_target_support_tickets')) {
        const row = {
          operation_id: values[0], proposal_id: values[1], proposal_tool_key: values[2], proposal_invocation_step: values[3], proposal_call_id: values[4],
          ticket_id: String(nextTicket++), target_id: values[5], source_launch_id: values[6], source_scenario_id: values[7], source_generation: values[8],
          source_platform_owner_id: values[9], source_platform_session_id: values[10], source_scene_id: values[11], source_scene_generation: values[12],
          source_grant_id: values[13], birth_launch_id: values[14], birth_scenario_id: values[15], birth_generation: values[16],
          birth_platform_owner_id: values[17], birth_platform_session_id: values[18], shop_user_id: values[19], persona_session_id: values[20],
          authority_version: values[21], turn_session_id: values[22], turn_request_id: values[23], turn_run_id: values[24], request_sha256: Buffer.from(values[25]),
          subject: values[26], body: values[27], subject_sha256: Buffer.from(values[28]), body_sha256: Buffer.from(values[29]),
          source_mode_snapshot: JSON.parse(values[30]), created_at: '2026-10-12T20:00:00.000Z', status: 'open' };
        tickets.set(row.operation_id, row);
        return { rows: [{ ...row, request_sha256: Buffer.from(row.request_sha256), subject_sha256: Buffer.from(row.subject_sha256), body_sha256: Buffer.from(row.body_sha256) }], rowCount: 1 };
      }
      if (text.startsWith('INSERT INTO secureshop_review.product_target_support_ticket_receipts')) {
        const row = { operation_id: values[0], ticket_id: String(values[1]), target_id: values[2], receipt_json: JSON.parse(values[3]), receipt_sha256: Buffer.from(values[4]) };
        receipts.set(row.operation_id, row);
        return { rows: [{ ...row, receipt_json: clone(row.receipt_json), receipt_sha256: Buffer.from(row.receipt_sha256) }], rowCount: 1 };
      }
      if (text.includes('WHERE t.target_id=$1::uuid')) {
        const rows = [...tickets.values()].filter(row => row.target_id === values[0] && row.shop_user_id !== values[14]);
        return { rows: rows.map(merged), rowCount: rows.length };
      }
      if (text.includes('product_target_support_ticket_retirements')) return { rows: [], rowCount: 0 };
      throw new Error(`unexpected query ${text.slice(0, 100)}`);
    },
    release() {},
  };
  return { pool: { async connect() { return client; } }, tickets, receipts, queries };
}

function customerInput(f) {
  return { scope: f.customerExecution, retainedScene: f.customerScene, persona: f.customerPersona,
    personaSession: f.customerSession, modeToken: f.customerMode, source: f.source, ticketProposal: f.proposal,
    originalMessage: f.message, sourceOrigin: f.origin, requestSha256: sha('protected journal request'), withEffect: async work => work() };
}
function adminInput(f) {
  return { scope: f.adminExecution, retainedScene: f.adminScene, persona: f.adminPersona,
    personaSession: f.adminSession, modeToken: f.adminMode };
}

test('ticket confirmation persists an immutable non-self-referential receipt and exact replay', async () => {
  const f = fixture(), state = memoryPool();
  let current = 0, effects = 0;
  const effect = async work => { effects += 1; return work(); };
  const repository = createSecureShopTicketRepository({ pool: state.pool, checkCurrent: async () => { current += 1; },
    modeAuthority: { assertToken: value => value } });
  await assert.rejects(repository.confirm({ ...customerInput(f), withEffect: undefined }), { code: 'TICKET_AUTHORITY_INVALID' });
  assert.equal(state.tickets.size, 0);
  const first = await repository.confirm({ ...customerInput(f), withEffect: effect });
  const replay = await repository.confirm({ ...customerInput(f), withEffect: effect });
  assert.deepEqual(replay, first);
  assert.equal(state.tickets.size, 1);
  assert.equal(state.receipts.size, 1);
  assert.equal(first.operationId, f.proposal.proposalId);
  assert.equal(first.requestId, f.origin.turnRequestId);
  assert.ok(current >= 4);
  assert.equal(state.queries.filter(({ text }) => text.startsWith('INSERT INTO secureshop_review.product_target_support_tickets')).length, 1);
  assert.equal(state.queries.filter(({ text }) => text.startsWith('INSERT INTO secureshop_review.product_target_support_ticket_receipts')).length, 1);
  const saved = await repository.readSavedCustomer({ ...customerInput(f), ticketProposal: undefined, originalMessage: undefined,
    sourceOrigin: undefined, requestSha256: undefined });
  assert.deepEqual(saved, first);
  const before = state.queries.length;
  await assert.rejects(repository.confirm({ ...customerInput(f), requestSha256: sha('different journal request') }), { code: 'TICKET_OPERATION_CONFLICT' });
  assert.equal(state.tickets.size, 1);
  assert.equal(effects, 2, 'each confirmation invokes the one outer effect callback exactly once');
  assert.ok(state.queries.length > before);
});

test('saved customer read is select-only and rejects a changed source/session or retired receipt', async () => {
  const f = fixture(), state = memoryPool();
  const repository = createSecureShopTicketRepository({ pool: state.pool, checkCurrent: async () => {}, modeAuthority: { assertToken: value => value } });
  await repository.confirm(customerInput(f));
  const before = state.queries.length;
  await repository.readSavedCustomer({ ...customerInput(f), ticketProposal: undefined, originalMessage: undefined,
    sourceOrigin: undefined, requestSha256: undefined });
  const readQueries = state.queries.slice(before).map(({ text }) => text);
  assert.equal(readQueries.some(text => /\b(?:INSERT|UPDATE|DELETE)\b/i.test(text)), false);
  await assert.rejects(repository.readSavedCustomer({ ...customerInput(f), source: { ...f.source,
    customer: { ...f.source.customer, personaSessionId: id() } } }), { code: 'TICKET_SOURCE_INVALID' });
  const receipt = state.receipts.get(f.source.proposalId);
  receipt.receipt_json.source.proposalOrigin.callId = 'tampered';
  await assert.rejects(repository.readSavedCustomer({ ...customerInput(f), ticketProposal: undefined, originalMessage: undefined,
    sourceOrigin: undefined, requestSha256: undefined }), { code: 'TICKET_RECEIPT_INVALID' });
});

test('admin reads require a distinct current admin grant and do not expose body in list output', async () => {
  const f = fixture(), state = memoryPool();
  const repository = createSecureShopTicketRepository({ pool: state.pool, checkCurrent: async () => {}, modeAuthority: { assertToken: value => value } });
  const result = await repository.confirm(customerInput(f));
  const list = await repository.listForAdmin(adminInput(f));
  assert.deepEqual(list, { version: 1, tickets: [{ ticketId: result.ticketId, subject: f.proposal.subject,
    status: 'open', createdAt: '2026-10-12T20:00:00.000Z' }], nextCursor: null });
  assert.equal(JSON.stringify(list).includes(f.proposal.body), false);
  const detail = await repository.readForAdmin(adminInput(f), { ticketId: result.ticketId });
  assert.equal(detail.body, f.proposal.body);
  const beforeAssessment = state.queries.length;
  const assessment = await repository.readForAssessment(adminInput(f), { ticketId: result.ticketId });
  assert.deepEqual(assessment.result, result);
  assert.deepEqual(assessment.proposal, f.proposal);
  assert.deepEqual(assessment.source, f.source);
  assert.equal(assessment.receipt.sha256, result.receiptSha256);
  assert.equal(state.queries.slice(beforeAssessment).some(({ text }) => /\b(?:INSERT|UPDATE|DELETE)\b/i.test(text)), false);
  const adminQuery = state.queries.find(({ text }) => text.includes('consumer_grant'));
  assert.ok(adminQuery);
  assert.equal(adminQuery.values[8], f.adminScene.scene.grantId);
  assert.equal(adminQuery.values[13], f.adminExecution.platformSessionId);
  assert.equal(adminQuery.values.at(-1), 21);
  const ownCustomer = await repository.listForAdmin({ ...adminInput(f), persona: { id: f.customerPersona.id, role: 'admin' } });
  assert.deepEqual(ownCustomer, { version: 1, tickets: [], nextCursor: null },
    'the admin reader never projects a ticket whose durable customer is the same shop user');
});

test('0049 makes support tickets immutable, source-grant-bound, retired on target reset, and runtime-minimal', () => {
  const migration = require('node:fs').readFileSync('db/postgres/workshop-migrations/secureshop_review/0049_bound_support_ticket_receipts.sql', 'utf8');
  for (const fragment of [
    'product_target_support_tickets', 'product_target_support_ticket_receipts', 'product_target_support_ticket_retirements',
    'proposal_invocation_step', 'proposal_call_id', 'guard_support_ticket_insert', 'source_grant_id',
    'retire_product_target_support_tickets', 'AFTER UPDATE OF lifecycle ON secureshop_review.product_targets',
    'REVOKE ALL ON TABLE', 'GRANT SELECT,INSERT ON secureshop_review.product_target_support_tickets',
  ]) assert.match(migration, new RegExp(fragment));
  assert.doesNotMatch(migration, /legacy.*support_tickets/i);
});
