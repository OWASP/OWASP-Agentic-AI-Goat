'use strict';

// Durable, launch-owned support tickets for the bound storefront. This does
// not access the legacy shared support_tickets teaching table.
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { withTransaction } = require('./index');
const Ticket = require('../../services/secureshopTicketContract');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const { executionScope, assertSceneGrant, withSceneLease } = require('../../services/secureshopSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{64}$/;
const fail = code => Object.assign(new Error('Support ticket repository unavailable'), { code, executionBoundary: true });
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
  : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const hash = value => createHash('sha256').update(canonical(value)).digest('hex');
const hex = value => {
  if (!Buffer.isBuffer(value) || value.length !== 32) throw fail('TICKET_RECEIPT_INVALID');
  return value.toString('hex');
};
const bytes = value => {
  if (typeof value !== 'string' || !SHA.test(value)) throw fail('TICKET_INVALID');
  return Buffer.from(value, 'hex');
};
const uuid = value => {
  if (typeof value !== 'string' || !UUID.test(value)) throw fail('TICKET_INVALID');
  return value.toLowerCase();
};
const positive = value => {
  if (!Number.isSafeInteger(value) || value < 1) throw fail('TICKET_INVALID');
  return value;
};
const sameScope = (left, right) => ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
  .every(key => left?.[key] === right?.[key]);

function context(input, role) {
  if (!input || typeof input !== 'object' || input.persona?.role !== role || !input.retainedScene?.scene) {
    throw fail('TICKET_AUTHORITY_INVALID');
  }
  const scope = createLaunchScope(input.scope);
  const retained = input.retainedScene;
  const current = executionScope(retained);
  const birth = createLaunchScope(retained);
  const scene = retained.scene;
  if (!sameScope(scope, current) || !UUID.test(retained.targetId || '') || !UUID.test(scene.sceneId || '')
      || !UUID.test(scene.grantId || '') || !Number.isSafeInteger(scene.sceneGeneration)
      || scene.sceneGeneration < 1 || scope.platformOwnerId !== birth.platformOwnerId
      || !Number.isSafeInteger(input.persona.id) || input.persona.id < 1
      || typeof input.personaSession?.authorityVersion !== 'string'
      || !/^[1-9]\d*$/.test(input.personaSession.authorityVersion)) {
    throw fail('TICKET_AUTHORITY_INVALID');
  }
  return Object.freeze({ scope, retained, birth, scene: Object.freeze({ sceneId: scene.sceneId,
    sceneGeneration: scene.sceneGeneration, targetId: retained.targetId, grantId: scene.grantId }),
  persona: Object.freeze({ id: input.persona.id, role }), personaSession: Object.freeze({
    sessionId: uuid(input.personaSession.sessionId), authorityVersion: input.personaSession.authorityVersion }) });
}

function mode(modeAuthority, raw, scope) {
  if (typeof modeAuthority?.assertToken !== 'function') throw fail('TICKET_MODE_STALE');
  const token = modeAuthority.assertToken(raw);
  const snapshot = token?.snapshot;
  if (!snapshot || snapshot.version !== 1 || snapshot.featureId !== 'support_tickets'
      || snapshot.policyVersion !== 'owned-ticket-render-v1' || !['vuln', 'fixed'].includes(snapshot.mode)
      || !sameScope(snapshot.scope, scope) || !Number.isSafeInteger(snapshot.generation)
      || snapshot.generation < 0 || typeof snapshot.modeStamp !== 'string' || !snapshot.modeStamp
      || typeof token.assertCurrent !== 'function') throw fail('TICKET_MODE_STALE');
  return Object.freeze({ token, snapshot: Object.freeze({ version: 1, featureId: snapshot.featureId,
    policyVersion: snapshot.policyVersion, mode: snapshot.mode, generation: snapshot.generation,
    modeStamp: snapshot.modeStamp, scope }) });
}

function ticketSource(value, ctx) {
  let source;
  try { source = Ticket.source(value); } catch { throw fail('TICKET_SOURCE_INVALID'); }
  const expectedScene = { sceneId: ctx.scene.sceneId, sceneGeneration: ctx.scene.sceneGeneration,
    targetId: ctx.scene.targetId, grantId: ctx.scene.grantId, birth: ctx.birth };
  if (!sameScope(source.execution, ctx.scope) || source.customer.shopUserId !== ctx.persona.id
      || source.customer.personaSessionId !== ctx.personaSession.sessionId
      || source.customer.authorityVersion !== ctx.personaSession.authorityVersion
      || !isDeepStrictEqual(source.scene, expectedScene)) throw fail('TICKET_SOURCE_INVALID');
  return source;
}

function proposal(input, source) {
  let value;
  try { value = Ticket.proposal(input.ticketProposal, { message: input.originalMessage, sourceOrigin: input.sourceOrigin }); }
  catch { throw fail('TICKET_PROPOSAL_INVALID'); }
  if (value.proposalId !== source.proposalId || value.origin.turnSessionId !== source.turn.sessionId
      || value.origin.turnRequestId !== source.turn.requestId) throw fail('TICKET_PROPOSAL_INVALID');
  return value;
}

function requestHash(value) {
  if (typeof value !== 'string' || !SHA.test(value)) throw fail('TICKET_REQUEST_INVALID');
  return value;
}

function sourceDocument(source, proposalValue, requestSha256, snapshot) {
  return Object.freeze({ execution: source.execution, customer: source.customer, scene: source.scene,
    turn: source.turn, proposalId: source.proposalId, requestSha256,
    subjectSha256: proposalValue.subjectSha256, bodySha256: proposalValue.bodySha256,
    proposalOrigin: proposalValue.origin, modeSnapshot: snapshot });
}

function resultDocument({ ticketId, source, proposalValue, receiptSha256 }) {
  return Object.freeze({ version: 1, kind: 'support_ticket', ticketId: String(ticketId),
    operationId: source.proposalId, requestId: source.turn.requestId, runId: source.turn.runId,
    proposalId: source.proposalId, status: 'open', subjectSha256: proposalValue.subjectSha256,
    bodySha256: proposalValue.bodySha256, receiptSha256 });
}

function receiptBasis(result, sourceDocumentValue) {
  const { receiptSha256: _receiptSha256, ...resultWithoutReceiptSha } = result;
  return Object.freeze({ version: 1, kind: 'support_ticket_receipt',
    result: Object.freeze(resultWithoutReceiptSha), source: sourceDocumentValue });
}

function receiptDocument(result, sourceDocumentValue) {
  return Object.freeze({ ...receiptBasis(result, sourceDocumentValue), result });
}

function operationFromRows(ticketRow, receiptRow) {
  if (!ticketRow || !receiptRow || ticketRow.operation_id !== receiptRow.operation_id
      || String(ticketRow.ticket_id) !== String(receiptRow.ticket_id)
      || ticketRow.target_id !== receiptRow.target_id || typeof receiptRow.receipt_json !== 'object'
      || !receiptRow.receipt_json) throw fail('TICKET_RECEIPT_INVALID');
  const source = Object.freeze({ execution: Object.freeze({ launchId: ticketRow.source_launch_id,
    scenarioId: ticketRow.source_scenario_id, generation: positive(Number(ticketRow.source_generation)),
    platformOwnerId: positive(Number(ticketRow.source_platform_owner_id)),
    platformSessionId: positive(Number(ticketRow.source_platform_session_id)) }),
  customer: Object.freeze({ shopUserId: positive(Number(ticketRow.shop_user_id)),
    personaSessionId: ticketRow.persona_session_id, authorityVersion: ticketRow.authority_version }),
  scene: Object.freeze({ sceneId: ticketRow.source_scene_id,
    sceneGeneration: positive(Number(ticketRow.source_scene_generation)), targetId: ticketRow.target_id,
    grantId: ticketRow.source_grant_id, birth: Object.freeze({ launchId: ticketRow.birth_launch_id,
      scenarioId: ticketRow.birth_scenario_id, generation: positive(Number(ticketRow.birth_generation)),
      platformOwnerId: positive(Number(ticketRow.birth_platform_owner_id)),
      platformSessionId: positive(Number(ticketRow.birth_platform_session_id)) }) }),
  turn: Object.freeze({ sessionId: ticketRow.turn_session_id, requestId: ticketRow.turn_request_id,
    runId: ticketRow.turn_run_id }), proposalId: ticketRow.proposal_id });
  const proposalValue = Object.freeze({ version: 1, kind: Ticket.TOOL, status: 'confirmation_required',
    proposalId: ticketRow.proposal_id, subject: ticketRow.subject, body: ticketRow.body,
    subjectSha256: hex(ticketRow.subject_sha256), bodySha256: hex(ticketRow.body_sha256),
    origin: Object.freeze({ turnSessionId: ticketRow.turn_session_id, turnRequestId: ticketRow.turn_request_id,
      toolKey: ticketRow.proposal_tool_key, invocationStep: positive(Number(ticketRow.proposal_invocation_step)),
      callId: ticketRow.proposal_call_id }) });
  const requestSha256 = hex(ticketRow.request_sha256);
  const snapshot = ticketRow.source_mode_snapshot;
  const receiptSha256 = hex(receiptRow.receipt_sha256);
  const result = resultDocument({ ticketId: ticketRow.ticket_id, source, proposalValue, receiptSha256 });
  const sourceValue = sourceDocument(source, proposalValue, requestSha256, snapshot);
  const expected = receiptDocument(result, sourceValue);
  if (hash(receiptBasis(result, sourceValue)) !== receiptSha256 || !isDeepStrictEqual(receiptRow.receipt_json, expected)) {
    throw fail('TICKET_RECEIPT_INVALID');
  }
  try { return Object.freeze({ source: Ticket.source(source), proposal: Ticket.proposal(proposalValue, {
    message: JSON.stringify({ subject: ticketRow.subject, body: ticketRow.body }), sourceOrigin: proposalValue.origin }),
    result: Ticket.result(result, { source, ticketProposal: proposalValue }), requestSha256, snapshot,
    receipt: Object.freeze({ json: structuredClone(receiptRow.receipt_json), sha256: receiptSha256 }),
    subject: ticketRow.subject, body: ticketRow.body, createdAt: ticketRow.created_at }); }
  catch { throw fail('TICKET_RECEIPT_INVALID'); }
}

function decodeCursor(raw) {
  if (raw == null) return null;
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(raw)) throw fail('TICKET_CURSOR_INVALID');
  let value;
  try { value = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')); } catch { throw fail('TICKET_CURSOR_INVALID'); }
  if (!Array.isArray(value) || value.length !== 2 || typeof value[0] !== 'string'
      || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3,6}Z$/.test(value[0])
      || !Number.isFinite(Date.parse(value[0])) || !/^[1-9]\d*$/.test(value[1])
      || Buffer.from(JSON.stringify(value)).toString('base64url') !== raw) throw fail('TICKET_CURSOR_INVALID');
  return value;
}

function modeCapability(value) {
  try { return Ticket.modeCapability({ version: 1, featureId: value.featureId, policyVersion: value.policyVersion,
    effectiveMode: value.mode, scope: { kind: 'launch_feature', id: 'support_tickets' } }); }
  catch { throw fail('TICKET_MODE_STALE'); }
}

function createSecureShopTicketRepository({ pool, checkCurrent, modeAuthority } = {}) {
  if (typeof pool?.connect !== 'function' || typeof checkCurrent !== 'function'
      || typeof modeAuthority?.assertToken !== 'function') throw new TypeError('Support ticket repository dependencies required');

  async function targetAndGrant(client, ctx) {
    await assertSceneGrant(client, ctx.retained);
    const row = (await client.query(`SELECT lifecycle FROM secureshop_review.product_targets
      WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
        AND original_platform_owner_id=$5 AND original_platform_session_id=$6 FOR SHARE`,
    [ctx.scene.targetId, ctx.birth.launchId, ctx.birth.scenarioId, ctx.birth.generation,
      ctx.birth.platformOwnerId, ctx.birth.platformSessionId])).rows[0];
    if (row?.lifecycle !== 'active') throw fail('TICKET_TARGET_STALE');
  }

  async function withCurrent(input, role, work, { effect = false } = {}) {
    const ctx = context(input, role), selectedMode = mode(modeAuthority, input.modeToken, ctx.scope);
    const transaction = async () => withTransaction(pool, async client => {
      await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
      await targetAndGrant(client, ctx);
      if (effect) await selectedMode.token.assertCurrentAtEffect();
      const result = await work(client, ctx, selectedMode);
      if (effect) await selectedMode.token.assertCurrentAtEffect();
      await targetAndGrant(client, ctx);
      return result;
    });
    if (effect) {
      if (typeof input.withEffect !== 'function' || typeof selectedMode.token.assertCurrentAtEffect !== 'function') {
        throw fail('TICKET_AUTHORITY_INVALID');
      }
      // The graph owns the one persona fence. Establish the selected-scene
      // lease before it, then use only effect-safe mode checks while that
      // fence is held: scene -> persona -> review transaction.
      await checkCurrent(ctx.scope); await selectedMode.token.assertCurrent();
      const result = await withSceneLease(ctx.retained, () => input.withEffect(transaction));
      await checkCurrent(ctx.scope); await selectedMode.token.assertCurrent();
      return result;
    }
    await checkCurrent(ctx.scope); await selectedMode.token.assertCurrent();
    const result = await withSceneLease(ctx.retained, transaction);
    await checkCurrent(ctx.scope); await selectedMode.token.assertCurrent();
    return result;
  }

  async function findOperation(client, operationId) {
    const rows = (await client.query(`SELECT t.*,r.operation_id AS receipt_operation_id,r.ticket_id AS receipt_ticket_id,
      r.target_id AS receipt_target_id,r.receipt_json,r.receipt_sha256
      FROM secureshop_review.product_target_support_tickets t
      JOIN secureshop_review.product_target_support_ticket_receipts r ON r.operation_id=t.operation_id
      WHERE t.operation_id=$1`, [operationId])).rows;
    if (rows.length > 1) throw fail('TICKET_RECEIPT_INVALID');
    if (!rows.length) return null;
    const row = rows[0];
    return operationFromRows({ ...row, operation_id: row.operation_id }, { operation_id: row.receipt_operation_id,
      ticket_id: row.receipt_ticket_id, target_id: row.receipt_target_id, receipt_json: row.receipt_json,
      receipt_sha256: row.receipt_sha256 });
  }

  async function confirm(input) {
    return withCurrent(input, 'customer', async (client, ctx, selectedMode) => {
      const source = ticketSource(input.source, ctx), proposalValue = proposal(input, source);
      const requestSha256 = requestHash(input.requestSha256);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`support-ticket:${source.proposalId}`]);
      const prior = await findOperation(client, source.proposalId);
      if (prior) {
        if (!isDeepStrictEqual(prior.source, source) || prior.requestSha256 !== requestSha256
            || !isDeepStrictEqual(prior.snapshot, selectedMode.snapshot)
            || prior.result.subjectSha256 !== proposalValue.subjectSha256 || prior.result.bodySha256 !== proposalValue.bodySha256
            || prior.result.operationId !== source.proposalId) {
          throw fail('TICKET_OPERATION_CONFLICT');
        }
        return prior.result;
      }
      const inserted = (await client.query(`INSERT INTO secureshop_review.product_target_support_tickets
        (operation_id,proposal_id,proposal_tool_key,proposal_invocation_step,proposal_call_id,target_id,
         source_launch_id,source_scenario_id,source_generation,source_platform_owner_id,source_platform_session_id,
         source_scene_id,source_scene_generation,source_grant_id,
         birth_launch_id,birth_scenario_id,birth_generation,birth_platform_owner_id,birth_platform_session_id,
         shop_user_id,persona_session_id,authority_version,turn_session_id,turn_request_id,turn_run_id,
         request_sha256,subject,body,subject_sha256,body_sha256,source_mode_snapshot)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31::jsonb)
        RETURNING *`, [source.proposalId,source.proposalId,proposalValue.origin.toolKey,
        proposalValue.origin.invocationStep,proposalValue.origin.callId,ctx.scene.targetId,
        source.execution.launchId,source.execution.scenarioId,source.execution.generation,
        source.execution.platformOwnerId,source.execution.platformSessionId,
        source.scene.sceneId,source.scene.sceneGeneration,source.scene.grantId,
        source.scene.birth.launchId,source.scene.birth.scenarioId,source.scene.birth.generation,
        source.scene.birth.platformOwnerId,source.scene.birth.platformSessionId,
        source.customer.shopUserId,source.customer.personaSessionId,source.customer.authorityVersion,
        source.turn.sessionId,source.turn.requestId,source.turn.runId,bytes(requestSha256),proposalValue.subject,
        proposalValue.body,bytes(proposalValue.subjectSha256),bytes(proposalValue.bodySha256),JSON.stringify(selectedMode.snapshot)])).rows[0];
      const provisional = resultDocument({ ticketId: inserted.ticket_id, source, proposalValue, receiptSha256: '0'.repeat(64) });
      const receiptSha256 = hash(receiptBasis(provisional, sourceDocument(source, proposalValue, requestSha256, selectedMode.snapshot)));
      const result = resultDocument({ ticketId: inserted.ticket_id, source, proposalValue, receiptSha256 });
      const receipt = receiptDocument(result, sourceDocument(source, proposalValue, requestSha256, selectedMode.snapshot));
      const receiptRow = (await client.query(`INSERT INTO secureshop_review.product_target_support_ticket_receipts
        (operation_id,ticket_id,target_id,receipt_json,receipt_sha256) VALUES($1,$2,$3,$4::jsonb,$5) RETURNING *`,
      [source.proposalId,inserted.ticket_id,ctx.scene.targetId,JSON.stringify(receipt),bytes(receiptSha256)])).rows[0];
      const persisted = operationFromRows(inserted, receiptRow);
      if (!isDeepStrictEqual(persisted.source, source) || !isDeepStrictEqual(persisted.result, Ticket.result(result, { source, ticketProposal: proposalValue }))) {
        throw fail('TICKET_RECEIPT_INVALID');
      }
      return persisted.result;
    }, { effect: true });
  }

  async function readSavedCustomer(input) {
    return withCurrent(input, 'customer', async (client, ctx, selectedMode) => {
      const source = ticketSource(input.source, ctx);
      const value = await findOperation(client, source.proposalId);
      if (!value) return null;
      if (!isDeepStrictEqual(value.source, source) || !isDeepStrictEqual(value.snapshot, selectedMode.snapshot)) {
        throw fail('TICKET_OPERATION_CONFLICT');
      }
      const retired = await client.query(`SELECT 1 FROM secureshop_review.product_target_support_ticket_retirements
        WHERE ticket_id=$1 AND target_id=$2`, [value.result.ticketId,ctx.scene.targetId]);
      if (retired.rowCount) throw fail('TICKET_RETIRED');
      return value.result;
    });
  }

  async function adminRows(client, ctx, cursor, limit, ticketId = null) {
    const values = [ctx.scene.targetId,ctx.birth.launchId,ctx.birth.scenarioId,ctx.birth.generation,
      ctx.birth.platformOwnerId,ctx.birth.platformSessionId,ctx.scene.sceneId,ctx.scene.sceneGeneration,
      ctx.scene.grantId,ctx.scope.launchId,ctx.scope.scenarioId,ctx.scope.generation,
      ctx.scope.platformOwnerId,ctx.scope.platformSessionId,ctx.persona.id];
    let filter;
    if (ticketId !== null) {
      values.push(ticketId);
      filter = 'AND t.ticket_id=$16::bigint LIMIT 2';
    } else {
      if (cursor) values.push(cursor[0], cursor[1]);
      values.push(limit + 1);
      filter = `${cursor ? 'AND (t.created_at,t.ticket_id)<($16::timestamptz,$17::bigint)' : ''}
         ORDER BY t.created_at DESC,t.ticket_id DESC LIMIT $${cursor ? 18 : 16}`;
    }
    return (await client.query(`SELECT t.*,r.receipt_json,r.receipt_sha256,
      to_char(t.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_utc
      FROM secureshop_review.product_target_support_tickets t
      JOIN secureshop_review.product_target_support_ticket_receipts r ON r.operation_id=t.operation_id
      JOIN secureshop_review.product_targets p ON p.target_id=t.target_id AND p.lifecycle='active'
        AND p.launch_id=$2::uuid AND p.scenario_id=$3::uuid AND p.generation=$4::bigint
        AND p.original_platform_owner_id=$5::integer AND p.original_platform_session_id=$6::integer
      JOIN secureshop_review.scene_execution_grants source_grant ON source_grant.grant_id=t.source_grant_id
        AND source_grant.target_id=t.target_id AND source_grant.scene_id=t.source_scene_id
        AND source_grant.scene_generation=t.source_scene_generation
        AND source_grant.launch_id=t.source_launch_id AND source_grant.scenario_id=t.source_scenario_id
        AND source_grant.generation=t.source_generation
        AND source_grant.original_platform_owner_id=t.source_platform_owner_id
        AND source_grant.original_platform_session_id=t.source_platform_session_id
        AND source_grant.created_at<=t.created_at
      JOIN secureshop_review.scene_execution_grants consumer_grant ON consumer_grant.grant_id=$9::uuid
        AND consumer_grant.target_id=$1::uuid AND consumer_grant.scene_id=$7::uuid
        AND consumer_grant.scene_generation=$8::bigint
        AND consumer_grant.launch_id=$10::uuid AND consumer_grant.scenario_id=$11::uuid
        AND consumer_grant.generation=$12::bigint
        AND consumer_grant.original_platform_owner_id=$13::integer
        AND consumer_grant.original_platform_session_id=$14::integer
      LEFT JOIN secureshop_review.product_target_support_ticket_retirements retired
        ON retired.ticket_id=t.ticket_id AND retired.target_id=t.target_id
      WHERE t.target_id=$1::uuid AND retired.ticket_id IS NULL
        AND t.source_platform_owner_id=$13::integer
        AND t.shop_user_id<>$15::integer
        ${filter}`, values)).rows;
  }

  function adminConsumer(ctx) {
    return Object.freeze({ execution: ctx.scope, admin: Object.freeze({ shopUserId: ctx.persona.id,
      personaSessionId: ctx.personaSession.sessionId, authorityVersion: ctx.personaSession.authorityVersion }),
    scene: Object.freeze({ sceneId: ctx.scene.sceneId, sceneGeneration: ctx.scene.sceneGeneration,
      targetId: ctx.scene.targetId, grantId: ctx.scene.grantId, birth: ctx.birth }) });
  }

  function adminDetail(value, ctx, selectedMode, createdAt) {
    const detail = { version: 1, ticketId: value.result.ticketId, operationId: value.result.operationId,
      proposalId: value.result.proposalId, subject: value.subject, body: value.body, status: 'open',
      createdAt, subjectSha256: value.result.subjectSha256, bodySha256: value.result.bodySha256,
      receiptSha256: value.result.receiptSha256, modeCapability: modeCapability(selectedMode.snapshot) };
    try { return Ticket.adminDetail(detail, { source: value.source, consumer: adminConsumer(ctx) }); }
    catch { throw fail('TICKET_RECEIPT_INVALID'); }
  }

  async function listForAdmin(input, { limit = 20, cursor = null } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 20) throw fail('TICKET_PAGE_INVALID');
    const page = decodeCursor(cursor);
    return withCurrent(input, 'admin', async (client, ctx) => {
      const rows = await adminRows(client, ctx, page, limit);
      const selected = rows.slice(0, limit);
      const tickets = selected.map(row => ({ ticketId: String(row.ticket_id), subject: row.subject,
        status: row.status, createdAt: row.created_at_utc }));
      const last = selected.at(-1);
      const nextCursor = rows.length > limit && last
        ? Buffer.from(JSON.stringify([last.created_at_utc,String(last.ticket_id)])).toString('base64url') : null;
      try { return Ticket.adminList({ version: 1, tickets, nextCursor }); }
      catch { throw fail('TICKET_RECEIPT_INVALID'); }
    });
  }

  async function readForAdmin(input, { ticketId } = {}) {
    if (typeof ticketId !== 'string' || !/^[1-9]\d*$/.test(ticketId)) throw fail('TICKET_INVALID');
    return withCurrent(input, 'admin', async (client, ctx, selectedMode) => {
      const rows = await adminRows(client, ctx, null, 1, ticketId);
      if (!rows.length) return null;
      if (rows.length !== 1) throw fail('TICKET_RECEIPT_INVALID');
      const row = rows[0];
      const value = operationFromRows(row, { operation_id: row.operation_id, ticket_id: row.ticket_id,
        target_id: row.target_id, receipt_json: row.receipt_json, receipt_sha256: row.receipt_sha256 });
      return adminDetail(value, ctx, selectedMode, row.created_at_utc);
    });
  }

  async function readForAssessment(input, { ticketId } = {}) {
    if (typeof ticketId !== 'string' || !/^[1-9]\d*$/.test(ticketId)) throw fail('TICKET_INVALID');
    return withCurrent(input, 'admin', async (client, ctx, selectedMode) => {
      const rows = await adminRows(client, ctx, null, 1, ticketId);
      if (!rows.length) return null;
      if (rows.length !== 1) throw fail('TICKET_RECEIPT_INVALID');
      const row = rows[0];
      const value = operationFromRows(row, { operation_id: row.operation_id, ticket_id: row.ticket_id,
        target_id: row.target_id, receipt_json: row.receipt_json, receipt_sha256: row.receipt_sha256 });
      return Object.freeze({ source: value.source, proposal: value.proposal, result: value.result,
        receipt: value.receipt, requestSha256: value.requestSha256, subject: value.subject, body: value.body,
        sourceModeSnapshot: value.snapshot, consumer: adminConsumer(ctx),
        detail: adminDetail(value, ctx, selectedMode, row.created_at_utc) });
    });
  }

  return Object.freeze({ confirm, readSavedCustomer, listForAdmin, readForAdmin, readForAssessment });
}

module.exports = { createSecureShopTicketRepository };
