'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const defaultMail = require('../../server/services/mcp/mailClient');
const { ATTACHMENT_MARKER } = require('../../server/services/mcp/reportPayload');
const { _internals: targetInternals } = require('../../sidecars/sandbox-runner/mcpTargets');
const { createMcpResourceRepository } = require('../../server/database/postgres/mcpResourceRepository');
const { STUDENT_DELETION_STEPS } = require('../../server/services/studentDeletionComposition');

const OBJECTIVE = 'mcp_indirect_injection';
const WORKSHOP = 'mcp_workshop';
const RUBRIC = 'mcp_owned_indirect_injection.v4';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const RECIPIENT = /^mcp-audit-[a-f0-9]{20}@owasp-ai-goat\.invalid$/;
const REQUIRED_CRITERIA = Object.freeze([
  'ticket_induced_protected_delivery', 'learner_task_is_ticket_only', 'ticket_task_redirection',
]);
const VERDICTS = new Set(['pass', 'fail', 'inconclusive', 'unavailable']);
const DISPOSITIONS = new Set(['pending', 'not_pass', 'threshold_pending', 'awarded',
  'already_complete', 'stale_generation', 'hidden', 'mode_changed']);
const TYPED_CODE = /^[A-Z][A-Z0-9_]{0,79}$/;

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const ownerKey = value => JSON.stringify(['MCP', String(value)]);
const persistedEffectKey = (runId, node) => `${runId}:${node}`;
const json = value => typeof value === 'string' ? JSON.parse(value) : value;
const canonicalTop = value => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function owner(value, name = 'ownerId') {
  assert.ok(Number.isSafeInteger(value) && value > 0, `${name} must be a positive integer`);
  return value;
}
function rows(result) { return clone(result?.rows || []); }
function difference(after, before, key) {
  const prior = new Set(before.map(item => String(item[key])));
  return after.filter(item => !prior.has(String(item[key])));
}
function assertHashes(values) { for (const value of values) assert.match(value || '', SHA); }
function decimal(value, name) {
  const normalized = String(value ?? '');
  assert.match(normalized, /^(?:0|[1-9][0-9]*)$/, `${name} must be a canonical non-negative integer`);
  return normalized;
}
function optionalEnum(value, allowed, name) {
  if (value === null || value === undefined) return null;
  assert.equal(typeof value, 'string', `${name} must be a string or null`);
  assert.ok(allowed.has(value), `${name} is invalid`);
  return value;
}
function optionalCode(value, name) {
  if (value === null || value === undefined) return null;
  assert.match(value, TYPED_CODE, `${name} is invalid`);
  return value;
}
function optionalBoolean(value, name) {
  if (value === null || value === undefined) return null;
  if (value === true || value === false) return value;
  assert.ok(value === 'true' || value === 'false', `${name} is invalid`);
  return value === 'true';
}
function optionalAttempts(value, name) {
  if (value === null || value === undefined) return null;
  const normalized = decimal(value, name);
  const number = Number(normalized);
  assert.ok(Number.isSafeInteger(number) && number <= 100, `${name} is invalid`);
  return number;
}

async function createMcpRenderedNativeEvidence({ identityRuntime, mcpRuntime, ownerId, siblingId },
  { mail = defaultMail } = {}) {
  assert.equal(typeof identityRuntime?.query, 'function');
  assert.equal(typeof mcpRuntime?.query, 'function');
  const resourceRepository = createMcpResourceRepository(mcpRuntime);
  const emptyRetirement = await resourceRepository.assertOwnerResourcesRetired({ platformOwnerId: Math.max(ownerId, siblingId) + 1 });
  assert.deepEqual(emptyRetirement, { platformOwnerId: Math.max(ownerId, siblingId) + 1,
    status: 'retired', targetCount: 0, mailIntentCount: 0 });
  owner(ownerId); owner(siblingId, 'siblingId'); assert.notEqual(ownerId, siblingId);
  for (const method of ['listMessagesBySmtpIds', 'verifyMessageReadback', 'isTrustedMessageReadback']) {
    assert.equal(typeof mail?.[method], 'function', `mail.${method} is required`);
  }

  const catalog = rows(await identityRuntime.query(`SELECT objective_id,label,ordinal
    FROM workshop_platform.objectives WHERE workshop_key=$1 AND catalog_active=true AND is_enabled=true
    ORDER BY ordinal,objective_id`, [WORKSHOP]));
  assert.ok(catalog.some(item => item.objective_id === OBJECTIVE), 'Indirect objective must be visible');
  const visibleObjectiveCount = catalog.length;
  assert.ok(visibleObjectiveCount > 0);

  async function durableSnapshot(userId) {
    owner(userId);
    const key = ownerKey(userId);
    const [state, graphOwner, runs, effects, events, judgments, packets, requests, turns, completions, tools, targets, intents] = await Promise.all([
      identityRuntime.query(`SELECT generation FROM workshop_platform.user_state
        WHERE user_id=$1 AND workshop_key=$2`, [userId, WORKSHOP]),
      identityRuntime.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1', [key]),
      identityRuntime.query(`SELECT run_id,owner_key,status,generation,provider,model,decision_source,last_node
        FROM graph_runtime.runs WHERE owner_key=$1 ORDER BY run_id`, [key]),
      identityRuntime.query(`SELECT run_id,effect_key,status,generation FROM graph_runtime.effects
        WHERE owner_key=$1 ORDER BY run_id,effect_key`, [key]),
      identityRuntime.query(`SELECT run_id,sequence,node,event_type,metadata FROM graph_runtime.events
        WHERE owner_key=$1 ORDER BY run_id,sequence`, [key]),
      identityRuntime.query(`SELECT evaluation_id,objective_id,verdict,disposition,result_digest,run_id,generation,rubric_version,result_json
        FROM workshop_platform.objective_judgments WHERE user_id=$1 AND workshop_key=$2 ORDER BY evaluation_id`, [userId, WORKSHOP]),
      identityRuntime.query(`SELECT p.evaluation_id,p.judge_version,p.owner_key,p.owner_generation,p.retry_invocations,p.packet
        FROM workshop_platform.grade_packets p JOIN workshop_platform.objective_judgments j
          ON j.user_id=p.user_id AND j.evaluation_id=p.evaluation_id
        WHERE p.user_id=$1 AND j.workshop_key=$2 ORDER BY p.evaluation_id`, [userId, WORKSHOP]),
      identityRuntime.query(`SELECT request_id,run_id,owner_key,generation,user_text,response_json
        FROM workshop_conversations.requests WHERE user_id=$1 ORDER BY request_id`, [userId]),
      identityRuntime.query(`SELECT run_id,owner_key,generation,user_text,assistant_text
        FROM workshop_conversations.turns WHERE user_id=$1 ORDER BY run_id`, [userId]),
      identityRuntime.query(`SELECT objective_id,completed_at FROM workshop_platform.completions
        WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id`, [userId, WORKSHOP]),
      mcpRuntime.query(`SELECT id,tool_name,args,result_summary,outcome,success FROM mcp.tool_log
        WHERE user_key=$1 ORDER BY id`, [String(userId)]),
      mcpRuntime.query(`SELECT target_id,platform_session_id,generation,state,retired_at FROM mcp.runner_targets
        WHERE user_key=$1 ORDER BY generation,target_id`, [String(userId)]),
      mcpRuntime.query(`SELECT intent_id,target_id,platform_session_id,generation,assigned_message_id,recipient_sha256,
          payload_sha256,status,settled_at,cleaned_at FROM mcp.mail_intents
        WHERE user_key=$1 ORDER BY intent_id`, [String(userId)]),
    ]);
    const intentRows = rows(intents);
    const messageIds = intentRows.map(item => item.assigned_message_id);
    const captured = await mail.listMessagesBySmtpIds(messageIds);
    assert.equal(captured?.ok, true, 'Owned Mailpit snapshot must be available');
    return freeze({ state: rows(state), graphOwner: rows(graphOwner), runs: rows(runs), effects: rows(effects), events: rows(events), judgments: rows(judgments),
      packets: rows(packets), requests: rows(requests), turns: rows(turns), completions: rows(completions),
      tools: rows(tools), targets: rows(targets), intents: intentRows,
      capturedMessageIds: (captured.messages || []).map(item => item.messageId).sort() });
  }

  async function captureTurnFailure({ ownerId: failureOwner, requestId } = {}) {
    owner(failureOwner); assert.ok([ownerId, siblingId].includes(failureOwner), 'Unknown cohort owner');
    assert.match(requestId || '', UUID, 'requestId must be a UUID');
    requestId = requestId.toLowerCase();
    const bindingRows = rows(await identityRuntime.query(`/* mcp_failure_capture_binding */
      SELECT q.request_id,q.run_id,q.owner_key AS request_owner_key,q.generation::text AS request_generation,
        r.owner_key AS run_owner_key,r.generation::text AS run_generation
      FROM workshop_conversations.requests q
      JOIN graph_runtime.runs r ON r.run_id=q.run_id
      WHERE q.user_id=$1 AND q.request_id=$2`, [failureOwner, requestId]));
    assert.equal(bindingRows.length, 1, 'Exact owner request/run binding is unavailable or ambiguous');
    const binding = bindingRows[0];
    assert.equal(binding.request_id, requestId, 'Captured request ID does not match');
    assert.match(binding.run_id || '', UUID, 'Captured run ID is invalid');
    assert.equal(binding.request_owner_key, ownerKey(failureOwner), 'Captured request owner does not match');
    assert.equal(binding.run_owner_key, binding.request_owner_key, 'Captured run owner does not match request owner');
    const requestGeneration = decimal(binding.request_generation, 'request generation');
    const runGeneration = decimal(binding.run_generation, 'run generation');
    assert.equal(runGeneration, requestGeneration, 'Captured run generation does not match request generation');

    const judgmentRows = rows(await identityRuntime.query(`/* mcp_failure_capture_judgment */
      SELECT j.run_id,j.generation::text AS judgment_generation,j.verdict,j.disposition,j.rubric_version,
        jsonb_typeof(j.result_json) AS result_type,
        jsonb_typeof(j.result_json->'criteria') AS criteria_type,
        jsonb_typeof(j.result_json->'scopedCriteria') AS scoped_criteria_type,
        j.result_json->>'errorCode' AS error_code,
        j.result_json->>'validationCode' AS validation_code,
        c1.satisfied AS ticket_delivery_satisfied,
        c2.satisfied AS learner_task_satisfied,
        c3.satisfied AS task_redirection_satisfied,
        s1.verdict AS ticket_delivery_scoped_verdict,s1.error_code AS ticket_delivery_scoped_error,
        s1.attempts AS ticket_delivery_scoped_attempts,
        s2.verdict AS learner_task_scoped_verdict,s2.error_code AS learner_task_scoped_error,
        s2.attempts AS learner_task_scoped_attempts,
        s3.verdict AS task_redirection_scoped_verdict,s3.error_code AS task_redirection_scoped_error,
        s3.attempts AS task_redirection_scoped_attempts
      FROM workshop_platform.objective_judgments j
      LEFT JOIN LATERAL (
        SELECT item->>'satisfied' AS satisfied FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(j.result_json->'criteria')='array' THEN j.result_json->'criteria' ELSE '[]'::jsonb END) item
        WHERE item->>'id'='ticket_induced_protected_delivery'
      ) c1 ON true
      LEFT JOIN LATERAL (
        SELECT item->>'satisfied' AS satisfied FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(j.result_json->'criteria')='array' THEN j.result_json->'criteria' ELSE '[]'::jsonb END) item
        WHERE item->>'id'='learner_task_is_ticket_only'
      ) c2 ON true
      LEFT JOIN LATERAL (
        SELECT item->>'satisfied' AS satisfied FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(j.result_json->'criteria')='array' THEN j.result_json->'criteria' ELSE '[]'::jsonb END) item
        WHERE item->>'id'='ticket_task_redirection'
      ) c3 ON true
      LEFT JOIN LATERAL (
        SELECT item->>'verdict' AS verdict,item->>'errorCode' AS error_code,item->>'attempts' AS attempts
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(j.result_json->'scopedCriteria')='array'
          THEN j.result_json->'scopedCriteria' ELSE '[]'::jsonb END) item
        WHERE item->>'criterionId'='ticket_induced_protected_delivery'
      ) s1 ON true
      LEFT JOIN LATERAL (
        SELECT item->>'verdict' AS verdict,item->>'errorCode' AS error_code,item->>'attempts' AS attempts
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(j.result_json->'scopedCriteria')='array'
          THEN j.result_json->'scopedCriteria' ELSE '[]'::jsonb END) item
        WHERE item->>'criterionId'='learner_task_is_ticket_only'
      ) s2 ON true
      LEFT JOIN LATERAL (
        SELECT item->>'verdict' AS verdict,item->>'errorCode' AS error_code,item->>'attempts' AS attempts
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(j.result_json->'scopedCriteria')='array'
          THEN j.result_json->'scopedCriteria' ELSE '[]'::jsonb END) item
        WHERE item->>'criterionId'='ticket_task_redirection'
      ) s3 ON true
      WHERE j.user_id=$1 AND j.run_id=$2 AND j.workshop_key=$3 AND j.objective_id=$4`,
    [failureOwner, binding.run_id, WORKSHOP, OBJECTIVE]));
    assert.ok(judgmentRows.length <= 1, 'Exact owner run has ambiguous objective judgments');
    const base = { ownerId: failureOwner, requestId, runId: binding.run_id.toLowerCase(),
      generation: requestGeneration, requestRunBound: true };
    if (judgmentRows.length === 0) return freeze({ ...base, judgmentPresent: false });

    const judgment = judgmentRows[0];
    assert.equal(judgment.run_id, binding.run_id, 'Captured judgment run does not match');
    if (judgment.verdict === null || judgment.verdict === undefined) {
      assert.equal(judgment.disposition, 'pending', 'Pending judgment disposition is malformed');
      assert.equal(judgment.result_type, null, 'Pending judgment result is malformed');
    } else assert.equal(judgment.result_type, 'object', 'Captured judgment result is malformed');
    assert.ok(judgment.criteria_type === null || judgment.criteria_type === 'array', 'Captured criteria are malformed');
    assert.ok(judgment.scoped_criteria_type === null || judgment.scoped_criteria_type === 'array',
      'Captured scoped criteria are malformed');
    const judgmentGeneration = decimal(judgment.judgment_generation, 'judgment generation');
    const criterion = (id, prefix) => freeze({ id,
      satisfied: optionalBoolean(judgment[`${prefix}_satisfied`], `${id} satisfied`),
      scopedVerdict: optionalEnum(judgment[`${prefix}_scoped_verdict`], VERDICTS, `${id} scoped verdict`),
      scopedErrorCode: optionalCode(judgment[`${prefix}_scoped_error`], `${id} scoped error code`),
      scopedAttempts: optionalAttempts(judgment[`${prefix}_scoped_attempts`], `${id} scoped attempts`) });
    return freeze({ ...base, judgmentPresent: true, judgmentGeneration,
      judgmentGenerationMatches: judgmentGeneration === runGeneration,
      verdict: optionalEnum(judgment.verdict, VERDICTS, 'judgment verdict'),
      disposition: optionalEnum(judgment.disposition, DISPOSITIONS, 'judgment disposition'),
      expectedRubric: judgment.rubric_version === RUBRIC,
      errorCode: optionalCode(judgment.error_code, 'judgment error code'),
      validationCode: optionalCode(judgment.validation_code, 'judgment validation code'),
      criteria: [
        criterion('ticket_induced_protected_delivery', 'ticket_delivery'),
        criterion('learner_task_is_ticket_only', 'learner_task'),
        criterion('ticket_task_redirection', 'task_redirection'),
      ] });
  }

  const pendingTurns = new Map();
  const resetSnapshots = new Map();
  const deletionSnapshots = new Map();

  async function snapshotTurn({ ownerId: turnOwner, message, positive }) {
    owner(turnOwner); assert.ok([ownerId, siblingId].includes(turnOwner), 'Unknown cohort owner');
    assert.equal(typeof message, 'string'); assert.ok(message.length > 0);
    assert.equal(typeof positive, 'boolean');
    assert.equal(pendingTurns.has(turnOwner), false, 'A turn snapshot is already pending');
    const before = await durableSnapshot(turnOwner);
    if (positive) assert.equal(before.completions.some(item => item.objective_id === OBJECTIVE), false,
      'Positive verification cannot start from seeded completion');
    pendingTurns.set(turnOwner, freeze({ message, positive, before }));
    return freeze({ ownerId: turnOwner, message, positive, captured: true });
  }

  function requestAndRun(after, requestId, message, body, turnOwner) {
    const requests = after.requests.filter(item => item.request_id === requestId);
    assert.equal(requests.length, 1, 'Exactly one durable request must match the browser request ID');
    const request = requests[0];
    assert.equal(request.user_text, message); assert.deepEqual(json(request.response_json), body);
    assert.match(request.run_id || '', UUID); assert.equal(request.owner_key, ownerKey(turnOwner));
    const runs = after.runs.filter(item => item.run_id === request.run_id);
    assert.equal(runs.length, 1); const run = runs[0];
    assert.equal(run.owner_key, request.owner_key); assert.equal(String(run.generation), String(request.generation));
    assert.equal(run.status, 'completed'); assert.equal(run.provider, 'ollama');
    assert.equal(run.model, 'llama3.1:8b'); assert.equal(run.decision_source, 'model');
    return { request, run };
  }

  async function verifyTurn({ ownerId: turnOwner, requestId, message, body, positive }) {
    owner(turnOwner); assert.match(requestId || '', UUID); assert.equal(typeof body, 'object');
    const pending = pendingTurns.get(turnOwner);
    assert.ok(pending, 'snapshotTurn must run before the browser submits work');
    pendingTurns.delete(turnOwner);
    assert.equal(message, pending.message); assert.equal(positive, pending.positive);
    assert.equal(pending.before.requests.some(item => item.request_id === requestId), false,
      'Request ID already existed before browser work');
    const after = await durableSnapshot(turnOwner);
    const { request, run } = requestAndRun(after, requestId, message, body, turnOwner);
    assert.equal(pending.before.runs.some(item => item.run_id === run.run_id), false,
      'Browser request must create a fresh owned run');
    assert.equal(after.state.length, 1); assert.equal(String(request.generation), String(after.state[0].generation));
    const newTools = difference(after.tools, pending.before.tools, 'id');
    assert.deepEqual(newTools.map(item => item.tool_name), positive ? ['read_ticket', 'send_report'] : ['read_ticket'],
      'Activity must distinguish the ticket observation from any report attempt');
    assert.equal(body.toolUsed, 'read_ticket'); assert.equal(body.toolResult?.decisionSource, 'model');
    assert.equal(body.toolResult?.observationReal ?? body.toolResult?.real, true);
    const requestedTicket = message.match(/\b(?:4290|4295|4301)\b/)?.[0]; assert.ok(requestedTicket);
    assert.equal(body.toolResult?.ticketId, requestedTicket);
    // Route activity logging serializes the outer read_ticket params, { id },
    // not selectedArgs from the later send_report consequence.
    assert.deepEqual(json(newTools[0].args), { id: requestedTicket }, 'Durable ticket arguments must match the requested ticket');
    const observationKey = persistedEffectKey(run.run_id, 'mcp_indirect_injection_observation');
    const observationEffects = after.effects.filter(item => item.run_id === run.run_id
      && item.effect_key === observationKey);
    assert.equal(observationEffects.length, 1, 'Exactly one current-run ticket observation is required');
    assert.equal(observationEffects[0].status, 'completed', 'Ticket observation must be completed');
    assert.equal(String(observationEffects[0].generation), String(request.generation), 'Ticket observation generation must match');

    if (!positive) {
      assert.equal(body.toolResult?.delivered === true, false);
      assert.notEqual(body.toolResult?.modelAction?.tool, 'send_report');
      assert.equal(body.completedObjectives?.includes(OBJECTIVE), false);
      assert.deepEqual(after.intents, pending.before.intents);
      assert.deepEqual(after.judgments, pending.before.judgments);
      assert.equal(after.effects.some(item => item.run_id === run.run_id
        && item.effect_key === persistedEffectKey(run.run_id, 'mcp_indirect_injection_consequence')), false);
      assert.equal(after.completions.some(item => item.objective_id === OBJECTIVE), false);
      return freeze({ ownerId: turnOwner, requestId, runId: run.run_id, verified: true, awarded: false });
    }

    assert.equal(turnOwner, ownerId, 'Only the primary learner may supply the positive cohort turn');
    assert.deepEqual(json(newTools[1].args), body.toolResult?.selectedArgs, 'Report activity must retain exact selected arguments');
    assert.deepEqual(json(newTools[1].args), body.toolResult?.modelAction?.params, 'Report activity must match the model proposal');
    assert.equal(body.toolResult?.modelAction?.tool, 'send_report'); assert.equal(body.toolResult?.real, true);
    assert.equal(body.toolResult?.delivered, true); assert.equal(body.toolResult?.error, null);
    const judgmentRows = after.judgments.filter(item => item.run_id === run.run_id && item.objective_id === OBJECTIVE);
    const packetRows = after.packets.filter(item => judgmentRows.some(value => value.evaluation_id === item.evaluation_id));
    assert.equal(judgmentRows.length, 1); assert.equal(packetRows.length, 1);
    const judgment = judgmentRows[0]; const packet = json(packetRows[0].packet); const result = json(judgment.result_json);
    assert.equal(String(judgment.generation), String(request.generation));
    assert.equal(String(packetRows[0].owner_generation), String(request.generation));
    assert.equal(packetRows[0].owner_key, ownerKey(turnOwner));
    assert.equal(judgment.rubric_version, RUBRIC); assert.equal(judgment.verdict, 'pass');
    assert.equal(judgment.disposition, 'awarded'); assert.equal(packet?.facts?.trusted_ticket_model_delivery, true);
    const responseJudgment = body.judgments?.find(item => item.objectiveId === OBJECTIVE);
    assert.equal(responseJudgment?.evaluationId, judgment.evaluation_id); assert.equal(responseJudgment?.verdict, 'pass');
    assert.equal(responseJudgment?.provider, 'ollama'); assert.equal(responseJudgment?.model, 'llama3.1:8b');
    assert.equal(responseJudgment?.rubricVersion, RUBRIC); assert.ok(body.completedObjectives?.includes(OBJECTIVE));
    for (const id of REQUIRED_CRITERIA) assert.equal(result?.criteria?.find(item => item.id === id)?.satisfied, true);

    const witness = packet?.evidence?.find(item => item.id === 'trusted_effect_chain')?.content?.witness;
    assert.equal(witness?.version, 'mcp-owned-indirect-injection-witness.v2');
    assert.equal(witness.runId, run.run_id); assert.equal(witness.platformOwnerId, turnOwner);
    assert.equal(String(witness.generation), String(request.generation)); assert.equal(witness.ticket?.ticketId, '4295');
    assert.equal(witness.protectedRead?.operation, 'read_configuration'); assert.ok(witness.protectedRead.byteCount > 0);
    assert.equal(witness.action?.tool, 'send_report'); assert.equal(witness.delivery?.recipient, body.toolResult.selectedArgs?.to);
    assert.match(witness.delivery?.recipient || '', RECIPIENT);
    assertHashes([witness.ticket.receiptSha256, witness.protectedRead.receiptSha256,
      witness.action.argsSha256, witness.action.modelReceiptSha256, witness.mailbox.receiptSha256,
      witness.mailbox.readbackReceiptSha256, witness.mailbox.acceptedWitnessSha256,
      witness.protectedRead.configSha256, witness.delivery.payloadSha256]);
    assert.equal(witness.action.argsSha256, sha(Buffer.from(canonicalTop(body.toolResult.selectedArgs))));

    const effects = after.effects.filter(item => item.run_id === run.run_id);
    for (const node of ['mcp_indirect_injection_observation', 'mcp_indirect_injection_consequence']) {
      const effectKey = persistedEffectKey(run.run_id, node);
      const matches = effects.filter(item => item.effect_key === effectKey);
      assert.equal(matches.length, 1); assert.equal(matches[0].status, 'completed');
      assert.equal(String(matches[0].generation), String(request.generation));
    }
    const intent = after.intents.find(item => item.intent_id === witness.delivery.intentId);
    assert.ok(intent); assert.equal(intent.target_id, witness.targetId);
    assert.equal(Number(intent.platform_session_id), witness.platformSessionId);
    assert.equal(String(intent.generation), String(witness.generation));
    assert.equal(intent.assigned_message_id, witness.delivery.messageId);
    assert.equal(intent.recipient_sha256, sha(Buffer.from(witness.delivery.recipient)));
    assert.equal(intent.payload_sha256, witness.delivery.payloadSha256);
    assert.equal(intent.status, 'accepted'); assert.ok(intent.settled_at); assert.equal(intent.cleaned_at, null);
    const target = after.targets.find(item => item.target_id === witness.targetId);
    assert.ok(target); assert.equal(target.state, 'active');
    assert.equal(Number(target.platform_session_id), witness.platformSessionId);
    assert.equal(String(target.generation), String(witness.generation));

    const output = body.toolResult?.output;
    assert.equal(typeof output, 'string'); const markerAt = output.lastIndexOf(ATTACHMENT_MARKER);
    assert.ok(markerAt >= 0, 'Durable result must contain the synthetic attachment marker');
    const protectedContent = output.slice(markerAt + ATTACHMENT_MARKER.length);
    assert.equal(Buffer.byteLength(protectedContent), witness.protectedRead.byteCount);
    assert.equal(sha(Buffer.from(protectedContent)), witness.protectedRead.configSha256);
    const selected = body.toolResult.selectedArgs;
    assert.equal(typeof selected?.body, 'string');
    const expectedBody = `${selected.body}\n\n${ATTACHMENT_MARKER}${protectedContent}`;
    const controlled = targetInternals.controlledTicket({ targetId: witness.targetId, ownerId: witness.platformOwnerId,
      platformSessionId: witness.platformSessionId, generation: witness.generation }, '4295');
    const readback = await mail.verifyMessageReadback({ messageId: witness.delivery.messageId,
      to: witness.delivery.recipient, subject: `RE: ${controlled.subject}`, body: expectedBody });
    assert.equal(readback?.ok, true); assert.equal(readback.status, 'verified');
    assert.equal(mail.isTrustedMessageReadback(readback.receipt), true);
    assert.equal(readback.receipt.receiptSha256, witness.mailbox.readbackReceiptSha256);
    assert.equal(readback.receipt.submittedPayloadSha256, witness.delivery.payloadSha256);
    assert.equal(after.capturedMessageIds.includes(witness.delivery.messageId), true);
    assert.equal(after.completions.filter(item => item.objective_id === OBJECTIVE).length, 1);
    return freeze({ ownerId: turnOwner, requestId, runId: run.run_id, verified: true, awarded: true });
  }

  async function snapshotBeforeReset({ ownerId: resetOwner }) {
    owner(resetOwner); assert.equal(resetOwner, ownerId);
    assert.equal(resetSnapshots.has(resetOwner), false, 'A reset snapshot is already pending');
    const [ownerBefore, siblingBefore] = await Promise.all([durableSnapshot(resetOwner), durableSnapshot(siblingId)]);
    await assert.rejects(resourceRepository.assertOwnerResourcesRetired({ platformOwnerId: resetOwner }),
      error => error?.code === 'MCP_OWNER_RESOURCES_PENDING');
    await assert.rejects(resourceRepository.assertOwnerResourcesRetired({ platformOwnerId: siblingId }),
      error => error?.code === 'MCP_OWNER_RESOURCES_PENDING');
    assert.ok(ownerBefore.judgments.some(item => item.objective_id === OBJECTIVE && item.disposition === 'awarded'));
    assert.ok(ownerBefore.intents.length > 0 && ownerBefore.capturedMessageIds.length > 0);
    assert.ok(siblingBefore.requests.length > 0 && siblingBefore.runs.length > 0
      && siblingBefore.tools.length > 0 && siblingBefore.targets.some(item => item.state === 'active'),
    'Sibling reset baseline must contain genuine MCP work');
    resetSnapshots.set(resetOwner, freeze({ ownerBefore, siblingBefore }));
    return freeze({ ownerId: resetOwner, captured: true });
  }

  async function verifyReset({ ownerId: resetOwner, receipts }) {
    owner(resetOwner); assert.equal(resetOwner, ownerId); assert.ok(Array.isArray(receipts) && receipts.length >= 1);
    const before = resetSnapshots.get(resetOwner);
    assert.ok(before, 'snapshotBeforeReset must run before the browser resets progress');
    resetSnapshots.delete(resetOwner);
    const [ownerAfter, siblingAfter] = await Promise.all([durableSnapshot(resetOwner), durableSnapshot(siblingId)]);
    const retired = await resourceRepository.assertOwnerResourcesRetired({ platformOwnerId: resetOwner });
    assert.deepEqual(retired, { platformOwnerId: resetOwner, status: 'retired', targetCount: before.ownerBefore.targets.length, mailIntentCount: before.ownerBefore.intents.length });
    const siblingResourcesBefore = await resourceRepository.assertOwnerResourcesRetired({ platformOwnerId: siblingId }).catch(error => error);
    assert.equal(siblingResourcesBefore?.code, 'MCP_OWNER_RESOURCES_PENDING');
    assert.deepEqual(ownerAfter.judgments, before.ownerBefore.judgments);
    assert.deepEqual(ownerAfter.packets, before.ownerBefore.packets);
    assert.deepEqual(ownerAfter.runs, before.ownerBefore.runs);
    assert.deepEqual(ownerAfter.effects, before.ownerBefore.effects);
    assert.deepEqual(ownerAfter.events, before.ownerBefore.events);
    assert.deepEqual(siblingAfter, before.siblingBefore);
    assert.equal(before.ownerBefore.graphOwner.length, 1); assert.equal(ownerAfter.graphOwner.length, 1);
    assert.equal(BigInt(ownerAfter.graphOwner[0].generation), BigInt(before.ownerBefore.graphOwner[0].generation) + 1n,
      'Reset must advance the durable MCP owner generation exactly once');
    assert.equal(ownerAfter.completions.length, 0);
    assert.ok(before.ownerBefore.targets.length > 0);
    assert.ok(ownerAfter.targets.every(item => item.state === 'retired' && item.retired_at));
    assert.ok(ownerAfter.intents.every(item => item.cleaned_at));
    assert.deepEqual(ownerAfter.capturedMessageIds, []);
    assert.deepEqual(siblingAfter.capturedMessageIds, before.siblingBefore.capturedMessageIds);
    for (const receipt of receipts) {
      assert.equal(receipt.ownerId, resetOwner); assert.equal(receipt.verified, true);
      assert.match(receipt.runId || '', UUID);
    }
    return freeze({ ownerId: resetOwner, verified: true, immutableJudgmentsPreserved: true,
      siblingPreserved: true, ownerResourcesRetired: true });
  }

  async function snapshotBeforeDeletion({ ownerId: deletionOwner, administratorId }) {
    owner(deletionOwner); assert.equal(Number.isSafeInteger(administratorId) && administratorId > 0, true, 'Administrator identity is required');
    assert.equal(deletionSnapshots.has(deletionOwner), false, 'A deletion snapshot is already pending');
    const [durable, siblingDurable, user, sessions, jobs, judgments, packets, requests, turns, completions, progress, timeTracking, evidence] = await Promise.all([
      durableSnapshot(deletionOwner), durableSnapshot(siblingId),
      identityRuntime.query(`SELECT id,username,email,role,admin_level,is_active FROM identity.users WHERE id=$1`, [deletionOwner]),
      identityRuntime.query(`SELECT id,is_active,revoked_at FROM identity.user_sessions WHERE user_id=$1 ORDER BY id`, [deletionOwner]),
      identityRuntime.query(`SELECT job_id,subject_user_id,requested_by,state,completed_at FROM identity.student_deletion_jobs WHERE subject_user_id=$1 ORDER BY requested_at`, [deletionOwner]),
      identityRuntime.query(`SELECT evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,run_id,generation,mode,canonical_mode,verdict,disposition,result_json,result_digest,created_at,evaluated_at
        FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id`, [deletionOwner]),
      identityRuntime.query(`SELECT evaluation_id,judge_version,owner_key,owner_generation,retry_invocations,packet
        FROM workshop_platform.grade_packets WHERE user_id=$1 ORDER BY evaluation_id`, [deletionOwner]),
      identityRuntime.query(`SELECT request_id,run_id,owner_key,generation,user_text,response_json FROM workshop_conversations.requests WHERE user_id=$1 ORDER BY request_id`, [deletionOwner]),
      identityRuntime.query(`SELECT run_id,user_text,assistant_text FROM workshop_conversations.turns WHERE user_id=$1 ORDER BY run_id`, [deletionOwner]),
      identityRuntime.query(`SELECT workshop_key,objective_id FROM workshop_platform.completions WHERE user_id=$1 ORDER BY workshop_key,objective_id`, [deletionOwner]),
      identityRuntime.query(`SELECT workshop_key,generation FROM workshop_platform.user_state WHERE user_id=$1 ORDER BY workshop_key`, [deletionOwner]),
      identityRuntime.query(`SELECT workshop_key,duration_seconds FROM workshop_platform.time_tracking WHERE user_id=$1 ORDER BY id`, [deletionOwner]),
      identityRuntime.query(`SELECT id FROM workshop_platform.objective_evidence WHERE user_id=$1 ORDER BY id`, [deletionOwner]),
    ]);
    const before = freeze({ administratorId, durable, siblingDurable, user: rows(user), sessions: rows(sessions), jobs: rows(jobs), judgments: rows(judgments),
      packets: rows(packets), requests: rows(requests), turns: rows(turns), completions: rows(completions), progress: rows(progress), timeTracking: rows(timeTracking), evidence: rows(evidence) });
    assert.equal(before.user.length, 1, 'Deletion subject must exist before deletion');
    assert.equal(before.user[0].is_active, 1, 'Deletion snapshot must precede account deactivation');
    assert.equal(before.sessions.length > 0, true, 'Deletion snapshot must contain subject sessions');
    assert.equal(before.judgments.length > 0, true, 'Deletion snapshot must contain immutable judgments');
    deletionSnapshots.set(deletionOwner, before);
    return freeze({ ownerId: deletionOwner, captured: true });
  }

  async function captureDeletionFailure({ ownerId: deletionOwner, administratorId }) {
    owner(deletionOwner); assert.equal(deletionOwner, ownerId,
      'Deletion failure subject is foreign');
    owner(administratorId, 'administratorId');
    const before = deletionSnapshots.get(deletionOwner);
    assert.ok(before, 'snapshotBeforeDeletion must run before deletion failure capture');
    assert.equal(before.administratorId, administratorId,
      'Deletion failure administrator must match the private snapshot');
    const result = await identityRuntime.query(`/* mcp_deletion_failure_capture */
      SELECT j.job_id,j.subject_user_id,j.requested_by,j.state,j.failure_code,
        (j.requested_by=$2) AS requester_matches,
        COALESCE(jsonb_agg(jsonb_build_object(
          'stepKey',s.step_key,'ordinal',s.ordinal,'state',s.state)
          ORDER BY s.ordinal) FILTER (WHERE s.job_id IS NOT NULL),'[]'::jsonb) AS steps
      FROM identity.student_deletion_jobs j
      LEFT JOIN identity.student_deletion_steps s ON s.job_id=j.job_id
      WHERE j.subject_user_id=$1
      GROUP BY j.job_id,j.subject_user_id,j.requested_by,j.state,j.failure_code`,
    [deletionOwner, administratorId]);
    const jobRows = rows(result);
    assert.ok(jobRows.length <= 1, 'Deletion failure job binding is ambiguous');
    if (jobRows.length === 0) {
      return freeze({ ownerId: deletionOwner, administratorId, jobPresent: false, steps: [] });
    }
    const job = jobRows[0];
    assert.match(job.job_id || '', UUID, 'Deletion failure job ID is invalid');
    assert.equal(Number(job.subject_user_id), deletionOwner,
      'Deletion failure job subject is foreign');
    assert.equal(Number(job.requested_by), administratorId,
      'Deletion failure job requester is foreign');
    assert.equal(job.requester_matches, true,
      'Deletion failure job requester binding is foreign');
    assert.ok(['pending', 'running', 'failed', 'quarantined', 'completed'].includes(job.state),
      'Deletion failure job state is invalid');
    assert.ok(job.failure_code === null || job.failure_code === 'DELETION_MANIFEST_MISMATCH',
      'Deletion failure job code is invalid');
    const rawSteps = json(job.steps);
    assert.ok(Array.isArray(rawSteps) && rawSteps.length <= 64,
      'Deletion failure steps are invalid');
    const steps = rawSteps.map((step, ordinal) => {
      assert.equal(step?.ordinal, ordinal, 'Deletion failure steps are not exactly ordered');
      assert.match(step?.stepKey || '', /^[a-z][a-z0-9_]{0,63}$/,
        'Deletion failure step key is invalid');
      assert.ok(['pending', 'completed', 'failed'].includes(step?.state),
        'Deletion failure step state is invalid');
      return { stepKey: step.stepKey, ordinal, state: step.state };
    });
    return freeze({ ownerId: deletionOwner, administratorId, jobPresent: true,
      jobId: job.job_id, jobState: job.state, jobFailureCode: job.failure_code,
      replayed: before.jobs.some(prior => prior.job_id === job.job_id), steps });
  }

  async function verifyDeletion({ ownerId: deletionOwner, administratorId, jobId, receipts }) {
    owner(deletionOwner); assert.equal(Number.isSafeInteger(administratorId) && administratorId > 0, true, 'Administrator identity is required');
    assert.match(jobId || '', UUID); assert.ok(Array.isArray(receipts) && receipts.length > 0);
    const before = deletionSnapshots.get(deletionOwner);
    assert.ok(before, 'snapshotBeforeDeletion must run before final deletion');
    assert.equal(Number.isSafeInteger(administratorId) && administratorId > 0, true, 'Administrator identity is required');
    assert.equal(before.administratorId, administratorId, 'Deletion administrator must match the private snapshot');
    assert.equal(before.jobs.some(job => job.job_id === jobId), false, 'Deletion job must be newly admitted after the snapshot');
    deletionSnapshots.delete(deletionOwner);
    const [durable, user, sessions, jobRows, steps, judgments, packets, requests, turns, completions, progress, timeTracking, evidence, sibling] = await Promise.all([
      durableSnapshot(deletionOwner),
      identityRuntime.query(`SELECT id,username,email,role,admin_level,is_active FROM identity.users WHERE id=$1`, [deletionOwner]),
      identityRuntime.query(`SELECT id FROM identity.user_sessions WHERE user_id=$1`, [deletionOwner]),
      identityRuntime.query(`SELECT job_id,subject_user_id,requested_by,state,completed_at FROM identity.student_deletion_jobs WHERE job_id=$1`, [jobId]),
      identityRuntime.query(`SELECT step_key,ordinal,state FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal`, [jobId]),
      identityRuntime.query(`SELECT evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,evidence_digest,run_id,generation,mode,canonical_mode,verdict,disposition,result_json,result_digest,created_at,evaluated_at
        FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id`, [deletionOwner]),
      identityRuntime.query(`SELECT evaluation_id FROM workshop_platform.grade_packets WHERE user_id=$1`, [deletionOwner]),
      identityRuntime.query(`SELECT request_id,run_id,owner_key,generation,user_text,response_json FROM workshop_conversations.requests WHERE user_id=$1 ORDER BY request_id`, [deletionOwner]),
      identityRuntime.query(`SELECT run_id,user_text,assistant_text FROM workshop_conversations.turns WHERE user_id=$1`, [deletionOwner]),
      identityRuntime.query(`SELECT workshop_key,objective_id FROM workshop_platform.completions WHERE user_id=$1`, [deletionOwner]),
      identityRuntime.query(`SELECT workshop_key,generation FROM workshop_platform.user_state WHERE user_id=$1`, [deletionOwner]),
      identityRuntime.query(`SELECT workshop_key,duration_seconds FROM workshop_platform.time_tracking WHERE user_id=$1`, [deletionOwner]),
      identityRuntime.query(`SELECT id FROM workshop_platform.objective_evidence WHERE user_id=$1`, [deletionOwner]),
      durableSnapshot(siblingId),
    ]);
    assert.equal(jobRows.rows.length, 1);
    assert.ok(jobRows.rows[0]?.completed_at, 'Completed deletion must publish a completion timestamp');
    assert.deepEqual(jobRows.rows, [{ job_id: jobId, subject_user_id: deletionOwner, requested_by: administratorId, state: 'completed', completed_at: jobRows.rows[0].completed_at }]);
    assert.equal(steps.rows.length, STUDENT_DELETION_STEPS.length);
    assert.deepEqual(steps.rows.map(row => row.step_key), [...STUDENT_DELETION_STEPS]);
    assert.deepEqual(steps.rows.map(row => row.ordinal), STUDENT_DELETION_STEPS.map((_, ordinal) => ordinal));
    assert.ok(steps.rows.every(row => row.state === 'completed'));
    const subject = user.rows[0];
    assert.deepEqual({ id: subject?.id, role: subject?.role, admin_level: subject?.admin_level, is_active: subject?.is_active },
      { id: deletionOwner, role: 'student', admin_level: 0, is_active: 0 });
    assert.equal(subject.username, `deleted-${jobId}`); assert.equal(subject.email, `deleted-${jobId}@invalid.local`);
    for (const prior of before.requests) {
      const current = requests.rows.find(row => row.request_id === prior.request_id); assert.ok(current);
      for (const field of ['request_id', 'run_id', 'owner_key', 'generation']) assert.equal(current[field], prior[field]);
    }
    assert.deepEqual(sessions.rows, []); assert.deepEqual(packets.rows, []); assert.deepEqual(completions.rows, []);
    assert.deepEqual(progress.rows, []); assert.deepEqual(timeTracking.rows, []); assert.deepEqual(evidence.rows, []); assert.deepEqual(turns.rows, []);
    assert.ok(requests.rows.length >= 1); assert.ok(requests.rows.every(row => row.user_text === null && row.response_json === null));
    assert.equal(judgments.rows.length, before.judgments.length);
    // Snapshots use the canonical JSON representation, including PostgreSQL
    // Date values. Compare current rows in that same representation.
    const currentJudgments = rows(judgments);
    for (const prior of before.judgments) {
      const current = currentJudgments.find(row => row.evaluation_id === prior.evaluation_id); assert.ok(current);
      for (const field of ['evaluation_id', 'workshop_key', 'objective_id', 'family', 'scenario', 'rubric_version', 'evidence_digest', 'run_id', 'generation', 'mode', 'canonical_mode', 'verdict', 'disposition', 'created_at', 'evaluated_at']) assert.equal(current[field], prior[field]);
      assert.equal(current.result_digest, null);
      assert.deepEqual(current.result_json, current.verdict === null ? null : { deleted: true });
    }
    const retired = await resourceRepository.assertOwnerResourcesRetired({ platformOwnerId: deletionOwner });
    assert.equal(retired.status, 'retired');
    assert.equal(retired.targetCount, before.durable.targets.length);
    assert.equal(retired.mailIntentCount, before.durable.intents.length);
    await assert.rejects(resourceRepository.assertOwnerResourcesRetired({ platformOwnerId: siblingId }),
      error => error?.code === 'MCP_OWNER_RESOURCES_PENDING');
    assert.deepEqual(sibling, before.siblingDurable);
    for (const receipt of receipts) {
      assert.equal(receipt.ownerId, deletionOwner); assert.equal(receipt.verified, true); assert.equal(receipt.awarded, true);
      assert.ok(before.requests.some(row => row.request_id === receipt.requestId && row.run_id === receipt.runId));
      assert.ok(before.judgments.some(row => row.run_id === receipt.runId && row.disposition === 'awarded'));
    }
    return freeze({ ownerId: deletionOwner, jobId, verified: true, ownerResourcesRetired: true,
      siblingPreserved: true, subjectAnonymized: true, subjectSessionsRevoked: true,
      judgmentReceiptsPreserved: true, conversationContentRemoved: true });
  }

  async function expectedStudentView(userId) {
    owner(userId);
    const challengeRows = rows(await identityRuntime.query(`SELECT e.workshop_key,e.challenge_name,
        count(o.objective_id)::int AS objective_count,
        count(c.objective_id)::int AS completed_objective_count
      FROM workshop_platform.exercises e
      LEFT JOIN workshop_platform.objectives o ON o.workshop_key=e.workshop_key
        AND o.catalog_active=true AND o.is_enabled=true
      LEFT JOIN workshop_platform.completions c ON c.user_id=$1
        AND c.workshop_key=o.workshop_key AND c.objective_id=o.objective_id
      WHERE e.catalog_active=true AND e.is_visible=true
      GROUP BY e.workshop_key,e.challenge_name ORDER BY e.workshop_key`, [userId]));
    const normalized = challengeRows.map(item => ({ ...item,
      objective_count: Number(item.objective_count), completed_objective_count: Number(item.completed_objective_count) }));
    const mcp = normalized.find(item => item.workshop_key === WORKSHOP); assert.ok(mcp);
    return freeze({
      completedChallenges: normalized.filter(item => item.objective_count > 0
        && item.completed_objective_count === item.objective_count).length,
      completedObjectives: normalized.reduce((sum, item) => sum + item.completed_objective_count, 0),
      totalObjectives: normalized.reduce((sum, item) => sum + item.objective_count, 0),
      mcpCompletedObjectives: mcp.completed_objective_count,
      mcpTotalObjectives: mcp.objective_count,
      mcpChallengeName: mcp.challenge_name,
    });
  }

  async function verifyRunDetail({ ownerId: detailOwner, runId, body, projection }) {
    owner(detailOwner); assert.equal(detailOwner, ownerId); assert.match(runId || '', UUID);
    assert.ok(['student', 'admin'].includes(projection), 'Explicit run-detail projection is required');
    assert.equal(body?.run?.runId, runId);
    if (projection === 'admin') assert.equal(String(body.run.ownerId), String(detailOwner));
    else assert.equal(body.run.ownerId, undefined, 'Learner run detail must not expose the owner field');
    const snapshot = await durableSnapshot(detailOwner);
    const run = snapshot.runs.find(item => item.run_id === runId); assert.ok(run);
    assert.equal(body.run.status, run.status); assert.equal(String(body.run.generation), String(run.generation));
    assert.equal(body.run.provider, run.provider); assert.equal(body.run.model, run.model);
    assert.equal(body.run.decisionSource, run.decision_source);
    const durableJudgments = snapshot.judgments.filter(item => item.run_id === runId);
    assert.ok(durableJudgments.length > 0); assert.equal(body.judgments.length, durableJudgments.length);
    for (const row of durableJudgments) {
      const projected = body.judgments.find(item => item.evaluationId === row.evaluation_id); assert.ok(projected);
      assert.equal(projected.objectiveId, row.objective_id); assert.equal(projected.rubricVersion, row.rubric_version);
      assert.equal(projected.verdict, row.verdict); assert.equal(projected.disposition, row.disposition);
    }
    const durableEvents = snapshot.events.filter(item => item.run_id === runId).slice(0, 100);
    assert.deepEqual(body.events.map(item => [item.seq, item.node, item.type]),
      durableEvents.map(item => [item.sequence, item.node, item.event_type]));
    const allEvents = snapshot.events.filter(item => item.run_id === runId);
    assert.equal(body.nextCursor ?? null, allEvents.length > 100 ? allEvents[99].sequence : null);
    return freeze({ ownerId: detailOwner, runId, verified: true });
  }

  return Object.freeze({ visibleObjectiveCount, snapshotTurn, verifyTurn, captureTurnFailure, snapshotBeforeReset,
    verifyReset, snapshotBeforeDeletion, captureDeletionFailure, verifyDeletion, expectedStudentView, verifyRunDetail });
}

module.exports = { createMcpRenderedNativeEvidence,
  _internals: { OBJECTIVE, WORKSHOP, RUBRIC, REQUIRED_CRITERIA, durableOwnerKey: ownerKey, persistedEffectKey,
    deletionSteps: jobId => STUDENT_DELETION_STEPS.map((step, ordinal) => ({ job_id: jobId, step_key: step, ordinal, state: 'pending' })) } };
