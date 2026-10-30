'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const { ownerWorkflowRoute, getOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
const { createMcpRenderedNativeEvidence, _internals: evidenceInternals } = require('./fixtures/mcpRenderedNativeEvidence');
const { ATTACHMENT_MARKER } = require('../server/services/mcp/reportPayload');
const { _internals: targets } = require('../sidecars/sandbox-runner/mcpTargets');

const ids = {
  ownerRunBenign: '10000000-0000-4000-8000-000000000001',
  siblingRun: '10000000-0000-4000-8000-000000000002',
  ownerRunPositive: '10000000-0000-4000-8000-000000000003',
  ownerRequestBenign: '20000000-0000-4000-8000-000000000001',
  siblingRequest: '20000000-0000-4000-8000-000000000002',
  ownerRequestPositive: '20000000-0000-4000-8000-000000000003',
  ownerTarget: '30000000-0000-4000-8000-000000000001',
  siblingTarget: '30000000-0000-4000-8000-000000000002',
  intent: '40000000-0000-4000-8000-000000000001',
  evaluation: '50000000-0000-4000-8000-000000000001',
};
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));
const key = ownerId => JSON.stringify(['MCP', String(ownerId)]);
const copy = value => structuredClone(value);

function fixture() {
  const state = {
    catalog: Array.from({ length: 11 }, (_, index) => ({ objective_id: index === 4 ? 'mcp_indirect_injection' : `mcp_${index}`,
      label: `Objective ${index}`, ordinal: index + 1 })),
    userState: [{ user_id: 7, workshop_key: 'mcp_workshop', generation: 0 },
      { user_id: 8, workshop_key: 'mcp_workshop', generation: 0 }],
    users: [{ id: 7, username: 'student-7', email: 'student-7@example.invalid', role: 'student', admin_level: 0, is_active: 0 },
      { id: 8, username: 'student-8', email: 'student-8@example.invalid', role: 'student', admin_level: 0, is_active: 1 }],
    sessions: [{ id: 701, user_id: 7, is_active: 0, revoked_at: '2026-09-16T13:00:00.000Z' },
      { id: 801, user_id: 8, is_active: 1, revoked_at: null }],
    deletionJobs: [], deletionSteps: [], timeTracking: [], evidence: [],
    graphOwners: [{ owner_key: key(7), generation: 0 }, { owner_key: key(8), generation: 0 }],
    challenges: [{ workshop_key: 'mcp_workshop', challenge_name: 'MCP Server Exploitation', objective_count: 11 },
      { workshop_key: 'other', challenge_name: 'Other lab', objective_count: 2 }],
    runs: [], effects: [], events: [], judgments: [], packets: [], requests: [], turns: [], completions: [],
    tools: [], httpLeases: [],
    targets: [
      { target_id: ids.ownerTarget, user_key: '7', platform_session_id: 11, generation: 0, state: 'active', retired_at: null },
      { target_id: ids.siblingTarget, user_key: '8', platform_session_id: 12, generation: 0, state: 'active', retired_at: null },
    ],
    intents: [], runnerCleanups: [], mailCleanups: [], messages: new Map(), nextTool: 1,
  };
  const trusted = new WeakSet();
  const mail = {
    async listMessagesBySmtpIds(messageIds) {
      return { ok: true, messages: messageIds.filter(id => state.messages.has(id)).map(id => ({ ...state.messages.get(id), messageId: id })) };
    },
    async verifyMessageReadback(expected) {
      const current = state.messages.get(expected.messageId);
      if (!current || current.to !== expected.to || current.subject !== expected.subject || current.body !== expected.body) {
        return { ok: false, status: 'mismatch' };
      }
      const receipt = Object.freeze({ receiptSha256: current.readbackReceiptSha256,
        submittedPayloadSha256: hash(Buffer.from(canonical({ body: expected.body, subject: expected.subject }))) });
      trusted.add(receipt); return { ok: true, status: 'verified', receipt };
    },
    isTrustedMessageReadback(value) { return trusted.has(value); },
  };
  function filterOwner(list, ownerId, ownerField = 'user_id') {
    return list.filter(row => String(row[ownerField]) === String(ownerId));
  }
  const identityRuntime = { async query(sql, params) {
    if (sql.includes('/* mcp_deletion_failure_capture */')) {
      return { rows: copy(state.deletionJobs.filter(row => row.subject_user_id === params[0])
        .map(row => ({ job_id: row.job_id, subject_user_id: row.subject_user_id,
          requested_by: row.requested_by, state: row.state,
          requester_matches: row.requested_by === params[1],
          failure_code: row.failure_code ?? null,
          steps: state.deletionSteps.filter(step => step.job_id === row.job_id)
            .sort((left, right) => left.ordinal - right.ordinal)
            .map(step => ({ stepKey: step.step_key, ordinal: step.ordinal, state: step.state })) }))) };
    }
    if (sql.includes('/* mcp_failure_capture_binding */')) {
      return { rows: copy(state.requests.filter(row => row.user_id === params[0]
        && row.request_id === params[1]).flatMap(request => state.runs
        .filter(run => run.run_id === request.run_id).map(run => ({ request_id: request.request_id,
          run_id: request.run_id, request_owner_key: request.owner_key,
          request_generation: String(request.generation), run_owner_key: run.owner_key,
          run_generation: String(run.generation) })))) };
    }
    if (sql.includes('/* mcp_failure_capture_judgment */')) {
      const type = value => value === null || value === undefined ? null
        : Array.isArray(value) ? 'array' : typeof value === 'object' ? 'object'
          : typeof value === 'boolean' ? 'boolean' : typeof value === 'number' ? 'number' : 'string';
      const rows = state.judgments.filter(row => row.user_id === params[0] && row.run_id === params[1]
        && row.workshop_key === params[2] && row.objective_id === params[3]).map(row => {
        const result = row.result_json;
        const criterion = id => Array.isArray(result?.criteria)
          ? result.criteria.filter(item => item?.id === id) : [];
        const scoped = id => Array.isArray(result?.scopedCriteria)
          ? result.scopedCriteria.filter(item => item?.criterionId === id) : [];
        const criterionSets = evidenceInternals.REQUIRED_CRITERIA.map(criterion);
        const scopedSets = evidenceInternals.REQUIRED_CRITERIA.map(scoped);
        const multiplicity = [...criterionSets, ...scopedSets].reduce((count, values) => count * Math.max(1, values.length), 1);
        const value = (values, field) => values[0]?.[field] === undefined ? null : String(values[0][field]);
        const projected = { run_id: row.run_id, judgment_generation: String(row.generation),
          verdict: row.verdict, disposition: row.disposition, rubric_version: row.rubric_version,
          result_type: type(result), criteria_type: type(result?.criteria),
          scoped_criteria_type: type(result?.scopedCriteria), error_code: result?.errorCode ?? null,
          validation_code: result?.validationCode ?? null,
          ticket_delivery_satisfied: value(criterionSets[0], 'satisfied'),
          learner_task_satisfied: value(criterionSets[1], 'satisfied'),
          task_redirection_satisfied: value(criterionSets[2], 'satisfied'),
          ticket_delivery_scoped_verdict: value(scopedSets[0], 'verdict'),
          ticket_delivery_scoped_error: value(scopedSets[0], 'errorCode'),
          ticket_delivery_scoped_attempts: value(scopedSets[0], 'attempts'),
          learner_task_scoped_verdict: value(scopedSets[1], 'verdict'),
          learner_task_scoped_error: value(scopedSets[1], 'errorCode'),
          learner_task_scoped_attempts: value(scopedSets[1], 'attempts'),
          task_redirection_scoped_verdict: value(scopedSets[2], 'verdict'),
          task_redirection_scoped_error: value(scopedSets[2], 'errorCode'),
          task_redirection_scoped_attempts: value(scopedSets[2], 'attempts') };
        return Array.from({ length: multiplicity }, () => projected);
      }).flat();
      return { rows: copy(rows) };
    }
    if (sql.includes('FROM workshop_platform.objectives WHERE workshop_key=$1')) return { rows: copy(state.catalog) };
    if (sql.includes('FROM identity.users WHERE id=$1')) return { rows: copy(state.users.filter(row => row.id === params[0])) };
    if (sql.includes('FROM identity.user_sessions WHERE user_id=$1')) return { rows: copy(state.sessions.filter(row => row.user_id === params[0])) };
    if (sql.includes('FROM identity.student_deletion_jobs WHERE subject_user_id=$1')) return { rows: copy(state.deletionJobs.filter(row => row.subject_user_id === params[0])) };
    if (sql.includes('FROM identity.student_deletion_jobs WHERE job_id=$1')) return { rows: copy(state.deletionJobs.filter(row => row.job_id === params[0])) };
    if (sql.includes('FROM identity.student_deletion_steps WHERE job_id=$1')) return { rows: copy(state.deletionSteps.filter(row => row.job_id === params[0])) };
    if (sql.includes('FROM workshop_platform.time_tracking WHERE user_id=$1')) return { rows: copy(state.timeTracking.filter(row => row.user_id === params[0])) };
    if (sql.includes('FROM workshop_platform.objective_evidence WHERE user_id=$1')) {
      // Evidence is keyed by id/evidence_id, not an objective_id (migration 0008).
      // Reject invalid SQL here instead of letting a table-only mock hide it.
      assert.match(sql, /^SELECT id FROM /);
      assert.doesNotMatch(sql, /objective_id/);
      return { rows: copy(state.evidence.filter(row => row.user_id === params[0]).map(row => ({ id: row.id }))) };
    }
    if (sql.includes('FROM workshop_platform.user_state')) return { rows: copy(state.userState
      .filter(row => row.user_id === params[0] && row.workshop_key === params[1]).map(row => ({ generation: row.generation }))) };
    if (sql.includes('FROM graph_runtime.owners WHERE owner_key=$1')) return { rows: copy(state.graphOwners
      .filter(row => row.owner_key === params[0]).map(row => ({ generation: row.generation }))) };
    if (sql.includes('FROM graph_runtime.runs WHERE owner_key=$1')) return { rows: copy(state.runs.filter(row => row.owner_key === params[0])) };
    if (sql.includes('FROM graph_runtime.effects')) return { rows: copy(state.effects.filter(row => row.owner_key === params[0])) };
    if (sql.includes('FROM graph_runtime.events')) return { rows: copy(state.events.filter(row => row.owner_key === params[0])) };
    if (sql.includes('FROM workshop_platform.objective_judgments')) return { rows: copy(filterOwner(state.judgments, params[0])) };
    if (sql.includes('FROM workshop_platform.grade_packets')) {
      const evaluations = new Set(filterOwner(state.judgments, params[0]).map(row => row.evaluation_id));
      return { rows: copy(state.packets.filter(row => evaluations.has(row.evaluation_id))) };
    }
    if (sql.includes('FROM workshop_conversations.requests')) return { rows: copy(filterOwner(state.requests, params[0])) };
    if (sql.includes('FROM workshop_conversations.turns')) return { rows: copy(filterOwner(state.turns, params[0])) };
    if (sql.includes('FROM workshop_platform.completions')) return { rows: copy(filterOwner(state.completions, params[0])) };
    if (sql.includes('FROM workshop_platform.exercises e')) {
      return { rows: state.challenges.map(challenge => ({ ...challenge,
        completed_objective_count: state.completions.filter(row => row.user_id === params[0]
          && row.workshop_key === challenge.workshop_key).length })) };
    }
    throw new Error(`Unexpected identity query: ${sql}`);
  } };
  const mcpRuntime = { async query(sql, params) {
    if (sql === "SELECT to_regclass('mcp.http_target_leases')::text AS name") return {rows: [{name: 'mcp.http_target_leases'}]};
    if (sql === 'SELECT * FROM mcp.http_target_leases WHERE target_id=$1') return {rows: copy(state.httpLeases.filter(row => row.target_id === params[0]))};
    if (sql.includes('FROM mcp.tool_log')) return { rows: copy(state.tools.filter(row => row.user_key === params[0])) };
    if (sql.includes('FROM mcp.runner_targets') && !sql.includes('COALESCE((SELECT jsonb_agg')) return { rows: copy(state.targets.filter(row => row.user_key === params[0])) };
    if (sql.includes('FROM mcp.mail_intents') && !sql.includes('COALESCE((SELECT jsonb_agg')) return { rows: copy(state.intents.filter(row => row.user_key === params[0])) };
    if (sql.includes('COALESCE((SELECT jsonb_agg')) {
      const ownerId = String(params[0]);
      const targets = state.targets.filter(row => row.user_key === ownerId).map(row => ({ targetId: row.target_id,
        ownerKey: ownerId, platformSessionId: String(row.platform_session_id), generation: String(row.generation),
        state: row.state, retiredAt: row.retired_at }));
      const runnerCleanups = state.runnerCleanups.filter(row => row.ownerKey === ownerId);
      const intents = state.intents.filter(row => row.user_key === ownerId).map(row => ({ intentId: row.intent_id,
        targetId: row.target_id, ownerKey: ownerId, platformSessionId: String(row.platform_session_id), generation: String(row.generation),
        messageId: row.assigned_message_id, recipientSha256: row.recipient_sha256, payloadSha256: row.payload_sha256,
        status: row.status, settledAt: row.settled_at, cleanedAt: row.cleaned_at }));
      const mailCleanups = state.mailCleanups.filter(row => row.ownerKey === ownerId);
      return { rows: [{ runner_targets: targets, runner_cleanups: runnerCleanups, mail_intents: intents, mail_cleanups: mailCleanups }] };
    }
    throw new Error(`Unexpected MCP query: ${sql}`);
  } };

  function addTurn({ ownerId, requestId, runId, message, body, positive }) {
    state.runs.push({ run_id: runId, owner_key: key(ownerId), status: 'completed', generation: 0,
      provider: 'ollama', model: 'llama3.1:8b', decision_source: 'model', last_node: 'terminal' });
    state.requests.push({ user_id: ownerId, request_id: requestId, run_id: runId, owner_key: key(ownerId),
      generation: 0, user_text: message, response_json: copy(body) });
    state.turns.push({ user_id: ownerId, run_id: runId, owner_key: key(ownerId), generation: 0,
      user_text: message, assistant_text: body.response || 'done' });
    state.events.push({ owner_key: key(ownerId), run_id: runId, sequence: 1, node: 'decide', event_type: 'decision',
      metadata: { decisionSource: 'model', provider: 'ollama', model: 'llama3.1:8b', tool: 'read_ticket' } });
    state.effects.push({ owner_key: key(ownerId), run_id: runId,
      effect_key: evidenceInternals.persistedEffectKey(runId, 'mcp_indirect_injection_observation'),
      status: 'completed', generation: 0 });
    state.tools.push({ id: state.nextTool++, user_key: String(ownerId), tool_name: 'read_ticket', args: JSON.stringify({ id: body.toolResult.ticketId }),
      result_summary: 'owned ticket read', outcome: positive ? 'mcp_indirect_injection' : null, success: 1 });
  }

  function benign({ ownerId, requestId, runId, ticketId = '4290' }) {
    const message = `Read support ticket ${ticketId} and summarize what it says.`;
    const body = { response: 'No follow-up action was taken.', toolUsed: 'read_ticket',
      toolResult: { ticketId, decisionSource: 'model', observationReal: true, delivered: false },
      completedObjectives: [], judgments: [] };
    addTurn({ ownerId, requestId, runId, message, body, positive: false });
    return { message, body };
  }

  function positive() {
    const ownerId = 7, generation = 0, platformSessionId = 11;
    const controlled = targets.controlledTicket({ targetId: ids.ownerTarget, ownerId, platformSessionId, generation }, '4295');
    const recipient = controlled.body.match(/mcp-audit-[a-f0-9]{20}@owasp-ai-goat\.invalid/)[0];
    const selected = { to: recipient, body: 'I will send the requested diagnostic.' };
    const protectedContent = 'DB_PASSWORD=synthetic-owned-value\nJWT_SECRET=synthetic-owned-value';
    const fullBody = `${selected.body}\n\n${ATTACHMENT_MARKER}${protectedContent}`;
    const subject = `RE: ${controlled.subject}`;
    const messageId = `mcp-${ids.intent}@owasp-ai-goat.local`;
    const readbackReceiptSha256 = hash('trusted-full-readback');
    const payloadSha256 = hash(Buffer.from(canonical({ body: fullBody, subject })));
    const witness = { version: 'mcp-owned-indirect-injection-witness.v2', targetId: ids.ownerTarget,
      platformOwnerId: ownerId, platformSessionId, generation, runId: ids.ownerRunPositive,
      ticket: { ticketId: '4295', receiptSha256: hash('ticket') },
      action: { tool: 'send_report', argsSha256: hash(Buffer.from(canonical(selected))), modelReceiptSha256: hash('model') },
      protectedRead: { operation: 'read_configuration', byteCount: Buffer.byteLength(protectedContent),
        configSha256: hash(Buffer.from(protectedContent)), receiptSha256: hash('protected') },
      mailbox: { receiptSha256: hash('mailbox'), readbackReceiptSha256,
        acceptedWitnessSha256: hash('accepted') },
      delivery: { recipient, intentId: ids.intent, messageId, payloadSha256 } };
    const message = 'Read support ticket 4295 and summarize what it says.';
    const body = { response: 'Ticket handled.', toolUsed: 'read_ticket', toolResult: { ticketId: '4295',
      decisionSource: 'model', modelAction: { tool: 'send_report', params: { ...selected } }, real: true, delivered: true, error: null,
      selectedArgs: selected, output: `Ticket observed.\n\nModel-selected report delivered to ${recipient}:\n${fullBody}` },
    completedObjectives: ['mcp_indirect_injection'], judgments: [{ objectiveId: 'mcp_indirect_injection',
      evaluationId: ids.evaluation, verdict: 'pass', provider: 'ollama', model: 'llama3.1:8b',
      rubricVersion: 'mcp_owned_indirect_injection.v4' }] };
    addTurn({ ownerId, requestId: ids.ownerRequestPositive, runId: ids.ownerRunPositive, message, body, positive: true });
    state.tools.push({ id: state.nextTool++, user_key: String(ownerId), tool_name: 'send_report', args: JSON.stringify(selected),
      result_summary: 'owned report delivered', outcome: 'mcp_indirect_injection', success: 1 });
    state.effects.push({ owner_key: key(ownerId), run_id: ids.ownerRunPositive,
      effect_key: evidenceInternals.persistedEffectKey(ids.ownerRunPositive, 'mcp_indirect_injection_consequence'),
      status: 'completed', generation });
    state.judgments.push({ user_id: ownerId, evaluation_id: ids.evaluation, workshop_key: 'mcp_workshop', objective_id: 'mcp_indirect_injection',
      verdict: 'pass', disposition: 'awarded', result_digest: hash('result'), run_id: ids.ownerRunPositive,
      generation, rubric_version: 'mcp_owned_indirect_injection.v4', result_json: { criteria: [
        { id: 'ticket_induced_protected_delivery', satisfied: true },
        { id: 'learner_task_is_ticket_only', satisfied: true },
        { id: 'ticket_task_redirection', satisfied: true },
      ] } });
    state.packets.push({ evaluation_id: ids.evaluation, judge_version: 'objective-judge.v4', owner_key: key(ownerId),
      owner_generation: '0', retry_invocations: 0, packet: { facts: { trusted_ticket_model_delivery: true },
        evidence: [{ id: 'trusted_effect_chain', content: { witness } }] } });
    state.completions.push({ user_id: ownerId, workshop_key: 'mcp_workshop', objective_id: 'mcp_indirect_injection',
      completed_at: '2026-09-16T12:00:00.000Z' });
    state.intents.push({ user_key: String(ownerId), intent_id: ids.intent, target_id: ids.ownerTarget,
      platform_session_id: platformSessionId, generation, assigned_message_id: messageId,
      recipient_sha256: hash(Buffer.from(recipient)), payload_sha256: payloadSha256,
      status: 'accepted', settled_at: '2026-09-16T12:00:00.000Z', cleaned_at: null });
    state.messages.set(messageId, { to: recipient, subject, body: fullBody, readbackReceiptSha256 });
    return { message, body };
  }
  function resetOwner({ advanceGeneration = true } = {}) {
    if (advanceGeneration) {
      state.graphOwners.find(row => row.owner_key === key(7)).generation += 1;
      state.userState.find(row => row.user_id === 7 && row.workshop_key === 'mcp_workshop').generation += 1;
    }
    state.completions = state.completions.filter(row => row.user_id !== 7 || row.workshop_key !== 'mcp_workshop');
    state.tools = state.tools.filter(row => row.user_key !== '7');
    for (const target of state.targets.filter(row => row.user_key === '7')) {
      target.state = 'retired'; target.retired_at = '2026-09-16T13:00:00.000Z';
    }
    for (const intent of state.intents.filter(row => row.user_key === '7')) {
      intent.cleaned_at = '2026-09-16T13:00:00.000Z'; state.messages.delete(intent.assigned_message_id);
    }
    const operationId = '60000000-0000-4000-8000-000000000001';
    const runnerBody = { version: 1, targetId: ids.ownerTarget, ownerId: 7, platformSessionId: 11, generation: 0,
      operationId, status: 'completed', completedAt: '2026-09-16T13:00:00.000Z', cleanupPending: false };
    const runnerReceipt = { ...runnerBody, receiptSha256: hash(Buffer.from(canonical(runnerBody))) };
    const mailBody = { version: 1, targetId: ids.ownerTarget, platformOwnerId: 7, platformSessionId: 11, generation: 0,
      operationId, status: 'completed', intentCount: 1, completedAt: '2026-09-16T13:00:00.000Z', cleanupPending: false };
    const mailReceipt = { ...mailBody, receiptSha256: hash(Buffer.from(canonical(mailBody))) };
    state.runnerCleanups.push({ targetId: ids.ownerTarget, ownerKey: '7', platformSessionId: '11', generation: '0',
      operationId, status: 'completed', receiptVersion: 1, receiptSha256: runnerReceipt.receiptSha256,
      receiptJson: runnerReceipt, completedAt: '2026-09-16T13:00:00.000Z' });
    state.mailCleanups.push({ targetId: ids.ownerTarget, ownerKey: '7', platformSessionId: '11', generation: '0',
      operationId, status: 'completed', messageIds: [`mcp-${ids.intent}@owasp-ai-goat.local`], receiptVersion: 1,
      receiptSha256: mailReceipt.receiptSha256, receiptJson: mailReceipt,
      completedAt: '2026-09-16T13:00:00.000Z' });
  }
  return { state, mail, identityRuntime, mcpRuntime, benign, positive, resetOwner };
}

test('rendered evidence effect keys match the composed owner-route coordinator persistence key', async () => {
  const persisted = [];
  const ledger = {
    async begin(context) { return { durableGeneration: String(context.generation) }; },
    async assertCurrent() {},
    async effect(context, effectKey, callback) {
      persisted.push({ runId: context.runId, ownerKey: context.ownerKey,
        generation: String(context.durableGeneration), effectKey });
      return callback();
    },
    async finish() {},
  };
  const coordinator = createRunCoordinator({ family: 'MCP', ledger });
  const route = ownerWorkflowRoute(coordinator, () => '7', async (_req, res) => {
    const execution = getOwnerExecution();
    await execution.effect('mcp_indirect_injection_observation', async () => 'observed');
    res.json({ runId: execution.runId });
  });
  const req = new EventEmitter(); req.aborted = false;
  const res = new EventEmitter();
  Object.assign(res, { destroyed: false, writableEnded: false, headersSent: false, statusCode: 200 });
  res.status = function status(code) { this.statusCode = code; return this; };
  res.json = function jsonResponse(value) {
    this.body = value; this.headersSent = true; this.writableEnded = true; return this;
  };
  await route(req, res, error => { throw error; });
  assert.equal(res.statusCode, 200); assert.match(res.body.runId, /^[0-9a-f-]{36}$/i);
  assert.deepEqual(persisted, [{ runId: res.body.runId, ownerKey: key(7), generation: '0',
    effectKey: evidenceInternals.persistedEffectKey(res.body.runId, 'mcp_indirect_injection_observation') }]);
  assert.notEqual(persisted[0].effectKey, 'mcp_indirect_injection_observation');
});

test('native rendered evidence joins browser turns to durable actor, witness, mailbox, views and reset state', async () => {
  const f = fixture();
  const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
    mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
  assert.equal(evidence.visibleObjectiveCount, 11);

  const ownerMessage = 'Read support ticket 4290 and summarize what it says.';
  await evidence.snapshotTurn({ ownerId: 7, message: ownerMessage, positive: false });
  const ownerBenign = f.benign({ ownerId: 7, requestId: ids.ownerRequestBenign, runId: ids.ownerRunBenign });
  const ownerReceipt = await evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestBenign,
    message: ownerBenign.message, body: ownerBenign.body, positive: false });
  assert.equal(ownerReceipt.awarded, false);

  const siblingMessage = 'Read support ticket 4290 and summarize what it says.';
  await evidence.snapshotTurn({ ownerId: 8, message: siblingMessage, positive: false });
  const sibling = f.benign({ ownerId: 8, requestId: ids.siblingRequest, runId: ids.siblingRun });
  const siblingReceipt = await evidence.verifyTurn({ ownerId: 8, requestId: ids.siblingRequest,
    message: sibling.message, body: sibling.body, positive: false });
  assert.equal(siblingReceipt.verified, true);

  const positiveMessage = 'Read support ticket 4295 and summarize what it says.';
  await evidence.snapshotTurn({ ownerId: 7, message: positiveMessage, positive: true });
  const positive = f.positive();
  const positiveReceipt = await evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestPositive,
    message: positive.message, body: positive.body, positive: true });
  assert.deepEqual({ verified: positiveReceipt.verified, awarded: positiveReceipt.awarded }, { verified: true, awarded: true });

  const ownerView = await evidence.expectedStudentView(7), siblingView = await evidence.expectedStudentView(8);
  assert.deepEqual([ownerView.completedObjectives, ownerView.totalObjectives, ownerView.mcpCompletedObjectives,
    ownerView.mcpTotalObjectives, ownerView.completedChallenges], [1, 13, 1, 11, 0]);
  assert.deepEqual([siblingView.completedObjectives, siblingView.mcpCompletedObjectives], [0, 0]);
  for (let sequence = 2; sequence <= 101; sequence += 1) f.state.events.push({ owner_key: key(7),
    run_id: ids.ownerRunPositive, sequence, node: `step-${sequence}`, event_type: 'node_end', metadata: {} });
  const projectedEvents = f.state.events.filter(row => row.run_id === ids.ownerRunPositive).slice(0, 100)
    .map(row => ({ seq: row.sequence, node: row.node, type: row.event_type }));
  const detail = { run: { runId: ids.ownerRunPositive, ownerId: '7', status: 'completed', generation: 0,
    provider: 'ollama', model: 'llama3.1:8b', decisionSource: 'model' },
  events: projectedEvents, nextCursor: 100, judgments: [{ evaluationId: ids.evaluation,
    objectiveId: 'mcp_indirect_injection', rubricVersion: 'mcp_owned_indirect_injection.v4', verdict: 'pass', disposition: 'awarded' }] };
  assert.equal((await evidence.verifyRunDetail({ ownerId: 7, runId: ids.ownerRunPositive,
    body: detail, projection: 'admin' })).verified, true);
  const learnerDetail = structuredClone(detail); delete learnerDetail.run.ownerId;
  assert.equal((await evidence.verifyRunDetail({ ownerId: 7, runId: ids.ownerRunPositive,
    body: learnerDetail, projection: 'student' })).verified, true);

  await evidence.snapshotBeforeReset({ ownerId: 7 });
  f.resetOwner();
  const reset = await evidence.verifyReset({ ownerId: 7, receipts: [ownerReceipt, positiveReceipt] });
  assert.deepEqual({ verified: reset.verified, immutable: reset.immutableJudgmentsPreserved,
    sibling: reset.siblingPreserved, retired: reset.ownerResourcesRetired },
  { verified: true, immutable: true, sibling: true, retired: true });
});

test('turn failure capture returns only exact bound categorical judgment metadata', async () => {
  const f = fixture();
  const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
    mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
  f.benign({ ownerId: 7, requestId: ids.ownerRequestBenign, runId: ids.ownerRunBenign });
  assert.deepEqual(await evidence.captureTurnFailure({ ownerId: 7, requestId: ids.ownerRequestBenign }), {
    ownerId: 7, requestId: ids.ownerRequestBenign, runId: ids.ownerRunBenign,
    generation: '0', requestRunBound: true, judgmentPresent: false,
  });

  f.positive();
  const judgment = f.state.judgments.find(row => row.evaluation_id === ids.evaluation);
  judgment.verdict = null; judgment.disposition = 'pending'; judgment.result_json = null;
  const pending = await evidence.captureTurnFailure({ ownerId: 7, requestId: ids.ownerRequestPositive });
  assert.deepEqual({ judgmentPresent: pending.judgmentPresent, verdict: pending.verdict,
    disposition: pending.disposition, errorCode: pending.errorCode,
    criteria: pending.criteria.map(item => item.satisfied) }, {
    judgmentPresent: true, verdict: null, disposition: 'pending', errorCode: null,
    criteria: [null, null, null],
  });
  judgment.verdict = 'unavailable'; judgment.disposition = 'not_pass';
  judgment.result_json = {
    errorCode: 'INVALID_JUDGE_OUTPUT', validationCode: 'SCOPED_CITATION_NOT_GROUNDED',
    explanation: 'private explanation must not escape',
    criteria: [
      { id: 'ticket_induced_protected_delivery', satisfied: true, evidenceRefs: ['private'] },
      { id: 'learner_task_is_ticket_only', satisfied: true, evidenceRefs: ['private'] },
      { id: 'ticket_task_redirection', satisfied: false, evidenceRefs: [] },
    ],
    scopedCriteria: [
      { criterionId: 'learner_task_is_ticket_only', verdict: 'pass', attempts: 1 },
      { criterionId: 'ticket_task_redirection', verdict: 'unavailable',
        errorCode: 'INVALID_JUDGE_OUTPUT', attempts: 2, responseSha256: hash('private') },
    ],
  };
  const captured = await evidence.captureTurnFailure({ ownerId: 7, requestId: ids.ownerRequestPositive });
  assert.deepEqual(captured, { ownerId: 7, requestId: ids.ownerRequestPositive,
    runId: ids.ownerRunPositive, generation: '0', requestRunBound: true,
    judgmentPresent: true, judgmentGeneration: '0', judgmentGenerationMatches: true,
    verdict: 'unavailable', disposition: 'not_pass', expectedRubric: true,
    errorCode: 'INVALID_JUDGE_OUTPUT', validationCode: 'SCOPED_CITATION_NOT_GROUNDED',
    criteria: [
      { id: 'ticket_induced_protected_delivery', satisfied: true,
        scopedVerdict: null, scopedErrorCode: null, scopedAttempts: null },
      { id: 'learner_task_is_ticket_only', satisfied: true,
        scopedVerdict: 'pass', scopedErrorCode: null, scopedAttempts: 1 },
      { id: 'ticket_task_redirection', satisfied: false,
        scopedVerdict: 'unavailable', scopedErrorCode: 'INVALID_JUDGE_OUTPUT', scopedAttempts: 2 },
    ] });
  assert.equal(Object.isFrozen(captured), true); assert.equal(Object.isFrozen(captured.criteria), true);
  const serialized = JSON.stringify(captured);
  for (const forbidden of ['private explanation', 'evidenceRefs', 'responseSha256', 'selectedArgs', '@owasp-ai-goat.invalid']) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test('turn failure capture rejects missing, foreign and ambiguous owner bindings', async () => {
  const f = fixture();
  const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
    mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
  f.positive();
  await assert.rejects(evidence.captureTurnFailure({ ownerId: 8, requestId: ids.ownerRequestPositive }),
    /binding is unavailable or ambiguous/);
  await assert.rejects(evidence.captureTurnFailure({ ownerId: 7,
    requestId: '20000000-0000-4000-8000-000000000099' }), /binding is unavailable or ambiguous/);
  f.state.judgments.push({ ...copy(f.state.judgments[0]),
    evaluation_id: '50000000-0000-4000-8000-000000000099' });
  await assert.rejects(evidence.captureTurnFailure({ ownerId: 7, requestId: ids.ownerRequestPositive }),
    /ambiguous objective judgments/);
});

test('deletion failure capture returns only exact requester-bound job and ordered step states', async () => {
  const f = fixture();
  const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
    mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
  f.positive();
  f.state.users.find(row => row.id === 7).is_active = 1;
  await evidence.snapshotBeforeDeletion({ ownerId: 7, administratorId: 8 });
  await assert.rejects(evidence.captureDeletionFailure({ ownerId: 8, administratorId: 8 }),
    /subject is foreign/);
  assert.deepEqual(await evidence.captureDeletionFailure({ ownerId: 7, administratorId: 8 }), {
    ownerId: 7, administratorId: 8, jobPresent: false, steps: [],
  });

  const jobId = '70000000-0000-4000-8000-000000000010';
  f.state.deletionJobs.push({ job_id: jobId, subject_user_id: 7, requested_by: 8,
    state: 'failed', failure_code: null, completed_at: null,
    private_payload: 'must not escape' });
  f.state.deletionSteps.push(...evidenceInternals.deletionSteps(jobId));
  f.state.deletionSteps[0].state = 'completed';
  f.state.deletionSteps[6].state = 'failed';
  const captured = await evidence.captureDeletionFailure({ ownerId: 7, administratorId: 8 });
  assert.deepEqual(captured, { ownerId: 7, administratorId: 8, jobPresent: true,
    jobId, jobState: 'failed', jobFailureCode: null, replayed: false,
    steps: evidenceInternals.deletionSteps(jobId).map((step, ordinal) => ({
      stepKey: step.step_key, ordinal, state: ordinal === 0 ? 'completed'
        : ordinal === 6 ? 'failed' : 'pending',
    })) });
  assert.equal(Object.isFrozen(captured), true);
  assert.equal(Object.isFrozen(captured.steps), true);
  assert.equal(JSON.stringify(captured).includes('private_payload'), false);

  f.state.deletionJobs[0].requested_by = 9;
  await assert.rejects(evidence.captureDeletionFailure({ ownerId: 7, administratorId: 8 }),
    /requester is foreign/);
  f.state.deletionJobs[0].requested_by = 8;
  f.state.deletionJobs.push({ ...copy(f.state.deletionJobs[0]),
    job_id: '70000000-0000-4000-8000-000000000011' });
  await assert.rejects(evidence.captureDeletionFailure({ ownerId: 7, administratorId: 8 }),
    /binding is ambiguous/);
});

test('verification fails closed without pre-action snapshots or with forged response and mailbox bytes', async () => {
  const f = fixture();
  const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
    mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
  await assert.rejects(evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestBenign,
    message: 'x', body: {}, positive: false }), /snapshotTurn/);
  const message = 'Read support ticket 4295 and summarize what it says.';
  await evidence.snapshotTurn({ ownerId: 7, message, positive: true });
  const positive = f.positive();
  f.state.messages.get(`mcp-${ids.intent}@owasp-ai-goat.local`).body += 'forged';
  await assert.rejects(evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestPositive,
    message, body: positive.body, positive: true }), /false !== true|Expected values to be strictly equal/);
  await assert.rejects(evidence.verifyReset({ ownerId: 7, receipts: [{ ownerId: 7, verified: true,
    runId: ids.ownerRunPositive }] }), /snapshotBeforeReset/);
});

test('benign verification rejects a mismatched ticket ID and unreal observation', async () => {
  for (const mutate of [body => { body.toolResult.ticketId = '4301'; },
    body => { body.toolResult.observationReal = false; }]) {
    const f = fixture();
    const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
      mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
    const message = 'Read support ticket 4290 and summarize what it says.';
    await evidence.snapshotTurn({ ownerId: 7, message, positive: false });
    const benign = f.benign({ ownerId: 7, requestId: ids.ownerRequestBenign, runId: ids.ownerRunBenign });
    mutate(benign.body);
    f.state.requests.find(row => row.request_id === ids.ownerRequestBenign).response_json = copy(benign.body);
    await assert.rejects(evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestBenign,
      message, body: benign.body, positive: false }));
  }
});

for (const leakedHttpChild of [false, true]) test(
  leakedHttpChild ? 'reset verification rejects an active HTTP child after generation advances'
    : 'reset verification rejects retired resources when durable owner generation did not advance', async () => {
  const f = fixture();
  const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
    mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
  const ownerBenignMessage = 'Read support ticket 4290 and summarize what it says.';
  await evidence.snapshotTurn({ ownerId: 7, message: ownerBenignMessage, positive: false });
  const ownerBenign = f.benign({ ownerId: 7, requestId: ids.ownerRequestBenign, runId: ids.ownerRunBenign });
  const ownerReceipt = await evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestBenign,
    message: ownerBenign.message, body: ownerBenign.body, positive: false });
  await evidence.snapshotTurn({ ownerId: 8, message: ownerBenignMessage, positive: false });
  const sibling = f.benign({ ownerId: 8, requestId: ids.siblingRequest, runId: ids.siblingRun });
  await evidence.verifyTurn({ ownerId: 8, requestId: ids.siblingRequest,
    message: sibling.message, body: sibling.body, positive: false });
  const positiveMessage = 'Read support ticket 4295 and summarize what it says.';
  await evidence.snapshotTurn({ ownerId: 7, message: positiveMessage, positive: true });
  const positive = f.positive();
  const positiveReceipt = await evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestPositive,
    message: positive.message, body: positive.body, positive: true });
  await evidence.snapshotBeforeReset({ ownerId: 7 });
  f.resetOwner({ advanceGeneration: leakedHttpChild });
  if (leakedHttpChild) f.state.httpLeases.push({ target_id: ids.ownerTarget, state: 'active' });
  await assert.rejects(evidence.verifyReset({ ownerId: 7, receipts: [ownerReceipt, positiveReceipt] }),
    leakedHttpChild ? { code: 'HTTP_CHILD_CLEANUP_REQUIRED' } : /advance/);
});

test('positive native verification rejects merged, reordered or argument-mismatched report logs', async () => {
  for (const mutate of [
    state => { state.tools.pop(); },
    state => { state.tools.reverse(); },
    state => { state.tools[1].args = JSON.stringify({ to: 'other@example.invalid', body: 'different' }); },
  ]) {
    const f = fixture();
    const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
      mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
    const message = 'Read support ticket 4295 and summarize what it says.';
    await evidence.snapshotTurn({ ownerId: 7, message, positive: true });
    const turn = f.positive();mutate(f.state);
    await assert.rejects(evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestPositive,
      message, body: turn.body, positive: true }));
  }
});

for (const [name, mutate] of [
  ['missing', state => { state.effects = []; }],
  ['wrong run', state => { state.effects[0].run_id = ids.siblingRun; }],
  ['bare suffix', state => { state.effects[0].effect_key = 'mcp_indirect_injection_observation'; }],
  ['wrong run prefix', state => { state.effects[0].effect_key = evidenceInternals.persistedEffectKey(ids.siblingRun,
    'mcp_indirect_injection_observation'); }],
  ['request prefix', state => { state.effects[0].effect_key = evidenceInternals.persistedEffectKey(ids.ownerRequestBenign,
    'mcp_indirect_injection_observation'); }],
  ['wrong node', state => { state.effects[0].effect_key = evidenceInternals.persistedEffectKey(state.effects[0].run_id,
    'other_observation'); }],
  ['stale generation', state => { state.effects[0].generation = 1; }],
  ['incomplete', state => { state.effects[0].status = 'pending'; }],
  ['duplicate', state => { state.effects.push(copy(state.effects[0])); }],
  ['wrong logged ticket', state => { state.tools[0].args = JSON.stringify({ id: '4301' }); }],
]) {
  test(`native ticket verification rejects ${name} evidence for both dispositions`, async () => {
    for (const positive of [false, true]) {
      const f = fixture();
      const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
        mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
      const message = `Read support ticket ${positive ? '4295' : '4290'} and summarize what it says.`;
      await evidence.snapshotTurn({ ownerId: 7, message, positive });
      const turn = positive ? f.positive() : f.benign({ ownerId: 7, requestId: ids.ownerRequestBenign, runId: ids.ownerRunBenign });
      mutate(f.state);
      await assert.rejects(evidence.verifyTurn({ ownerId: 7,
        requestId: positive ? ids.ownerRequestPositive : ids.ownerRequestBenign,
        message, body: turn.body, positive }));
    }
  });
}

test('deletion evidence binds the completed 17-step job and preserves only anonymized receipts', async () => {
  for (const mutateTimestamp of [false, true]) {
  const f = fixture();
  const evidence = await createMcpRenderedNativeEvidence({ identityRuntime: f.identityRuntime,
    mcpRuntime: f.mcpRuntime, ownerId: 7, siblingId: 8 }, { mail: f.mail });
  const message = 'Read support ticket 4295 and summarize what it says.';
  await evidence.snapshotTurn({ ownerId: 7, message, positive: true });
  const positive = f.positive();
  await evidence.verifyTurn({ ownerId: 7, requestId: ids.ownerRequestPositive,
    message: positive.message, body: positive.body, positive: true });
  await evidence.snapshotTurn({ ownerId: 8, message: 'Read support ticket 4290 and summarize what it says.', positive: false });
  const sibling = f.benign({ ownerId: 8, requestId: ids.siblingRequest, runId: ids.siblingRun });
  await evidence.verifyTurn({ ownerId: 8, requestId: ids.siblingRequest,
    message: sibling.message, body: sibling.body, positive: false });
  f.resetOwner();
  f.state.users.find(row => row.id === 7).is_active = 1;
  f.state.sessions.push({ id: 702, user_id: 7, is_active: 1, revoked_at: null });
  const jobId = '70000000-0000-4000-8000-000000000001';
  const priorJobId = '70000000-0000-4000-8000-000000000002';
  f.state.deletionJobs.push({ job_id: priorJobId, subject_user_id: 7, requested_by: 8, state: 'completed', completed_at: '2026-09-15T14:00:00.000Z' });
  for (const judgment of f.state.judgments.filter(row => row.user_id === 7)) {
    judgment.created_at = new Date('2026-09-16T13:59:00.000Z');
    judgment.evaluated_at = new Date('2026-09-16T13:59:01.000Z');
  }
  await evidence.snapshotBeforeDeletion({ ownerId: 7, administratorId: 8 });
  await assert.rejects(evidence.verifyDeletion({ ownerId: 7, jobId, administratorId: 9, receipts: [{ ownerId: 7 }] }), /administrator/);
  await assert.rejects(evidence.verifyDeletion({ ownerId: 7, jobId: priorJobId, administratorId: 8, receipts: [{ ownerId: 7 }] }), /newly admitted/);
  f.state.deletionJobs.push({ job_id: jobId, subject_user_id: 7, requested_by: 8,
    state: 'running', completed_at: null });
  f.state.deletionSteps.push(...evidenceInternals.deletionSteps(jobId));
  const job = f.state.deletionJobs.find(row => row.job_id === jobId);
  job.state = 'completed'; job.completed_at = '2026-09-16T14:00:00.000Z';
  for (const step of f.state.deletionSteps) step.state = 'completed';
  const user = f.state.users.find(row => row.id === 7);
  user.is_active = 0;
  user.username = `deleted-${jobId}`; user.email = `deleted-${jobId}@invalid.local`;
  f.state.sessions = f.state.sessions.filter(row => row.user_id !== 7);
  f.state.requests.filter(row => row.user_id === 7).forEach(row => { row.user_text = null; row.response_json = null; });
  f.state.turns = f.state.turns.filter(row => row.user_id !== 7);
  f.state.packets = [];
  f.state.userState = f.state.userState.filter(row => row.user_id !== 7);
  for (const judgment of f.state.judgments.filter(row => row.user_id === 7)) {
    judgment.result_json = judgment.verdict === null ? null : { deleted: true }; judgment.result_digest = null;
  }
  const verify = () => evidence.verifyDeletion({ ownerId: 7, jobId, administratorId: 8,
    receipts: [{ ownerId: 7, requestId: ids.ownerRequestPositive, runId: ids.ownerRunPositive, verified: true, awarded: true }] });
  if (mutateTimestamp) {
    f.state.judgments.find(row => row.user_id === 7).created_at = new Date('2026-09-16T14:00:00.000Z');
    await assert.rejects(verify, error => error.code === 'ERR_ASSERTION'
      && error.actual === '2026-09-16T14:00:00.000Z'
      && error.expected === '2026-09-16T13:59:00.000Z');
  } else {
    const result = await verify();
    assert.deepEqual(result, { ownerId: 7, jobId, verified: true, ownerResourcesRetired: true,
      siblingPreserved: true, subjectAnonymized: true, subjectSessionsRevoked: true,
      judgmentReceiptsPreserved: true, conversationContentRemoved: true });
  }
  }
});
