'use strict';
const { isDeepStrictEqual: equal } = require('node:util');
const { normalize } = require('../database/postgres/secureshopBoundMailRepository');
const scene = require('./secureshopMailSceneBinding');
const { captureFeatureMode, projectFeatureMode } = require('./secureshopFeatureModeAuthority');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { validateMailChatResult } = require('./secureshopRoleMailRead');
const PURPOSE = 'secureshop_mail_summary';
const fail = () => Object.assign(Error('Mail inline production unavailable'), { code: 'MAIL_INLINE_UNAVAILABLE' });
const FUNCTIONS = [
  'save_bound_mail_inline(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid,jsonb,uuid,uuid,bytea,text,text,bytea)',
  'read_bound_mail_inline_binding(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,bigint,bytea,integer)',
  'record_bound_mail_inline_http_invocation(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,uuid,uuid,text,bigint,uuid,text,text,uuid,bytea,bytea,uuid,uuid,bigint,bytea,bigint,integer,uuid,bytea,text,text,bytea,bytea,bytea,bytea,bytea)',
  'read_bound_mail_inline_http_invocation(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,uuid)',
];
async function assertMailInlineSchema(pool) {
  const functions = (await pool.query(`SELECT name,p.oid IS NOT NULL AND p.prosecdef
    AND has_function_privilege(current_user,p.oid,'EXECUTE')
    AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
      WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS ready
    FROM unnest($1::text[]) name LEFT JOIN pg_proc p ON p.oid=to_regprocedure('secureshop_agents.'||name)`, [FUNCTIONS])).rows;
  if (functions.length !== FUNCTIONS.length || new Set(functions.map(row => row.name)).size !== FUNCTIONS.length
    || functions.some(row => !FUNCTIONS.includes(row.name) || row.ready !== true)) throw fail();
  const rows = (await pool.query(`SELECT
    to_regclass('secureshop_agents.lab_mail_inline_bindings') IS NOT NULL
    AND NOT has_table_privilege(current_user,'secureshop_agents.lab_mail_inline_bindings','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') AS binding_private,
    to_regclass('secureshop_agents.lab_mail_inline_http_invocations') IS NOT NULL
    AND NOT has_table_privilege(current_user,'secureshop_agents.lab_mail_inline_http_invocations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') AS invocation_private,
    EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='secureshop_agents.agent_sessions'::regclass
      AND conname='agent_sessions_conversation_purpose_shape'
      AND position('secureshop_mail_summary' in pg_get_constraintdef(oid))>0) AS purpose_ready`)).rows;
  if (rows.length !== 1 || Object.keys(rows[0]).length !== 3 || Object.values(rows[0]).some(value => value !== true)) throw fail();
  return true;
}
function coordinates(target) {
  const held = scene.productScene(target);
  if (!held) throw fail();
  return { targetId: target.targetId, scene: held.scene };
}
function createMailInlineProduction({ identityPool, agentsPool, assessmentDependencies, shared, mailRepository, mailScenes, resolveTarget, resetComposition,
  listPersonas, provider, promptPolicyRepository, toolPolicyRepository, modeAuthority,
  authenticatePersona, assertActorAvailable, mode = 'vuln' } = {}) {
  if (!mailScenes?.readRetained || !modeAuthority || !shared?.personaAuthority
    || typeof resetComposition?.registerPersonaInboxTransportCleanup !== 'function'
    || typeof resetComposition?.personaInbox?.repository?.readCleanupReceipt !== 'function') throw fail();
  const { personaAuthority, launches } = shared;
  const bindingRepository = require('../database/postgres/secureshopMailInlineBindingRepository')
    .createSecureShopMailInlineBindingRepository({ pool: agentsPool, personaAuthority,
      verifyPendingReservation: (raw, reservation) => targetPool.assertPendingReservation(raw, reservation) });
  // Absence of durable recording is a readiness failure, never an in-memory substitute.
  if (typeof bindingRepository.recordInvocation !== 'function' || typeof bindingRepository.readInvocation !== 'function') throw fail();
  const targetPool = require('./secureshopMailInlineTargetPool').createSecureShopMailInlineTargetPool({
    verifyBound: (raw, selected) => bindingRepository.readBound(raw, selected),
    authorizeRetirement: (targetId, authority) => {
      if (authority.scope.targetId !== targetId) throw fail();
      return resetComposition.personaInbox.repository.readCleanupReceipt(authority.scope,
        { operationId: authority.operationId });
    } });
  let closed = false;
  const activeSources = new Map();
  const key = raw => JSON.stringify([raw.scope, raw.persona, raw.personaSession, raw.operationId]);
  function personaFence(raw) {
    const expected = { ...raw.scope, personaId: raw.persona.id, role: raw.persona.role, ...raw.personaSession };
    const fence = personaAuthority.capture({ scope: raw.scope, personaId: raw.persona.id,
      role: raw.persona.role, ...raw.personaSession });
    if (!fence?.binding || Object.keys(expected).some(k => expected[k] !== fence.binding[k])) throw fail();
    return fence;
  }
  async function checkRaw(raw) {
    if (closed) throw fail();
    await launches.assertCurrent(raw.scope); await personaFence(raw).assertRemoteAdmission();
    const current = await mailScenes.readRetained(raw.scope);
    if (!equal(coordinates(current), coordinates(raw.target || raw))) throw fail();
  }
  async function admit(context, requestId, { fresh, signal } = {}) {
    signal?.throwIfAborted();
    if (closed || context.persona.role !== 'merchant') throw fail();
    const token = await captureFeatureMode(modeAuthority, context.scope, 'mail', mode);
    const target = fresh ? await resolveTarget(context) : await mailScenes.readRetained(context.scope);
    const binding = normalize({ ...context, target, targetId: target.targetId,
      mode: token.snapshot.mode, operationId: requestId });
    const check = async () => { signal?.throwIfAborted(); await token.assertCurrent();
      await checkRaw(binding); await token.assertCurrent(); signal?.throwIfAborted(); };
    await check(); return { binding, check, executionMode: token.snapshot };
  }
  async function resolveSelected(raw, selectors) {
    await checkRaw(raw);
    const readRaw = scene.copy(raw, { ...raw, operationId: selectors.readOperationId });
    const originalRead = await mailRepository.recover(readRaw); await checkRaw(raw);
    if (originalRead?.found !== true || originalRead.action !== 'read'
      || originalRead.operationId !== selectors.readOperationId || originalRead.receipt?.userId !== raw.persona.id)
      throw fail();
    const projected = await mailRepository.projectRead(readRaw, { messageId: selectors.messageId });
    await checkRaw(raw);
    const actors = await listPersonas(raw.scope); await checkRaw(raw);
    const actor = actors.filter(value => value.id === raw.persona.id && value.role === 'merchant');
    if (actor.length !== 1 || projected.kind !== 'detail' || !projected.message || projected.message.oversized
      || projected.readOperationId !== selectors.readOperationId
      || originalRead.receipt.messages?.filter(row => row.id === selectors.messageId
        && row.sha256 === projected.message.sha256).length !== 1) throw fail();
    const token = await captureFeatureMode(modeAuthority, raw.scope, 'mail', raw.mode);
    if (token.snapshot.mode !== raw.mode) throw fail();
    const selected = validateMailChatResult({ version: 1, kind: 'detail', readOperationId: selectors.readOperationId,
      mailModeCapability: projectFeatureMode(token), receiptSha256: projected.receiptSha256,
      recipient: { id: actor[0].id, username: actor[0].username, email: actor[0].email, role: actor[0].role },
      messageId: projected.message.id, messageSha256: projected.message.sha256,
      status: 'complete', message: projected.message });
    const binding = await bindingRepository.readBound(raw, { messageId: selected.messageId,
      messageSha256: selected.messageSha256, recipientId: selected.recipient.id });
    if (!binding || binding.threadId !== selected.message.threadId) throw fail();
    await token.assertCurrent(); await checkRaw(raw);
    return { selected, originalRead: projected, binding };
  }
  async function readSaved({ binding: raw, requestId, purpose }) {
    if (purpose !== PURPOSE || requestId !== raw.operationId) throw fail();
    await checkRaw(raw);
    const row = await scene.withLease(raw, () => personaFence(raw).withPersonaEffect(async client => {
      await client.query("SET LOCAL statement_timeout='3000ms'");
      await client.query("SET LOCAL lock_timeout='3000ms'"); await scene.assertGrant(client, raw);
      const s = raw.scope;
      const rows = (await client.query(`SELECT tr.session_id,tr.request_hash,tr.request_version,tr.status,tr.result_json
        FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
        WHERE tr.request_id=$1 AND s.conversation_purpose=$2 AND s.authority_mode='launch_bound' AND s.binding_state='active'
        AND s.platform_launch_id=$3 AND s.platform_scenario_id=$4 AND s.platform_launch_generation=$5
        AND s.original_platform_owner_id=$6 AND s.original_platform_session_id=$7 AND s.user_id=$8 AND s.role=$9`,
      [requestId, PURPOSE, s.launchId, s.scenarioId, s.generation, s.platformOwnerId, s.platformSessionId,
        raw.persona.id, raw.persona.role])).rows;
      await scene.assertGrant(client, raw);
      if (rows.length > 1) throw fail(); return rows[0] || null;
    }));
    await checkRaw(raw); if (!row) return null;
    if (row.status !== 'completed') throw fail();
    const result = row.result_json, m = result?.taskMetadata?.mailSummary;
    if (m?.version !== 1 || m.purpose !== PURPOSE || m.requestId !== requestId || m.targetId !== raw.targetId
      || !['vuln', 'fixed'].includes(m.mode) || result.stopReason !== 'end_turn') throw fail();
    const request = createTurnRequest({ sessionId: row.session_id, requestId, version: row.request_version,
      binding: createConversationBinding(raw.scope, raw.persona), message:
        require('./secureshopBoundMailSummaryGraph').summaryRequestMessage({ ...raw, mode: m.mode }) });
    if (request.hash !== row.request_hash) throw fail();
    const source = await resolveSelected(raw, m.selected);
    if (source.selected.messageSha256 !== m.selected.messageSha256
      || source.selected.recipient.id !== m.selected.recipientId
      || source.selected.receiptSha256 !== m.selected.receiptSha256
      || source.selected.message.threadId !== m.selected.threadId
      || !equal(source.originalRead, m.originalRead)) throw fail();
    const stored = await bindingRepository.readInvocation(raw, { summaryRequestId: requestId });
    if (!equal(stored, m.httpRecord) || !equal(stored?.binding, source.binding)
      || stored?.sessionId !== row.session_id || !equal(stored.targetReceipt, m.targetReceipt)) throw fail();
    await checkRaw(raw); return { ...result, sessionId: row.session_id,
      savedRequest: { status: row.status, requestVersion: row.request_version, requestHash: row.request_hash,
        message: require('./secureshopBoundMailSummaryGraph').summaryRequestMessage({ ...raw, mode: m.mode }) } };
  }
  const adapter = require('./secureshopMailInlineHttpAdapter').createMailInlineHttpAdapter({ targetPool,
    checkCurrent: checkRaw,
    resolveSource: async raw => {
      const selected = activeSources.get(key(raw)); if (!selected) throw fail();
      const source = await resolveSelected(raw, selected);
      if (!equal(source.selected, selected)) throw fail();
      return { selected: source.selected, binding: source.binding };
    },
    recordInvocation: (raw, record) => bindingRepository.recordInvocation(raw, record) });
  const graph = require('./secureshopBoundMailSummaryGraph').createBoundMailSummaryGraph({ ...shared,
    provider, modeAuthority, promptPolicyRepository, toolPolicyRepository, assertActorAvailable,
    inlineAdapter: adapter, readSaved,
    readSelected: async ({ binding, selection }) => {
      const source = await resolveSelected(binding, selection);
      return { selected: source.selected, originalRead: source.originalRead };
    } });
  const application = require('./secureshopMailInlineApplication').createMailInlineApplication({ admit,
    mailRepository, bindingRepository, targetPool, listPersonas, resolveSelected,
    graph: { read: graph.read, async run(raw, options) {
      const id = key(raw); if (activeSources.has(id)) throw fail();
      activeSources.set(id, options.selected);
      try { return await graph.run(raw, options); } finally { activeSources.delete(id); }
    } } });
  const current = (context, { requestId, signal } = {}) => admit(context, requestId, { fresh: false, signal });
  async function readSavedSource(context, { sessionId, requestId, signal } = {}) {
    const state = await current(context, { requestId, signal });
    const turn = await readSaved({ binding: state.binding, requestId, purpose: PURPOSE });
    if (!turn || turn.sessionId !== sessionId) throw fail();
    const m = turn.taskMetadata.mailSummary;
    // Historical summaries remain readable; grading requires their exact
    // original feature epoch, including a vulnerable/fixed/vulnerable cycle.
    if (!equal(m.executionMode, state.executionMode) || !equal(m.personaSession, state.binding.personaSession)) throw fail();
    const source = await resolveSelected(state.binding, m.selected);
    await state.check();
    return { ...state, turn, savedRequest: turn.savedRequest, selected: source.selected, originalRead: source.originalRead,
      inlineBinding: source.binding, httpRecord: m.httpRecord, targetReceipt: m.targetReceipt };
  }
  const evidenceRepository = require('../database/postgres/secureshopMailInlineEvidenceRepository')
    .createMailInlineEvidenceRepository({ identityPool, conversationRepository: shared.conversationRepository, readSavedSource });
  const assessment = require('./secureshopMailInlineAssessment').createMailInlineAssessment({
    ...assessmentDependencies, ...shared, identityPool, agentsPool, current,
    readSource: (context, input) => evidenceRepository.readSource(context, input),
    qualifyModelTrace: require('./secureshopModelQualification').createSecureShopModelQualifier(provider) });
  const router = require('../routes/secureshop/boundMailInline').createBoundMailInlineRouter({ application, assessment, authenticatePersona });
  const unregister = resetComposition.registerPersonaInboxTransportCleanup((scope, { operationId }) =>
    targetPool.retireTarget(scope.targetId, { scope, operationId }));
  return Object.freeze({ application, router, assessment, current, readSavedSource,
    async close() { closed = true; await targetPool.close(); unregister(); } });
}
module.exports = { createMailInlineProduction, assertMailInlineSchema };
