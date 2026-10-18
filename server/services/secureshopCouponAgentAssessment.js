'use strict';

const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { createCouponAgentOriginalReader } = require('./secureshopCouponAgentOriginalReader');
const { originalSelection } = require('./secureshopCouponAgentProposalService');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createTurnAdmission } = require('./secureshopTurnAdmission');
const { createAssessmentPersonaCapture } = require('./secureshopAssessmentPersonaCapture');
const { readSecureShopAssessmentEligibility } = require('./secureshopAssessmentEligibility');
const { createObjectiveCompletionService } = require('./secureshopObjectiveCompletionService');
const { prepareJudgeInput } = require('../agent-runtime/objectiveJudge');
const { projectJudgment } = require('../agent-runtime/dpiSemanticCreditPolicy');
const { hash: isolatedHash } = require('../../sidecars/analytics-sql-target/contract');
const { OBJECTIVE, RUBRIC, RUBRIC_V2, buildCouponAgentCandidate,
  createCouponAgentJudgeGuard } = require('./secureshopCouponAgentEvidence');

const WORKSHOP = 'secureshop_agent_security';
const PURPOSE = 'persona_inbox';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const unavailable = () => Object.assign(new Error('Coupon assessment unavailable'),
  { code: 'COUPON_AGENT_ASSESSMENT_UNAVAILABLE' });
const ineligible = () => Object.freeze({ completed: false, status: 'ineligible',
  modelEvaluated: false });
const unconfirmed = () => Object.freeze({ completed: false, status: 'unconfirmed',
  modelEvaluated: false });
const SHA = /^[a-f0-9]{64}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
const rubricForVersion = version => version === RUBRIC.version ? RUBRIC
  : version === RUBRIC_V2.version ? RUBRIC_V2 : null;
const assessmentMessage = (ids, personaSession) => JSON.stringify([OBJECTIVE,
  ids.proposalId, ids.sessionId, ids.requestId, personaSession.sessionId,
  personaSession.authorityVersion]);

function storedJudgment(row) {
  if (!row || !UUID.test(row.evaluation_id || '')
    || !SHA.test(row.result_digest || '')
    || !row.result_json || typeof row.result_json !== 'object'
    || Array.isArray(row.result_json)
    || !['pass','fail','inconclusive','unavailable'].includes(row.verdict)
    || row.result_json.verdict !== row.verdict) throw unavailable();
  if (row.result_serialized !== null && row.result_serialized !== undefined) {
    if (typeof row.result_serialized !== 'string'
      || digest(row.result_serialized) !== row.result_digest
      || !equal(JSON.parse(row.result_serialized), row.result_json))
      throw unavailable();
  }
  return Object.freeze({ completed: ['awarded','already_complete'].includes(row.disposition),
    judgment: Object.freeze({ ...projectJudgment({ disposition: row.disposition,
      result: row.result_json }), evaluationId: row.evaluation_id,
      canRetry: false }) });
}

function createCouponAgentAssessment({ identityPool, launches, conversationRepository,
  coordinator, journal, personaAuthority, personaBindings, receipts, progress,
  judge, qualifyModel,
  captureCurrent, bindingRepository, readConfirmedCoupon,
  readCouponReceipt } = {}) {
  for (const method of [identityPool?.query, launches?.assertCurrent,
    conversationRepository?.getMessages, conversationRepository?.getTraceEvents,
    conversationRepository?.getBoundSession,
    conversationRepository?.acquireBoundSession,
    conversationRepository?.activateBoundSession,
    coordinator?.run, journal?.readBoundRequest,
    journal?.readCouponAgentAssessment, personaAuthority?.capture,
    personaBindings?.capture,
    judge, qualifyModel, captureCurrent, bindingRepository?.read,
    readConfirmedCoupon, readCouponReceipt])
    if (typeof method !== 'function') throw unavailable();
  const originalReader = createCouponAgentOriginalReader({
    current: async holder => holder.state,
    bindingRepository, journal, conversations: conversationRepository });
  const conversations = createBoundConversationService({
    conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  const admission = createTurnAdmission({ journal });
  const capture = createAssessmentPersonaCapture(personaBindings);
  const scopes = new WeakMap();
  const completion = createObjectiveCompletionService({ receipts, progress,
    judge: createCouponAgentJudgeGuard(judge, qualifyModel), ...capture.options,
    captureInstanceScope: execution => {
      const scope = scopes.get(execution);
      if (!scope) throw unavailable();
      return scope;
    } });
  const enabled = async scope => (await readSecureShopAssessmentEligibility(
    identityPool, scope, [OBJECTIVE])).includes(OBJECTIVE);

  async function current(context, signal) {
    signal?.throwIfAborted();
    const state = await captureCurrent(context);
    const binding = createConversationBinding(state.scope, state.persona);
    if (binding.role !== 'customer' || typeof state.check !== 'function'
      || state.mode?.snapshot?.featureId !== 'customer_chat'
      || state.couponMode?.snapshot?.featureId !== 'coupons'
      || state.couponMode.snapshot.mode !== 'vuln'
      || !equal(state.mode.snapshot.scope, createLaunchScope(binding))
      || !equal(state.couponMode.snapshot.scope, createLaunchScope(binding))
      || !state.target?.scene?.grantId
      || typeof state.mode.assertCurrent !== 'function'
      || typeof state.couponMode.assertCurrent !== 'function') return null;
    const check = async () => {
      signal?.throwIfAborted();
      await launches.assertCurrent(binding);
      await state.check();
      await state.mode.assertCurrent();
      await state.couponMode.assertCurrent();
      await state.check();
      signal?.throwIfAborted();
    };
    const trusted = Object.freeze({ ...state, scope: binding, check });
    await check();
    return trusted;
  }

  async function evidence(state, ids, signal, evidenceVersion = 1) {
    const { sessionId, requestId, proposalId } = ids;
    const source = await originalReader({ state }, { sessionId, requestId });
    const selected = originalSelection(source, ids, qualifyModel);
    if (selected.proposal.proposalId !== proposalId) throw unavailable();
    await state.check();
    const saved = await readConfirmedCoupon(Object.freeze({
      scope: state.scope, persona: state.persona,
      personaSession: state.personaSession,
      code: selected.proposal.code, operationId: proposalId,
      expectedTarget: Object.freeze({ targetId: state.target.targetId,
        sceneId: state.target.scene.sceneId,
        sceneGeneration: state.target.scene.sceneGeneration,
        grantId: state.target.scene.grantId }),
      customerMode: state.mode, couponMode: state.couponMode,
      checkCurrent: state.check, signal,
    }));
    await state.check();
    if (saved === null) return null;
    if (saved.state !== 'completed' || saved.request?.operationId !== proposalId
      || saved.request.code !== selected.proposal.code) throw unavailable();
    const ownedQuery = await readCouponReceipt(Object.freeze({
      scope: createLaunchScope(state.scope),
      operationId: proposalId,
      requestSha256: isolatedHash({ kind: 'coupon-v1', request: saved.request }),
    }), { signal });
    await state.check();
    if (!ownedQuery) return null;
    return buildCouponAgentCandidate({ binding: state.scope,
      personaSession: state.personaSession, target: state.target,
      customerMode: state.mode, couponMode: state.couponMode,
      sessionId, requestId, source, saved,
      sqlTargetId: ownedQuery.targetId,
      queryReceipt: ownedQuery.receipt, qualifyModel, evidenceVersion });
  }

  async function readOutcome({ scope, persona, personaSession, sessionId,
    requestId, proposalId, signal } = {}) {
    if (![sessionId, requestId, proposalId].every(id => UUID.test(id || '')))
      throw unavailable();
    const state = await current({ scope, persona, personaSession }, signal);
    if (!state || !await enabled(state.scope)) return ineligible();
    await conversations.assertOwned(sessionId, state.scope, persona,
      require('./secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES.customerChat);
    const ids = { sessionId, requestId, proposalId };
    const legacyCandidate = await evidence(state, ids, signal);
    await state.check();
    if (!legacyCandidate) return unconfirmed();
    const row = await journal.readCouponAgentAssessment({
      requestId: proposalId, binding: state.scope });
    await state.check();
    if (!row) return unconfirmed();
    const expected = createTurnRequest({ sessionId: row.session_id,
      requestId: proposalId, binding: state.scope,
      message: assessmentMessage(ids, personaSession) });
    if (row.request_hash !== expected.hash
      || row.request_version !== expected.version) throw unavailable();
    if (row.status !== 'completed') return unconfirmed();
    const result = row.result_json;
    if (equal(result, ineligible())) return ineligible();
    if (!result || typeof result !== 'object' || Array.isArray(result)
      || !equal(Object.keys(result).sort(), ['completed','judgment'])
      || typeof result.completed !== 'boolean'
      || !UUID.test(result.judgment?.evaluationId || '')) throw unavailable();
    const rows = (await identityPool.query(`SELECT j.*,r.child_id,
      to_jsonb(child) AS child_row,m.mode AS live_mode,
      m.generation AS live_generation,m.revision::text AS live_revision,
      e.tenant_id AS current_tenant_id,
      e.principal_id AS current_principal_id,
      s.membership_version::text AS current_membership_version,
      g.generation::text AS live_owner_generation
      FROM secureshop_auth.execution_authority_state e
      JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
      JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
      JOIN secureshop_auth.tenant_modes m
        ON m.tenant_id=e.tenant_id AND m.principal_id=e.principal_id
      JOIN secureshop_auth.assessment_judgments j
        ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
      LEFT JOIN secureshop_auth.assessment_retries r
        ON r.tenant_id=j.tenant_id AND r.principal_id=j.principal_id
          AND r.parent_id=j.evaluation_id
      LEFT JOIN secureshop_auth.assessment_judgments child
        ON child.tenant_id=r.tenant_id AND child.principal_id=r.principal_id
          AND child.evaluation_id=r.child_id
      LEFT JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
      WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1
        AND e.expires_at>clock_timestamp() AND p.shop_user_id=$3
        AND j.evaluation_id=$4 AND j.objective_id=$5 LIMIT 2`,
    [state.scope.platformSessionId, state.scope.platformOwnerId,
      persona.id, result.judgment.evaluationId, OBJECTIVE])).rows;
    await conversations.assertOwned(sessionId, state.scope, persona,
      require('./secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES.customerChat);
    await state.check();
    if (rows.length !== 1) throw unavailable();
    const judgment = rows[0], execution = judgment.execution_json;
    const rubric = rubricForVersion(judgment.rubric_version);
    if (!rubric) throw unavailable();
    const candidate = rubric === RUBRIC ? legacyCandidate
      : await evidence(state, ids, signal, 2);
    await state.check();
    if (!candidate) throw unavailable();
    const packet = prepareJudgeInput({ rubric: { ...rubric, mode: 'vuln' },
      facts: candidate.facts, evidence: candidate.evidence });
    if (packet.evidenceError || !SHA.test(packet.evidenceDigest || ''))
      throw unavailable();
    if (judgment.workshop_key !== WORKSHOP
      || judgment.shop_user_id !== persona.id
      || judgment.objective_id !== OBJECTIVE
      || judgment.family !== packet.rubric.family
      || judgment.scenario !== packet.rubric.scenario
      || judgment.rubric_version !== packet.rubric.version
      || judgment.packet !== packet.packet
      || judgment.evidence_digest !== packet.evidenceDigest
      || judgment.mode !== 'vuln' || judgment.mode !== judgment.live_mode
      || String(judgment.generation) !== String(judgment.live_generation)
      || judgment.mode_stamp !== digest(JSON.stringify([
        'shop-tenant-mode-v1', judgment.tenant_id, judgment.principal_id,
        judgment.live_generation, judgment.live_revision,
        judgment.live_mode]))
      || judgment.owner_key !== JSON.stringify(['SecureShopBoundConversation',
        row.session_id])
      || String(judgment.owner_generation) !== judgment.live_owner_generation
      || execution?.tenantId !== judgment.current_tenant_id
      || execution.principalId !== judgment.current_principal_id
      || execution.membershipVersion !== judgment.current_membership_version
      || !equal(execution.scope, createLaunchScope(state.scope))
      || execution.personaSessionId !== personaSession.sessionId
      || execution.personaAuthorityVersion !== personaSession.authorityVersion
      || execution.role !== persona.role
      || execution.runId !== judgment.run_id) throw unavailable();
    const parent = storedJudgment(judgment);
    if (result.completed !== parent.completed
      || !equal({ ...result.judgment, canRetry: false }, parent.judgment))
      throw unavailable();
    if (!judgment.child_id) return Object.freeze({ ...result, replayed: true });
    const child = judgment.child_row;
    if (!child || child.evaluation_id !== judgment.child_id
      || child.tenant_id !== judgment.tenant_id
      || child.principal_id !== judgment.principal_id
      || child.objective_id !== OBJECTIVE || child.workshop_key !== WORKSHOP
      || child.evidence_digest !== judgment.evidence_digest
      || child.packet !== judgment.packet
      || child.generation !== judgment.generation
      || child.mode !== judgment.mode || child.mode_stamp !== judgment.mode_stamp
      || child.owner_key !== judgment.owner_key
      || String(child.owner_generation) !== String(judgment.owner_generation)
      || !equal({ ...child.execution_json, runId: null },
        { ...execution, runId: null })) throw unavailable();
    if (!child.verdict) return Object.freeze({ ...parent, replayed: true });
    return Object.freeze({ ...storedJudgment(child), replayed: true });
  }

  async function assertRetainedPacket({ packet, scope, persona,
    personaSession, signal } = {}) {
    if (!packet || Object.getPrototypeOf(packet) !== Object.prototype
      || !equal(Object.keys(packet).sort(), ['evidence', 'facts', 'rubric'])
      || !Array.isArray(packet.evidence)
      || packet.rubric?.objectiveId !== OBJECTIVE
      || packet.rubric.mode !== 'vuln') throw unavailable();
    const rubric = rubricForVersion(packet.rubric.version);
    if (!rubric || packet.evidence.length !== (rubric === RUBRIC ? 2 : 4))
      throw unavailable();
    const source = packet.evidence[0];
    if (source?.id !== 'coupon_original'
      || source.source !== 'server_observation') throw unavailable();
    const retained = source.content;
    if (!UUID.test(retained?.sessionId || '')
      || !UUID.test(retained?.requestId || '')
      || !UUID.test(packet.evidence[1]?.content?.request?.operationId || ''))
      throw unavailable();
    const ids = Object.freeze({ sessionId: retained.sessionId,
      requestId: retained.requestId,
      proposalId: packet.evidence[1].content.request.operationId });
    const expectedRubric = prepareJudgeInput({ rubric: { ...rubric, mode: 'vuln' },
      facts: packet.facts, evidence: packet.evidence });
    if (expectedRubric.evidenceError || !equal(packet.rubric, expectedRubric.rubric))
      throw unavailable();
    const guard = createCouponAgentJudgeGuard(async () => true, qualifyModel);
    if (await guard(packet) !== true) throw unavailable();
    const assertCurrent = async () => {
      const state = await current({ scope, persona, personaSession }, signal);
      if (!state || !equal(state.scope, retained.scope)
        || state.persona.id !== retained.personaId
        || state.personaSession.sessionId !== retained.personaSessionId
        || state.personaSession.authorityVersion !== retained.authorityVersion)
        throw unavailable();
      const candidate = await evidence(state, ids, signal,
        rubric === RUBRIC ? 1 : 2);
      await state.check();
      if (!candidate || !equal(candidate.facts, packet.facts)
        || !equal(candidate.evidence, packet.evidence)) throw unavailable();
    };
    await assertCurrent();
    return Object.freeze({ assertCurrent });
  }

  return Object.freeze({ objectiveId: OBJECTIVE, completionService: completion,
    assertRetainedPacket, readOutcome,
    async runAttempt({ scope, persona, personaSession, sessionId, requestId,
      proposalId, signal } = {}) {
      if (![sessionId, requestId, proposalId].every(id => UUID.test(id || '')))
        throw unavailable();
      const state = await current({ scope, persona, personaSession }, signal);
      if (!state || !await enabled(state.scope)) return ineligible();
      // Resolve the original turn, completed local receipt and isolated SQL
      // receipt before claiming any grading turn. No source read can execute SQL.
      const candidate = await evidence(state,
        { sessionId, requestId, proposalId }, signal, 2);
      await state.check();
      if (!candidate) return ineligible();
      const fence = personaAuthority.capture({ scope: state.scope,
        personaId: state.persona.id, role: 'customer',
        sessionId: state.personaSession.sessionId,
        authorityVersion: state.personaSession.authorityVersion });
      await fence.assertRemoteAdmission();
      const actor = capture.prepare(state.scope, fence);
      const assessmentSession = await conversations.create(state.scope,
        state.persona, PURPOSE);
      const message = assessmentMessage({ sessionId, requestId, proposalId },
        state.personaSession);
      let prepared;
      const prepare = async () => {
        await state.check();
        prepared = await admission.prepare({ sessionId: assessmentSession.id,
          requestId: proposalId, binding: state.scope, message });
        return prepared.status === 'completed'
          ? { skip: true, value: prepared.outcome }
          : { skip: false, value: prepared };
      };
      try {
        const outcome = await turns.run(assessmentSession.id, state.scope,
          state.persona, { signal, idempotencyKey: proposalId,
            conversationPurpose: PURPOSE, admit: prepare }, async original => {
            const boundary = { ...original, async check() {
              await original.check(); await state.check();
            } };
            await boundary.check();
            if (!prepared) {
              await prepare();
              if (prepared.status === 'completed') return prepared.outcome;
            }
            return admission.execute(prepared, boundary, async () => {
              const execution = Object.freeze({ runId: boundary.identity.runId,
                ownerKey: boundary.identity.ownerKey,
                durableGeneration: boundary.identity.durableGeneration,
                signal: boundary.signal, check: boundary.check });
              scopes.set(execution, state.scope);
              capture.bind(execution, actor);
              const attempt = await completion.beginAttempt({
                userId: state.scope.platformOwnerId, workshopKey: WORKSHOP,
                objectiveId: OBJECTIVE, execution });
              await boundary.check();
              if (attempt.mode !== 'vuln' || !await enabled(state.scope))
                return ineligible();
              const verified = await evidence(state,
                { sessionId, requestId, proposalId }, signal, 2);
              await boundary.check();
              if (!verified || !equal(verified, candidate)) return ineligible();
              const result = await completion.evaluate({
                userId: state.scope.platformOwnerId, workshopKey: WORKSHOP,
                objectiveId: OBJECTIVE, evaluationId: randomUUID(), execution,
                attempt, rubric: { ...RUBRIC_V2, mode: attempt.mode },
                facts: candidate.facts, evidence: candidate.evidence });
              await boundary.check();
              return { completed: result.completed === true,
                judgment: result.judgment };
            }, fence);
          });
        await state.check();
        if (outcome.result?.status === 'ineligible') return ineligible();
        return Object.freeze({ ...outcome.result,
          replayed: outcome.replayed === true });
      } catch (error) {
        await admission.abandon(prepared);
        throw error;
      }
    },
  });
}

module.exports = { createCouponAgentAssessment };
