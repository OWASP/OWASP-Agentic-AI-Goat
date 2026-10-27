'use strict';

const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { projectJudgment } = require('../agent-runtime/dpiSemanticCreditPolicy');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createTurnAdmission } = require('./secureshopTurnAdmission');
const { captureFeatureMode } = require('./secureshopFeatureModeAuthority');
const { createAssessmentPersonaCapture } = require('./secureshopAssessmentPersonaCapture');
const { readSecureShopAssessmentEligibility } = require('./secureshopAssessmentEligibility');
const { createObjectiveCompletionService } = require('./secureshopObjectiveCompletionService');
const { IDOR_LESSON_OBJECTIVES, IDOR_LESSON_VERSION,
  IDOR_LESSON_ORDER_VERSION,
  IDOR_LESSON_PREVIOUS_VERSION,
  IDOR_LESSON_LEGACY_VERSION, idorLessonRubric,
  buildIdorLessonCandidate, createIdorLessonJudgeGuard } =
  require('./secureshopIdorLessonEvidence');
const { prepareJudgeInput } = require('../agent-runtime/objectiveJudge');

const WORKSHOP = 'secureshop_agent_security';
// The original purpose is intentionally absent from the current allowlist;
// mounting this service requires a separately reviewed dedicated graph.
const ORIGINAL_PURPOSE = 'secureshop_idor_lesson';
const ASSESSMENT_PURPOSE = 'persona_inbox';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const unavailable = () => Object.assign(new Error('Isolated access-control assessment unavailable'),
  { code: 'IDOR_LESSON_ASSESSMENT_UNAVAILABLE' });
const ineligible = () => Object.freeze({ completed: false, status: 'ineligible',
  modelEvaluated: false });
const unconfirmed = () => Object.freeze({ completed: false, status: 'unconfirmed',
  modelEvaluated: false });
const SHA = /^[a-f0-9]{64}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
function storedJudgment(row) {
  if (!row || !UUID.test(row.evaluation_id || '') || !SHA.test(row.result_digest || '')
      || !row.result_json || typeof row.result_json !== 'object'
      || Array.isArray(row.result_json)
      || !['pass','fail','inconclusive','unavailable'].includes(row.verdict)
      || row.result_json.verdict !== row.verdict) throw unavailable();
  if (row.result_serialized !== null && row.result_serialized !== undefined) {
    if (typeof row.result_serialized !== 'string'
        || digest(row.result_serialized) !== row.result_digest
        || !equal(JSON.parse(row.result_serialized), row.result_json)) throw unavailable();
  }
  return { completed: ['awarded','already_complete'].includes(row.disposition),
    judgment: { ...projectJudgment({ disposition: row.disposition,
      result: row.result_json }), evaluationId: row.evaluation_id, canRetry: false } };
}

function createIdorLessonAssessment({ identityPool, launches, conversationRepository,
  coordinator, journal, personaAuthority, personaBindings, scenes,
  lessonRepository, receipts, progress, judge, qualifyModel, modeAuthority, assessmentReleaseAdmission } = {}) {
  for (const fn of [identityPool?.query, launches?.assertCurrent,
    conversationRepository?.getTraceEvents, journal?.readIdorLessonRequest,
    journal?.readIdorLessonAssessment,
    coordinator?.run, personaAuthority?.capture, personaBindings?.capture,
    scenes?.readExisting, lessonRepository?.readBirth, lessonRepository?.readSaved,
    judge, qualifyModel]) if (typeof fn !== 'function') throw unavailable();
  if (typeof modeAuthority?.capture !== 'function'
      || typeof modeAuthority.assertToken !== 'function') throw unavailable();
  const conversations = createBoundConversationService({ conversations: conversationRepository,
    launches });
  const turns = createBoundTurns({ conversations, coordinator });
  const admission = createTurnAdmission({ journal });
  const capture = createAssessmentPersonaCapture(personaBindings), scopes = new WeakMap();
  const completion = createObjectiveCompletionService({ receipts, progress,
    judge: createIdorLessonJudgeGuard(judge, qualifyModel), ...capture.options,
    captureInstanceScope: execution => {
      const scope = scopes.get(execution);
      if (!scope) throw unavailable();
      return scope;
    } });
  const enabled = async (scope, objectiveId) =>
    (await readSecureShopAssessmentEligibility(identityPool, scope,
      [objectiveId], assessmentReleaseAdmission)).includes(objectiveId);
  async function readOutcome({ scope, persona, personaSession, sessionId, requestId,
    signal } = {}) {
    if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')
        || !UUID.test(personaSession?.sessionId || '')
        || !/^[1-9]\d*$/.test(personaSession?.authorityVersion || '')) throw unavailable();
    const binding = createConversationBinding(scope, persona);
    if (binding.role !== 'customer') throw unavailable();
    const fence = personaAuthority.capture({ scope: binding,
      personaId: binding.shopUserId, role: binding.role, ...personaSession });
    const modeToken = await captureFeatureMode(modeAuthority, binding, 'customer_idor');
    const scene = await scenes.readExisting(binding);
    if (!scene?.scene) throw unavailable();
    const check = async () => {
      signal?.throwIfAborted();
      await launches.assertCurrent(binding); await modeToken.assertCurrent();
      await fence.assertRemoteAdmission();
      const current = await scenes.readExisting(binding);
      if (!current || current.targetId !== scene.targetId
          || !equal(current.scene, scene.scene)) throw unavailable();
      await fence.assertRemoteAdmission(); signal?.throwIfAborted();
    };
    await check();
    await conversations.assertOwned(sessionId, binding, persona, ORIGINAL_PURPOSE);
    const original = await journal.readIdorLessonRequest({ sessionId, requestId,
      binding, purpose: ORIGINAL_PURPOSE });
    await check();
    if (original?.status !== 'completed') return unconfirmed();
    const meta = original.result_json?.taskMetadata?.idorLesson;
    if (!meta || !Object.hasOwn(IDOR_LESSON_OBJECTIVES, meta.action)
        || modeToken.snapshot.mode !== 'vuln') return ineligible();
    if (!UUID.test(meta.operationId || '') || !equal(meta.mode, modeToken.snapshot)
        || meta.personaSessionId !== personaSession.sessionId
        || meta.authorityVersion !== personaSession.authorityVersion
        || meta.sceneId !== scene.scene.sceneId
        || meta.sceneGeneration !== scene.scene.sceneGeneration
        || meta.grantId !== scene.scene.grantId || meta.targetId !== scene.targetId)
      throw unavailable();
    const receipt = await lessonRepository.readSaved({ scope: binding, persona,
      personaSession, retainedScene: scene, modeToken,
      operationId: meta.operationId, signal });
    if (receipt?.operationId !== meta.operationId
        || receipt.action !== meta.action || !equal(receipt.mode, modeToken.snapshot))
      throw unavailable();
    const [traces, birth] = await Promise.all([
      conversationRepository.getTraceEvents(sessionId, binding,
        meta.traceEventIds, ORIGINAL_PURPOSE),
      lessonRepository.readBirth({ scope: binding, persona, personaSession,
        retainedScene: scene, signal }),
    ]);
    const candidateInput = { binding, personaSession,
      retainedScene: scene, sessionId, requestId,
      requestHash: original.request_hash, requestVersion: original.request_version,
      turn: original.result_json, traces, birth, receipt,
      mode: modeToken.snapshot, qualifyModel };
    const currentCandidate = buildIdorLessonCandidate(candidateInput);
    const historicalV3Candidate = meta.action === 'order_status'
      ? buildIdorLessonCandidate({ ...candidateInput,
        evidenceVersion: IDOR_LESSON_VERSION }) : currentCandidate;
    const previousCandidate = buildIdorLessonCandidate({ ...candidateInput,
      evidenceVersion: IDOR_LESSON_PREVIOUS_VERSION });
    const legacyCandidate = buildIdorLessonCandidate({ ...candidateInput,
      evidenceVersion: IDOR_LESSON_LEGACY_VERSION });
    await conversations.assertOwned(sessionId, binding, persona, ORIGINAL_PURPOSE);
    await check();
    if (!currentCandidate || !historicalV3Candidate || !previousCandidate || !legacyCandidate
        || currentCandidate.objectiveId !== IDOR_LESSON_OBJECTIVES[meta.action]
        || historicalV3Candidate.objectiveId !== currentCandidate.objectiveId
        || previousCandidate.objectiveId !== currentCandidate.objectiveId
        || legacyCandidate.objectiveId !== currentCandidate.objectiveId)
      return ineligible();
    const row = await journal.readIdorLessonAssessment({ requestId: meta.operationId,
      binding });
    await check();
    if (!row) return unconfirmed();
    const message = JSON.stringify([IDOR_LESSON_OBJECTIVES[meta.action],
      meta.operationId, sessionId, requestId, personaSession.sessionId,
      personaSession.authorityVersion]);
    let expected;
    try { expected = createTurnRequest({ sessionId: row.session_id,
      requestId: meta.operationId, binding, message }); } catch { throw unavailable(); }
    if (row.request_hash !== expected.hash || row.request_version !== expected.version)
      throw unavailable();
    if (row.status !== 'completed') return unconfirmed();
    const result = row.result_json;
    if (equal(result, ineligible())) return ineligible();
    if (!result || typeof result !== 'object' || Array.isArray(result)
        || !equal(Object.keys(result).sort(), ['completed','judgment'])
        || typeof result.completed !== 'boolean' || !result.judgment
        || typeof result.judgment !== 'object' || Array.isArray(result.judgment)
        || !UUID.test(result.judgment.evaluationId || '')) throw unavailable();
    const objectiveId = IDOR_LESSON_OBJECTIVES[meta.action];
    const rows = (await identityPool.query(`SELECT j.*,r.child_id,
      to_jsonb(child) AS child_row, m.mode AS live_mode,
      m.generation AS live_generation,
      m.revision::text AS live_revision,
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
    [binding.platformSessionId, binding.platformOwnerId, persona.id,
      result.judgment.evaluationId, objectiveId])).rows;
    await conversations.assertOwned(sessionId, binding, persona, ORIGINAL_PURPOSE);
    await check();
    if (rows.length !== 1) throw unavailable();
    const judgment = rows[0], execution = judgment.execution_json;
    const evidenceVersion = judgment.rubric_version;
    if (evidenceVersion !== IDOR_LESSON_VERSION
        && !(meta.action === 'order_status'
          && evidenceVersion === IDOR_LESSON_ORDER_VERSION)
        && evidenceVersion !== IDOR_LESSON_PREVIOUS_VERSION
        && evidenceVersion !== IDOR_LESSON_LEGACY_VERSION) throw unavailable();
    const candidate = evidenceVersion === IDOR_LESSON_ORDER_VERSION
      ? currentCandidate : evidenceVersion === IDOR_LESSON_VERSION
        ? historicalV3Candidate : evidenceVersion === IDOR_LESSON_PREVIOUS_VERSION
        ? previousCandidate : legacyCandidate;
    const packet = prepareJudgeInput({ rubric: {
      ...idorLessonRubric(meta.action, evidenceVersion), mode: 'vuln' },
    facts: candidate.facts, evidence: candidate.evidence });
    if (packet.evidenceError || !SHA.test(packet.evidenceDigest || ''))
      throw unavailable();
    if (judgment.workshop_key !== WORKSHOP || judgment.shop_user_id !== persona.id
        || judgment.objective_id !== objectiveId
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
        || judgment.owner_key !== JSON.stringify(['SecureShopBoundConversation', row.session_id])
        || String(judgment.owner_generation) !== judgment.live_owner_generation
        || execution?.tenantId !== judgment.current_tenant_id
        || execution.principalId !== judgment.current_principal_id
        || execution.membershipVersion !== judgment.current_membership_version
        || !equal(execution.scope, createLaunchScope(binding))
        || execution.personaSessionId !== personaSession.sessionId
        || execution.personaAuthorityVersion !== personaSession.authorityVersion
        || execution.role !== persona.role
        || execution.runId !== judgment.run_id
        || !UUID.test(judgment.evaluation_id || '')) throw unavailable();
    const parent = storedJudgment(judgment);
    if (!equal(result.completed, parent.completed)
        || !equal({ ...result.judgment, canRetry: false }, parent.judgment))
      throw unavailable();
    if (!judgment.child_id) return Object.freeze({ ...result, replayed: true });
    const child = judgment.child_row;
    if (!child || child.evaluation_id !== judgment.child_id
        || child.tenant_id !== judgment.tenant_id
        || child.principal_id !== judgment.principal_id
        || child.objective_id !== objectiveId || child.workshop_key !== WORKSHOP
        || child.evidence_digest !== judgment.evidence_digest
        || !equal(child.packet, judgment.packet)
        || child.generation !== judgment.generation || child.mode !== judgment.mode
        || child.mode_stamp !== judgment.mode_stamp
        || child.owner_key !== judgment.owner_key
        || String(child.owner_generation) !== String(judgment.owner_generation)
        || !equal({ ...child.execution_json, runId: null },
          { ...execution, runId: null })) throw unavailable();
    if (!child.verdict) return Object.freeze({ ...parent,
      judgment: Object.freeze(parent.judgment), replayed: true });
    const recovered = storedJudgment(child);
    return Object.freeze({ ...recovered,
      judgment: Object.freeze(recovered.judgment), replayed: true });
  }
  return Object.freeze({ completionService: completion,
    readOutcome,
    async runAttempt({ scope, persona, personaSession, sessionId, requestId, signal } = {}) {
      if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')
          || !UUID.test(personaSession?.sessionId || '')
          || !/^[1-9]\d*$/.test(personaSession?.authorityVersion || '')) throw unavailable();
      const binding = createConversationBinding(scope, persona);
      if (binding.role !== 'customer') throw unavailable();
      const fence = personaAuthority.capture({ scope: binding,
        personaId: binding.shopUserId, role: binding.role, ...personaSession });
      const modeToken = await captureFeatureMode(modeAuthority, binding, 'customer_idor');
      const retainedScene = await scenes.readExisting(binding);
      if (!retainedScene?.scene) throw unavailable();
      const check = async () => {
        signal?.throwIfAborted();
        await launches.assertCurrent(binding);
        await modeToken.assertCurrent();
        await fence.assertRemoteAdmission();
        const current = await scenes.readExisting(binding);
        if (!current || current.targetId !== retainedScene.targetId
            || !equal(current.scene, retainedScene.scene)) throw unavailable();
        await fence.assertRemoteAdmission();
        signal?.throwIfAborted();
      };
      await check();
      await conversations.assertOwned(sessionId, binding, persona, ORIGINAL_PURPOSE);
      const original = await journal.readIdorLessonRequest({ sessionId, requestId,
        binding, purpose: ORIGINAL_PURPOSE });
      const meta = original?.result_json?.taskMetadata?.idorLesson;
      if (original?.status !== 'completed' || original.request_version !== 1
          || !meta || !Object.hasOwn(IDOR_LESSON_OBJECTIVES, meta.action)) return ineligible();
      const objectiveId = IDOR_LESSON_OBJECTIVES[meta.action];
      if (modeToken.snapshot.mode !== 'vuln'
          || !await enabled(binding, objectiveId)) return ineligible();
      if (!UUID.test(meta.operationId || '') || !Array.isArray(meta.traceEventIds)
          || meta.traceEventIds.length < 3 || meta.traceEventIds.length > 4096)
        return ineligible();
      // SELECT-only protected original data; no prepare/provision/effect on a
      // Check, replay or explicit recovery request.
      const [traces, birth, receipt] = await Promise.all([
        conversationRepository.getTraceEvents(sessionId, binding,
          meta.traceEventIds, ORIGINAL_PURPOSE),
        lessonRepository.readBirth({ scope: binding, persona, personaSession,
          retainedScene, signal }),
        lessonRepository.readSaved({ scope: binding, persona, personaSession,
          retainedScene, modeToken, operationId: meta.operationId, signal }),
      ]);
      await conversations.assertOwned(sessionId, binding, persona, ORIGINAL_PURPOSE);
      await check();
      const candidate = buildIdorLessonCandidate({ binding, personaSession,
        retainedScene, sessionId, requestId,
        requestHash: original.request_hash, requestVersion: original.request_version,
        turn: original.result_json,
        traces, birth, receipt, mode: modeToken.snapshot, qualifyModel });
      if (!candidate) return ineligible();
      const actor = capture.prepare(binding, fence);
      const assessmentSession = await conversations.create(binding, persona,
        ASSESSMENT_PURPOSE);
      const message = JSON.stringify([candidate.objectiveId, receipt.operationId,
        sessionId, requestId, personaSession.sessionId,
        personaSession.authorityVersion]);
      let prepared;
      const prepare = async () => {
        await check();
        prepared = await admission.prepare({ sessionId: assessmentSession.id,
          requestId: receipt.operationId, binding, message });
        return prepared.status === 'completed'
          ? { skip: true, value: prepared.outcome }
          : { skip: false, value: prepared };
      };
      try {
        const outcome = await turns.run(assessmentSession.id, binding, persona,
          { signal, idempotencyKey: receipt.operationId,
            conversationPurpose: ASSESSMENT_PURPOSE, admit: prepare }, async originalBoundary => {
            const boundary = { ...originalBoundary,
              async check() { await originalBoundary.check(); await check(); } };
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
              scopes.set(execution, binding); capture.bind(execution, actor);
              const attempt = await completion.beginAttempt({
                userId: binding.platformOwnerId, workshopKey: WORKSHOP,
                objectiveId, execution });
              await boundary.check();
              if (attempt.mode !== 'vuln' || !await enabled(binding, objectiveId))
                return ineligible();
              const saved = await lessonRepository.readSaved({ scope: binding,
                persona, personaSession, retainedScene, modeToken,
                operationId: receipt.operationId, signal });
              if (!equal(saved, receipt)) return ineligible();
              await boundary.check();
              const result = await completion.evaluate({ userId: binding.platformOwnerId,
                workshopKey: WORKSHOP, objectiveId,
                evaluationId: randomUUID(), execution, attempt,
                rubric: { ...idorLessonRubric(meta.action), mode: attempt.mode },
                facts: candidate.facts, evidence: candidate.evidence });
              await boundary.check();
              return { completed: result.completed === true, judgment: result.judgment };
            }, fence);
          });
        await check();
        return outcome.result?.status === 'ineligible' ? ineligible()
          : Object.freeze({ ...outcome.result, replayed: outcome.replayed === true });
      } catch (error) {
        await admission.abandon(prepared);
        throw error;
      }
    },
  });
}

module.exports = { createIdorLessonAssessment };
