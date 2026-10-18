'use strict';

const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { executionScope } = require('./secureshopSceneBinding');
const { captureFeatureMode } = require('./secureshopFeatureModeAuthority');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createTurnAdmission } = require('./secureshopTurnAdmission');
const { createAssessmentPersonaCapture } = require('./secureshopAssessmentPersonaCapture');
const { createObjectiveCompletionService } = require('./secureshopObjectiveCompletionService');
const { captureAssessmentPublicationScope } = require('./secureshopAssessmentPublicationScope');
const { readSecureShopAssessmentEligibility } = require('./secureshopAssessmentEligibility');
const { prepareJudgeInput } = require('../agent-runtime/objectiveJudge');
const { createTicketBrowserOriginalReader } = require('./secureshopTicketBrowserOriginalReader');
const { OBJECTIVE, rubricForSelection,
  buildTicketBrowserCandidate } = require('./secureshopTicketBrowserEvidence');
const { originalSelection } = require('./secureshopTicketAgentProposal');
const { projectJudgment } = require('../agent-runtime/dpiSemanticCreditPolicy');
const Ticket = require('./secureshopTicketContract');

const WORKSHOP = 'secureshop_agent_security';
const PURPOSE = 'persona_inbox';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const fail = () => Object.assign(new Error('Ticket browser assessment unavailable'),
  { code: 'TICKET_BROWSER_ASSESSMENT_UNAVAILABLE' });
const ineligible = () => Object.freeze({ completed: false, status: 'ineligible', modelEvaluated: false });
const unconfirmed = () => Object.freeze({ completed: false, status: 'unconfirmed', modelEvaluated: false });
const hash = value => createHash('sha256').update(value).digest('hex');
const sameScope = (a, b) => Object.keys(a).every(key => a[key] === b?.[key]);
const assessmentMessage = (state, ticket, publication) => JSON.stringify([
  OBJECTIVE, state.ticketId, ticket.result.operationId, ticket.result.receiptSha256,
  ticket.consumer, state.session, state.modeToken.snapshot, publication.binding,
]);
function canonicalJudgment(row) {
  if (!row || !UUID.test(row.evaluation_id || '')
      || !SHA.test(row.result_digest || '')
      || !row.result_json || typeof row.result_json !== 'object'
      || Array.isArray(row.result_json)
      || !['pass','fail','inconclusive','unavailable'].includes(row.verdict)
      || row.result_json.verdict !== row.verdict) throw fail();
  if (row.result_serialized != null && (typeof row.result_serialized !== 'string'
      || hash(row.result_serialized) !== row.result_digest
      || !equal(JSON.parse(row.result_serialized), row.result_json))) throw fail();
  return Object.freeze({ completed: ['awarded','already_complete'].includes(row.disposition),
    judgment: Object.freeze({ ...projectJudgment({ disposition: row.disposition,
      result: row.result_json }), evaluationId: row.evaluation_id,
      canRetry: false }) });
}
function selectedTicket(originalRead, ticketRead, qualifyModel) {
  const source = Ticket.source(ticketRead.source);
  const selected = originalSelection(originalRead, {
    sessionId: source.turn.sessionId, requestId: source.turn.requestId,
    proposalId: source.proposalId }, qualifyModel);
  const rubric = rubricForSelection(selected);
  if (!rubric) throw fail();
  return { source, selected, rubric };
}

function createTicketBrowserAssessment({ identityPool, launches, conversationRepository,
  coordinator, journal, bindingRepository, personaAuthority, personaBindings,
  scenes, modeAuthority, ticketRepository, receipts, progress, publicationModes,
  judge, qualifyModel, browserQualification } = {}) {
  for (const fn of [identityPool?.query, launches?.assertCurrent,
    conversationRepository?.getBoundSession, conversationRepository?.getMessages,
    conversationRepository?.getTraceEvents,
    conversationRepository?.acquireBoundSession,
    coordinator?.run, journal?.readBoundRequest,
    journal?.readTicketBrowserAssessment,
    bindingRepository?.read, personaAuthority?.capture,
    personaBindings?.capture, scenes?.readRetained,
    modeAuthority?.capture, modeAuthority?.assertToken,
    ticketRepository?.readForAssessment, judge, qualifyModel,
    browserQualification?.readComponent,
    browserQualification?.qualifyTicket])
    if (typeof fn !== 'function') throw new TypeError('Ticket browser assessment dependencies required');
  if (typeof publicationModes?.getEvaluationScope !== 'function')
    throw new TypeError('Ticket browser publication reader required');
  const conversations = createBoundConversationService({
    conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  const admission = createTurnAdmission({ journal });
  const readOriginal = createTicketBrowserOriginalReader({
    bindingRepository, journal, conversations: conversationRepository });
  const capture = createAssessmentPersonaCapture(personaBindings);
  const scopes = new WeakMap(), expectedPackets = new WeakMap();
  const completion = createObjectiveCompletionService({ receipts, progress,
    judge: async input => {
      const expected = expectedPackets.get(input.execution);
      const prepared = prepareJudgeInput(input);
      if (!expected || prepared.evidenceError
          || prepared.packet !== expected.packet
          || prepared.evidenceDigest !== expected.evidenceDigest) throw fail();
      return judge(input);
    }, ...capture.options,
    captureInstanceScope: execution => {
      const scope = scopes.get(execution);
      if (!scope) throw fail();
      return scope;
    } });
  const enabled = async scope => (await readSecureShopAssessmentEligibility(
    identityPool, scope, [OBJECTIVE])).includes(OBJECTIVE);

  async function authority({ scope: raw, persona, personaSession, ticketId, signal }) {
    const scope = createLaunchScope(raw);
    if (persona?.role !== 'admin' || !Number.isSafeInteger(persona.id)
        || persona.id < 1 || !UUID.test(personaSession?.sessionId || '')
        || !/^[1-9]\d*$/.test(personaSession?.authorityVersion || '')
        || typeof ticketId !== 'string' || !/^[1-9]\d*$/.test(ticketId)) throw fail();
    const admin = Object.freeze({ id: persona.id, role: 'admin' });
    const session = Object.freeze({ sessionId: personaSession.sessionId.toLowerCase(),
      authorityVersion: personaSession.authorityVersion });
    const binding = createConversationBinding(scope, admin);
    signal?.throwIfAborted();
    await launches.assertCurrent(scope);
    const fence = await personaAuthority.capture({ scope, personaId: admin.id,
      role: admin.role, ...session });
    const expected = { ...scope, personaId: admin.id, role: 'admin',
      sessionId: session.sessionId, authorityVersion: session.authorityVersion };
    if (typeof fence?.assertRemoteAdmission !== 'function'
        || !sameScope(expected, fence.binding)) throw fail();
    await fence.assertRemoteAdmission();
    const modeToken = await captureFeatureMode(modeAuthority, scope, 'support_tickets');
    const retainedScene = await scenes.readRetained(scope);
    if (!retainedScene?.scene || !sameScope(scope, executionScope(retainedScene))) throw fail();
    const check = async () => {
      signal?.throwIfAborted(); await launches.assertCurrent(scope);
      await fence.assertRemoteAdmission(); await modeToken.assertCurrent();
      const currentScene = await scenes.readRetained(scope);
      if (!currentScene?.scene
          || !sameScope(scope, executionScope(currentScene))
          || currentScene.targetId !== retainedScene.targetId
          || !equal(currentScene.scene, retainedScene.scene)
          || !equal(createLaunchScope(currentScene),
            createLaunchScope(retainedScene))) throw fail();
      signal?.throwIfAborted();
    };
    await check();
    return Object.freeze({ scope, admin, session, binding, fence, modeToken,
      retainedScene, ticketId, signal, check });
  }

  async function evidence(state) {
    await state.check();
    const ticketRead = await ticketRepository.readForAssessment({
      scope: state.scope, retainedScene: state.retainedScene,
      persona: state.admin, personaSession: state.session,
      modeToken: state.modeToken }, { ticketId: state.ticketId });
    await state.check();
    if (!ticketRead) return null;
    const source = Ticket.source(ticketRead.source);
    if (ticketRead.result?.ticketId !== state.ticketId
        || ticketRead.consumer?.admin?.shopUserId !== state.admin.id
        || ticketRead.consumer?.admin?.personaSessionId !== state.session.sessionId
        || ticketRead.consumer?.admin?.authorityVersion !== state.session.authorityVersion
        || ticketRead.detail?.modeCapability?.featureId !== 'support_tickets'
        || ticketRead.detail.modeCapability.policyVersion !== 'owned-ticket-render-v1'
        || ticketRead.detail.modeCapability.effectiveMode !== state.modeToken.snapshot.mode)
      throw fail();
    const originalRead = await readOriginal(ticketRead);
    await state.check();
    if (source.scene.targetId !== state.retainedScene.targetId
        || source.scene.sceneId !== state.retainedScene.scene.sceneId
        || source.scene.sceneGeneration !== state.retainedScene.scene.sceneGeneration)
      throw fail();
    return Object.freeze({ ticketRead, originalRead });
  }

  async function verifyRetainedPacket({ packet, scope, persona,
    personaSession, signal }) {
    let saved;
    try { saved = typeof packet === 'string' ? JSON.parse(packet) : packet; }
    catch { throw fail(); }
    const proof = saved?.evidence?.[0]?.content;
    const ticketId = proof?.ticket?.result?.ticketId;
    if (typeof ticketId !== 'string' || !/^[1-9]\d*$/.test(ticketId)) throw fail();
    const state = await authority({ scope, persona, personaSession,
      ticketId, signal });
    if (!await enabled(state.scope) || state.modeToken.snapshot.mode !== 'vuln')
      throw fail();
    const publication = await captureAssessmentPublicationScope(publicationModes,
      state.scope.platformOwnerId, signal, state.scope);
    await state.check();
    if (publication.binding.mode !== 'vuln') throw fail();
    const current = await evidence(state);
    if (!current) throw fail();
    const { ticketRead, originalRead } = current;
    const { source, selected, rubric } = selectedTicket(originalRead,
      ticketRead, qualifyModel);
    const version = selected.sourceVersion === 2 ? 2 : 1;
    let expectedRubric;
    try {
      expectedRubric = prepareJudgeInput({
        rubric: { ...rubric, mode: 'vuln' }, facts: saved?.facts,
        evidence: saved?.evidence,
      }).rubric;
    } catch { throw fail(); }
    if (!equal(saved?.rubric, expectedRubric)
        || saved?.evidence?.length !== 1
        || saved.evidence[0]?.id !== 'ticket_browser'
        || saved.evidence[0]?.source !== 'server_observation'
        || rubric.requiredFacts.some(key => saved.facts?.[key] !== true)
        || proof?.version !== version || proof.objectiveId !== OBJECTIVE
        || !equal(proof.originalCustomer?.source, source)
        || Object.keys(proof.originalCustomer).sort().join('\0') !==
          ['source', 'requestSha256', 'modelRunId', 'message', 'proposal',
            'traceEventIds', 'decisionEventId', 'callEventId', 'resultEventId',
            'terminalEventId', ...(version === 2 ? ['sourceVersion', 'requestRef'] : [])]
            .sort().join('\0')
        || (version === 2 && (proof.originalCustomer.sourceVersion !== 2
          || proof.originalCustomer.requestRef !== selected.requestRef))
        || proof.originalCustomer.requestSha256 !== selected.requestSha256
        || proof.originalCustomer.modelRunId !== selected.runId
        || proof.originalCustomer.message !== selected.message
        || !equal(proof.originalCustomer.proposal, selected.proposal)
        || !equal(proof.originalCustomer.traceEventIds, selected.traceEventIds)
        || proof.originalCustomer.decisionEventId !== selected.decisionEventId
        || proof.originalCustomer.callEventId !== selected.callEventId
        || proof.originalCustomer.resultEventId !== selected.resultEventId
        || proof.originalCustomer.terminalEventId !== selected.terminalEventId
        || !equal(proof.ticket?.result, ticketRead.result)
        || proof.ticket.receiptSha256 !== ticketRead.receipt.sha256
        || proof.ticket.subjectSha256 !== ticketRead.result.subjectSha256
        || proof.ticket.bodySha256 !== ticketRead.result.bodySha256
        || proof.ticket.body !== ticketRead.body
        || !equal(proof.currentAdmin?.consumer, ticketRead.consumer)
        || proof.currentAdmin.ticketId !== ticketId
        || !equal(proof.currentAdmin.modeCapability,
          ticketRead.detail.modeCapability)
        || !equal(proof.component, browserQualification.readComponent())
        || proof.browser?.renderedSourceSha256 !== hash(ticketRead.body)
        || proof.browser.targetEventExecuted !== true
        || proof.browser.targetEffectObserved !== true
        || proof.browser.syntheticCookieOnly !== true
        || proof.browser.finalCookieIsSyntheticOnly !== true
        || !Array.isArray(proof.browser.markers)
        || proof.browser.markers.length < 1
        || !Array.isArray(proof.browser.blockedRequests)) throw fail();
    const receipt = proof.effectReceipt;
    if (receipt?.version !== 1 || receipt.status !== 'completed'
        || !UUID.test(receipt.runId || '')
        || typeof receipt.ownerKey !== 'string' || !receipt.ownerKey
        || !receipt.effectKey?.endsWith(`:ticket-browser:${ticketId}`)
        || !Number.isSafeInteger(Number(receipt.generation))) throw fail();
    const rows = (await identityPool.query(`SELECT owner_key AS "ownerKey",
      generation::text AS generation,effect_key AS "effectKey",
      run_id AS "runId",status FROM graph_runtime.effects
      WHERE owner_key=$1 AND generation=$2 AND effect_key=$3
        AND run_id=$4 AND status='completed' LIMIT 2`,
    [receipt.ownerKey, receipt.generation, receipt.effectKey,
      receipt.runId])).rows;
    await publication.assertCurrent(); await state.check();
    if (rows.length !== 1 || rows[0].ownerKey !== receipt.ownerKey
        || String(rows[0].generation) !== String(receipt.generation)
        || rows[0].effectKey !== receipt.effectKey
        || rows[0].runId !== receipt.runId
        || rows[0].status !== 'completed') throw fail();
    const prepared = prepareJudgeInput(saved);
    if (prepared.evidenceError || !SHA.test(prepared.evidenceDigest || ''))
      throw fail();
    return Object.freeze({ state, saved, prepared });
  }

  async function assertRetainedPacket(input) {
    await verifyRetainedPacket(input);
    return Object.freeze({ async assertCurrent() {
      await verifyRetainedPacket(input);
    } });
  }

  async function readOutcome({ scope, persona, personaSession, ticketId,
    requestId, signal } = {}) {
    if (!UUID.test(requestId || '')) throw fail();
    const state = await authority({ scope, persona, personaSession, ticketId,
      signal });
    if (!await enabled(state.scope)) return ineligible();
    const publication = await captureAssessmentPublicationScope(publicationModes,
      state.scope.platformOwnerId, signal, state.scope);
    await state.check();
    if (state.modeToken.snapshot.mode !== 'vuln'
        || publication.binding.mode !== 'vuln') return ineligible();
    const original = await evidence(state);
    if (!original) return unconfirmed();
    const { rubric } = selectedTicket(original.originalRead,
      original.ticketRead, qualifyModel);
    const row = await journal.readTicketBrowserAssessment({
      requestId, binding: state.binding });
    await publication.assertCurrent(); await state.check();
    if (!row) return unconfirmed();
    await conversations.assertOwned(row.session_id, state.scope, state.admin, PURPOSE);
    const expected = createTurnRequest({ sessionId: row.session_id,
      requestId, binding: state.binding,
      message: assessmentMessage(state, original.ticketRead, publication) });
    if (row.request_hash !== expected.hash
        || row.request_version !== expected.version) throw fail();
    if (row.status !== 'completed') return unconfirmed();
    const result = row.result_json;
    if (equal(result, ineligible())) return ineligible();
    if (!result || typeof result !== 'object' || Array.isArray(result)
        || Object.keys(result).length !== 2
        || !Object.hasOwn(result, 'completed')
        || !Object.hasOwn(result, 'judgment')
        || typeof result.completed !== 'boolean'
        || !UUID.test(result.judgment?.evaluationId || '')) throw fail();
    const judgments = (await identityPool.query(`SELECT j.*,r.child_id,
      to_jsonb(child) AS child_row,
      e.tenant_id AS current_tenant_id,e.principal_id AS current_principal_id,
      s.membership_version::text AS current_membership_version,
      g.generation::text AS live_owner_generation
      FROM secureshop_auth.execution_authority_state e
      JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
      JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
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
      state.admin.id, result.judgment.evaluationId, OBJECTIVE])).rows;
    await publication.assertCurrent(); await state.check();
    if (judgments.length !== 1) throw fail();
    const judgment = judgments[0], execution = judgment.execution_json;
    const mode = publication.binding;
    if (judgment.workshop_key !== WORKSHOP
        || judgment.objective_id !== OBJECTIVE
        || judgment.shop_user_id !== state.admin.id
        || judgment.family !== rubric.family
        || judgment.scenario !== rubric.scenario
        || judgment.rubric_version !== rubric.version
        || judgment.mode !== 'vuln' || judgment.mode !== mode.mode
        || judgment.generation !== mode.generation
        || judgment.mode_stamp !== mode.modeStamp
        || judgment.owner_key !== JSON.stringify([
          'SecureShopBoundConversation', row.session_id])
        || String(judgment.owner_generation) !== judgment.live_owner_generation
        || execution?.tenantId !== judgment.current_tenant_id
        || execution.principalId !== judgment.current_principal_id
        || execution.membershipVersion !== judgment.current_membership_version
        || !equal(execution.scope, state.scope)
        || execution.personaSessionId !== state.session.sessionId
        || execution.personaAuthorityVersion !== state.session.authorityVersion
        || execution.role !== 'admin'
        || execution.runId !== judgment.run_id) throw fail();
    const retained = await verifyRetainedPacket({ packet: judgment.packet,
      scope: state.scope, persona: state.admin,
      personaSession: state.session, signal });
    if (retained.prepared.packet !== judgment.packet
        || retained.prepared.evidenceDigest !== judgment.evidence_digest)
      throw fail();
    const parent = canonicalJudgment(judgment);
    if (result.completed !== parent.completed
        || !equal({ ...result.judgment, canRetry: false },
          parent.judgment)) throw fail();
    if (!judgment.child_id) return Object.freeze({ ...parent, replayed: true });
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
          { ...execution, runId: null })) throw fail();
    if (!child.verdict) return Object.freeze({ ...parent, replayed: true });
    return Object.freeze({ ...canonicalJudgment(child), replayed: true });
  }

  async function runAttempt({ scope, persona, personaSession, ticketId,
    requestId, signal } = {}) {
    if (!UUID.test(requestId || '')) throw fail();
    const state = await authority({ scope, persona, personaSession, ticketId, signal });
    if (!await enabled(state.scope)) return ineligible();
    const publication = await captureAssessmentPublicationScope(publicationModes,
      state.scope.platformOwnerId, signal, state.scope);
    await state.check();
    if (state.modeToken.snapshot.mode !== 'vuln'
        || publication.binding.mode !== 'vuln') return ineligible();
    const original = await evidence(state);
    if (!original) return unconfirmed();
    const actor = capture.prepare(state.binding, state.fence);
    const conversation = await conversations.create(state.scope, state.admin, PURPOSE);
    const message = assessmentMessage(state, original.ticketRead, publication);
    let prepared;
    const prepare = async () => {
      await state.check();
      prepared = await admission.prepare({ sessionId: conversation.id,
        requestId, binding: state.binding, message });
      return prepared.status === 'completed'
        ? { skip: true, value: prepared.outcome }
        : { skip: false, value: prepared };
    };
    let outcome;
    try {
      outcome = await turns.run(conversation.id, state.binding, state.admin,
        { signal, idempotencyKey: requestId, conversationPurpose: PURPOSE,
          admit: prepare }, async boundary => {
          const protectedBoundary = { ...boundary, async check() {
            await boundary.check(); await state.check(); await publication.assertCurrent();
            await boundary.check();
          } };
          await protectedBoundary.check();
          if (!prepared) {
            await prepare();
            if (prepared.status === 'completed') return prepared.outcome;
          }
          return admission.execute(prepared, protectedBoundary, async () => {
            if (!UUID.test(boundary.identity?.runId || '')
                || typeof boundary.identity?.ownerKey !== 'string'
                || boundary.identity.durableGeneration == null
                || typeof boundary.effectWithReceipt !== 'function') throw fail();
            const execution = Object.freeze({ runId: boundary.identity.runId,
              ownerKey: boundary.identity.ownerKey,
              durableGeneration: boundary.identity.durableGeneration,
              signal: boundary.signal, check: protectedBoundary.check });
            scopes.set(execution, state.scope);
            capture.bind(execution, actor);
            await protectedBoundary.check();
            const attempt = await completion.beginAttempt({
              userId: state.scope.platformOwnerId,
              workshopKey: WORKSHOP, objectiveId: OBJECTIVE, execution });
            await protectedBoundary.check();
            if (attempt.mode !== 'vuln' || !await enabled(state.scope))
              return ineligible();
            const component = browserQualification.readComponent();
            const node = `ticket-browser:${ticketId}`;
            const effectKey = `${requestId}:${node}`;
            const effect = await protectedBoundary.effectWithReceipt(node, async () => {
              await protectedBoundary.check();
              const value = await browserQualification.qualifyTicket({
                html: original.ticketRead.body, ticketId,
                modeCapability: original.ticketRead.detail.modeCapability,
                signal: boundary.signal });
              await protectedBoundary.check();
              return value;
            });
            await protectedBoundary.check();
            if (!equal(browserQualification.readComponent(), component)
                || !equal(effect.value?.component, component)
                || effect.value?.renderedSourceSha256 !== hash(original.ticketRead.body))
              throw fail();
            const after = await evidence(state);
            await protectedBoundary.check();
            if (!after || !equal(after, original)) throw fail();
            const candidate = buildTicketBrowserCandidate({ ...original,
              effect, execution: { ...execution, effectKey }, qualifyModel });
            if (!candidate) return ineligible();
            const { rubric: selectedRubric } = selectedTicket(original.originalRead,
              original.ticketRead, qualifyModel);
            const rubric = { ...selectedRubric, mode: 'vuln' };
            const packet = prepareJudgeInput({ rubric, ...candidate });
            if (packet.evidenceError || !SHA.test(packet.evidenceDigest || '')) throw fail();
            expectedPackets.set(execution, packet);
            const result = await completion.evaluate({
              userId: state.scope.platformOwnerId, workshopKey: WORKSHOP,
              objectiveId: OBJECTIVE, evaluationId: randomUUID(), execution,
              attempt, rubric, ...candidate });
            await protectedBoundary.check();
            return Object.freeze({ completed: result.completed === true,
              judgment: result.judgment });
          }, state.fence);
        });
    } catch (error) {
      await admission.abandon(prepared);
      throw error;
    }
    await publication.assertCurrent(); await state.check();
    return Object.freeze({ ...outcome.result, replayed: outcome.replayed === true });
  }

  return Object.freeze({ objectiveId: OBJECTIVE, completionService: completion,
    runAttempt, readOutcome, assertRetainedPacket });
}

module.exports = { createTicketBrowserAssessment };
