'use strict';

const { createHash, randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createTurnAdmission } = require('./secureshopTurnAdmission');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { SECURESHOP_CONVERSATION_PURPOSES } = require('./secureshopConversationPurpose');
const { captureFeatureMode } = require('./secureshopFeatureModeAuthority');
const { createAssessmentPersonaCapture } = require('./secureshopAssessmentPersonaCapture');
const { captureAssessmentPublicationScope } = require('./secureshopAssessmentPublicationScope');
const { readSecureShopAssessmentEligibility } = require('./secureshopAssessmentEligibility');
const { createObjectiveCompletionService } = require('./secureshopObjectiveCompletionService');
const { createSavedAssessmentOutcomeReader } = require('./secureshopSavedAssessmentOutcomeReader');
const { prepareJudgeInput } = require('../agent-runtime/objectiveJudge');
const { OBJECTIVE, RUBRIC, RUBRIC_V2, RUBRIC_V3, RUBRIC_V4, PREVIOUS_VERSION, HISTORICAL_V3, HISTORICAL_V4,
  buildAgencyRoleCandidate, isAgencyRoleJudgeInputValid,
  createAgencyRoleJudgeGuard } = require('./secureshopAgencyRoleEvidence');

const WORKSHOP = 'secureshop_agent_security';
const PURPOSE = 'persona_inbox';
const SOURCE_PURPOSE = SECURESHOP_CONVERSATION_PURPOSES.customerChat;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const fail = () => Object.assign(new Error('Agency role assessment unavailable'),
  { code: 'AGENCY_ROLE_ASSESSMENT_UNAVAILABLE', executionBoundary: true });
const status = value => Object.freeze({ completed: false, status: value, modelEvaluated: false });

function assessmentRequestId(sessionId, requestId) {
  if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')) throw fail();
  const bytes = createHash('sha256').update(JSON.stringify([OBJECTIVE, sessionId, requestId])).digest();
  bytes[6] = bytes[6] & 15 | 80;
  bytes[8] = bytes[8] & 63 | 128;
  const h = bytes.subarray(0, 16).toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function createAgencyRoleAssessment({ identityPool, agentsPool, launches, conversationRepository,
  coordinator, journal, personaAuthority, personaBindings, scenes, modeAuthority, sourceReader,
  receipts, progress, publicationModes, judge, qualifyModel } = {}) {
  for (const fn of [identityPool?.query, agentsPool?.query, launches?.assertCurrent,
    conversationRepository?.getBoundSession, conversationRepository?.acquireBoundSession,
    coordinator?.run, journal?.claim, journal?.complete, journal?.markUncertain,
    personaAuthority?.capture, personaBindings?.capture, scenes?.readRetained, modeAuthority?.capture,
    modeAuthority?.assertToken, sourceReader?.read, publicationModes?.getEvaluationScope, judge, qualifyModel]) {
    if (typeof fn !== 'function') throw TypeError('Agency role assessment dependencies required');
  }
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  const admission = createTurnAdmission({ journal });
  const capture = createAssessmentPersonaCapture(personaBindings);
  const scopes = new WeakMap(), packets = new WeakMap();
  const savedOutcome = createSavedAssessmentOutcomeReader({ identityPool, objectiveId: OBJECTIVE,
    rubric: RUBRIC, role: 'customer' });
  const savedHistoricalV2 = createSavedAssessmentOutcomeReader({ identityPool,
    objectiveId: OBJECTIVE, rubric: RUBRIC_V2, role: 'customer' });
  const savedHistoricalV3 = createSavedAssessmentOutcomeReader({ identityPool,
    objectiveId: OBJECTIVE, rubric: RUBRIC_V3, role: 'customer' });
  const savedHistoricalV4 = createSavedAssessmentOutcomeReader({ identityPool,
    objectiveId: OBJECTIVE, rubric: RUBRIC_V4, role: 'customer' });
  const guardedJudge = createAgencyRoleJudgeGuard(judge, qualifyModel);
  const completion = createObjectiveCompletionService({ receipts, progress, ...capture.options,
    captureInstanceScope: execution => {
      const scope = scopes.get(execution);
      if (!scope) throw fail();
      return scope;
    },
    judge: async input => {
      const expected = packets.get(input.execution), actual = prepareJudgeInput(input);
      if (!expected || actual.evidenceError || actual.packet !== expected.packet
          || actual.evidenceDigest !== expected.evidenceDigest) throw fail();
      return guardedJudge(input);
    }
  });
  const enabled = async binding => (await readSecureShopAssessmentEligibility(identityPool, binding, [OBJECTIVE])).includes(OBJECTIVE);

  async function authority({ scope, persona, personaSession, sessionId, requestId, signal }) {
    const binding = createConversationBinding(scope, persona), key = assessmentRequestId(sessionId, requestId);
    if (binding.role !== 'customer' || !UUID.test(personaSession?.sessionId || '')
        || typeof personaSession.authorityVersion !== 'string' || !/^[1-9]\d*$/.test(personaSession.authorityVersion)) throw fail();
    const customer = Object.freeze({ id: binding.shopUserId, role: 'customer' });
    const session = Object.freeze({ sessionId: personaSession.sessionId.toLowerCase(), authorityVersion: personaSession.authorityVersion });
    const fence = await personaAuthority.capture({ scope: binding, personaId: customer.id, role: 'customer', ...session });
    const expected = { ...createLaunchScope(binding), personaId: customer.id, role: 'customer', ...session };
    if (typeof fence?.assertRemoteAdmission !== 'function'
        || !Object.keys(expected).every(key => fence.binding?.[key] === expected[key])) throw fail();
    const mode = await captureFeatureMode(modeAuthority, binding, 'customer_chat');
    const target = await scenes.readRetained(binding);
    if (!target?.scene || !UUID.test(target.targetId || '')
        || !equal(createLaunchScope(executionScope(target)), createLaunchScope(binding))) throw fail();
    const publication = await captureAssessmentPublicationScope(publicationModes, binding.platformOwnerId, signal, binding);
    const check = async () => {
      signal?.throwIfAborted();
      await launches.assertCurrent(binding); await fence.assertRemoteAdmission();
      await conversations.assertOwned(sessionId, binding, customer, SOURCE_PURPOSE);
      await mode.assertCurrent(); await publication.assertCurrent();
      const current = await scenes.readRetained(binding);
      if (!current?.scene || current.targetId !== target.targetId || !equal(current.scene, target.scene)
          || !equal(createLaunchScope(executionScope(current)), createLaunchScope(binding))) throw fail();
      signal?.throwIfAborted();
    };
    await check();
    return Object.freeze({ binding, customer, personaSession: session, fence, mode, target,
      publication, check, signal, key, source: { sessionId, requestId } });
  }

  async function original(state, evidenceVersion) {
    await state.check();
    const source = await sourceReader.read({ scope: state.binding, persona: state.customer,
      personaSession: state.personaSession, sessionId: state.source.sessionId,
      requestId: state.source.requestId, target: state.target, mode: state.mode.snapshot,
      check: state.check, signal: state.signal });
    await state.check();
    if (!source || typeof source !== 'object' || Array.isArray(source)) return null;
    if (Object.hasOwn(source, 'binding') || Object.hasOwn(source, 'personaSession')
        || Object.hasOwn(source, 'qualifyModel')) throw fail();
    const r = source.row?.result_json?.taskMetadata?.agencyRole?.receipt;
    if (source.row?.session_id !== state.source.sessionId || source.row?.request_id !== state.source.requestId
        || !equal(r?.scope, createLaunchScope(state.binding)) || !equal(r?.scene, {
          targetId: state.target.targetId, sceneId: state.target.scene.sceneId,
          sceneGeneration: state.target.scene.sceneGeneration, grantId: state.target.scene.grantId
        }) || !equal(r?.persona, state.customer) || !equal(r?.personaSession, state.personaSession)
        || !equal(r?.modeExecution, state.mode.snapshot)
        || source.sourceBinding?.sessionId !== state.source.sessionId
        || source.sourceBinding?.requestId !== state.source.requestId
        || source.sourceBinding?.targetId !== state.target.targetId
        || source.sourceBinding?.sceneId !== state.target.scene.sceneId
        || source.sourceBinding?.sceneGeneration !== state.target.scene.sceneGeneration
        || source.sourceBinding?.grantId !== state.target.scene.grantId) return null;
    const candidate = buildAgencyRoleCandidate({ ...source, binding: state.binding,
      personaSession: state.personaSession, qualifyModel },
      evidenceVersion ? { evidenceVersion } : undefined);
    return candidate ? Object.freeze({ source: structuredClone(source), candidate }) : null;
  }

  const eligible = async state => state.mode.snapshot.mode === 'vuln'
    && state.publication.binding.mode === 'vuln' && await enabled(state.binding);
  const message = (state, source) => JSON.stringify([OBJECTIVE, state.source,
    source.candidate.evidence[0].content.sourceDigest, state.personaSession,
    state.mode.snapshot, state.publication.binding]);

  async function retained(state, packet, canonicalExecution, historicalVersion = null) {
    let input;
    try { input = typeof packet === 'string' ? JSON.parse(packet) : structuredClone(packet); } catch { throw fail(); }
    if (!canonicalExecution || !isAgencyRoleJudgeInputValid(input, qualifyModel,
      { allowHistorical: historicalVersion !== null })
      ||input.rubric.version!==(historicalVersion||RUBRIC.version)||!await eligible(state)) throw fail();
    const source = await original(state, historicalVersion || undefined);
    const current = source && prepareJudgeInput({ rubric: historicalVersion===PREVIOUS_VERSION?RUBRIC_V2
      :historicalVersion===HISTORICAL_V3?RUBRIC_V3:historicalVersion===HISTORICAL_V4?RUBRIC_V4:RUBRIC,
      ...source.candidate });
    const saved = prepareJudgeInput(input);
    if (!source || current.evidenceError || saved.evidenceError || current.packet !== saved.packet
        || current.evidenceDigest !== saved.evidenceDigest) throw fail();
    let owner;
    try { owner = JSON.parse(canonicalExecution.ownerKey); } catch { throw fail(); }
    if (!Array.isArray(owner) || owner.length !== 2 || owner[0] !== 'SecureShopBoundConversation'
        || !UUID.test(owner[1] || '')) throw fail();
    await conversations.assertOwned(owner[1], state.binding, state.customer, PURPOSE);
    await state.check();
    return current;
  }

  async function assessmentRow(state) {
    const b = state.binding;
    const rows = (await agentsPool.query(`SELECT t.session_id,t.request_id,t.request_hash,t.request_version,t.status,t.result_json
      FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE t.request_id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active'
        AND s.conversation_purpose='persona_inbox' AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
        AND s.platform_launch_generation=$4 AND s.original_platform_owner_id=$5
        AND s.original_platform_session_id=$6 AND s.user_id=$7 AND s.role='customer' LIMIT 2`,
    [state.key, b.launchId, b.scenarioId, b.generation, b.platformOwnerId, b.platformSessionId, b.shopUserId])).rows;
    if (rows.length > 1) throw fail();
    return rows[0] || null;
  }

  async function readOutcome(input) {
    const state = await authority(input);
    if (!await eligible(state) || !await original(state)) return status('ineligible');
    const row = await assessmentRow(state); await state.check();
    if (!row) return status('unconfirmed');
    await conversations.assertOwned(row.session_id, state.binding, state.customer, PURPOSE);
    const source = await original(state), expected = createTurnRequest({ sessionId: row.session_id,
      requestId: state.key, binding: state.binding, message: message(state, source) });
    if (row.request_hash !== expected.hash || Number(row.request_version) !== expected.version) throw fail();
    if (row.status !== 'completed') return status('pending');
    if (equal(row.result_json, status('ineligible'))) return status('ineligible');
    const args = { binding: state.binding, personaSession: state.personaSession,
      publication: state.publication.binding, assessmentOwnerKey: JSON.stringify(['SecureShopBoundConversation', row.session_id]),
      turnResult: row.result_json, check: state.check };
    try {
      return await savedOutcome.read({ ...args,
        prepareRetainedPacket: (packet, execution) => retained(state, packet, execution) });
    } catch (error) {
      if (!['SAVED_ASSESSMENT_UNAVAILABLE','AGENCY_ROLE_ASSESSMENT_UNAVAILABLE']
        .includes(error?.code)) throw error;
      for (const [reader, version] of [[savedHistoricalV4,HISTORICAL_V4],
        [savedHistoricalV3,HISTORICAL_V3], [savedHistoricalV2,PREVIOUS_VERSION]]) {
        try { return await reader.read({ ...args,
          prepareRetainedPacket: (packet, execution) => retained(state, packet, execution, version) }); }
        catch (historicalError) {
          if (!['SAVED_ASSESSMENT_UNAVAILABLE','AGENCY_ROLE_ASSESSMENT_UNAVAILABLE']
            .includes(historicalError?.code) || version === PREVIOUS_VERSION) throw historicalError;
        }
      }
    }
  }

  async function runAttempt(input) {
    const state = await authority(input);
    if (!await eligible(state)) return status('ineligible');
    const source = await original(state);
    if (!source) return status('ineligible');
    const actor = capture.prepare(state.binding, state.fence);
    const session = await conversations.create(state.binding, state.customer, PURPOSE);
    let prepared;
    const prepare = async () => {
      await state.check();
      prepared = await admission.prepare({ sessionId: session.id, requestId: state.key,
        binding: state.binding, message: message(state, source) });
      return prepared.status === 'completed' ? { skip: true, value: prepared.outcome } : { skip: false, value: prepared };
    };
    try {
      const outcome = await turns.run(session.id, state.binding, state.customer, { signal: state.signal,
        idempotencyKey: state.key, conversationPurpose: PURPOSE, admit: prepare }, async boundary => {
        let sourceCheck;
        const check = async () => { await boundary.check(); await state.check(); if (sourceCheck) await sourceCheck(); await boundary.check(); };
        await check(); if (!prepared) { await prepare(); if (prepared.status === 'completed') return prepared.outcome; }
        return admission.execute(prepared, { ...boundary, check }, async () => {
          const execution = Object.freeze({ runId: boundary.identity.runId, ownerKey: boundary.identity.ownerKey,
            durableGeneration: boundary.identity.durableGeneration, signal: boundary.signal, check });
          scopes.set(execution, state.binding); capture.bind(execution, actor);
          const attempt = await completion.beginAttempt({ userId: state.binding.platformOwnerId, workshopKey: WORKSHOP,
            objectiveId: OBJECTIVE, execution });
          await check(); if (attempt.mode !== 'vuln' || !await eligible(state)) return status('ineligible');
          const current = await original(state);
          if (!current || !equal(current.candidate, source.candidate)) return status('ineligible');
          const packet = prepareJudgeInput({ rubric: RUBRIC, ...source.candidate });
          if (packet.evidenceError) throw fail();
          packets.set(execution, packet);
          sourceCheck = async () => { const again = await original(state);
            if (!again || !equal(again.candidate, source.candidate) || !await eligible(state)) throw fail(); };
          const result = await completion.evaluate({ userId: state.binding.platformOwnerId, workshopKey: WORKSHOP,
            objectiveId: OBJECTIVE, evaluationId: randomUUID(), execution, attempt, rubric: RUBRIC, ...source.candidate });
          await check(); return { completed: result.completed === true, judgment: result.judgment };
        }, state.fence);
      });
      await state.check();
      if (outcome.replayed === true) return readOutcome(input);
      return equal(outcome.result, status('ineligible')) ? status('ineligible') : Object.freeze({ ...outcome.result, replayed: false });
    } catch (error) { await admission.abandon(prepared); throw error; }
  }

  async function assertRetainedPacket({ packet, scope, persona, personaSession, signal }) {
    let input;
    try { input = typeof packet === 'string' ? JSON.parse(packet) : structuredClone(packet); } catch { throw fail(); }
    const ref = input?.evidence?.[0]?.content;
    if (!ref || !UUID.test(ref.requestId || '')) throw fail();
    const state = await authority({ scope, persona, personaSession, sessionId: ref.source?.row?.session_id, requestId: ref.requestId, signal });
    const check = async () => {
      await state.check();
      if (!await eligible(state) || !isAgencyRoleJudgeInputValid(input, qualifyModel)) throw fail();
      const source = await original(state), current = source && prepareJudgeInput({ rubric: RUBRIC, ...source.candidate });
      const saved = prepareJudgeInput(input);
      if (!source || current.evidenceError || saved.evidenceError || current.packet !== saved.packet
          || current.evidenceDigest !== saved.evidenceDigest || !SHA.test(saved.evidenceDigest)) throw fail();
      await state.check();
    };
    await check(); return Object.freeze({ assertCurrent: check });
  }
  return Object.freeze({ objectiveId: OBJECTIVE, completionService: completion, runAttempt, readOutcome, assertRetainedPacket });
}

module.exports = { createAgencyRoleAssessment, assessmentRequestId };
