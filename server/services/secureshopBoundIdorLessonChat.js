'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { captureFeatureMode, guardFeatureFence, projectFeatureMode } =
  require('./secureshopFeatureModeAuthority');
const { withSceneLease } = require('./secureshopSceneBinding');
const { IDOR_LESSON_MANIFEST, IDOR_LESSON_TOOLS,
  normalizeIdorLessonSelection } = require('./secureshopIdorLessonContract');
const { createSecureShopIdorLessonTools } = require('./secureshopIdorLessonTools');
const { projectIdorLessonObservation } = require('./secureshopIdorLessonTools');
const { issueIdorFinalAnswerContract } = require('./secureshopIdorFinalAnswerContract');
const { idorLessonBasePrompt } = require('./secureshopDisclosurePromptGuidance');

const PURPOSE = 'secureshop_idor_lesson';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const fail = () => Object.assign(new Error('Isolated access-control lesson unavailable'),
  { code: 'IDOR_LESSON_UNAVAILABLE', executionBoundary: true });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function shouldAssessCommittedIdorLesson(result, savedEffect) {
  return !!savedEffect
    && result?.taskMetadata?.idorLesson?.operationId === savedEffect.receipt?.operationId
    && savedEffect.receipt.mode?.mode === 'vuln'
    && ['deleted','disclosed'].includes(savedEffect.receipt.result?.status);
}

function createSecureShopBoundIdorLessonChat({ launches, personaAuthority, modeAuthority,
  conversations: conversationRepository, journal, coordinator, provider, scenes,
  lessonRepository, assessment } = {}) {
  for (const fn of [launches?.assertCurrent, personaAuthority?.capture,
    conversationRepository?.getBoundSession, journal?.readIdorLessonRequest,
    journal?.claim,
    journal?.complete, journal?.markUncertain,
    coordinator?.run, provider?.chat, provider?.finalResponse, scenes?.readExisting,
    lessonRepository?.prepare, lessonRepository?.readCards,
    lessonRepository?.execute, lessonRepository?.readSaved])
    if (typeof fn !== 'function') throw fail();
  if (typeof modeAuthority?.capture !== 'function'
      || typeof modeAuthority.assertToken !== 'function'
      || assessment !== undefined && typeof assessment?.runAttempt !== 'function') throw fail();
  const conversations = createBoundConversationService({ conversations: conversationRepository,
    launches });
  const turns = createBoundTurns({ conversations, coordinator });
  async function authority(scope, persona, personaSession, signal) {
    if (!UUID.test(personaSession?.sessionId || '')
        || !/^[1-9]\d*$/.test(personaSession?.authorityVersion || '')) throw fail();
    const binding = createConversationBinding(scope, persona);
    if (binding.role !== 'customer') throw fail();
    const token = await captureFeatureMode(modeAuthority, binding, 'customer_idor');
    const base = personaAuthority.capture({ scope: binding,
      personaId: binding.shopUserId, role: binding.role, ...personaSession });
    const fence = guardFeatureFence(base, token);
    const retainedScene = await scenes.readExisting(binding);
    if (!retainedScene?.scene) throw fail();
    const check = async () => {
      signal?.throwIfAborted();
      await launches.assertCurrent(binding);
      await fence.assertRemoteAdmission();
      const current = await scenes.readExisting(binding);
      if (!current || current.targetId !== retainedScene.targetId
          || !equal(current.scene, retainedScene.scene)) throw fail();
      await fence.assertRemoteAdmission();
      signal?.throwIfAborted();
    };
    await check();
    return Object.freeze({ binding, token, fence, retainedScene, check });
  }
  return Object.freeze({ purpose: PURPOSE,
    async createSession(scope, persona, personaSession, signal) {
      const a = await authority(scope, persona, personaSession, signal);
      const session = await conversations.create(a.binding, persona, PURPOSE);
      await a.check();
      return session;
    },
    async prepare(scope, persona, personaSession, signal) {
      const a = await authority(scope, persona, personaSession, signal);
      const prepared = await withSceneLease(a.retainedScene, () =>
        a.fence.withCrossStoreEffect(() => lessonRepository.prepare({
          scope: a.binding, persona, personaSession, retainedScene: a.retainedScene,
          signal })));
      await a.check();
      if (!Array.isArray(prepared?.cards) || prepared.cards.length !== 2
          || !prepared.birth) throw fail();
      // The private victim birth never enters the UI.
      return Object.freeze({ cards: prepared.cards,
        modeCapability: projectFeatureMode(a.token) });
    },
    async readCards(scope, persona, personaSession, signal) {
      const a = await authority(scope, persona, personaSession, signal);
      const cards = await lessonRepository.readCards({ scope: a.binding, persona,
        personaSession, retainedScene: a.retainedScene, signal });
      await a.check();
      return Object.freeze({ cards, modeCapability: projectFeatureMode(a.token) });
    },
    async readRequest({ scope, persona, personaSession, sessionId, requestId,
      signal } = {}) {
      if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')) throw fail();
      sessionId = sessionId.toLowerCase(); requestId = requestId.toLowerCase();
      const a = await authority(scope, persona, personaSession, signal);
      await conversations.assertOwned(sessionId, a.binding, persona, PURPOSE);
      const row = await journal.readIdorLessonRequest({ sessionId, requestId,
        binding: a.binding, purpose: PURPOSE });
      await a.check();
      const unconfirmed = () => Object.freeze({ sessionId, requestId,
        status: 'unconfirmed' });
      if (!row || row.status !== 'completed') return unconfirmed();
      const turn = row.result_json, meta = turn?.taskMetadata?.idorLesson;
      if (typeof turn?.text !== 'string' || !turn.text.isWellFormed()
          || Buffer.byteLength(turn.text, 'utf8') > 2048
          || !Array.isArray(turn.hops) || turn.hops.length > 3
          || !equal(turn.modeCapability, projectFeatureMode(a.token))) throw fail();
      const common = { version: 1, originalEnvelope: meta?.originalEnvelope,
        mode: a.token.snapshot, personaSessionId: personaSession.sessionId,
        authorityVersion: personaSession.authorityVersion,
        sceneId: a.retainedScene.scene.sceneId,
        sceneGeneration: a.retainedScene.scene.sceneGeneration,
        grantId: a.retainedScene.scene.grantId,
        targetId: a.retainedScene.targetId };
      if (!meta || typeof meta.originalEnvelope !== 'string'
          || Buffer.byteLength(meta.originalEnvelope, 'utf8') > 16384) throw fail();
      let request;
      try { request = createTurnRequest({ sessionId, requestId, binding: a.binding,
        message: meta.originalEnvelope, version: row.request_version }); }
      catch { throw fail(); }
      if (request.hash !== row.request_hash) throw fail();
      let envelope;
      try { envelope = JSON.parse(meta.originalEnvelope); } catch { throw fail(); }
      if (!exact(envelope, ['version','sceneId','sceneGeneration','targetId',
        'selection','message']) || meta.originalEnvelope !== JSON.stringify(envelope)
          || envelope.version !== 1 || envelope.sceneId !== common.sceneId
          || envelope.sceneGeneration !== common.sceneGeneration
          || envelope.targetId !== common.targetId
          || typeof envelope.message !== 'string' || !envelope.message.trim()
          || !envelope.message.isWellFormed() || envelope.message.includes('\0')
          || Buffer.byteLength(envelope.message, 'utf8') > 8192) throw fail();
      let result = null;
      if (meta.state === 'no_effect') {
        if (!exact(meta, ['version','state','originalEnvelope','mode',
          'personaSessionId','authorityVersion','sceneId','sceneGeneration',
          'grantId','targetId']) || !equal(meta, { ...common, state: 'no_effect' })
            || turn.hops.length !== 0) throw fail();
        normalizeIdorLessonSelection(envelope.selection);
      } else {
        if (!exact(meta, ['version','birthId','operationId','action','numericId',
          'origin','originalEnvelope','traceEventIds','mode','personaSessionId',
          'authorityVersion','sceneId','sceneGeneration','grantId','targetId'])
            || !Object.keys(common).every(key => equal(meta[key], common[key]))
            || !UUID.test(meta.operationId || '') || !UUID.test(meta.birthId || '')
            || !equal(envelope.selection,
              { action: meta.action, numericId: meta.numericId })
            || turn.stopReason !== 'end_turn'
            || turn.hops.length !== 1 || !Array.isArray(meta.traceEventIds)
            || meta.traceEventIds.length < 3) throw fail();
        const receipt = await lessonRepository.readSaved({ scope: a.binding,
          persona, personaSession, retainedScene: a.retainedScene,
          modeToken: a.token, operationId: meta.operationId, signal });
        const observed = projectIdorLessonObservation(receipt, meta.action,
          meta.numericId, meta.origin);
        const hop = turn.hops[0];
        if (!equal(receipt.mode, a.token.snapshot)
            || receipt.operationId !== meta.operationId
            || receipt.birthId !== meta.birthId
            || receipt.personaSessionId !== personaSession.sessionId
            || receipt.authorityVersion !== personaSession.authorityVersion
            || receipt.turnOrigin.sessionId !== sessionId
            || receipt.turnOrigin.requestId !== requestId
            || !equal(receipt.turnOrigin, meta.origin)
            || hop.step !== meta.origin.step || hop.tool !== meta.origin.toolKey
            || !equal(hop.params, { numericId: meta.numericId })
            || !equal(hop.result, observed) || hop.error !== null
            || hop.policyViolation !== null) throw fail();
        const projected = JSON.parse(observed.content[0].text);
        if (projected.operationId !== meta.operationId) throw fail();
        const { operationId: _privateOperationId, ...publicResult } = projected;
        result = Object.freeze(publicResult);
      }
      await conversations.assertOwned(sessionId, a.binding, persona, PURPOSE);
      await a.check();
      return Object.freeze({ sessionId, requestId, status: 'completed',
        text: turn.text, result, modeCapability: projectFeatureMode(a.token) });
    },
    async run({ scope, persona, personaSession, sessionId, requestId, message,
      selection, signal, stream } = {}) {
      if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')
          || typeof message !== 'string' || !message.trim()
          || !message.isWellFormed() || message.includes('\0')
          || Buffer.byteLength(message, 'utf8') > 8192) throw fail();
      const chosen = normalizeIdorLessonSelection(selection);
      const a = await authority(scope, persona, personaSession, signal);
      await conversations.assertOwned(sessionId, a.binding, persona, PURPOSE);
      const cards = await lessonRepository.readCards({ scope: a.binding, persona,
        personaSession, retainedScene: a.retainedScene, signal });
      await a.check();
      if (!Array.isArray(cards) || cards.length !== 2
          || cards.filter(card => card.action === chosen.action
            && card.numericId === chosen.numericId).length !== 1) throw fail();
      const manifest = Object.freeze({ getForRole: role => role === 'customer'
        ? IDOR_LESSON_MANIFEST.filter(tool => `${tool.agent}.${tool.tool}`
          === IDOR_LESSON_TOOLS[chosen.action]) : [] });
      const selectedTool = IDOR_LESSON_TOOLS[chosen.action];
      let savedEffect = null;
      const checkedProvider = Object.freeze({
        config: provider.config, provider: provider.provider, model: provider.model,
        modelId: provider.modelId,
        chat: input => provider.chat(input),
        async finalResponse(input) {
          await a.check();
          const completed = savedEffect;
          const disclosed = chosen.action === 'order_status'
            && a.token.snapshot.mode === 'vuln'
            && completed?.receipt?.result?.status === 'disclosed';
          if (disclosed && provider.capabilities?.idorFinalAnswerContract !== true)
            throw Object.assign(new Error('Lesson final response capability unavailable'),
              { code: 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED' });
          const result = await provider.finalResponse(disclosed
            ? { ...input, idorFinalAnswerContract: issueIdorFinalAnswerContract(completed) }
            : input);
          await a.check();
          return result;
        },
      });
      const localAuthority = Object.freeze({});
      // These exact server-authored bytes are both the admitted turn request
      // and the saved original request used by the assessment.
      const envelope = JSON.stringify({ version: 1,
        sceneId: a.retainedScene.scene.sceneId,
        sceneGeneration: a.retainedScene.scene.sceneGeneration,
        targetId: a.retainedScene.targetId, selection: chosen, message });
      const runner = createBoundAgentRunner({ turns, conversations,
        repository: conversationRepository, journal, provider: checkedProvider,
        conversationPurpose: PURPOSE, executionScope: 'turn',
        limits: { maxSteps: 3, maxParallelTools: 1 },
        capturePersonaAuthority: () => a.fence,
        personaLocalToolModes: { [selectedTool]: 'remote_admission' },
        pool: { async callTool() { throw fail(); } }, manifest,
        buildBasePrompt: () => idorLessonBasePrompt(chosen.action, chosen.numericId, selectedTool),
        buildPolicyBlock: async () => '',
        checkToolAcl: async (role, agent, tool) => {
          const allowed = role === 'customer' && `${agent}.${tool}` === selectedTool;
          return { allowed, action: allowed ? 'dispatch' : 'block',
            policyViolation: allowed ? null : 'blocked', enforcement: true };
        },
        createLocalTools(_binding, context, token, execution, fence) {
          if (token !== localAuthority || fence !== a.fence) throw fail();
          return createSecureShopIdorLessonTools({ repository: lessonRepository,
            scope: a.binding, persona, personaSession, retainedScene: a.retainedScene,
            modeToken: a.token, personaFence: a.fence, selected: chosen,
            context, checkCurrent: a.check, signal,
            onReceipt(value) { savedEffect = value; } });
        },
        enterFinalResponseAfterLocalTool: async () => true,
        captureResultTraces: true,
        resultMetadata({ result, traces }) {
          if (!savedEffect || result.stopReason !== 'end_turn')
            return Object.freeze({ idorLesson: Object.freeze({ version: 1,
              state: 'no_effect', originalEnvelope: envelope,
              mode: a.token.snapshot,
              personaSessionId: personaSession.sessionId,
              authorityVersion: personaSession.authorityVersion,
              sceneId: a.retainedScene.scene.sceneId,
              sceneGeneration: a.retainedScene.scene.sceneGeneration,
              grantId: a.retainedScene.scene.grantId,
              targetId: a.retainedScene.targetId }) });
          const { receipt, origin } = savedEffect;
          if (receipt.action !== chosen.action || receipt.numericId !== chosen.numericId
              || !Array.isArray(traces) || traces.length < 3 || traces.length > 4096
              || traces.some(row => !UUID.test(row?.event_id || ''))) throw fail();
          return Object.freeze({ idorLesson: Object.freeze({ version: 1,
            birthId: receipt.birthId, operationId: receipt.operationId,
            action: chosen.action, numericId: chosen.numericId, origin,
            originalEnvelope: envelope,
            traceEventIds: traces.map(row => row.event_id.toLowerCase()),
            mode: a.token.snapshot,
            personaSessionId: personaSession.sessionId,
            authorityVersion: personaSession.authorityVersion,
            sceneId: a.retainedScene.scene.sceneId,
            sceneGeneration: a.retainedScene.scene.sceneGeneration,
            grantId: a.retainedScene.scene.grantId,
            targetId: a.retainedScene.targetId }) });
        },
        afterJournalCommit: assessment ? async ({ result }) => {
          if (!shouldAssessCommittedIdorLesson(result, savedEffect)) return;
          await assessment.runAttempt({ scope: a.binding, persona, personaSession,
            sessionId, requestId, signal });
        } : undefined,
      });
      const outcome = await runner.run({ sessionId, requestId, scope: a.binding,
        persona, personaSession, message: envelope, signal, stream,
        localToolAuthority: localAuthority });
      await a.check();
      return outcome;
    },
  });
}

module.exports = { createSecureShopBoundIdorLessonChat,
  shouldAssessCommittedIdorLesson };
