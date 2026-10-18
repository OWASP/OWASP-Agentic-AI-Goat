'use strict';

const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { executionScope: sceneExecution } = require('./secureshopSceneBinding');
const { canonicalDigest } = require('./mcp/protocolContext');
const { resolveProductSimilarObservation } = require('./secureshopManualRagSourceContract');
const { resolveProductSummaryObservation } = require('./secureshopProductSummarySourceContract');
const {captureFeatureMode,guardFeatureFence}=require('./secureshopFeatureModeAuthority');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('./secureshopConversationPurpose');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { createSecureShopProductExecutionConfig, PRODUCT_RETRIEVAL_MODES } = require('./secureshopProductExecutionConfig');

const OPERATIONS = Object.freeze({
  summary: 'summarizer.summarize_product',
  similar: 'product-search.similar',
});
const DENIED_MODEL_IDENTITIES = /^(mock|fixture|scripted|fallback|unavailable)$/i;

function unavailable(message = 'Bound product model unavailable') {
  return Object.assign(new Error(message), { code: 'PRODUCT_MODEL_UNAVAILABLE' });
}

function interrupted(signal) {
  if (signal?.aborted && signal.reason instanceof Error) return signal.reason;
  const error = new Error('Bound product request cancelled');
  error.name = 'AbortError';
  return error;
}

function customerPersona(value) {
  if (!value || !Number.isInteger(value.id) || value.id < 1 || value.id > 2147483647
      || value.role !== 'customer') {
    throw Object.assign(new TypeError('Customer persona required'), { code: 'INVALID_ARGUMENT' });
  }
  return Object.freeze({ id: value.id, role: value.role });
}

function productId(value) {
  if (!Number.isInteger(value) || value < 1 || value > 2147483647) {
    throw Object.assign(new TypeError('Invalid product ID'), { code: 'INVALID_ARGUMENT' });
  }
  return value;
}

function assertExactToolArgs(value, expectedProductId) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).length !== 1 || value.product_id !== expectedProductId) {
    throw Object.assign(new Error('Product tool arguments do not match server authority'), {
      code: 'INVALID_TOOL_ARGUMENTS',
    });
  }
}

function actualModelIdentity(result) {
  const provider = typeof result?.provider === 'string' ? result.provider.trim() : '';
  const model = typeof result?.model === 'string' ? result.model.trim() : '';
  if (!provider || !model || result.mocked !== false || result.fallback === true
      || DENIED_MODEL_IDENTITIES.test(provider) || DENIED_MODEL_IDENTITIES.test(model)) {
    throw unavailable();
  }
  return Object.freeze({ provider, model });
}

function oneJsonToolResult(observation) {
  if (!observation || observation.result?.isError === true
      || !Array.isArray(observation.result?.content)
      || observation.result.content.length !== 1
      || observation.result.content[0]?.type !== 'text'
      || typeof observation.result.content[0].text !== 'string') {
    throw unavailable('Bound product tool did not return a successful observation');
  }
  let value;
  try { value = JSON.parse(observation.result.content[0].text); } catch {}
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
    throw unavailable('Bound product tool returned an invalid observation');
  }
  return value;
}

function optionalText(value) {
  return value === null || value === undefined || typeof value === 'string';
}

function summaryObservation(value, expectedProductId) {
  if (value.product_id !== expectedProductId || typeof value.name !== 'string' || !value.name
      || !['number', 'string'].includes(typeof value.price)
      || !Number.isInteger(value.stock_quantity) || value.stock_quantity < 0
      || !optionalText(value.category) || !optionalText(value.description)
      || !optionalText(value.description_html)) {
    throw unavailable('Bound product summary observation is invalid');
  }
  return Object.freeze({
    product_id: value.product_id,
    name: value.name,
    price: value.price,
    category: value.category ?? null,
    stock_quantity: value.stock_quantity,
    description: value.description ?? null,
    description_html: value.description_html ?? null,
  });
}

function similarObservation(value, expectedProductId) {
  if (!Array.isArray(value.results) || !Number.isSafeInteger(value.count)
      || value.count !== value.results.length || !PRODUCT_RETRIEVAL_MODES.includes(value.mode)
      || !value.seed || Object.getPrototypeOf(value.seed) !== Object.prototype
      || value.seed.id !== expectedProductId || typeof value.seed.name !== 'string'
      || !Array.isArray(value.retrieved_context)) {
    throw unavailable('Bound similar-products observation is invalid');
  }
  const ids = new Set();
  for (const row of value.results) {
    if (!row || Object.getPrototypeOf(row) !== Object.prototype
        || !Number.isInteger(row.id) || row.id < 1 || row.id > 2147483647
        || row.id === expectedProductId || ids.has(row.id)) {
      throw unavailable('Bound similar-products observation contains an invalid product');
    }
    ids.add(row.id);
  }
  return Object.freeze({
    results: structuredClone(value.results),
    count: value.count,
    mode: value.mode,
    seed: structuredClone(value.seed),
    retrieved_context: structuredClone(value.retrieved_context),
  });
}

function createSecureShopBoundProductAssist({ launches, conversationRepository, journal, coordinator,
  provider, createProductTools, assessmentFactory, personaAuthority, modeAuthority, toolPolicyRepository, promptPolicyRepository, makeId = randomUUID,
  taskPoliciesEnabled = false, policySearch, catalog, scenes, afterSimilarCommit, afterSummaryCommit, limits = { maxSteps: 4, maxParallelTools: 1 } } = {}) {
  if (catalog !== undefined && typeof catalog?.getProduct !== 'function' || scenes !== undefined && typeof scenes?.readRetained !== 'function'
      || afterSimilarCommit !== undefined && typeof afterSimilarCommit !== 'function'
      || afterSummaryCommit !== undefined && typeof afterSummaryCommit !== 'function') throw TypeError('Product saved workflow dependencies required');
  if (typeof taskPoliciesEnabled !== 'boolean') throw new TypeError('Bound product task policy configuration required');
  const policyOptions = require('./secureshopPromptPolicyRunnerOptions').promptPolicyRunnerOptions;
  const promptPolicyOptions = Object.freeze({
    summary: policyOptions(promptPolicyRepository, personaAuthority,
      taskPoliciesEnabled ? { recipient: 'summarizer' } : undefined),
    similar: policyOptions(promptPolicyRepository, personaAuthority,
      taskPoliciesEnabled ? { recipient: null } : undefined),
  });
  if (toolPolicyRepository !== undefined && (typeof toolPolicyRepository?.admitTool !== 'function'
      || typeof personaAuthority?.capture !== 'function')) throw new TypeError('Policy repository and persona authority required');
  if(policySearch!==undefined&&(typeof policySearch?.search!=='function'||!taskPoliciesEnabled))throw new TypeError('Bound policy search requires task policies');
  if (typeof launches?.assertCurrent !== 'function' || typeof coordinator?.run !== 'function'
      || typeof provider?.chat !== 'function' || typeof provider?.finalResponse !== 'function'
      || typeof createProductTools !== 'function' || typeof makeId !== 'function'
      || (assessmentFactory !== undefined && typeof assessmentFactory !== 'function')) {
    if (assessmentFactory !== undefined && typeof assessmentFactory !== 'function') {
      throw new TypeError('Bound product assessment factory required');
    }
    throw new TypeError('Bound product graph dependencies required');
  }
  if(modeAuthority!=null&&typeof personaAuthority?.capture!=='function')throw TypeError('Product mode requires persona authority');
  if(personaAuthority!==undefined&&typeof personaAuthority?.capture!=='function')throw TypeError('Persona authority required');
  const conversations = createBoundConversationService({
    conversations: conversationRepository,
    launches,
    makeId,
  });
  const turns = createBoundTurns({ conversations, coordinator });
  const unavailablePool = Object.freeze({
    async callTool() {
      throw Object.assign(new Error('Product tool unavailable'), { code: 'SCOPED_TOOL_UNAVAILABLE' });
    },
  });

  async function execute(operation, input = {}, answerQuestion = false, ownedSimilar = false, ownedSummary = false) {
    const ownedProduct = ownedSimilar || ownedSummary;
    const question=answerQuestion?input.message:undefined;
    const selectedSessionId=answerQuestion||ownedProduct?input.sessionId:undefined;
    const selectedRequestId=answerQuestion||ownedProduct?input.requestId:undefined;
    if (ownedProduct) savedIds(input);
    const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
    if(answerQuestion&&(typeof question!=='string'||!question.trim()||!question.isWellFormed()||question.includes('\0')||Buffer.byteLength(question)>8192
      ||selectedSessionId!==undefined&&!uuid.test(selectedSessionId)||selectedRequestId!==undefined&&!uuid.test(selectedRequestId)))throw Object.assign(new TypeError('Invalid product question'),{code:'INVALID_ARGUMENT'});
      const trustedPersonaSession = input.personaSession === undefined ? undefined : Object.freeze({
        sessionId: input.personaSession?.sessionId, authorityVersion: input.personaSession?.authorityVersion });
    const selectedTool = OPERATIONS[operation];
    const scope = createLaunchScope(input.scope);
    const persona = customerPersona(input.persona);
    const selectedProductId = productId(input.productId);
    const modeToken=await captureFeatureMode(modeAuthority,scope,'product_assist');
    const capturedFence=await personaAuthority?.capture({scope,personaId:persona.id,role:persona.role,sessionId:trustedPersonaSession?.sessionId,authorityVersion:trustedPersonaSession?.authorityVersion});
    const fence=capturedFence?guardFeatureFence(capturedFence,modeToken):undefined;
    const personaEffect=fence?require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence):undefined;
    await personaEffect?.check(scope);
    input.signal?.throwIfAborted();
    let session;
    if(selectedSessionId){await conversations.assertOwned(selectedSessionId,scope,persona,PURPOSES.productAssist);session={id:selectedSessionId};}
    else session = await conversations.create(scope, persona, PURPOSES.productAssist);
    input.signal?.throwIfAborted();
    const requestId = selectedRequestId||randomUUID();
    const authority = Object.freeze({ operation, productId: selectedProductId });
    const policySearchEnabled=modeToken.snapshot.mode!=='fixed'&&operation==='summary'&&policySearch!==undefined;
    const executionConfig = createSecureShopProductExecutionConfig(operation,{policySearchEnabled,mode:modeToken.snapshot.mode,answerQuestion});
    let acceptedObservation = null;
    let acceptedPolicyObservation = null;
    let _policySnapshot = null;
    let finalModel = null; let completedExecution = null;

    const checkedProvider = Object.freeze({
      ...(provider.config ? { config: provider.config } : {}),
      async chat(args) {
        const result = await provider.chat({ ...args, closedToolCatalog: true, maxToolCalls: 1, requireToolCall: true });
        actualModelIdentity(result);
        if (result.stop_reason !== 'tool_use' || !Array.isArray(result.tool_uses)
            || result.tool_uses.length !== 1) throw unavailable('Bound product model did not select a tool');
        return result;
      },
      async finalResponse(args) {
        const result = await provider.finalResponse(args);
        finalModel = actualModelIdentity(result);
        return result;
      },
    });
    let capturedSource = null; let sourceCount = 0;
    let admittedTarget = null;
    const checkCurrent = async () => {
      input.signal?.throwIfAborted();
      await modeToken.assertCurrent();await launches.assertCurrent(scope);await personaEffect?.check(scope);await modeToken.assertCurrent();
      if (ownedProduct && admittedTarget) {
        const selected = await scenes.readRetained(scope);
        if (!equal(selected, admittedTarget)) throw unavailable('Saved product scene changed');
        await modeToken.assertCurrent(); await personaEffect.check(scope);
      }
      input.signal?.throwIfAborted();
    };
    if (ownedProduct) {
      credential(input.personaSession);
      if (!scenes || !fence) throw unavailable('Saved product authority unavailable');
      admittedTarget = await scenes.readRetained(scope); await checkCurrent();
      if (!admittedTarget?.scene || !equal(sceneExecution(admittedTarget), scope)) throw unavailable('Saved product scene unavailable');
    }
    const validateObservation = observation => {
      if(observation.tool==='summarizer.search_policy'&&policySearchEnabled){
        const value=oneJsonToolResult(observation);
        if(value.policyVersion!==_policySnapshot.policyVersion||value.policySnapshotSha256!==_policySnapshot.sha256
          ||typeof value.revisionId!=='string'||!Array.isArray(value.results)||!value.results.length)throw unavailable('Bound policy observation is invalid');
        acceptedPolicyObservation=structuredClone(value);return null;
      }
      if (observation.tool !== selectedTool) throw unavailable('Bound product tool selection is invalid');
      assertExactToolArgs(observation.args, selectedProductId);
      const raw = oneJsonToolResult(observation);
      return operation === 'summary'
        ? summaryObservation(raw, selectedProductId)
        : similarObservation(raw, selectedProductId);
    };
    const runnerConfig = { ...promptPolicyOptions[operation],
      ...(toolPolicyRepository === undefined ? {} : { toolPolicyAdmission: require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({ repository: toolPolicyRepository, workflow: operation === 'summary' ? (policySearchEnabled?'product-summary-policy':'product-summary') : 'product-similar', declaredTools: executionConfig.manifest.getForRole('customer') }) }),
      ...(fence?{capturePersonaAuthority:()=>fence,personaLocalToolModes:{[selectedTool]:'remote_admission',...(policySearchEnabled?{'summarizer.search_policy':'remote_admission'}:{})}}:{}),
      turns,
      conversations,
      repository: conversationRepository,
      journal,
      provider: checkedProvider,
      pool: unavailablePool,
      manifest: executionConfig.manifest,
      buildBasePrompt: executionConfig.buildBasePrompt,
      buildPolicyBlock: executionConfig.buildPolicyBlock,
      checkToolAcl: executionConfig.checkToolAcl,
      conversationPurpose: PURPOSES.productAssist,
      executionScope: answerQuestion?'conversation':'turn',
      limits, captureResultTraces: operation === 'similar' || ownedSummary,
      async createLocalTools(_binding, context, localAuthority) {
        if (!localAuthority || localAuthority.operation !== operation
            || localAuthority.productId !== selectedProductId
            || Object.keys(localAuthority).length !== 2) {
          throw new TypeError('Bound product tool authority required');
        }
        const tools = await createProductTools({ scope, persona, productId: selectedProductId,
          operation, signal: input.signal, checkCurrent, personaEffect, mode:modeToken.snapshot.mode,
          ...(operation === 'similar' ? { captureManualRagSource: value => {
            sourceCount++; capturedSource = structuredClone(value);
          } } : {}) });
        if (!(tools instanceof Map) || tools.size !== 1 || typeof tools.get(selectedTool) !== 'function') {
          throw new TypeError('Bound product tool factory returned an invalid registry');
        }
        const executeTool = tools.get(selectedTool),local=new Map([[selectedTool, async args => {
          assertExactToolArgs(args, selectedProductId);
          await checkCurrent();
          const result = await executeTool(args);
          await checkCurrent();
          return result;
        }]]);
        if(policySearchEnabled){
          _policySnapshot=context.promptPolicySnapshot;
          if(!_policySnapshot||_policySnapshot.recipient!=='summarizer')throw new TypeError('Bound policy snapshot required');
          local.set('summarizer.search_policy',async args=>{
            if(!args||Object.getPrototypeOf(args)!==Object.prototype||Object.keys(args).length!==1||typeof args.query!=='string')throw Object.assign(Error('Invalid policy query'),{code:'INVALID_TOOL_ARGUMENTS'});
            const value=await policySearch.search({scope,persona,query:args.query,policySnapshot:_policySnapshot});
            return {content:[{type:'text',text:JSON.stringify(value)}]};
          });
        }
        return local;
      },
      async enterFinalResponseAfterLocalTool({ localToolAuthority, observation }) {
        if (localToolAuthority !== authority) throw new TypeError('Bound product authority changed');
        if (observation.result?.isError === true) return false;
        const value=validateObservation(observation);
        if(value===null)return false;
        if(policySearchEnabled&&!acceptedPolicyObservation)return false;
        acceptedObservation=value;return true;
      },
      async resultMetadata({ result, execution, binding, sessionId, requestId, traces }) {
        if (result.stopReason === 'cancelled') throw interrupted(input.signal);
        await checkCurrent();
        if (!acceptedObservation || !finalModel) throw unavailable();
        const metadata = { productAssist: { version: 1, operation,...(answerQuestion?{answerQuestion:true}:{}),
          productId: selectedProductId, observation: acceptedObservation,
          provider: finalModel.provider, model: finalModel.model } };
        if (ownedProduct) {
          if (ownedSimilar && capturedSource?.target && !equal(capturedSource.target, JSON.parse(JSON.stringify(admittedTarget))))
            throw unavailable('Selected product source scene changed');
          const hop = result.hops.filter(h => h.tool === selectedTool && h.error === null && h.policyViolation === null);
          if (hop.length !== 1) throw unavailable('Selected product observation unavailable');
          metadata.productAssist = { version: 2, operation, productId: selectedProductId,
            provider: finalModel.provider, model: finalModel.model,
            observationHop: { step: hop[0].step, observationSha256: canonicalDigest(hop[0].result) } };
          if (!equal((ownedSimilar ? similarObservation(resolveProductSimilarObservation(metadata.productAssist, result), selectedProductId)
            : summaryObservation(resolveProductSummaryObservation(metadata.productAssist, result), selectedProductId)), acceptedObservation))
            throw unavailable('Selected product observation changed');
        }
        if (ownedSummary) {
          completedExecution = execution;
          metadata.productSummaryOrigin = { version: 1, binding, personaSession: trustedPersonaSession,
            source: { sessionId, requestId }, runId: execution.runId, traceEventIds: traces.map(row => row.event_id),
            execution: modeToken.snapshot, productId: selectedProductId, target: JSON.parse(JSON.stringify(admittedTarget)) };
        }
        if (operation === 'similar') {
          completedExecution = execution;
          const origin = { version: 1, binding, personaSession: trustedPersonaSession,
            source: { sessionId, requestId }, runId: execution.runId, traceEventIds: traces.map(row => row.event_id),
            execution: modeToken.snapshot, productId: selectedProductId,
            target: capturedSource?.target || (admittedTarget && JSON.parse(JSON.stringify(admittedTarget))),
            lineage: sourceCount === 1 ? capturedSource.lineage : { eligible: false, reason: sourceCount > 1 ? 'multiple_sources' : 'missing_original' } };
          metadata.manualRagConsumerOrigin = origin;
          if (Buffer.byteLength(JSON.stringify(metadata)) > 65536) {
            origin.lineage = { eligible: false, reason: 'metadata_limit' };
            if (Buffer.byteLength(JSON.stringify(metadata)) > 65536) origin.traceEventIds = [];
            if (Buffer.byteLength(JSON.stringify(metadata)) > 65536 && !ownedSimilar) delete metadata.manualRagConsumerOrigin;
          }
        }
        return Object.freeze(metadata);
      },
    };
    if (operation === 'similar' && assessmentFactory) runnerConfig.assessmentFactory = assessmentFactory;
    const runner = createBoundAgentRunner(runnerConfig);
    const result = await runner.run({ sessionId: session.id, requestId, scope, persona,
      message: answerQuestion?`Answer this question about the server-selected product ${selectedProductId}:\n${question}`:operation === 'summary' ? `Summarize product ${selectedProductId}.`
        : `Find products similar to product ${selectedProductId}.`,
      signal: input.signal, personaSession:trustedPersonaSession, localToolAuthority: authority });
    if (result.stopReason === 'cancelled') throw interrupted(input.signal);
    await checkCurrent();
    if (ownedProduct && result.replayed) {
      const saved = await (ownedSimilar ? readSimilar(input) : readSummary(input));
      if (saved.status !== 'completed') throw unavailable('Saved product replay unavailable');
      return saved.result;
    }
    const metadata = result.taskMetadata?.productAssist;
    if (result.stopReason !== 'end_turn' || typeof result.text !== 'string' || !result.text.trim()
        || !metadata || metadata.version !== (ownedProduct ? 2 : 1) || metadata.operation !== operation
        || metadata.productId !== selectedProductId || (answerQuestion&&metadata.answerQuestion!==true) || typeof metadata.provider !== 'string'
        || typeof metadata.model !== 'string') {
      throw unavailable();
    }
    if(answerQuestion)return Object.freeze({product_id:selectedProductId,answer:result.text.trim(),sessionId:session.id,requestId,
      provider:metadata.provider,model:metadata.model,...(result.modeCapability?{modeCapability:result.modeCapability}:{})});
    if (operation === 'summary') {
      const observation = summaryObservation(ownedSummary ? resolveProductSummaryObservation(metadata, result) : metadata.observation, selectedProductId);
      if (ownedSummary && !result.replayed && afterSummaryCommit) {
        try {
          await checkCurrent();
          const { replayed, ...committedResult } = result;
          await afterSummaryCommit({ execution: completedExecution, result: structuredClone(committedResult),
            binding: createConversationBinding(scope, persona), sessionId: session.id, requestId,
            scope, persona, personaSession: trustedPersonaSession, productId: selectedProductId, signal: input.signal });
        } catch { console.warn('SecureShop summary assessment unavailable; completed response retained.'); }
        await checkCurrent();
      }
      return Object.freeze({ ...observation, summary: result.text.trim(),
        provider: metadata.provider, model: metadata.model, ...(result.modeCapability?{modeCapability:result.modeCapability}:{}),
        ...(ownedSummary ? { sessionId: session.id, requestId } : {}) });
    }
    const observation = similarObservation(resolveProductSimilarObservation(metadata, result), selectedProductId);
    // runner.run has now returned through coordinator.finish. The original
    // journal and graph run are both terminal before optional source assessment.
    // Replay never repeats this callback; an assessment error cannot erase the
    // completed ordinary result, while authority checks still fence publication.
    if (!result.replayed && afterSimilarCommit) {
      try {
        await checkCurrent();
        const { replayed, ...committedResult } = result;
        await afterSimilarCommit({ execution: completedExecution, result: structuredClone(committedResult),
          binding: createConversationBinding(scope, persona), sessionId: session.id, requestId,
          scope, persona, personaSession: trustedPersonaSession, productId: selectedProductId, signal: input.signal });
      } catch { console.warn('SecureShop similar assessment unavailable; completed response retained.'); }
      await checkCurrent();
    }
    return Object.freeze({ ...observation, recommendation: result.text.trim(),
      provider: metadata.provider, model: metadata.model, ...(result.modeCapability?{modeCapability:result.modeCapability}:{}),
      ...(ownedSimilar ? { sessionId: session.id, requestId } : {}) });
  }

  const savedUuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
  function savedIds(input) {
    if (!savedUuid.test(input.sessionId || '') || !savedUuid.test(input.requestId || ''))
      throw Object.assign(TypeError('Invalid saved product identity'), { code: 'INVALID_ARGUMENT' });
  }
  function credential(value) {
    if (!value || !savedUuid.test(value.sessionId || '') || typeof value.authorityVersion !== 'string'
        || !/^[1-9]\d*$/.test(value.authorityVersion) || BigInt(value.authorityVersion) > 9223372036854775807n)
      throw Object.assign(TypeError('Product persona session required'), { code: 'INVALID_ARGUMENT' });
    return { sessionId: value.sessionId, authorityVersion: value.authorityVersion };
  }
  async function savedAuthority(input) {
    const scope = createLaunchScope(input.scope), persona = customerPersona(input.persona), selected = productId(input.productId);
    const personaSession = credential(input.personaSession);
    if (!scenes || !personaAuthority) throw unavailable('Saved product authority unavailable');
    const mode = await captureFeatureMode(modeAuthority, scope, 'product_assist');
    const fence = guardFeatureFence(await personaAuthority.capture({ scope, personaId: persona.id, role: persona.role,
      sessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion }), mode);
    const effect = require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence);
    const check = async () => { input.signal?.throwIfAborted(); await mode.assertCurrent(); await launches.assertCurrent(scope);
      await effect.check(scope); await mode.assertCurrent(); input.signal?.throwIfAborted(); };
    await check();
    return { scope, persona, personaSession, selected, mode, check, effect };
  }
  async function createSimilarSession(input = {}, summaryRecovery = false) {
    if (!catalog) throw unavailable('Owned product catalog unavailable');
    const a = await savedAuthority(input);
    const found = await catalog.getProduct({ scope: a.scope, persona: a.persona, productId: a.selected, personaEffect: a.effect });
    await a.check();
    if (!found || found.product?.id !== a.selected) throw Object.assign(Error('Product not found'), { code: 'NOT_FOUND' });
    const session = await conversations.create(a.scope, a.persona, PURPOSES.productAssist); await a.check();
    if (!summaryRecovery) return Object.freeze({ sessionId: session.id });
    const target = await scenes.readRetained(a.scope); await a.check();
    if (!target?.scene || !equal(sceneExecution(target), a.scope)) throw unavailable('Saved product scene unavailable');
    // A lookup namespace only, never authority. Keep IDs from older modes and
    // credentials while deriving the current selection from server state.
    const recoveryKey = canonicalDigest({ version:1, binding:createConversationBinding(a.scope,a.persona),
      personaSession:a.personaSession, productId:a.selected, execution:a.mode.snapshot,
      target:JSON.parse(JSON.stringify(target)) });
    return Object.freeze({ sessionId:session.id, recoveryKey });
  }
  async function readSimilar(input = {}) {
    savedIds(input);
    if (typeof journal.readBoundRequest !== 'function') throw unavailable('Saved product reader unavailable');
    const a = await savedAuthority(input), binding = createConversationBinding(a.scope, a.persona);
    await conversations.assertOwned(input.sessionId, a.scope, a.persona, PURPOSES.productAssist); await a.check();
    const target = await scenes.readRetained(a.scope); await a.check();
    if (!target?.scene || !equal(sceneExecution(target), a.scope)) throw unavailable('Saved product scene unavailable');
    const row = await journal.readBoundRequest({ sessionId: input.sessionId, requestId: input.requestId, binding, purpose: PURPOSES.productAssist });
    await a.check();
    const again = await scenes.readRetained(a.scope); await a.check();
    if (!equal(target, again)) throw unavailable('Saved product scene changed');
    const identity = { sessionId: input.sessionId, requestId: input.requestId };
    if (!row) return Object.freeze({ status: 'not_found', ...identity });
    const request = createTurnRequest({ ...identity, binding, message: `Find products similar to product ${a.selected}.` });
    if (row.session_id !== input.sessionId || row.request_id !== undefined && row.request_id !== input.requestId
        || row.request_version !== 1 || row.request_hash !== request.hash) throw unavailable('Saved product request mismatch');
    if (['started','uncertain'].includes(row.status)) return Object.freeze({ status: 'pending', ...identity });
    const result = row.result_json, metadata = result?.taskMetadata?.productAssist, origin = result?.taskMetadata?.manualRagConsumerOrigin;
    if (row.status !== 'completed' || result?.stopReason !== 'end_turn' || typeof result.text !== 'string' || !result.text.trim()
        || ![1,2].includes(metadata?.version) || metadata.operation !== 'similar' || metadata.productId !== a.selected
        || !origin || origin.version !== 1 || !equal(origin.binding, binding) || !equal(origin.personaSession, a.personaSession)
        || !equal(origin.source, identity) || origin.productId !== a.selected || !equal(origin.execution, a.mode.snapshot)
        || !equal(origin.target, JSON.parse(JSON.stringify(target))) || !savedUuid.test(origin.runId || '')
        || typeof metadata.provider !== 'string' || !metadata.provider || typeof metadata.model !== 'string' || !metadata.model)
      throw unavailable('Saved product result mismatch');
    let observation;
    try { observation = similarObservation(resolveProductSimilarObservation(metadata, result), a.selected); }
    catch { throw unavailable('Saved product observation mismatch'); }
    await a.check();
    return Object.freeze({ status: 'completed', result: Object.freeze({ ...observation, recommendation: result.text.trim(),
      provider: metadata.provider, model: metadata.model, ...(result.modeCapability ? {modeCapability:result.modeCapability} : {}), ...identity }) });
  }
  async function readSummary(input = {}) {
    savedIds(input);
    if (typeof journal.readBoundRequest !== 'function') throw unavailable('Saved product reader unavailable');
    const a = await savedAuthority(input), binding = createConversationBinding(a.scope, a.persona);
    await conversations.assertOwned(input.sessionId, a.scope, a.persona, PURPOSES.productAssist); await a.check();
    const target = await scenes.readRetained(a.scope); await a.check();
    if (!target?.scene || !equal(sceneExecution(target), a.scope)) throw unavailable('Saved product scene unavailable');
    const row = await journal.readBoundRequest({ sessionId: input.sessionId, requestId: input.requestId, binding, purpose: PURPOSES.productAssist });
    await a.check();
    const again = await scenes.readRetained(a.scope); await a.check();
    if (!equal(target, again)) throw unavailable('Saved product scene changed');
    const identity = { sessionId: input.sessionId, requestId: input.requestId };
    if (!row) return Object.freeze({ status: 'not_found', ...identity });
    const request = createTurnRequest({ ...identity, binding, message: `Summarize product ${a.selected}.` });
    if (row.session_id !== input.sessionId || row.request_id !== undefined && row.request_id !== input.requestId
        || row.request_version !== 1 || row.request_hash !== request.hash) throw unavailable('Saved product request mismatch');
    if (['started','uncertain'].includes(row.status)) return Object.freeze({ status: 'pending', ...identity });
    const result = row.result_json, metadata = result?.taskMetadata?.productAssist, origin = result?.taskMetadata?.productSummaryOrigin;
    if (row.status !== 'completed' || result?.stopReason !== 'end_turn' || typeof result.text !== 'string' || !result.text.trim()
        || metadata?.version !== 2 || metadata.operation !== 'summary' || metadata.productId !== a.selected
        || !origin || origin.version !== 1 || !equal(origin.binding, binding) || !equal(origin.personaSession, a.personaSession)
        || !equal(origin.source, identity) || origin.productId !== a.selected || !equal(origin.execution, a.mode.snapshot)
        || !equal(origin.target, JSON.parse(JSON.stringify(target))) || !savedUuid.test(origin.runId || '')
        || typeof metadata.provider !== 'string' || !metadata.provider || typeof metadata.model !== 'string' || !metadata.model)
      throw unavailable('Saved product result mismatch');
    let observation;
    try { observation = summaryObservation(resolveProductSummaryObservation(metadata, result), a.selected); }
    catch { throw unavailable('Saved product observation mismatch'); }
    await a.check();
    return Object.freeze({ status: 'completed', result: Object.freeze({ ...observation, summary: result.text.trim(),
      provider: metadata.provider, model: metadata.model, ...(result.modeCapability ? {modeCapability:result.modeCapability} : {}), ...identity }) });
  }
  return Object.freeze({
    purpose: PURPOSES.productAssist,
    summary: input => execute('summary', input),
    question: input => execute('summary', input, true),
    similar: input => execute('similar', input),
    runSimilar: input => execute('similar', input, false, true),
    createSimilarSession, readSimilar,
    createSummarySession: input => createSimilarSession(input, true),
    runSummary: input => execute('summary', input, false, false, true),
    readSummary,
  });
}

module.exports = { createSecureShopBoundProductAssist };
