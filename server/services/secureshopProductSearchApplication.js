'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { executionScope } = require('./secureshopSceneBinding');
const { guardFeatureFence, POLICIES } = require('./secureshopFeatureModeAuthority');
const { createBoundProductSearchGraph, PURPOSE, TOOL, MAX_SEARCHES, operationId, publicObservation } = require('./secureshopBoundProductSearchGraph');
const Protocol = require('./secureshopProductSearchSqlContract');
const Coupon = require('./secureshopCouponContract');

const fail = () => Object.assign(new Error('Product search unavailable'),
  { code: 'PRODUCT_SEARCH_UNAVAILABLE', executionBoundary: true });
function ids(input) {
  if (![input.sessionId, input.requestId].every(value => typeof value === 'string' && Coupon.UUID.test(value))) throw fail();
  return { sessionId: input.sessionId.toLowerCase(), requestId: input.requestId.toLowerCase() };
}
function createProductSearchApplication({ captureCurrent, personaAuthority, modeAuthority, launches,
  conversationRepository, journal, coordinator, provider, searchService, agentsPool,
  promptPolicyRepository, toolPolicyRepository, assertActorAvailable } = {}) {
  if ([captureCurrent, personaAuthority?.capture, modeAuthority?.assertToken, launches?.assertCurrent,
    agentsPool?.query].some(fn => typeof fn !== 'function')) throw TypeError('Product search authority required');
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const graph = createBoundProductSearchGraph({ conversations, conversationRepository, journal, coordinator,
    provider, searchService, promptPolicyRepository, personaAuthority, toolPolicyRepository, assertActorAvailable });
  async function current(context, { signal } = {}) {
    signal?.throwIfAborted();
    const raw = await captureCurrent(context), scope = createLaunchScope(raw?.scope);
    const b = createConversationBinding(scope, raw.persona), persona = Object.freeze({ id: b.shopUserId, role: b.role });
    const credential = raw.personaSession;
    if (persona.role !== 'customer' || typeof raw.check !== 'function' || !raw.target?.scene
      || !equal(createLaunchScope(executionScope(raw.target)), scope)
      || !equal(createLaunchScope(context.scope), scope) || !equal(context.persona, persona)
      || !equal(context.personaSession, credential) || !Coupon.UUID.test(credential?.sessionId || '')
      || typeof credential.authorityVersion !== 'string' || !/^[1-9][0-9]*$/.test(credential.authorityVersion)) throw fail();
    const personaSession = Object.freeze({ sessionId: credential.sessionId, authorityVersion: credential.authorityVersion });
    for (const [token, feature] of [[raw.mode, 'customer_chat'], [raw.searchMode, 'product_search']]) {
      modeAuthority.assertToken(token);
      if (token.snapshot?.version !== 1 || token.snapshot.featureId !== feature
        || token.snapshot.policyVersion !== POLICIES[feature] || !equal(token.snapshot.scope, scope)
        || !['vuln', 'fixed'].includes(token.snapshot.mode)) throw fail();
    }
    const fence = await personaAuthority.capture({ scope, personaId: persona.id, role: persona.role,
      sessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion });
    if (!equal(fence.binding, { ...scope, personaId: persona.id, role: persona.role, ...personaSession })) throw fail();
    const check = async () => {
      signal?.throwIfAborted(); await launches.assertCurrent(scope); await raw.check();
      await raw.mode.assertCurrent(); await raw.searchMode.assertCurrent();
      await fence.assertRemoteAdmission(); signal?.throwIfAborted();
    };
    await check();
    const personaFence = guardFeatureFence({ ...fence, assertRemoteAdmission: check }, raw.searchMode);
    const scene = raw.target.scene;
    const sourceBinding = Object.freeze({ sceneId: scene.sceneId, sceneGeneration: scene.sceneGeneration,
      grantId: scene.grantId, productTargetId: raw.target.targetId,
      personaSession, customerMode: structuredClone(raw.mode.snapshot), searchMode: structuredClone(raw.searchMode.snapshot) });
    return { state: Object.freeze({ scope, persona, personaSession, target: raw.target,
      mode: raw.mode, searchMode: raw.searchMode, check, personaFence, sourceBinding }), check };
  }
  function validateSaved(state, pair, result) {
    const m = result?.taskMetadata?.productSearch;
    if (m?.version !== 1 || m.purpose !== PURPOSE || m.sessionId !== pair.sessionId || m.requestId !== pair.requestId
      || result.stopReason !== 'end_turn' || !equal(m.sourceBinding, state.sourceBinding)
      || typeof result.text !== 'string' || !result.text.trim() || Buffer.byteLength(result.text) > 65536
      || !m.finalModel || m.finalModel.mocked !== false || m.finalModel.fallback !== false
      || typeof m.finalModel.provider !== 'string' || typeof m.finalModel.model !== 'string'
      || !m.finalModel.provider || !m.finalModel.model
      || !Array.isArray(m.searches) || m.searches.length > MAX_SEARCHES
      || !Array.isArray(m.traceEventIds) || !m.traceEventIds.length || m.traceEventIds.length > 256
      || m.traceEventIds.some(id => !Coupon.UUID.test(id)) || new Set(m.traceEventIds).size !== m.traceEventIds.length
      || !Coupon.UUID.test(m.execution?.runId || '')
      || m.execution.ownerKey !== JSON.stringify(['SecureShopBoundConversation', pair.sessionId])
      || typeof m.execution.generation !== 'string' || !/^(0|[1-9][0-9]*)$/.test(m.execution.generation)
      || new Set(m.searches.map(p => p?.operationId)).size !== m.searches.length
      || new Set(m.searches.map(p => p?.execution?.callId)).size !== m.searches.length) throw fail();
    for (const [index, search] of m.searches.entries()) {
      if (search.execution?.runId !== m.execution.runId || search.execution.ownerKey !== m.execution.ownerKey
        || search.execution.generation !== m.execution.generation || search.execution.sessionId !== pair.sessionId
        || search.execution.requestId !== pair.requestId || search.execution.step !== index + 1
        || search.operationId !== operationId({ ...search.execution }) || !equal(search.receipt?.scope, state.scope)
        || (index && (search.receipt.targetId !== m.searches[0].receipt.targetId
          || search.receipt.sourceManifestSha256 !== m.searches[0].receipt.sourceManifestSha256))) throw fail();
      Protocol.receipt(search.receipt, Protocol.request({ version: 1, search: { scope: state.scope,
        operationId: search.operationId, persona: state.persona, personaSession: state.personaSession,
        mode: state.searchMode.snapshot.mode, ...search.search }, execution: search.execution }));
      const observation = search.observation;
      if (observation?.step !== search.execution.step || observation.callId !== search.execution.callId
        || observation.tool !== TOOL || !equal(observation.args, search.args)
        || !equal(observation.result, { content: [{ type: 'text', text: JSON.stringify(publicObservation(search.search, search.receipt)) }] })
        || !equal(observation.effectReceipt, { version: 1, status: 'completed', ...m.execution,
          effectKey: `${pair.requestId}:${JSON.stringify([search.execution.step, search.execution.callId, TOOL])}` })) throw fail();
    }
    return m;
  }
  function project(state, pair, result, replayed) {
    const m = validateSaved(state, pair, result);
    return Object.freeze({ status: 'completed', ...pair, text: result.text,
      provider: m.finalModel.provider, model: m.finalModel.model, stopReason: 'end_turn',
      searches: m.searches.map(p => publicObservation(p.search, p.receipt)), replayed });
  }
  async function saved(context, selectors, allowMissing) {
    const pair = ids(selectors), { state, check } = await current(context, selectors);
    await conversations.assertOwned(pair.sessionId, state.scope, state.persona, PURPOSE); await check();
    const s = state.scope;
    const rows = (await agentsPool.query(`SELECT tr.session_id,tr.request_id,tr.request_hash,tr.request_version,tr.status,tr.result_json
      FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
      WHERE tr.session_id=$1 AND tr.request_id=$2 AND s.conversation_purpose=$3
      AND s.authority_mode='launch_bound' AND s.binding_state='active'
      AND s.platform_launch_id=$4 AND s.platform_scenario_id=$5 AND s.platform_launch_generation=$6
      AND s.original_platform_owner_id=$7 AND s.original_platform_session_id=$8 AND s.user_id=$9 AND s.role=$10`,
    [pair.sessionId, pair.requestId, PURPOSE, s.launchId, s.scenarioId, s.generation,
      s.platformOwnerId, s.platformSessionId, state.persona.id, state.persona.role])).rows;
    await check(); if (!Array.isArray(rows) || rows.length > 1) throw fail();
    if (!rows.length) { if (allowMissing) return null; throw fail(); }
    const row = rows[0];
    if (row.status !== 'completed' || row.session_id !== pair.sessionId || row.request_id !== pair.requestId) throw fail();
    const m = validateSaved(state, pair, row.result_json);
    const request = createTurnRequest({ ...pair, binding: createConversationBinding(state.scope, state.persona),
      message: m.message, version: row.request_version });
    if (request.hash !== row.request_hash) throw fail();
    await check(); return { state, check, savedRequest: { status: row.status, requestVersion: row.request_version,
      requestHash: row.request_hash, message: m.message }, turn: row.result_json };
  }
  return Object.freeze({ current,
    async createSession(context) {
      const { state, check } = await current(context, context);
      const session = await conversations.create(state.scope, state.persona, PURPOSE); await check();
      return Object.freeze({ sessionId: session.id });
    },
    async run(input) {
      const pair = ids(input), { state, check } = await current(input, input);
      createTurnRequest({ ...pair, binding: createConversationBinding(state.scope, state.persona), message: input.message });
      const result = await graph.run(state, { ...pair, message: input.message, signal: input.signal });
      await check(); return project(state, pair, result, result.replayed === true);
    },
    async read(input) {
      const pair = ids(input), source = await saved(input, input, true);
      return source ? project(source.state, pair, source.turn, true) : Object.freeze({ status: 'unconfirmed', ...pair });
    },
    readSavedSource(context, selectors) { return saved(context, selectors, false); },
  });
}
module.exports = { createProductSearchApplication };
