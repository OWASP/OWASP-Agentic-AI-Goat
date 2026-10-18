'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { executionScope } = require('./secureshopSceneBinding');
const { guardFeatureFence, POLICIES } = require('./secureshopFeatureModeAuthority');
const { createBoundCouponProbeGraph, PURPOSE, TOOL, MAX_PROBES, operationId, publicObservation } = require('./secureshopBoundCouponProbeGraph');
const Protocol = require('./secureshopCouponProbeContract');
const Coupon = require('./secureshopCouponContract');
const Request = require('./secureshopCouponProbeRequest');
const Arithmetic = require('./secureshopCouponProbeArithmetic');

const fail = () => Object.assign(new Error('Coupon investigation unavailable'),
  { code: 'COUPON_PROBE_UNAVAILABLE', executionBoundary: true });
function ids(input) {
  if (![input.sessionId, input.requestId].every(value => typeof value === 'string' && Coupon.UUID.test(value))) throw fail();
  return { sessionId: input.sessionId.toLowerCase(), requestId: input.requestId.toLowerCase() };
}
function createCouponProbeApplication({ captureCurrent, personaAuthority, modeAuthority, launches,
  conversationRepository, journal, coordinator, provider, probeService, readCoupons, agentsPool,
  promptPolicyRepository, toolPolicyRepository, assertActorAvailable } = {}) {
  if ([captureCurrent, personaAuthority?.capture, modeAuthority?.assertToken, launches?.assertCurrent,
    agentsPool?.query].some(fn => typeof fn !== 'function')) throw TypeError('Coupon probe authority required');
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const graph = createBoundCouponProbeGraph({ conversations, conversationRepository, journal, coordinator,
    provider, probeService, readCoupons, promptPolicyRepository, personaAuthority, toolPolicyRepository, assertActorAvailable });
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
    for (const [token, feature] of [[raw.mode, 'customer_chat'], [raw.couponMode, 'coupons']]) {
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
      await raw.mode.assertCurrent(); await raw.couponMode.assertCurrent();
      await fence.assertRemoteAdmission(); signal?.throwIfAborted();
    };
    await check();
    const personaFence = guardFeatureFence({ ...fence, assertRemoteAdmission: check }, raw.couponMode);
    const scene = raw.target.scene;
    const sourceBinding = Object.freeze({ sceneId: scene.sceneId, sceneGeneration: scene.sceneGeneration,
      grantId: scene.grantId, productTargetId: raw.target.targetId,
      personaSession, customerMode: structuredClone(raw.mode.snapshot), couponMode: structuredClone(raw.couponMode.snapshot) });
    return { state: Object.freeze({ scope, persona, personaSession, target: raw.target,
      mode: raw.mode, couponMode: raw.couponMode, check, personaFence, sourceBinding }), check };
  }
  function validateSaved(state, pair, result) {
    const m = result?.taskMetadata?.couponProbe;
    const identity = Request.saved(m);
    if (m?.version !== Request.version(identity.protocol) || m.purpose !== PURPOSE || m.sessionId !== pair.sessionId || m.requestId !== pair.requestId
      || !['end_turn', ...(identity.protocol === Request.GUIDED_V2 ? ['incomplete'] : [])].includes(result.stopReason)
      || !equal(m.sourceBinding, state.sourceBinding)
      || typeof result.text !== 'string' || !result.text.trim() || Buffer.byteLength(result.text) > 65536
      || !m.finalModel || m.finalModel.mocked !== false || m.finalModel.fallback !== false
      || typeof m.finalModel.provider !== 'string' || typeof m.finalModel.model !== 'string'
      || !m.finalModel.provider || !m.finalModel.model
      || !Array.isArray(m.probes) || m.probes.length > (identity.protocol ? 7 : MAX_PROBES) || !Array.isArray(m.couponBank)
      || !Array.isArray(m.traceEventIds) || !m.traceEventIds.length || m.traceEventIds.length > 256
      || m.traceEventIds.some(id => !Coupon.UUID.test(id)) || new Set(m.traceEventIds).size !== m.traceEventIds.length
      || !Coupon.UUID.test(m.execution?.runId || '')
      || m.execution.ownerKey !== JSON.stringify(['SecureShopBoundConversation', pair.sessionId])
      || typeof m.execution.generation !== 'string' || !/^(0|[1-9][0-9]*)$/.test(m.execution.generation)
      || new Set(m.probes.map(p => p?.operationId)).size !== m.probes.length
      || new Set(m.probes.map(p => p?.execution?.callId)).size !== m.probes.length) throw fail();
    const arithmetic = identity.protocol === Request.GUIDED_V2 ? m.arithmetic : null;
    const continuation = identity.protocol === Request.GUIDED_V2 ? m.continuation : undefined;
    if (identity.protocol === Request.GUIDED_V2) {
      if (!Object.hasOwn(m, 'arithmetic')) throw fail();
      if (continuation !== undefined && (!continuation || !equal(continuation,
        { version: 1, reason: 'missing_contrast', afterSql: 6 })
        || m.probes.length < 6 || !m.probes[5].receipt?.result?.coupon)) throw fail();
      if (continuation !== undefined && result.stopReason === 'end_turn' && m.probes.length !== 7) throw fail();
      if (result.stopReason === 'incomplete' && (continuation === undefined || m.probes.length !== 6)) throw fail();
      if (arithmetic !== null) {
        if (m.probes.length < 5 || !arithmetic || typeof arithmetic !== 'object'
          || arithmetic.execution?.step !== 6 || arithmetic.execution.runId !== m.execution.runId
          || arithmetic.execution.ownerKey !== m.execution.ownerKey
          || arithmetic.execution.generation !== m.execution.generation
          || arithmetic.execution.sessionId !== pair.sessionId
          || arithmetic.execution.requestId !== pair.requestId
          || typeof arithmetic.execution.callId !== 'string' || !arithmetic.execution.callId
          || m.probes.some(p => p.execution.callId === arithmetic.execution.callId)) throw fail();
        let recorded; try { recorded = Arithmetic.validateRecordedResult(m.probes.slice(0, 5),
          arithmetic.args, arithmetic.result); }
        catch { throw fail(); }
        if (arithmetic.observation?.tool !== Arithmetic.TOOL
          || arithmetic.observation.step !== arithmetic.execution.step
          || arithmetic.observation.callId !== arithmetic.execution.callId
          || !equal(arithmetic.observation.args, arithmetic.args)
          || !equal(arithmetic.observation.result, { content: [{ type: 'text', text: JSON.stringify(recorded) }] })
          || !equal(arithmetic.observation.effectReceipt, { version: 1, status: 'completed', ...m.execution,
            effectKey: `${pair.requestId}:${JSON.stringify([6, arithmetic.execution.callId, Arithmetic.TOOL])}` })) throw fail();
      }
    } else if (Object.hasOwn(m, 'arithmetic') || Object.hasOwn(m, 'continuation')) throw fail();
    for (const [index, probe] of m.probes.entries()) {
      if (probe.execution?.runId !== m.execution.runId || probe.execution.ownerKey !== m.execution.ownerKey
        || probe.execution.generation !== m.execution.generation || probe.execution.sessionId !== pair.sessionId
        || probe.execution.requestId !== pair.requestId
        || probe.execution.step !== index + 1 + (arithmetic && index >= 5 ? 1 : 0)
          + (continuation && index >= 6 ? 1 : 0)
        || probe.operationId !== operationId({ ...probe.execution }) || !equal(probe.receipt?.scope, state.scope)
        || (index && (probe.receipt.targetId !== m.probes[0].receipt.targetId
          || probe.receipt.sourceManifestSha256 !== m.probes[0].receipt.sourceManifestSha256))) throw fail();
      Protocol.receipt(probe.receipt, Protocol.request({ version: 1, lookup: { scope: state.scope,
        operationId: probe.operationId, persona: state.persona, personaSession: state.personaSession,
        mode: state.couponMode.snapshot.mode, code: probe.code, coupons: m.couponBank }, execution: probe.execution }));
      const observation = probe.observation;
      if (observation?.step !== probe.execution.step || observation.callId !== probe.execution.callId
        || observation.tool !== TOOL || !equal(observation.args, { code: probe.code })
        || !equal(observation.result, { content: [{ type: 'text', text: JSON.stringify(publicObservation(probe.code, probe.receipt)) }] })
        || !equal(observation.effectReceipt, { version: 1, status: 'completed', ...m.execution,
          effectKey: `${pair.requestId}:${JSON.stringify([probe.execution.step, probe.execution.callId, TOOL])}` })) throw fail();
    }
    Request.saved(m);
    return m;
  }
  function project(state, pair, result, replayed) {
    const m = validateSaved(state, pair, result);
    return Object.freeze({ status: result.stopReason === 'incomplete' ? 'incomplete' : 'completed',
      ...pair, text: result.text, provider: m.finalModel.provider, model: m.finalModel.model,
      stopReason: result.stopReason,
      probes: m.probes.map(p => publicObservation(p.code, p.receipt)), replayed });
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
      createTurnRequest({ ...pair, binding: createConversationBinding(state.scope, state.persona), message: Request.encode(input.message,input.protocol) });
      const result = await graph.run(state, { ...pair, message: Request.encode(input.message,input.protocol), originalMessage: input.message, protocol: Request.protocol(input.protocol), signal: input.signal });
      Request.assertReplay(result?.taskMetadata?.couponProbe,input.message,input.protocol);
      await check(); return project(state, pair, result, result.replayed === true);
    },
    async read(input) {
      const pair = ids(input), source = await saved(input, input, true);
      return source ? project(source.state, pair, source.turn, true) : Object.freeze({ status: 'unconfirmed', ...pair });
    },
    readSavedSource(context, selectors) { return saved(context, selectors, false); },
  });
}
module.exports = { createCouponProbeApplication };
