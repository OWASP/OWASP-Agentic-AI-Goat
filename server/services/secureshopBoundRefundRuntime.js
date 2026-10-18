'use strict';
const { randomUUID } = require('node:crypto');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('./secureshopConversationPurpose');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { createSecureShopBoundRefundTools } = require('./secureshopBoundRefundTools');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { isDeepStrictEqual } = require('node:util');
const { captureFeatureMode, guardFeatureFence, featureModeForFence } = require('./secureshopFeatureModeAuthority');
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function invalidAuthority() { return Object.assign(new Error('Refund persona authority required'),
  { code: 'SHOP_AUTH_INVALID', executionBoundary: true }); }
function admittedRefundIntent(message) {
  if (typeof message !== 'string' || /\b(?:do not|don't|never|cancel|no)\s+(?:a\s+)?refund\b/i.test(message)
      || !/^(?:\s*please\s+)?(?:refund|return)\b|^\s*i\s+(?:want|need|would like|am requesting)\s+(?:a\s+)?refund\b|^\s*(?:can|could|would)\s+you\s+refund\b/i.test(message)) return null;
  const matches = [...message.matchAll(/\border\s*(?:number\s*)?#?\s*(\d{1,10})\b/gi)];
  if (matches.length !== 1) return null;
  const orderId = Number(matches[0][1]);
  if (!Number.isSafeInteger(orderId) || orderId < 1 || orderId > 2147483647) return null;
  const explicitReason = /\b(?:because|reason\s*:)\s*(.{1,1024})$/is.exec(message)?.[1]?.trim();
  const reason = explicitReason && Buffer.byteLength(explicitReason, 'utf8') <= 4096
    ? explicitReason : `Customer requested a refund for order ${orderId}`;
  return Object.freeze({ orderId, reason });
}
function createSecureShopBoundRefundRuntime({ launches, conversationRepository, journal, coordinator,
  provider, manifest, buildBasePrompt, buildPolicyBlock, checkToolAcl, refundRepository, commerce,
  resolveTarget, resolveExistingTarget, resolveRetainedTarget, createToolPool, authenticatePersona, personaAuthority, toolPolicyRepository, promptPolicyRepository,
  modeAuthority = null, limits = { maxSteps: 4, maxParallelTools: 1 } } = {}) {
  const promptPolicyOptions = require('./secureshopPromptPolicyRunnerOptions').promptPolicyRunnerOptions(promptPolicyRepository, personaAuthority);
  if (toolPolicyRepository !== undefined && (typeof toolPolicyRepository?.admitTool !== 'function'
      || typeof personaAuthority?.capture !== 'function')) throw new TypeError('Policy repository and persona authority required');
  if (typeof launches?.assertCurrent !== 'function' || typeof coordinator?.run !== 'function'
      || typeof authenticatePersona !== 'function' || typeof resolveTarget !== 'function') throw new TypeError('Refund runtime authority required');
  if(personaAuthority!==undefined&&typeof personaAuthority?.capture!=='function')throw TypeError('Candidate persona authority required');
  if(resolveRetainedTarget!==undefined&&(typeof resolveRetainedTarget!=='function'||!personaAuthority))throw TypeError('Retained refund scene authority required');
  if (modeAuthority !== null && modeAuthority !== undefined && typeof personaAuthority?.capture !== 'function') {
    throw new TypeError('Feature mode requires refund persona authority');
  }
  const capturePersonaAuthority=personaAuthority?async({binding,personaSession})=>{
    const token = await captureFeatureMode(modeAuthority, binding, 'refund', 'vuln');
    const fence = await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,
      sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});
    if(!fence||!resolveRetainedTarget)return fence ? guardFeatureFence(fence, token) : fence;
    const stale=()=>Object.assign(new Error('Refund practice is unavailable'),{code:'SHOP_SCENE_STALE',executionBoundary:true});
    const read=async()=>{
      await launches.assertCurrent(binding);await fence.assertRemoteAdmission();
      let target;
      try{target=await resolveRetainedTarget(binding);}catch(cause){
        throw Object.assign(new Error('Refund practice authority unavailable'),{
          code:cause?.code||'SHOP_SCENE_STALE',executionBoundary:true,cause});
      }
      await launches.assertCurrent(binding);await fence.assertRemoteAdmission();
      if(!target||!SESSION_ID.test(target.targetId||'')
        ||!isDeepStrictEqual(createLaunchScope(executionScope(target)),createLaunchScope(binding)))throw stale();
      return {targetId:target.targetId,scene:target.scene?{
        sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration,grantId:target.scene.grantId}:null};
    };
    const original=await read();
    // A shared-practice reset can retire the product scene while the launch
    // and persona remain live. Fence before provider admission, not only when
    // a later model-selected tool finally resolves a product target.
    return guardFeatureFence({...fence,async assertRemoteAdmission(){
      if(!isDeepStrictEqual(await read(),original))throw stale();
    }},token);
  }:undefined;
  async function captureSessionAuthority(binding, personaSession) {
    if (!capturePersonaAuthority) return undefined;
    if (typeof personaSession?.sessionId !== 'string' || !SESSION_ID.test(personaSession.sessionId)
        || typeof personaSession.authorityVersion !== 'string'
        || !/^[1-9]\d*$/.test(personaSession.authorityVersion)) throw invalidAuthority();
    const credential = Object.freeze({ sessionId: personaSession.sessionId.toLowerCase(),
      authorityVersion: personaSession.authorityVersion });
    const fence = await capturePersonaAuthority({ binding, personaSession: credential });
    const actual = fence?.binding;
    if (typeof fence?.assertRemoteAdmission !== 'function' || !actual
        || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
          .some(key => actual[key] !== binding[key])
        || actual.personaId !== binding.shopUserId || actual.role !== binding.role
        || actual.sessionId !== credential.sessionId
        || actual.authorityVersion !== credential.authorityVersion) throw invalidAuthority();
    return fence;
  }
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  const pool = createToolPool || (() => ({ async callTool() { throw Object.assign(new Error('Tool unavailable'), { code: 'SCOPED_TOOL_UNAVAILABLE' }); } }));
  const refundManifest = Object.freeze({ getForRole: role => role === 'customer' ? [
    { agent: 'support', tool: 'order_status', description: 'Read the current customer order before acting.', inputSchema: { type: 'object', properties: { order_id: { type: 'integer', minimum: 1 } }, required: ['order_id'], additionalProperties: false } },
    { agent: 'support', tool: 'refund_request', description: 'File one support refund request for an eligible owned order.', inputSchema: { type: 'object', properties: { order_id: { type: 'integer', minimum: 1 }, reason: { type: 'string', minLength: 1, maxLength: 4096 } }, required: ['order_id', 'reason'], additionalProperties: false } },
  ] : [] });
  const trustedIntents = new WeakMap();
  const innerRunner = createBoundAgentRunner({ turns, conversations, ...promptPolicyOptions, repository: conversationRepository, journal,
    ...(capturePersonaAuthority?{capturePersonaAuthority,personaLocalToolModes:{'support.order_status':'remote_admission','support.refund_request':'remote_admission'}}:{}),
    ...(toolPolicyRepository === undefined ? {} : { toolPolicyAdmission: require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({ repository: toolPolicyRepository, workflow: 'refund', declaredTools: refundManifest.getForRole('customer') }) }),
    conversationPurpose: PURPOSES.refundRequest, buildBasePrompt, buildPolicyBlock, checkToolAcl, provider,
    createToolPool: pool, manifest: refundManifest, limits, executionScope: 'turn',
    createLocalTools: (binding, context, localToolAuthority, _execution, personaFence) => new Map(Object.entries(createSecureShopBoundRefundTools({
      repository: personaFence?require('./secureshopPersonaRefundEffect').createPersonaRefundEffect({fence:personaFence,repository:refundRepository}):refundRepository, commerce: personaFence ? {
        order: input => commerce.order({ ...input, personaSession: Object.freeze({
          sessionId: personaFence.binding.sessionId, authorityVersion: personaFence.binding.authorityVersion }) }),
      } : commerce, binding: { requestId: localToolAuthority?.requestId || context?.requestId, runId: localToolAuthority?.runId || context?.runId || null }, persona: { id: binding.shopUserId, role: binding.role },
      scope: binding, checkCurrent: async value => { await launches.assertCurrent(value); await personaFence?.assertRemoteAdmission(); }, resolveTarget,
      mode: featureModeForFence(personaFence)?.effectiveMode || 'vuln',
      fixedIntent: trustedIntents.get(localToolAuthority) || null,
    }))),
  });
  const runner = Object.freeze({
    run(input) {
      // The caller supplies only the customer message. Never accept a claimed
      // order, reason, run identity, or alternate effect request ID from model
      // args, request DTOs, or an existing ticket. The journal turn and local
      // effect must use the same request UUID.
      const privateAuthority = Object.freeze({
        ...(input?.requestId ? { requestId: input.requestId } : {}),
      });
      trustedIntents.set(privateAuthority, admittedRefundIntent(input?.message));
      return innerRunner.run({ ...input, localToolAuthority: privateAuthority });
    },
  });
  return Object.freeze({ purpose: PURPOSES.refundRequest, conversations, runner,
    async readRequest(scope, persona, personaSession, sessionId, requestId) {
      const binding = createConversationBinding(scope, persona);
      if (typeof sessionId !== 'string' || !SESSION_ID.test(sessionId)
          || typeof requestId !== 'string' || !SESSION_ID.test(requestId)) {
        throw Object.assign(new TypeError('Invalid refund reference'), { code: 'INVALID_ARGUMENT' });
      }
      if (typeof journal?.readBoundRequest !== 'function' || typeof refundRepository?.readRequest !== 'function'
          || typeof resolveExistingTarget !== 'function') throw Object.assign(new Error('Refund recovery unavailable'), { code: 'SERVICE_UNAVAILABLE' });
      const fence = await captureSessionAuthority(binding, personaSession);
      await fence?.assertRemoteAdmission();
      await conversations.assertOwned(sessionId.toLowerCase(), binding, persona, PURPOSES.refundRequest);
      const turn = await journal.readBoundRequest({ sessionId: sessionId.toLowerCase(),
        requestId: requestId.toLowerCase(), binding, purpose: PURPOSES.refundRequest });
      if (!turn) { await fence?.assertRemoteAdmission(); return Object.freeze({ requestId: requestId.toLowerCase(), status: 'unconfirmed' }); }
      if (!['started', 'uncertain', 'completed'].includes(turn.status)) throw Object.assign(new Error('Refund recovery unavailable'), { code: 'SERVICE_UNAVAILABLE' });
      const target = await resolveExistingTarget(binding);
      if (!target) { await fence?.assertRemoteAdmission(); return Object.freeze({ requestId: requestId.toLowerCase(), status: 'unconfirmed' }); }
      const receipt = await refundRepository.readRequest(target, { requestId: requestId.toLowerCase(),
        shopUserId: binding.shopUserId, personaSessionId: personaSession?.sessionId,
        authorityVersion: personaSession?.authorityVersion });
      // Refund receipts identify the admitted turn UUID. A second retained
      // conversation claiming that UUID during the cross-store read makes its
      // provenance ambiguous, even if the first lookup was unique.
      const reaffirmed = await journal.readBoundRequest({ sessionId: sessionId.toLowerCase(),
        requestId: requestId.toLowerCase(), binding, purpose: PURPOSES.refundRequest });
      if (!reaffirmed || reaffirmed.request_hash !== turn.request_hash
          || reaffirmed.request_version !== turn.request_version) {
        throw Object.assign(new Error('Refund recovery unavailable'), { code: 'TURN_REQUEST_CONFLICT' });
      }
      await conversations.assertOwned(sessionId.toLowerCase(), binding, persona, PURPOSES.refundRequest);
      await fence?.assertRemoteAdmission();
      return receipt ? Object.freeze({ requestId: requestId.toLowerCase(), status: 'saved', ...receipt })
        : Object.freeze({ requestId: requestId.toLowerCase(), status: 'unconfirmed' });
    },
    async createSession(scope, persona, personaSession) {
      const binding = createConversationBinding(scope, persona);
      const fence = await captureSessionAuthority(binding, personaSession);
      await fence?.assertRemoteAdmission();
      const session = await conversations.create(binding,
        Object.freeze({ id: binding.shopUserId, role: binding.role }), PURPOSES.refundRequest);
      // A revocation racing the durable conversation insert can leave an inert
      // orphan.  Never return that session as admitted after authority changed.
      await fence?.assertRemoteAdmission();
      return session;
    },
    newRequestId: randomUUID,
  });
}
module.exports = { createSecureShopBoundRefundRuntime };
