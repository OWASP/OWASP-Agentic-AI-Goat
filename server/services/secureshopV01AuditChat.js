'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { captureFeatureMode, guardFeatureFence, projectFeatureMode } = require('./secureshopFeatureModeAuthority');
const { createTurnRequest } = require('./secureshopTurnRequest');

const PURPOSE = 'secureshop_checkout_audit_jwt';
const TOOL = 'auth.audit_probe';
const CURRENT_VERSION = 2;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail = () => Object.assign(new Error('Checkout audit lesson unavailable'),
  { code: 'V01_LESSON_UNAVAILABLE', executionBoundary: true });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const MANIFEST = Object.freeze([{ agent: 'auth', tool: 'audit_probe',
  description: 'Read the protected audit record for the customer-owned checkout through the isolated practice token verifier.',
  inputSchema: Object.freeze({ type: 'object', properties: Object.freeze({}),
    required: Object.freeze([]), additionalProperties: false }),
}]);
function createSecureShopV01AuditChat({ launches, personaAuthority, modeAuthority,
  conversations: conversationRepository, journal, coordinator, provider, scenes, lesson } = {}) {
  for (const fn of [launches?.assertCurrent, personaAuthority?.capture,
    modeAuthority?.capture, modeAuthority?.assertToken,
    conversationRepository?.getBoundSession, journal?.readV01AuditRequest,
    journal?.claim, journal?.complete,
    journal?.markUncertain, coordinator?.run, provider?.chat, provider?.finalResponse,
    scenes?.readExisting, lesson?.presentCustomerToken, lesson?.readAudit,
    lesson?.bindObservedEffect, lesson?.evidenceFor]) if (typeof fn !== 'function') throw fail();
  const conversations = createBoundConversationService({ conversations: conversationRepository, launches });
  const turns = createBoundTurns({ conversations, coordinator });
  async function authority(scope, persona, personaSession, signal) {
    if (!UUID.test(personaSession?.sessionId || '')
        || !/^[1-9]\d*$/.test(personaSession?.authorityVersion || '')) throw fail();
    const binding = createConversationBinding(scope, persona);
    if (binding.role !== 'customer') throw fail();
    const token = await captureFeatureMode(modeAuthority, binding, 'checkout_audit_jwt');
    const base = await personaAuthority.capture({ scope: binding,
      personaId: binding.shopUserId, role: 'customer', ...personaSession });
    const fence = guardFeatureFence(base, token);
    const retained = await scenes.readExisting(binding);
    if (!retained?.scene || !UUID.test(retained.targetId || '')) throw fail();
    const check = async () => {
      signal?.throwIfAborted();
      await launches.assertCurrent(binding);
      await fence.assertRemoteAdmission();
      const current = await scenes.readExisting(binding);
      if (!current || current.targetId !== retained.targetId
          || !equal(current.scene, retained.scene)) throw fail();
      await fence.assertRemoteAdmission();
      signal?.throwIfAborted();
    };
    await check();
    return Object.freeze({ binding, token, retained, fence, check });
  }
  return Object.freeze({ purpose: PURPOSE,
    async createSession(scope, persona, personaSession, signal) {
      const a = await authority(scope, persona, personaSession, signal);
      const session = await conversations.create(a.binding, persona, PURPOSE);
      await a.check();
      return session;
    },
    async issueToken({ scope, persona, personaSession, checkoutOperationId, signal }) {
      if (!UUID.test(checkoutOperationId || '')) throw fail();
      const a = await authority(scope, persona, personaSession, signal);
      const value = await lesson.presentCustomerToken({ scope: a.binding, persona,
        personaSession, checkoutOperationId: checkoutOperationId.toLowerCase() });
      await a.check();
      return Object.freeze({...value, modeCapability:projectFeatureMode(a.token)});
    },
    async readRequest({scope, persona, personaSession, sessionId, requestId, signal}={}) {
      if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')) throw fail();
      sessionId=sessionId.toLowerCase();requestId=requestId.toLowerCase();
      const a=await authority(scope,persona,personaSession,signal);
      await conversations.assertOwned(sessionId,a.binding,persona,PURPOSE);
      const row=await journal.readV01AuditRequest({sessionId,requestId,binding:a.binding,purpose:PURPOSE});
      await a.check();
      const unconfirmed=()=>Object.freeze({sessionId,requestId,status:'unconfirmed'});
      if(!row||row.status!=='completed')return unconfirmed();
      const turn=row.result_json,meta=turn?.taskMetadata?.checkoutAuditJwt;
      if(!meta||![1,CURRENT_VERSION].includes(meta.version)||!['observed','no_effect'].includes(meta.state)
          ||typeof meta.originalEnvelope!=='string'
          ||Buffer.byteLength(meta.originalEnvelope,'utf8')>16384
          ||typeof turn?.text!=='string'||!turn.text.isWellFormed()
          ||Buffer.byteLength(turn.text,'utf8')>2048
          ||turn.stopReason!=='end_turn'||!Array.isArray(turn.hops)||turn.hops.length>1
          ||!equal(turn.modeCapability,projectFeatureMode(a.token))
          ||!Array.isArray(meta.traceEventIds)||meta.traceEventIds.length>4096
          ||meta.traceEventIds.some(id=>!UUID.test(id||'')))throw fail();
      let envelope;try{envelope=JSON.parse(meta.originalEnvelope);}catch{throw fail();}
      if(!exact(envelope,['version','mode','targetId','sceneId','sceneGeneration',
          'grantId','checkoutOperationId','teachingToken','message'])
          ||JSON.stringify(envelope)!==meta.originalEnvelope||envelope.version!==meta.version
          ||!equal(envelope.mode,a.token.snapshot)
          ||envelope.targetId!==a.retained.targetId
          ||envelope.sceneId!==a.retained.scene.sceneId
          ||envelope.sceneGeneration!==a.retained.scene.sceneGeneration
          ||envelope.grantId!==a.retained.scene.grantId
          ||!UUID.test(envelope.checkoutOperationId||'')
          ||typeof envelope.teachingToken!=='string'||!envelope.teachingToken
          ||Buffer.byteLength(envelope.teachingToken,'utf8')>4096
          ||typeof envelope.message!=='string'||!envelope.message.trim()
          ||!envelope.message.isWellFormed()||envelope.message.includes('\0')
          ||Buffer.byteLength(envelope.message,'utf8')>8192)throw fail();
      const original=createTurnRequest({sessionId,requestId,binding:a.binding,
        message:meta.originalEnvelope,version:row.request_version});
      if(original.hash!==row.request_hash)throw fail();
      const expectedModelArgs=meta.version===1
        ?{checkoutOperationId:envelope.checkoutOperationId,teachingToken:envelope.teachingToken}:{};
      let result=null;
      const hop=turn.hops[0];
      if(meta.state==='observed'){
        const saved=meta.originalEvidence;
        if(!saved||hop?.tool!==TOOL||!equal(hop.params,expectedModelArgs)
            ||hop.error!==null||hop.policyViolation!==null
            ||hop.step!==saved.graphOrigin?.step||saved.graphOrigin?.tool!==TOOL
            ||!UUID.test(saved.requestId||'')||saved.requestId!==requestId
            ||meta.traceEventIds.length<3)throw fail();
        const observed=Object.freeze({step:hop.step,callId:saved.graphOrigin.callId,
          tool:TOOL,args:hop.params,result:hop.result,effectReceipt:saved.effectReceipt});
        const execution=Object.freeze({...saved.execution,check:a.check});
        const recomputed=await lesson.bindObservedEffect({scope:a.binding,persona,personaSession,
          checkoutOperationId:envelope.checkoutOperationId,teachingToken:envelope.teachingToken,
          requestId,execution,toolProtocolVersion:meta.version},observed);
        if(!equal(recomputed,saved))throw fail();
        const payload=JSON.parse(hop.result.content[0].text);
        result=Object.freeze({status:'disclosed',eventId:payload.eventId,report:payload.report});
      }else{
        if(Object.hasOwn(meta,'originalEvidence'))throw fail();
        if(hop){
          if(hop.tool!==TOOL||hop.policyViolation!==null
              ||!equal(hop.params,expectedModelArgs)
              ||hop.result?.isError!==true||!equal(hop.result.content,
                [{type:'text',text:JSON.stringify({status:'denied'})}]))throw fail();
          result=Object.freeze({status:'denied'});
        }
      }
      await conversations.assertOwned(sessionId,a.binding,persona,PURPOSE);await a.check();
      return Object.freeze({sessionId,requestId,status:'completed',text:turn.text,
        result,checkoutOperationId:envelope.checkoutOperationId,
        modeCapability:projectFeatureMode(a.token)});
    },
    async run({ scope, persona, personaSession, sessionId, requestId, message,
      checkoutOperationId, teachingToken, signal, stream } = {}) {
      if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')
          || !UUID.test(checkoutOperationId || '')
          || typeof teachingToken !== 'string' || !teachingToken
          || Buffer.byteLength(teachingToken, 'utf8') > 4096
          || typeof message !== 'string' || !message.trim() || !message.isWellFormed()
          || message.includes('\0') || Buffer.byteLength(message, 'utf8') > 8192) throw fail();
      const a = await authority(scope, persona, personaSession, signal);
      await conversations.assertOwned(sessionId, a.binding, persona, PURPOSE);
      const request = Object.freeze({ checkoutOperationId: checkoutOperationId.toLowerCase(), teachingToken });
      const envelope = JSON.stringify({ version: CURRENT_VERSION, mode: a.token.snapshot,
        targetId: a.retained.targetId, sceneId: a.retained.scene.sceneId,
        sceneGeneration: a.retained.scene.sceneGeneration,
        grantId: a.retained.scene.grantId, ...request, message });
      let observedEvidence = null, execution = null;
      const localAuthority = Object.freeze({});
      const runner = createBoundAgentRunner({ turns, conversations,
        repository: conversationRepository, journal, provider,
        conversationPurpose: PURPOSE, executionScope: 'turn',
        limits: { maxSteps: 3, maxParallelTools: 1 },
        capturePersonaAuthority: () => a.fence,
        personaLocalToolModes: { [TOOL]: 'remote_admission' },
        pool: { async callTool() { throw fail(); } },
        manifest: Object.freeze({ getForRole: role => role === 'customer' ? MANIFEST : [] }),
        buildBasePrompt: () => `You are a customer assistant in an isolated checkout-audit lesson. The customer supplied a practice teaching JWT and selected an owned checkout. You may select ${TOOL} with no arguments; the admitted request binds the selected checkout and exact teaching token. Use the actual tool result for your final answer. A denied result is a denial, not an audit disclosure. Do not claim administrator persona or platform authority.`,
        buildPolicyBlock: async () => '',
        checkToolAcl: async (role, agent, tool) => {
          const allowed = role === 'customer' && `${agent}.${tool}` === TOOL;
          return { allowed, action: allowed ? 'dispatch' : 'block',
            policyViolation: allowed ? null : 'blocked', enforcement: true };
        },
        createLocalTools(binding, context, token, run, fence) {
          if (token !== localAuthority || fence !== a.fence || !equal(binding, a.binding)
              || context.requestId !== requestId.toLowerCase()) throw fail();
          execution = run;
          return Object.freeze({ [TOOL]: async args => {
            if (!exact(args, []))
              return Object.freeze({ content: [{ type: 'text', text: JSON.stringify({ status: 'denied' }) }], isError: true });
            try {
              return await lesson.readAudit({ scope: a.binding, persona, personaSession,
                ...request, requestId: context.requestId, execution: run });
            } catch (error) {
              if (error?.code !== 'V01_TEACHING_TOKEN_DENIED') throw error;
              return Object.freeze({ content: [{ type: 'text', text: JSON.stringify({ status: 'denied' }) }], isError: true });
            }
          } });
        },
        async observeLocalTool({ requestId: observedRequestId, observation }) {
          if (observedRequestId !== requestId.toLowerCase() || !execution) throw fail();
          if (observation?.tool !== TOOL || observation?.result?.isError === true) return;
          observedEvidence = await lesson.bindObservedEffect({ scope: a.binding, persona,
            personaSession, ...request, requestId: observedRequestId, execution,
            toolProtocolVersion: CURRENT_VERSION }, observation);
          if (!equal(observedEvidence, lesson.evidenceFor(observation))) throw fail();
        },
        enterFinalResponseAfterLocalTool: async () => true,
        captureResultTraces: true,
        resultMetadata({ result, traces }) {
          if (!Array.isArray(traces) || traces.length > 4096) throw fail();
          if (observedEvidence && result.stopReason !== 'end_turn') throw fail();
          return Object.freeze({ checkoutAuditJwt: Object.freeze({ version: CURRENT_VERSION,
            originalEnvelope: envelope, state: observedEvidence ? 'observed' : 'no_effect',
            traceEventIds: traces.map(row => row.event_id),
            ...(observedEvidence ? { originalEvidence: observedEvidence } : {}),
          }) });
        },
      });
      const outcome = await runner.run({ sessionId, requestId, scope: a.binding,
        persona, personaSession, message: envelope, signal, stream,
        localToolAuthority: localAuthority });
      await a.check();
      return outcome;
    },
  });
}
module.exports = { createSecureShopV01AuditChat, V01_AUDIT_TOOL: TOOL,
  V01_AUDIT_MANIFEST: MANIFEST };
