'use strict';
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createBoundGraphStore } = require('./secureshopBoundGraphStore');
const { createSupervisorGraph } = require('../agent-runtime/secureshopSupervisorGraph');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { createTurnAdmission } = require('./secureshopTurnAdmission');
const { normalizeConversationPurpose } = require('./secureshopConversationPurpose');
const { withSecureShopFailurePhase } = require('./secureshopFailureDiagnostic');
const { createPersonaToolDispatch } = require('./secureshopPersonaToolDispatch');
const { validatePolicySnapshot } = require('./secureshopPromptPolicySnapshot');
const { validateTaskPolicySnapshot, RECIPIENTS } = require('./secureshopPromptPolicyTaskSnapshot');
const {featureModeForFence}=require('./secureshopFeatureModeAuthority');
const MAX_MESSAGE_BYTES = 64 * 1024;

// Application composition for launch-bound runs. Provider, tools and policy
// dependencies are supplied by the server factory, never by the request body.
function createBoundAgentRunner({ turns, conversations, repository, journal, buildBasePrompt,
  buildPolicyBlock, checkToolAcl, provider, pool, manifest, createLocalTools,
  observeLocalTool, observeExternalTool, assessmentFactory, createToolPool, createManifest, enterFinalResponseAfterLocalTool, finalResponseAfterBlockedLocalTool = false, finalResponseAfterBlockedUnknownTool = false, terminalAfterLocalTool,
  enterFinalResponseAfterExternalTool, resultMetadata, captureResultTraces = false, afterJournalCommit, capturePersonaAuthority, personaLocalToolModes, toolPolicyAdmission,
  promptPolicyAdmission, promptPolicyRecipient, beforePromptPolicyAdmission, finalDecisionAdmission,
  onPromptPolicyAdmissionRejected, conversationPurpose, executionScope = 'conversation', decisionRouting,
  limits = { maxSteps: 8, maxParallelTools: 4 } }) {
  const budget = Object.freeze({ maxSteps: limits?.maxSteps, maxParallelTools: limits?.maxParallelTools });
  const routed=decisionRouting===undefined?undefined:structuredClone(decisionRouting);
  conversationPurpose = normalizeConversationPurpose(conversationPurpose);
  if (!Number.isInteger(budget.maxSteps) || budget.maxSteps < 1
    || budget.maxSteps > 32
    || !Number.isInteger(budget.maxParallelTools) || budget.maxParallelTools < 1
    || budget.maxParallelTools > 8
    || [turns?.run, conversations?.assertOwned, conversations?.getMessages,
      repository?.appendMessage, repository?.getTokens, repository?.addTokens, repository?.appendTraces,
      buildBasePrompt, buildPolicyBlock, checkToolAcl, provider?.chat,
      createLocalTools].some(method => typeof method !== 'function')
    || (createManifest !== undefined && typeof createManifest !== 'function')
    || (createManifest === undefined && typeof manifest?.getForRole !== 'function')
    || (routed !== undefined && typeof provider?.routeWorkflow !== 'function')
    || (manifest?.buildExternalMcpPromptBlock !== undefined && typeof manifest.buildExternalMcpPromptBlock !== 'function')
    || (observeLocalTool !== undefined && typeof observeLocalTool !== 'function')
    || (observeExternalTool !== undefined && typeof observeExternalTool !== 'function')
    || (createToolPool !== undefined && typeof createToolPool !== 'function')
    || (createToolPool === undefined && typeof pool?.callTool !== 'function')
    || (assessmentFactory !== undefined && typeof assessmentFactory !== 'function')
    || (terminalAfterLocalTool !== undefined && typeof terminalAfterLocalTool !== 'function')
    || (enterFinalResponseAfterLocalTool !== undefined && typeof enterFinalResponseAfterLocalTool !== 'function')
    || typeof finalResponseAfterBlockedLocalTool !== 'boolean'
    || (finalResponseAfterBlockedLocalTool && typeof enterFinalResponseAfterLocalTool !== 'function')
    || typeof finalResponseAfterBlockedUnknownTool !== 'boolean'
    || (finalResponseAfterBlockedUnknownTool && typeof enterFinalResponseAfterLocalTool !== 'function')
    || (enterFinalResponseAfterExternalTool !== undefined && typeof enterFinalResponseAfterExternalTool !== 'function')
    || (capturePersonaAuthority !== undefined && (typeof capturePersonaAuthority !== 'function' || !personaLocalToolModes || typeof personaLocalToolModes !== 'object'))
    || (toolPolicyAdmission !== undefined && (typeof toolPolicyAdmission !== 'function' || typeof capturePersonaAuthority !== 'function'))
    || (promptPolicyAdmission !== undefined && (typeof promptPolicyAdmission !== 'function' || typeof capturePersonaAuthority !== 'function'))
    || (beforePromptPolicyAdmission !== undefined && (typeof beforePromptPolicyAdmission !== 'function' || typeof promptPolicyAdmission !== 'function'))
    || (onPromptPolicyAdmissionRejected !== undefined && (typeof onPromptPolicyAdmissionRejected !== 'function'
      || typeof beforePromptPolicyAdmission !== 'function'))
    || (promptPolicyRecipient !== undefined && (typeof promptPolicyAdmission !== 'function'
      || (promptPolicyRecipient !== null && (typeof promptPolicyRecipient !== 'string' || !Object.hasOwn(RECIPIENTS, promptPolicyRecipient)))))
    || (afterJournalCommit !== undefined && typeof afterJournalCommit !== 'function')
    || (finalDecisionAdmission !== undefined && typeof finalDecisionAdmission !== 'function')
    || (resultMetadata !== undefined && typeof resultMetadata !== 'function')
    || typeof captureResultTraces !== 'boolean'
    || (captureResultTraces && typeof resultMetadata !== 'function')
    || !['conversation', 'turn'].includes(executionScope)
    || ((enterFinalResponseAfterLocalTool || enterFinalResponseAfterExternalTool)
      && (budget.maxSteps < 2 || typeof provider.finalResponse !== 'function'))) {
    throw new TypeError('Bound execution configuration required');
  }
  const admission = createTurnAdmission({ journal });
  return Object.freeze({
    async run({ sessionId, requestId, scope, persona, personaSession, message, signal, stream, localToolAuthority }) {
      if (typeof message !== 'string' || !message.trim() || Buffer.byteLength(message, 'utf8') > MAX_MESSAGE_BYTES) {
        throw Object.assign(new TypeError('Message must contain 1 to 65536 UTF-8 bytes'), { code: 'INVALID_MESSAGE' });
      }
      const binding = createConversationBinding(scope, persona);
      const request = createTurnRequest({ sessionId, requestId, binding, message });
      sessionId = request.sessionId;
      const trustedPersona = Object.freeze({ id: binding.shopUserId, role: binding.role });
      const trustedPersonaSession = personaSession ? Object.freeze({...personaSession}) : undefined;
      const personaFence = capturePersonaAuthority ? await capturePersonaAuthority(Object.freeze({binding,sessionId,requestId:request.requestId,personaSession:trustedPersonaSession})) : null;
      if(capturePersonaAuthority && !personaFence) throw Object.assign(new Error('Persona authority required'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
      if((toolPolicyAdmission || promptPolicyAdmission) && (!trustedPersonaSession || !personaFence.binding
        || personaFence.binding.personaId!==trustedPersona.id || personaFence.binding.role!==trustedPersona.role
        || personaFence.binding.sessionId!==trustedPersonaSession.sessionId
        || personaFence.binding.authorityVersion!==trustedPersonaSession.authorityVersion
        || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key=>personaFence.binding[key]!==binding[key]))) {
        throw Object.assign(new Error('Policy persona authority required'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
      }
      if(personaFence) await personaFence.assertRemoteAdmission();
      const modeCapability=featureModeForFence(personaFence);
      const pendingStream = stream ? { send(name, data) {
        if (name !== 'assistant_message' && name !== 'done') stream.send(name, {...data,...(modeCapability?{modeCapability}:{})});
      } } : undefined;
      let prepared;
      const prepare = async () => {
        prepared = await admission.prepare({ sessionId, requestId: request.requestId, binding, message });
        return prepared.status === 'completed'
          ? Object.freeze({ skip: true, value: prepared.outcome })
          : Object.freeze({ skip: false, value: prepared });
      };
      let outcome;
      try {
        outcome = await withSecureShopFailurePhase('admission_publish', () => turns.run(sessionId, binding, trustedPersona,
          { signal, idempotencyKey: request.requestId, admit: prepare, conversationPurpose }, async boundary => {
        const checkAuthority = personaFence ? async () => {
          await boundary.check();
          await personaFence.assertRemoteAdmission();
          await boundary.check();
        } : boundary.check;
        // Compatibility for injected test coordinators which predate the
        // durable admission option. Configured BoundTurns always prepares
        // under its retained coordinator lease.
        if (!prepared) {
          await checkAuthority();
          prepared = await admission.prepare({ sessionId, requestId: request.requestId, binding, message });
          await checkAuthority();
          if (prepared.status === 'completed') return prepared.outcome;
        }
        let committedExecution;
        const committed=await withSecureShopFailurePhase('admission_publish', () => admission.execute(prepared, personaFence ? {...boundary,check:checkAuthority} : boundary, async () => {
        await checkAuthority();
        // A local effect that independently holds the exact matching persona
        // fence may use this coordinator-only check while that fence validates
        // persona authority before and after its callback. Calling the full
        // checkAuthority from inside the held persona lease would re-enter its
        // advisory locks through a second agents connection.
        const checkAtEffect = async () => { await boundary.check(); };
        const execution = Object.freeze({ runId: boundary.identity?.runId,
          ownerKey: boundary.identity?.ownerKey, durableGeneration: boundary.identity?.durableGeneration ?? null,
          signal: boundary.signal, check: checkAuthority, checkAtEffect,
          ...(typeof boundary.trace === 'function' ? { trace: boundary.trace } : {}) });
        committedExecution=execution;
        if (assessmentFactory && (typeof execution.runId !== 'string' || !execution.runId
          || typeof execution.ownerKey !== 'string' || !execution.ownerKey || execution.durableGeneration === null)) {
          await withSecureShopFailurePhase('assessment_begin', async () => {
            throw new Error('Assessment execution identity unavailable');
          });
        }
        let admittedPromptPolicySnapshot = null;
        if (promptPolicyAdmission) {
          await checkAuthority();
          if (!execution.runId) throw new Error('Policy run identity unavailable');
          const stageValue = Object.freeze({binding,sessionId,requestId:request.requestId,
            requestHash:request.hash,claimId:prepared.claimId,runId:execution.runId,
            personaSession:trustedPersonaSession});
          const capability=require('./secureshopMailExecutionCapability');
          const rejected=async stage=>{
            if (!onPromptPolicyAdmissionRejected) return;
            try {
              await checkAuthority();
              await onPromptPolicyAdmissionRejected(
                capability.issueMailExecutionCapability(stage,stageValue),stage,personaFence);
              await checkAuthority();
            } catch { /* No receipt means the turn remains uncertain. */ }
          };
          if (beforePromptPolicyAdmission) {
            try {
              await checkAuthority();
              const allowed=await beforePromptPolicyAdmission(
                capability.issueMailExecutionCapability('thread_admission',stageValue),personaFence);
              if (allowed!==true) throw new Error('Bound thread admission unavailable');
              await checkAuthority();
            } catch (error) {
              await rejected('thread_admission_rejected');
              throw error;
            }
          }
          const taskPolicy = promptPolicyRecipient !== undefined;
          const recipientRoles = RECIPIENTS[promptPolicyRecipient];
          if (taskPolicy && promptPolicyRecipient !== null
              && !(Array.isArray(recipientRoles) ? recipientRoles.includes(trustedPersona.role) : recipientRoles === trustedPersona.role)) {
            throw new Error('Policy task role mismatch');
          }
          try {
            const rawSnapshot = await promptPolicyAdmission(Object.freeze({
              scope: Object.freeze(Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(key => [key, binding[key]]))),
              persona: trustedPersona, personaSession: trustedPersonaSession, runId: execution.runId,
              ...(taskPolicy ? { policyContractVersion: 2, recipient: promptPolicyRecipient } : {}),
            }));
            admittedPromptPolicySnapshot = taskPolicy
              ? validateTaskPolicySnapshot(rawSnapshot) : validatePolicySnapshot(rawSnapshot);
            if (admittedPromptPolicySnapshot.role !== trustedPersona.role
                || (taskPolicy && admittedPromptPolicySnapshot.recipient !== promptPolicyRecipient)) {
              throw new Error('Policy snapshot identity mismatch');
            }
          } catch (error) {
            await rejected('prompt_policy_admission_rejected');
            throw error;
          }
          await checkAuthority();
        }
        const assessmentContext = Object.freeze({ binding, sessionId, requestId: request.requestId,
          runId: execution.runId,
          ...(admittedPromptPolicySnapshot === null ? {} : { promptPolicySnapshot: admittedPromptPolicySnapshot }),
          ...(localToolAuthority === undefined ? {} : { localToolAuthority }) });
        const assessment = assessmentFactory ? await withSecureShopFailurePhase('assessment_begin', async () => {
          if(personaFence)await execution.check();
          const value = personaFence
            ? await assessmentFactory(assessmentContext, personaFence)
            : await assessmentFactory(assessmentContext);
          if (!value || [value.begin, value.observe, value.finalize].some(method => typeof method !== 'function')) {
            throw new TypeError('Invalid turn assessment lifecycle');
          }
          return value;
        }) : null;
        await checkAuthority();
        if(personaFence)await execution.check();
        const attempt = assessment
          ? await withSecureShopFailurePhase('assessment_begin', () => assessment.begin(execution)) : null;
        await checkAuthority();
        // This factory only creates closures. Reservation/provisioning belongs
        // inside a selected tool callback so the effect boundary covers it.
        let localTools = await withSecureShopFailurePhase('tool_pool', () =>
          createLocalTools(binding, assessmentContext, localToolAuthority, execution, personaFence));
        await checkAuthority();
        let toolPool = await withSecureShopFailurePhase('tool_pool', async () => {
          const value = createToolPool
            ? await createToolPool(binding,Object.freeze({execution,sessionId, requestId:request.requestId}), personaFence) : pool;
          if (typeof value?.callTool !== 'function') throw new TypeError('Bound tool pool required');
          return value;
        });
        await checkAuthority();
        const turnManifest = await withSecureShopFailurePhase('tool_pool', async () => {
          const value = createManifest
            ? await createManifest(binding, Object.freeze({execution, sessionId, requestId:request.requestId, toolPool}), personaFence)
            : manifest;
          if (typeof value?.getForRole !== 'function'
              || (value.buildExternalMcpPromptBlock !== undefined && typeof value.buildExternalMcpPromptBlock !== 'function')) {
            throw new TypeError('Bound turn manifest required');
          }
          return value;
        });
        await checkAuthority();
        if (personaFence) {
          const dispatch=createPersonaToolDispatch({fence:personaFence,binding,localTools,pool:toolPool,modes:personaLocalToolModes});
          localTools=dispatch.localTools;toolPool=dispatch.pool;
        }
        const assessmentTraces = [];
        const result = await withSecureShopFailurePhase('graph', () => {
          const { store, Trace } = createBoundGraphStore({ sessionId, scope: binding,
            persona: trustedPersona, service: conversations, repository, check: checkAuthority,
            conversationPurpose, executionScope, ...(modeCapability?{modeCapability}:{}),
            onTracesPersisted: assessment || captureResultTraces ? rows => {
              if (assessmentTraces.length + rows.length > 4096) throw new Error('Assessment trace capacity exceeded');
              assessmentTraces.push(...rows);
            } : undefined });
          const boundToolAcl = toolPolicyAdmission ? async (role, agent, tool, invocation) => {
            const available = await checkToolAcl(role, agent, tool, invocation);
            // This is a hard workflow/role boundary, separate from the editable
            // teaching ACL. A launch policy cannot make an unavailable tool run.
            if (available.action === 'block') return available;
            if (available.action !== 'dispatch' || available.allowed !== true) {
              throw Object.assign(new Error('Policy workflow availability is ambiguous'), {code:'ACL_TOOL_UNAVAILABLE'});
            }
            if (!invocation || !Number.isSafeInteger(invocation.step) || invocation.step < 0
              || typeof invocation.callId !== 'string' || !invocation.callId) throw new Error('Policy invocation unavailable');
            await checkAuthority();
            const admission = await toolPolicyAdmission(Object.freeze({
              scope: Object.freeze(Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(key=>[key,binding[key]]))),
              persona: trustedPersona, personaSession: trustedPersonaSession,
              runId: execution.runId, invocationId: `${invocation.step}:${invocation.callId}`,
              agent, tool, args: invocation.args,
            }));
            await checkAuthority();
            return Object.freeze({allowed:admission.allowed,action:admission.action,
              policyViolation:admission.policyViolation,enforcement:admission.enforcement,admission});
          } : checkToolAcl;
          const boundPolicyBlock = promptPolicyAdmission ? async role => {
            await checkAuthority();
            if (role !== trustedPersona.role || !execution.runId) throw new Error('Policy run identity unavailable');
            const taskPolicy = promptPolicyRecipient !== undefined;
            const snapshot = admittedPromptPolicySnapshot;
            if (!snapshot) throw new Error('Policy snapshot unavailable');
            if (snapshot.role !== role) throw new Error('Policy snapshot role mismatch');
            if (taskPolicy && snapshot.recipient !== promptPolicyRecipient) throw new Error('Policy snapshot recipient mismatch');
            await checkAuthority();
            const policyTrace = new Trace(sessionId);
            policyTrace.record({ step: 0, actor: 'supervisor', kind: 'prompt_policy_snapshot',
              result_json: JSON.stringify({ runId: execution.runId, policyVersion: snapshot.policyVersion,
                sha256: snapshot.sha256, role, policyCount: snapshot.policies.length,
                ...(taskPolicy ? { policyContractVersion: 2, recipient: promptPolicyRecipient } : {}) }) });
            await policyTrace.flush();
            await checkAuthority();
            return snapshot.text;
          } : buildPolicyBlock;
          // Several task configurations intentionally return a fixed base
          // prompt and ignore `extra`; append admitted policy content here.
          const boundBasePrompt = promptPolicyAdmission ? (role, options) => {
            const base = buildBasePrompt(role, { ...options, extra: '' });
            if (typeof base !== 'string') throw new TypeError('Base prompt required');
            return `${base}\n\n${options.extra}`;
          } : buildBasePrompt;
          const graph = createSupervisorGraph({ store, Trace, buildBasePrompt: boundBasePrompt, buildPolicyBlock: boundPolicyBlock, checkToolAcl: boundToolAcl });
          return graph(sessionId, message, {
          provider, pool: toolPool, manifest: turnManifest, localTools, stream: pendingStream,
          decisionRouting:routed,
          role: trustedPersona.role, callerRole: trustedPersona.role,
          callerId: trustedPersona.id, ownerId: sessionId,
          signal: boundary.signal, check: checkAuthority, effect: boundary.effect,
          effectWithReceipt: boundary.effectWithReceipt,
          terminalAfterLocalTool: terminalAfterLocalTool ? observation => terminalAfterLocalTool(Object.freeze({execution,binding,sessionId,requestId:request.requestId,observation})) : undefined,
          onFinalDecision: finalDecisionAdmission ? decision => finalDecisionAdmission(Object.freeze({
            execution, binding, sessionId, requestId: request.requestId, ...decision })) : undefined,
          shouldEnterFinalResponse: enterFinalResponseAfterLocalTool ? observation =>
            enterFinalResponseAfterLocalTool(Object.freeze({ execution, binding, sessionId,
              requestId: request.requestId, localToolAuthority, observation })) : undefined,
          finalResponseAfterBlockedLocalTool,
          finalResponseAfterBlockedUnknownTool,
          onLocalToolObservation: observeLocalTool || assessment ? async observation => {
            const envelope = Object.freeze({ run: boundary.identity, binding, sessionId,
              requestId: request.requestId, observation });
            if (assessment) await withSecureShopFailurePhase('assessment_observe', () =>
              assessment.observe(execution, Object.freeze({ attempt, ...envelope })));
            if (observeLocalTool) await observeLocalTool(envelope);
          } : undefined,
          onExternalToolObservation: observeExternalTool ? async observation => {
            const envelope=Object.freeze({run:execution,binding,sessionId,requestId:request.requestId,observation});
            const category = observation?.result?.isError === true ? 'external_tool_error' : 'external_record_rejected';
            const externalRecord=await withSecureShopFailurePhase('external_observation',
              () => observeExternalTool(envelope, personaFence), category);
            if(assessment)await withSecureShopFailurePhase('assessment_observe', () =>
              assessment.observe(execution,Object.freeze({attempt,...envelope,externalRecord})));
            return externalRecord;
          } : undefined,
          enterFinalResponseAfterExternalTool: enterFinalResponseAfterExternalTool ? async packet =>
            enterFinalResponseAfterExternalTool(Object.freeze({ execution, binding, sessionId,
              requestId: request.requestId, localToolAuthority, ...packet })) : undefined,
          }, budget);
        });
        await checkAuthority();
        if (assessment) await withSecureShopFailurePhase('assessment_finalize', () =>
          assessment.finalize(execution, Object.freeze({ attempt, binding, sessionId,
            requestId: request.requestId, result, traces: Object.freeze([...assessmentTraces]) })));
        await checkAuthority();
        if (!resultMetadata) return modeCapability?Object.freeze({...result,modeCapability}):result;
        if (Object.hasOwn(result, 'taskMetadata')) throw new TypeError('Graph result metadata collision');
        const metadata = await withSecureShopFailurePhase('result_metadata', () => resultMetadata(Object.freeze({
          execution, binding, sessionId, requestId: request.requestId, localToolAuthority, result,
          ...(captureResultTraces ? {traces:Object.freeze([...assessmentTraces])} : {}),
        })));
        const encoded = JSON.stringify(metadata);
        if (encoded === undefined || Buffer.byteLength(encoded, 'utf8') > 65536) {
          throw new TypeError('Invalid trusted result metadata');
        }
        const taskMetadata = JSON.parse(encoded);
        if (!taskMetadata || typeof taskMetadata !== 'object' || Array.isArray(taskMetadata)) {
          throw new TypeError('Invalid trusted result metadata');
        }
        return Object.freeze({ ...result, taskMetadata: Object.freeze(taskMetadata),...(modeCapability?{modeCapability}:{}) });
        }, ...(personaFence?[personaFence]:[])));
        // Durable terminal is authoritative. This optional assessment cannot
        // erase it, and completed admission replay never invokes the callback.
        if(afterJournalCommit)try{await checkAuthority();await afterJournalCommit(Object.freeze({execution:committedExecution,result:committed.result,binding,sessionId,requestId:request.requestId}));}catch{console.warn('SecureShop post-journal assessment unavailable; completed response retained.');}
        return committed;
      }));
      } catch (error) {
        await admission.abandon(prepared);
        throw error;
      }
      return withSecureShopFailurePhase('admission_publish', async () => {
        // The journal result and coordinator finish have both settled. Recheck
        // launch ownership before publishing either a fresh or replayed terminal.
        signal?.throwIfAborted();
        await conversations.assertOwned(sessionId, binding, trustedPersona, conversationPurpose);
        signal?.throwIfAborted();
        if(personaFence) await personaFence.assertRemoteAdmission();
        const result = outcome.result;
        if (stream) {
          stream.send('assistant_message', { text: result.text, stopReason: result.stopReason, hops: result.hops.length,...(result.modeCapability?{modeCapability:result.modeCapability}:{}) });
          stream.send('done', { sessionId, stopReason: result.stopReason, steps: result.steps,...(result.modeCapability?{modeCapability:result.modeCapability}:{}) });
        }
        return { ...result, replayed: outcome.replayed };
      });
    },
  });
}
module.exports = { createBoundAgentRunner, MAX_MESSAGE_BYTES };
