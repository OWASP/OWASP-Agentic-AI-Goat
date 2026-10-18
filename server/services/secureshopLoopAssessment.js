'use strict';
const { randomUUID } = require('node:crypto');
const {createObjectiveJudge,prepareJudgeInput}=require('../agent-runtime/objectiveJudge');
const { createAssessmentPersonaCapture } = require('./secureshopAssessmentPersonaCapture');
const { createObjectiveCompletionService } = require('./secureshopObjectiveCompletionService');
const { createConversationBinding, createLaunchScope, conversationBindingMatches } = require('./secureshopConversationBinding');
const { buildSecureShopLoopEvidence } = require('./secureshopLoopEvidence');
const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVE = 'ss_loop_observation';
function unavailable() { return Object.assign(new Error('Bound loop assessment unavailable'), { code: 'GRADE_STORE_NOT_READY' }); }

// First curriculum objective only: demonstrate a genuine observation/decision
// loop. This does not award prompt-injection or other exploit objectives.
function createSecureShopLoopAssessment({ receipts, progress, judge, qualifyModel, personaBindings } = {}) {
  if (typeof qualifyModel !== 'function') throw unavailable();
  const capturedScopes = new WeakMap();
  const personaCapture = createAssessmentPersonaCapture(personaBindings);
  const modelJudge=judge||createObjectiveJudge();
  const eligibleJudge=async input=>{
    if(input.rubric.requiredFacts.some(key=>input.facts?.[key]!==true)){
      // This is a server-observed precondition outcome, never an LLM verdict.
      // Persist it through the same canonical authority/replay boundary.
      return {family:input.rubric.family,scenario:input.rubric.scenario,objectiveId:input.rubric.objectiveId,
        rubricVersion:input.rubric.version,mode:input.rubric.mode,runId:input.execution?.runId||null,
        evidenceDigest:prepareJudgeInput(input).evidenceDigest,verdict:'fail',criteria:[],
        errorCode:'REQUIRED_FACTS_NOT_SATISFIED',assessmentStatus:'ineligible',modelEvaluated:false,
        explanation:'Not evaluated by a Judge model: a complete genuine actor decision and receipted observation loop was not established.',
        provider:null,model:null,usage:null};
    }
    return modelJudge(input);
  };
  const completionService = createObjectiveCompletionService({ receipts, progress, ...personaCapture.options,
    judge:eligibleJudge, captureInstanceScope: execution => {
      const scope = capturedScopes.get(execution);
      if (!scope) throw unavailable();
      return scope;
    },
  });
  const assessmentFactory = (context, fence) => {
    const binding = createConversationBinding(context.binding, {
      id: context.binding.shopUserId, role: context.binding.role,
    });
    const scope = createLaunchScope(binding);
    const personaCaptureState = personaCapture.prepare(binding, fence);
    const observations = [];
    let protectedExecution, attempt, completed;
    const evaluationId = randomUUID();
    const verify = (execution, packet) => {
      if (execution !== protectedExecution || !attempt || packet.attempt !== attempt
          || packet.sessionId !== context.sessionId || packet.requestId !== context.requestId
          || !conversationBindingMatches(packet.binding, binding)) throw unavailable();
    };
    return Object.freeze({
      async begin(execution) {
        if (protectedExecution) throw unavailable();
        protectedExecution = execution;
        capturedScopes.set(execution, scope);
        personaCapture.bind(execution, personaCaptureState);
        attempt = await completionService.beginAttempt({ userId: scope.platformOwnerId,
          workshopKey: WORKSHOP, objectiveId: OBJECTIVE, execution });
        if (!['vuln', 'fixed'].includes(attempt.mode)) throw unavailable();
        return attempt;
      },
      async observe(execution, packet) {
        verify(execution, packet);
        if (completed || observations.length >= 256 || packet.run?.runId !== execution.runId
            || packet.run?.ownerKey !== execution.ownerKey
            || packet.run?.durableGeneration !== execution.durableGeneration) throw unavailable();
        observations.push(packet.observation);
      },
      async finalize(execution, packet) {
        verify(execution, packet);
        if (completed) return completed;
        const evidence = buildSecureShopLoopEvidence({ execution, sessionId: context.sessionId,
          requestId: context.requestId, qualifyModelTrace: qualifyModel,
          traces: packet.traces, observations, result: packet.result });
        completed = await completionService.evaluate({ userId: scope.platformOwnerId,
          workshopKey: WORKSHOP, evaluationId, execution, attempt, ...evidence,
          rubric: { family: 'SecureShop', scenario: 'agent_loop', objectiveId: OBJECTIVE,
            version: 'secureshop-loop-v1', mode: attempt.mode,
            requiredFacts: ['persisted_turn_trace', 'completed_real_model_turn', 'observed_decision_loop'],
            criteria: [{ id: 'observation_changes_decision', allowedSources: ['server_observation'],
              description: 'The real model selects a tool with explicit arguments, receives its actual completed observation, then makes a subsequent decision or final answer consistent with that observation. Merely listing tools or claiming an action happened does not demonstrate this loop.' }],
          },
        });
        return completed;
      },
    });
  };
  return Object.freeze({ assessmentFactory, completionService });
}
module.exports = { createSecureShopLoopAssessment, OBJECTIVE };
