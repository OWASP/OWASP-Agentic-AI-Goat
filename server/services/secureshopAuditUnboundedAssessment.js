'use strict';

const { randomUUID } = require('node:crypto');
const { createObjectiveCompletionService } = require('./secureshopObjectiveCompletionService');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { createAssessmentPersonaCapture } = require('./secureshopAssessmentPersonaCapture');
const { AUDIT_UNBOUNDED_OBJECTIVE, AUDIT_UNBOUNDED_RUBRIC_V3, prepareSecureShopAuditUnboundedJudgePacket } =
  require('./secureshopAuditUnboundedEvidence');

const WORKSHOP = 'secureshop_agent_security';

// This remains unmounted until composition supplies a protected source reader
// for the server-created witness. The witness is never accepted from HTTP or a
// model tool argument.
function createSecureShopAuditUnboundedAssessment({ receipts, progress, judge, qualifyModel, personaBindings,
  readWitness, createCompletionService = createObjectiveCompletionService,
  createPersonaCapture = createAssessmentPersonaCapture } = {}) {
  if (typeof qualifyModel !== 'function' || typeof readWitness !== 'function'
      || typeof createCompletionService !== 'function' || typeof createPersonaCapture !== 'function') {
    throw new TypeError('Trusted audit unbounded assessment dependencies required');
  }
  const scopes = new WeakMap();
  const personaCapture = createPersonaCapture(personaBindings);
  const completion = createCompletionService({ receipts, progress, ...(judge ? { judge } : {}),
    ...personaCapture.options,
    captureInstanceScope: execution => {
      const scope = scopes.get(execution);
      if (!scope) throw new Error('Audit unbounded assessment scope unavailable');
      return scope;
    },
  });
  return async function begin({ binding: input, execution } = {}, personaFence) {
    const binding = createConversationBinding(input, { id: input?.shopUserId, role: input?.role });
    if (binding.role !== 'admin' || typeof execution?.check !== 'function' || !execution.runId || scopes.has(execution)) {
      throw new TypeError('Protected audit unbounded assessment required');
    }
    const scope = createLaunchScope(binding);
    const capture = personaCapture.prepare(binding, personaFence);
    scopes.set(execution, scope); personaCapture.bind(execution, capture);
    const attempt = await completion.beginAttempt({ userId: scope.platformOwnerId, workshopKey: WORKSHOP,
      objectiveId: AUDIT_UNBOUNDED_OBJECTIVE, execution });
    if (!['vuln', 'fixed'].includes(attempt.mode) || !Number.isSafeInteger(attempt.generation) || attempt.generation < 0) {
      throw new Error('Audit unbounded grading mode or generation is unavailable');
    }
    let started = false, settled = false, result;
    return Object.freeze({
      async consume(evidence) {
        await execution.check();
        if (started || evidence?.runId !== execution.runId) throw new Error('Audit unbounded evidence mismatch or replay');
        started = true;
        if (capture) await capture.fence.assertRemoteAdmission();
        const boundedWitness = await readWitness({ binding, execution, evidence });
        await execution.check();
        const prepared = await prepareSecureShopAuditUnboundedJudgePacket(evidence, {
          qualifyModel, check: execution.check, mode: attempt.mode, boundedWitness,
          rubricVersion: AUDIT_UNBOUNDED_RUBRIC_V3,
        });
        if (capture) { await capture.fence.assertRemoteAdmission(); await execution.check(); }
        result = await completion.evaluate({ userId: scope.platformOwnerId, workshopKey: WORKSHOP,
          evaluationId: randomUUID(), execution, attempt, ...prepared.packet });
        await execution.check(); settled = true;
      },
      outcome() {
        if (!settled) throw new Error('Audit unbounded assessment did not complete');
        return result;
      },
    });
  };
}

module.exports = { createSecureShopAuditUnboundedAssessment };
