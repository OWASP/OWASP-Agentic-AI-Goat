'use strict';

const { createCsrfBrowserAttempt } = require('./csrfBrowserAttempt');
const { createCsrfManagedDispatch } = require('./csrfManagedDispatch');
const { createCsrfActionHandler } = require('./csrfActionHandler');
const { issueCsrfBrowserReceipt } = require('./csrfBrowserReceipt');

const DEFAULT_WORKFLOW_TIMEOUT_MS = 45000;
const TRUST_BOUNDARY = 'browser provenance depends on the injected trusted executor; this workflow does not accept public observations';

function abortError(message, code) {
  const error = new Error(message);
  error.name = 'AbortError';
  error.code = code;
  return error;
}

function plainCopy(value, label) {
  let json;
  try { json = JSON.stringify(value == null ? null : value); }
  catch { throw new Error(`Invalid ${label}`); }
  if (typeof json !== 'string' || Buffer.byteLength(json) > 65536) throw new Error(`Invalid ${label}`);
  return JSON.parse(json);
}

function expectedOutcome(objectiveId) {
  const outcomes = {
    csrf_g2: { method: 'GET', status: 200, resources: ['image'], vectors: ['direct_get'] },
    csrf_g3: { method: 'GET', status: 403, resources: ['image'], vectors: ['direct_get'] },
    csrf_p1: { method: 'POST', status: 200, resources: ['document'], vectors: ['direct_post'] },
    csrf_p2: { method: 'POST', status: 200, resources: ['fetch'], vectors: ['fetch'] },
    csrf_p3: { method: 'POST', status: 403, resources: ['document', 'fetch'], vectors: ['direct_post', 'fetch'] },
  };
  return outcomes[objectiveId];
}

function createCsrfBrowserWorkflow({ executor,
  attemptFactory = createCsrfBrowserAttempt,
  managedDispatchFactory = createCsrfManagedDispatch,
  actionHandlerFactory = createCsrfActionHandler,
  timeoutMs = DEFAULT_WORKFLOW_TIMEOUT_MS,
  now = Date.now } = {}) {
  if (!executor || typeof executor.execute !== 'function') throw new TypeError('Trusted CSRF browser executor required');
  if (![attemptFactory, managedDispatchFactory, actionHandlerFactory].every(value => typeof value === 'function')) {
    throw new TypeError('CSRF browser workflow factories required');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > require('./csrfRuntimeBudget').workflowMs || typeof now !== 'function') {
    throw new TypeError('Invalid CSRF browser workflow timeout');
  }

  return Object.freeze({
    async run({ execution, userId, objectiveId, tab, html, victimCookie,
      attackerOrigin, victimOrigin, victimPath = '/api/workshop/csrf/agent-action',
      actionHandlerDeps, beginGrading, finalGrade } = {}) {
      if (!execution || typeof execution.check !== 'function' || !execution.signal
        || typeof execution.runId !== 'string' || typeof execution.ownerKey !== 'string'
        || !Number.isSafeInteger(execution.generation)) throw new TypeError('Captured owner execution required');
      if (!Number.isSafeInteger(userId) || userId < 1 || execution.ownerKey !== JSON.stringify(['CSRF', String(userId)])) throw new TypeError('Captured learner scope mismatch');
      if (!actionHandlerDeps || typeof actionHandlerDeps !== 'object') throw new TypeError('CSRF action handler dependencies required');
      if (typeof finalGrade !== 'function') throw new TypeError('Final CSRF grader required');
      if (beginGrading !== undefined && typeof beginGrading !== 'function') throw new TypeError('Invalid grading admission hook');

      const deadlineAt = now() + timeoutMs;
      const workflowController = new AbortController();
      const cancel = () => workflowController.abort(execution.signal.reason
        || abortError('CSRF browser workflow cancelled', 'CSRF_BROWSER_WORKFLOW_CANCELLED'));
      execution.signal.addEventListener('abort', cancel, { once: true });
      if (execution.signal.aborted) cancel();
      const timer = setTimeout(() => workflowController.abort(
        abortError('CSRF browser workflow timed out', 'CSRF_BROWSER_WORKFLOW_TIMEOUT')), timeoutMs);

      let attempt;
      let gradingAttempt = null;
      let candidate = null;
      let activity = null;
      let admittedObservation = null;
      let handlerResponse = null;
      let browserSignal;
      const cancelFromBrowser = () => workflowController.abort(browserSignal.reason);
      const checkLifetime = async () => {
        if (workflowController.signal.aborted) throw workflowController.signal.reason;
        if (now() >= deadlineAt) {
          const error = abortError('CSRF browser workflow timed out', 'CSRF_BROWSER_WORKFLOW_TIMEOUT');
          workflowController.abort(error);
          throw error;
        }
        await execution.check();
        if (workflowController.signal.aborted) throw workflowController.signal.reason;
      };
      // Every downstream await sees both the original owner fence and this
      // workflow's independent deadline. Scope identifiers remain unchanged.
      const childExecution = Object.freeze({ ...execution,
        signal: workflowController.signal,
        check: checkLifetime,
      });

      try {
        await checkLifetime();
        if (beginGrading) {
          gradingAttempt = await beginGrading(childExecution);
          await checkLifetime();
        }
        const originalRecordActivity = actionHandlerDeps.recordActivity;
        if (typeof originalRecordActivity !== 'function') throw new TypeError('CSRF activity recorder required');
        const handler = actionHandlerFactory({
          ...actionHandlerDeps,
          canonicalMode:()=>gradingAttempt?.mode??'vuln',
          assertCanonicalMode:async()=>{await checkLifetime();await actionHandlerDeps.assertCanonicalMode?.();},
          // The observed request is synthetic, not the outer authenticated HTTP
          // request. Bind only the already-checked parent owner; never consult
          // its body/cookie or bypass the outer route authority resolver.
          getUserId: () => userId,
          getUserKey: () => String(userId),
          sessionIdFor: () => `csrf_${userId}`,
          recordActivity: async (userKey, tabId, name, args, result) => {
            await originalRecordActivity(userKey, tabId, name, args, result);
            activity = Object.freeze({ userKey: String(userKey), tabId, name,
              args: plainCopy(args || {}, 'CSRF activity arguments'),
              result: plainCopy(result || {}, 'CSRF activity result') });
          },
          // The action handler may nominate an objective after a real effect, but
          // cannot publish completion. Final grading happens only after the
          // trusted executor has observed and completed the browser response.
          creditObjective: async (userKey, candidateId, candidateUserId) => {
            await checkLifetime();
            if (candidateId === objectiveId && candidateUserId === userId
              && String(userKey) === String(userId)) {
              candidate = Object.freeze({ objectiveId: candidateId, tab,
                userId, userKey: String(userKey) });
            }
            return false;
          },
        });
        const managedDispatch = managedDispatchFactory({ handleAgentAction: handler, execution: childExecution, userId,
          attackerOrigin, victimOrigin, victimPath, tab });
        const dispatch = async input => {
          handlerResponse = await managedDispatch(input);
          return handlerResponse;
        };
        attempt = attemptFactory({ execution: childExecution, objectiveId, tab, html, dispatch,
          ttlMs: timeoutMs, now });
        const browser = await executor.execute({ html, victimCookie,
          signal: workflowController.signal,
          onRequest: (observation, browserExecution) => {
            if (admittedObservation) throw new Error('Trusted executor attempted more than one action');
            admittedObservation = observation;
            browserSignal = browserExecution?.signal;
            if (browserSignal) {
              browserSignal.addEventListener('abort', cancelFromBrowser, { once: true });
              if (browserSignal.aborted) cancelFromBrowser();
            }
            return attempt.consume(observation);
          } });
        await checkLifetime();

        if (!candidate) {
          return Object.freeze({ graded: false, grade: null, browser,
            payloadDigest: attempt.binding.payloadDigest, trustBoundary: TRUST_BOUNDARY });
        }
        const expected = expectedOutcome(objectiveId);
        if (!browser || browser.observation !== admittedObservation
          || browser.observation?.cookiePresent !== true
          || browser.observation.frameOrigin !== new URL(attackerOrigin).origin
          || browser.observation.method !== expected?.method
          || !expected.resources.includes(browser.observation.resourceType)
          || browser.responseObserved !== true
          || browser.responseStatus !== expected.status
          || browser.responseStatus !== handlerResponse?.status
          || !expected.vectors.includes(activity?.result?.vector)) {
          throw new Error('Trusted executor result is incomplete');
        }
        const grade = await finalGrade(Object.freeze({
          userId,
          objectiveId,
          tab,
          binding: attempt.binding,
          gradingAttempt,
          receipt: issueCsrfBrowserReceipt({ binding: attempt.binding, observation: browser.observation,
            responseStatus: browser.responseStatus, execution: childExecution, activity }),
          observation: browser.observation,
          responseStatus: browser.responseStatus,
          activity,
          execution: childExecution,
          check: checkLifetime,
          signal: workflowController.signal,
        }));
        await checkLifetime();
        return Object.freeze({ graded: true, grade, browser,
          payloadDigest: attempt.binding.payloadDigest, trustBoundary: TRUST_BOUNDARY });
      } finally {
        clearTimeout(timer);
        execution.signal.removeEventListener('abort', cancel);
        browserSignal?.removeEventListener('abort', cancelFromBrowser);
        attempt?.revoke();
      }
    },
  });
}

module.exports = { createCsrfBrowserWorkflow, DEFAULT_WORKFLOW_TIMEOUT_MS, TRUST_BOUNDARY };
