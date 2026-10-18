'use strict';

const { createCsrfGadgetBrowserAttempt, GADGET_OBJECTIVES } = require('./csrfGadgetBrowserAttempt');
const { createCsrfGadgetManagedDispatch } = require('./csrfGadgetManagedDispatch');
const { createCsrfActionHandler } = require('./csrfActionHandler');
const { issueCsrfGadgetBrowserReceipt } = require('./csrfGadgetBrowserReceipt');

const DEFAULT_TIMEOUT_MS = 30000;
const TRUST_BOUNDARY = 'intercepted victim-origin gadget document; deployed origins and model latency are not qualified';

function abortError(message, code) { const error = new Error(message); error.name = 'AbortError'; error.code = code; return error; }
function freezeRecord(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freezeRecord); Object.freeze(value); }
  return value;
}
function plainCopy(value) {
  const json = JSON.stringify(value == null ? null : value);
  if (typeof json !== 'string' || Buffer.byteLength(json) > 65536) throw new Error('Invalid CSRF gadget activity');
  return JSON.parse(json);
}

function createCsrfGadgetBrowserWorkflow({ executor,
  attemptFactory = createCsrfGadgetBrowserAttempt,
  managedDispatchFactory = createCsrfGadgetManagedDispatch,
  actionHandlerFactory = createCsrfActionHandler,
  timeoutMs = DEFAULT_TIMEOUT_MS, now = Date.now } = {}) {
  if (!executor || typeof executor.execute !== 'function') throw new TypeError('Trusted victim-document executor required');
  if (![attemptFactory, managedDispatchFactory, actionHandlerFactory].every(value => typeof value === 'function')) {
    throw new TypeError('CSRF gadget workflow factories required');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000 || typeof now !== 'function') {
    throw new TypeError('Invalid CSRF gadget workflow timeout');
  }

  return Object.freeze({
    async run({ execution, userId, objectiveId, tab, html, victimCookie, victimOrigin,
      victimPath = '/api/workshop/csrf/agent-action', actionHandlerDeps } = {}) {
      const selected = GADGET_OBJECTIVES[objectiveId];
      if (!selected || selected.tab !== tab) throw new TypeError('Invalid gadget objective selection');
      if (!execution || typeof execution.check !== 'function' || !(execution.signal instanceof AbortSignal)
        || typeof execution.runId !== 'string' || typeof execution.ownerKey !== 'string'
        || !Number.isSafeInteger(execution.generation)) throw new TypeError('Captured owner execution required');
      if (!Number.isSafeInteger(userId) || userId < 1
        || execution.ownerKey !== JSON.stringify(['CSRF', String(userId)])) throw new TypeError('Captured learner scope mismatch');
      if (!actionHandlerDeps || typeof actionHandlerDeps.recordActivity !== 'function') {
        throw new TypeError('CSRF action handler dependencies required');
      }

      const controller = new AbortController();
      const cancel = () => controller.abort(execution.signal.reason
        || abortError('CSRF gadget browser workflow cancelled', 'CSRF_GADGET_WORKFLOW_CANCELLED'));
      execution.signal.addEventListener('abort', cancel, { once: true });
      if (execution.signal.aborted) cancel();
      const timer = setTimeout(() => controller.abort(
        abortError('CSRF gadget browser workflow timed out', 'CSRF_GADGET_WORKFLOW_TIMEOUT')), timeoutMs);
      const deadlineAt = now() + timeoutMs;
      const check = async () => {
        if (controller.signal.aborted) throw controller.signal.reason;
        if (now() >= deadlineAt) { cancel(); throw controller.signal.reason; }
        await execution.check();
        if (controller.signal.aborted) throw controller.signal.reason;
      };
      const childExecution = Object.freeze({ ...execution, signal: controller.signal, check });
      let attempt;
      let activity = null;
      let admittedObservation = null;
      let handlerResponse = null;
      let browserSignal;
      const cancelFromBrowser = () => controller.abort(browserSignal.reason
        || abortError('CSRF gadget browser executor cancelled', 'CSRF_GADGET_EXECUTOR_CANCELLED'));
      try {
        const originalRecordActivity = actionHandlerDeps.recordActivity;
        const handler = actionHandlerFactory({ ...actionHandlerDeps,
          recordActivity: async (userKey, tabId, name, args, result) => {
            await originalRecordActivity(userKey, tabId, name, args, result);
            activity = Object.freeze({ userKey: String(userKey), tabId, name,
              result: freezeRecord(plainCopy(result || {})) });
          },
          // The shared handler may nominate objectives, but this adapter never
          // publishes credit. Later grading must inspect the private receipt.
          creditObjective: async () => false,
        });
        const managedDispatch = managedDispatchFactory({ handleAgentAction: handler,
          execution: childExecution, userId, objectiveId, victimOrigin, victimPath, tab });
        attempt = attemptFactory({ execution: childExecution, objectiveId, tab, html,
          dispatch: async input => { handlerResponse = await managedDispatch(input); return handlerResponse; },
          ttlMs: timeoutMs, now });
        const browser = await executor.execute({ html, victimCookie, signal: controller.signal,
          onRequest: (observation, browserExecution) => {
            if (admittedObservation) throw new Error('Trusted executor attempted more than one gadget action');
            admittedObservation = observation;
            browserSignal = browserExecution?.signal;
            if (browserSignal) {
              browserSignal.addEventListener('abort', cancelFromBrowser, { once: true });
              if (browserSignal.aborted) cancelFromBrowser();
            }
            return attempt.consume(observation);
          } });
        await check();
        if (!browser || browser.observation !== admittedObservation || browser.observation?.cookiePresent !== true
          || browser.observation.frameOrigin !== new URL(victimOrigin).origin
          || browser.observation.method !== 'POST' || browser.observation.resourceType !== 'fetch'
          || browser.responseObserved !== true || browser.responseStatus !== handlerResponse?.status) {
          throw new Error('Trusted gadget executor result is incomplete');
        }
        const result = activity?.result;
        const exactEffect = activity?.userKey === String(userId) && activity?.tabId === tab && result?.kind === 'attack'
          && result.executed === true && result.blocked === false && !result.error;
        if (browser.responseStatus !== 200 || handlerResponse.status !== 200) {
          return Object.freeze({ qualified: false, receipt: null, activity,
            observedVector: typeof result?.vector === 'string' ? result.vector : null,
            reason: 'response_not_accepted', browser,
            payloadDigest: attempt.binding.payloadDigest, trustBoundary: TRUST_BOUNDARY });
        }
        if (!exactEffect || result.vector !== selected.vector) {
          return Object.freeze({ qualified: false, receipt: null, activity,
            observedVector: typeof result?.vector === 'string' ? result.vector : null,
            reason: !exactEffect ? 'effect_not_observed' : 'observed_vector_mismatch',
            browser, payloadDigest: attempt.binding.payloadDigest, trustBoundary: TRUST_BOUNDARY });
        }
        const receipt = issueCsrfGadgetBrowserReceipt({ binding: attempt.binding,
          observation: browser.observation, responseStatus: browser.responseStatus,
          execution, activity });
        return Object.freeze({ qualified: true, receipt, activity,
          observedVector: result.vector, reason: null, browser,
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

module.exports = { createCsrfGadgetBrowserWorkflow, DEFAULT_TIMEOUT_MS, TRUST_BOUNDARY };
