'use strict';

const { parseCsrfGadgetBrowserRequest } = require('./csrfGadgetBrowserRequest');
const { GADGET_OBJECTIVES } = require('./csrfGadgetBrowserAttempt');
const { withOwnerExecution } = require('../agent-runtime/ownerWorkflowRoutes');

const MAX_RESPONSE_BYTES = 65536;

function exactOrigin(value) {
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password
    || parsed.pathname !== '/' || parsed.search || parsed.hash) throw new TypeError('Invalid gadget victim origin');
  return parsed.origin;
}

function responseCapture() {
  let statusCode = 200;
  let body;
  let sent = false;
  const headers = Object.create(null);
  const api = {
    status(code) {
      if (sent || !Number.isSafeInteger(code) || code < 100 || code > 599) throw new Error('Invalid managed response status');
      statusCode = code; return api;
    },
    setHeader(name, value) {
      if (sent || typeof name !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(name)) {
        throw new Error('Invalid managed response header');
      }
      const key = name.toLowerCase();
      if (!Object.hasOwn(headers, key) && Object.keys(headers).length >= 32) throw new Error('Too many managed response headers');
      const encoded = Array.isArray(value) ? value.map(String).join(', ') : String(value);
      if (Buffer.byteLength(encoded) > 2048 || /[\r\n]/.test(encoded)) throw new Error('Invalid managed response header');
      headers[key] = encoded; return api;
    },
    getHeader(name) { return headers[String(name).toLowerCase()]; },
    type(value) { return api.setHeader('content-type', value); },
    send(value) {
      if (sent) throw new Error('Managed response already sent');
      body = value == null ? '' : value;
      if (typeof body !== 'string' && !Buffer.isBuffer(body)) body = JSON.stringify(body);
      if (Buffer.byteLength(body) > MAX_RESPONSE_BYTES) throw new Error('Managed response is too large');
      sent = true; return api;
    },
    json(value) {
      if (!Object.hasOwn(headers, 'content-type')) api.setHeader('content-type', 'application/json; charset=utf-8');
      return api.send(JSON.stringify(value));
    },
    end(value = '') { return api.send(value); },
  };
  Object.defineProperties(api, {
    headersSent: { get: () => sent }, writableEnded: { get: () => sent }, destroyed: { get: () => false },
  });
  return { res: api, result() {
    if (!sent) throw new Error('Managed action handler did not send a response');
    return Object.freeze({ status: statusCode,
      contentType: headers['content-type'] || (Buffer.isBuffer(body) ? 'application/octet-stream' : 'text/plain; charset=utf-8'),
      body, headers: Object.freeze({ ...headers }) });
  } };
}

function createCsrfGadgetManagedDispatch({ handleAgentAction, execution, userId, objectiveId,
  victimOrigin, victimPath = '/api/workshop/csrf/agent-action', tab }) {
  const selected = GADGET_OBJECTIVES[objectiveId];
  if (typeof handleAgentAction !== 'function') throw new TypeError('Managed action handler required');
  if (!execution || typeof execution.check !== 'function' || !(execution.signal instanceof AbortSignal)
    || typeof execution.runId !== 'string' || typeof execution.ownerKey !== 'string'
    || !Number.isSafeInteger(execution.generation)) throw new TypeError('Captured owner execution required');
  if (!Number.isSafeInteger(userId) || userId < 1
    || execution.ownerKey !== JSON.stringify(['CSRF', String(userId)])) throw new TypeError('Captured learner scope mismatch');
  if (!selected || selected.tab !== tab) throw new TypeError('Invalid gadget objective scope');
  const trustedVictimOrigin = exactOrigin(victimOrigin);
  if (typeof victimPath !== 'string' || !victimPath.startsWith('/') || victimPath.includes('?') || victimPath.includes('#')) {
    throw new TypeError('Invalid managed victim path');
  }

  return async function dispatchManagedGadgetRequest({ observation, binding,
    execution: suppliedExecution, check } = {}) {
    if (suppliedExecution !== execution || typeof check !== 'function' || !binding
      || binding.runId !== execution.runId || binding.ownerKey !== execution.ownerKey
      || binding.generation !== execution.generation || binding.objectiveId !== objectiveId
      || binding.tab !== tab || binding.expectedVector !== selected.vector) {
      throw new Error('Managed gadget browser attempt scope mismatch');
    }
    if (observation?.cookiePresent !== true || observation.frameOrigin !== trustedVictimOrigin) {
      throw new Error('Trusted victim-document browser observation required');
    }
    return withOwnerExecution(execution, async () => {
      await check(); await execution.check();
      const parsed = parseCsrfGadgetBrowserRequest(observation, { victimOrigin: trustedVictimOrigin, victimPath, tab });
      const body = Object.freeze({ ...parsed.body, tab });
      const headers = parsed.headers;
      const req = {
        method: 'POST', query: Object.freeze({}), body, headers,
        user: Object.freeze({ id: userId }), session: Object.freeze({ userId }),
        get(name) { return headers[String(name).toLowerCase()]; },
      };
      const capture = responseCapture();
      await handleAgentAction(req, capture.res);
      await check(); await execution.check();
      return capture.result();
    });
  };
}

module.exports = { createCsrfGadgetManagedDispatch, MAX_RESPONSE_BYTES };
