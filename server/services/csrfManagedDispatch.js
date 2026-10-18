'use strict';

const { parseCsrfBrowserRequest } = require('./csrfBrowserRequest');
const { withOwnerExecution } = require('../agent-runtime/ownerWorkflowRoutes');

const MAX_RESPONSE_BYTES = 65536;
const MAX_RESPONSE_HEADERS = 32;

function normalizeOrigin(value, label) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new TypeError(`Invalid ${label} origin`); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password
    || parsed.pathname !== '/' || parsed.search || parsed.hash) throw new TypeError(`Invalid ${label} origin`);
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
      statusCode = code;
      return api;
    },
    setHeader(name, value) {
      if (sent || typeof name !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(name)) {
        throw new Error('Invalid managed response header');
      }
      const key = name.toLowerCase();
      if (!Object.hasOwn(headers, key) && Object.keys(headers).length >= MAX_RESPONSE_HEADERS) {
        throw new Error('Too many managed response headers');
      }
      const encoded = Array.isArray(value) ? value.map(String).join(', ') : String(value);
      if (Buffer.byteLength(encoded) > 2048 || /[\r\n]/.test(encoded)) throw new Error('Invalid managed response header');
      headers[key] = encoded;
      return api;
    },
    getHeader(name) { return headers[String(name).toLowerCase()]; },
    type(value) { return api.setHeader('content-type', value); },
    send(value) {
      if (sent) throw new Error('Managed response already sent');
      body = value == null ? '' : value;
      if (typeof body !== 'string' && !Buffer.isBuffer(body)) body = JSON.stringify(body);
      if (Buffer.byteLength(body) > MAX_RESPONSE_BYTES) throw new Error('Managed response is too large');
      sent = true;
      return api;
    },
    json(value) {
      if (!Object.hasOwn(headers, 'content-type')) api.setHeader('content-type', 'application/json; charset=utf-8');
      return api.send(JSON.stringify(value));
    },
    end(value = '') { return api.send(value); },
  };
  Object.defineProperties(api, {
    headersSent: { get: () => sent },
    writableEnded: { get: () => sent },
    destroyed: { get: () => false },
  });
  return {
    res: api,
    result() {
      if (!sent) throw new Error('Managed action handler did not send a response');
      const contentType = headers['content-type'] || (Buffer.isBuffer(body)
        ? 'application/octet-stream' : 'text/plain; charset=utf-8');
      return Object.freeze({ status: statusCode, contentType, body,
        headers: Object.freeze({ ...headers }) });
    },
  };
}

function createCsrfManagedDispatch({ handleAgentAction, execution, userId,
  attackerOrigin, victimOrigin, victimPath = '/api/workshop/csrf/agent-action', tab }) {
  if (typeof handleAgentAction !== 'function') throw new TypeError('Managed action handler required');
  if (!execution || typeof execution.check !== 'function' || !execution.signal
    || typeof execution.runId !== 'string' || typeof execution.ownerKey !== 'string'
    || !Number.isSafeInteger(execution.generation)) throw new TypeError('Captured owner execution required');
  if (!Number.isSafeInteger(userId) || userId < 1) throw new TypeError('Captured learner identity required');
  if (execution.ownerKey !== JSON.stringify(['CSRF', String(userId)])) throw new TypeError('Captured learner scope mismatch');
  if (!['get', 'post'].includes(tab)) throw new TypeError('Invalid managed action tab');
  const trustedAttackerOrigin = normalizeOrigin(attackerOrigin, 'attacker');
  const trustedVictimOrigin = normalizeOrigin(victimOrigin, 'victim');
  if (trustedAttackerOrigin === trustedVictimOrigin) throw new TypeError('Managed browser origins must differ');
  if (typeof victimPath !== 'string' || !victimPath.startsWith('/') || victimPath.includes('?') || victimPath.includes('#')) {
    throw new TypeError('Invalid managed victim path');
  }

  return async function dispatchManagedBrowserRequest({ observation, binding,
    execution: suppliedExecution, check } = {}) {
    if (suppliedExecution !== execution || typeof check !== 'function' || !binding
      || binding.runId !== execution.runId || binding.ownerKey !== execution.ownerKey
      || binding.generation !== execution.generation || binding.tab !== tab) {
      throw new Error('Managed browser attempt scope mismatch');
    }
    if (observation?.cookiePresent !== true || observation.frameOrigin !== trustedAttackerOrigin) {
      throw new Error('Trusted browser request observation required');
    }

    return withOwnerExecution(execution, async () => {
      await check();
      await execution.check();
      const parsed = parseCsrfBrowserRequest(observation, {
        victimOrigin: trustedVictimOrigin,
        victimPath,
        tab,
      });
      const headers = Object.freeze({ ...parsed.headers });
      const capturedUser = Object.freeze({ id: userId });
      const capturedSession = Object.freeze({ userId });
      const req = {
        method: parsed.method,
        query: parsed.query,
        body: parsed.body,
        headers,
        user: capturedUser,
        session: capturedSession,
        get(name) { return headers[String(name).toLowerCase()]; },
      };
      const capture = responseCapture();
      await handleAgentAction(req, capture.res);
      // A handler may send early and continue asynchronous persistence. Awaiting
      // it and checking again prevents a late response from escaping cancellation.
      await check();
      await execution.check();
      return capture.result();
    });
  };
}

module.exports = { createCsrfManagedDispatch, MAX_RESPONSE_BYTES, MAX_RESPONSE_HEADERS };
