'use strict';

const { createHash } = require('node:crypto');
const sha = value => createHash('sha256').update(value).digest('hex');
const MODEL = 'llama3.1:8b';
const ORIGIN = 'http://127.0.0.1:11434';

// Qualification helper only. No global patch or network call occurs on import.
// Full provider bytes stay in this closure; only publicCalls() is report-safe.
function createSqlNoSqlModelProvenance({ fetchImpl, mountedHttpOrigin, maxCallsPerScope = 32, maxCallsTotal = 128 } = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('An explicit fetch implementation is required');
  if (mountedHttpOrigin !== undefined) {
    const mounted = new URL(mountedHttpOrigin);
    if (mounted.origin !== mountedHttpOrigin || mounted.protocol !== 'http:' || mounted.hostname !== '127.0.0.1'
        || !mounted.port || mounted.origin === ORIGIN || mounted.username || mounted.password) {
      throw new TypeError('An explicit separate mounted loopback HTTP origin is required');
    }
  }
  if (!Number.isInteger(maxCallsPerScope) || maxCallsPerScope < 1 || !Number.isInteger(maxCallsTotal) || maxCallsTotal < maxCallsPerScope) {
    throw new TypeError('Finite positive model-call bounds are required');
  }
  const scopes = new Map();
  let active = null;
  async function withScope(scopeId, callback) {
    if (typeof scopeId !== 'string' || !/^[a-zA-Z0-9_-]{1,100}$/.test(scopeId)
        || scopes.has(scopeId) || active !== null || typeof callback !== 'function') {
      throw new TypeError('A unique serial qualification scope is required');
    }
    const scope = { records: [], pending: 0, closed: false };
    scopes.set(scopeId, scope); active = scope;
    try { return await callback(); }
    finally {
      scope.closed = true; active = null;
      if (scope.pending) for (const record of scope.records) {
        record.qualified = false; record.failureCode = 'SCOPE_CLOSED_WITH_PENDING_CALLS';
      }
    }
  }
  async function fetchCaptured(input, options = {}) {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    if (mountedHttpOrigin && url.origin === mountedHttpOrigin && !url.username && !url.password) return fetchImpl(input, options);
    if (url.origin !== ORIGIN || !['/api/chat', '/api/generate'].includes(url.pathname)
        || url.username || url.password || url.search || url.hash) throw new Error('PROVENANCE_ENDPOINT_REJECTED');
    if (!active) throw new Error('PROVENANCE_SCOPE_REQUIRED');
    const scope = active;
    const totalCalls = [...scopes.values()].reduce((sum, value) => sum + value.records.length, 0);
    if (scope.records.length >= maxCallsPerScope || totalCalls >= maxCallsTotal) {
      throw new Error('PROVENANCE_CALL_BUDGET_EXCEEDED');
    }
    const signal = options.signal || (input instanceof Request ? input.signal : null);
    // Reserve the call before any asynchronous Request-body read. Otherwise
    // parallel Request inputs can all pass the budget check while their body
    // clones are waiting, then dispatch more calls than the published bound.
    const record = { request: '', response: '', text: '', endpoint: url.pathname,
      qualified: false, failureCode: null, model: null, httpStatus: null };
    scope.records.push(record); scope.pending++;
    try {
      const request = typeof options.body === 'string' ? options.body : input instanceof Request ? await input.clone().text() : '';
      record.request = request;
      if (scope.closed) {
        record.failureCode = 'SCOPE_CLOSED_WITH_PENDING_CALLS';
        throw new Error('PROVENANCE_SCOPE_CLOSED');
      }
      const parsedRequest = JSON.parse(request);
      if (parsedRequest.model !== MODEL) throw new Error('PROVENANCE_REQUEST_MODEL_REJECTED');
      if (signal?.aborted) throw new Error('PROVENANCE_ABORTED');
      const response = await fetchImpl(input, { ...options, redirect: 'error' });
      if (response.redirected || (response.url && response.url !== url.href)) {
        record.failureCode = 'PROVENANCE_RESPONSE_ENDPOINT_REJECTED';
        return response;
      }
      record.httpStatus = response.status;
      record.response = await response.clone().text();
      if (signal?.aborted) throw new Error('PROVENANCE_ABORTED');
      if (!response.ok) { record.failureCode = 'HTTP_FAILED'; return response; }
      try {
        let rows;
        try { rows = [JSON.parse(record.response)]; }
        catch { rows = record.response.split('\n').filter(line => line.trim()).map(line => JSON.parse(line)); }
        if (!rows.length || rows.some(row => !row || typeof row !== 'object' || Array.isArray(row) || row.error)) throw new Error();
        if (rows.at(-1).done !== true || rows.slice(0, -1).some(row => row.done === true)) throw new Error();
        if (rows.some(row => row.model !== MODEL)) { record.failureCode = 'RESPONSE_MODEL_MISMATCH'; return response; }
        const key = url.pathname === '/api/chat' ? 'chat' : 'generate';
        const fragments = rows.map(row => {
          const value = key === 'chat' ? row.message?.content : row.response;
          // Terminal generate frames may omit response, but never accept an
          // arbitrary shape as an empty successful model result.
          if (value === undefined && row.done === true) return '';
          if (typeof value !== 'string') throw new Error();
          return value;
        });
        record.text = fragments.join(''); record.model = MODEL;
        if (!record.text.trim()) { record.failureCode = 'EMPTY_MODEL_OUTPUT'; return response; }
        if (scope.closed) { record.failureCode = 'SCOPE_CLOSED_WITH_PENDING_CALLS'; return response; }
        record.qualified = true;
      } catch { record.failureCode = 'MALFORMED_OR_TRUNCATED_RESPONSE'; }
      return response;
    } catch (error) {
      record.failureCode = scope.closed ? 'SCOPE_CLOSED_WITH_PENDING_CALLS'
        : signal?.aborted || error?.name === 'AbortError' ? 'PROVENANCE_ABORTED'
        : ['PROVENANCE_REQUEST_MODEL_REJECTED', 'PROVENANCE_ABORTED'].includes(error?.message) ? error.message : 'TRANSPORT_OR_REQUEST_FAILED';
      throw error;
    } finally { scope.pending--; }
  }
  function records(scopeId) {
    const scope = scopes.get(scopeId);
    if (!scope || !scope.closed || scope.pending) throw new Error('PROVENANCE_SCOPE_NOT_COMPLETE');
    return scope.records;
  }
  function exactDecision(scopeId, { tool, params }) {
    // No prefix matching, code-fence repair, fabricated model outputs or subset
    // parameter comparisons are accepted as selection proof.
    const matches = records(scopeId).filter(record => {
      if (!record.qualified) return false;
      try {
        const decision = JSON.parse(record.text);
        return decision.tool === tool && sameJson(decision.params, params);
      } catch { return false; }
    });
    return matches.length > 0;
  }
  function publicCalls(scopeId) {
    return records(scopeId).map(record => Object.freeze({
      provider: 'ollama', model: record.model, endpoint: record.endpoint,
      qualified: record.qualified, failureCode: record.failureCode, httpStatus: record.httpStatus,
      requestSha256: sha(record.request), requestBytes: Buffer.byteLength(record.request),
      responseSha256: sha(record.response), responseBytes: Buffer.byteLength(record.response),
      outputSha256: sha(record.text), outputBytes: Buffer.byteLength(record.text),
    }));
  }
  function getPrivateCalls(scopeId) {
    return records(scopeId).map(record => Object.freeze({ ...record }));
  }
  function totalCalls() {
    return [...scopes.values()].reduce((sum, value) => sum + value.records.length, 0);
  }
  return Object.freeze({ fetch: fetchCaptured, withScope, exactDecision, publicCalls, getPrivateCalls, totalCalls });
}
function sameJson(left, right) {
  if (left === right) return true;
  if (left === null || right === null || typeof left !== 'object' || typeof right !== 'object' || Array.isArray(left) !== Array.isArray(right)) return false;
  const keys = Object.keys(left).sort();
  return keys.length === Object.keys(right).length && keys.every(key => Object.hasOwn(right, key) && sameJson(left[key], right[key]));
}
module.exports = { createSqlNoSqlModelProvenance };
