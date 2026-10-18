'use strict';

const crypto = require('node:crypto');
const { normalizeRequest } = require('./contract');
const { createSystemConfigExecutor } = require('./executor');
const { validateSystemConfigReceipt } = require('./receipt');
const { createOwnedSystemMetrics } = require('./health-metrics');
const { validateOwnedSystemMetrics } = require('./health-contract');
const HTTP_VERSION = 'secureshop-owned-system-http.v1';
const CAPABILITY = 'secureshop-owned-system-config-read.v1';
const { ISOLATION } = require('./contract');
const MAX_BODY_BYTES = 32 * 1024;
const fail = (status, code) => Object.assign(new Error(code), { status, code });

// Explicit opt-in factory only. No main service mounting or deployment changes.
function createSystemConfigHttpHandler({ enabled = false, token, executor, metrics, maxConcurrent = 2, bodyTimeoutMs = 3000 } = {}) {
  if (typeof enabled !== 'boolean') throw new TypeError('Explicit System feature flag required');
  if (!enabled) return Object.freeze({ handle: async () => false, close: async () => {} });
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(token)) throw new TypeError('Private System bearer required');
  executor = executor || createSystemConfigExecutor();
  metrics = metrics || createOwnedSystemMetrics();
  if (typeof executor.read !== 'function' || typeof executor.assertReady !== 'function' || typeof metrics.snapshot !== 'function'
      || !Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16
      || !Number.isInteger(bodyTimeoutMs) || bodyTimeoutMs < 100 || bodyTimeoutMs > 10000) throw new TypeError('Bounded System HTTP configuration required');
  const expected = Buffer.from(`Bearer ${token}`);
  const active = new Set();
  let closing = false;
  function respond(res, status, body) {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
      ...(status >= 400 ? { connection: 'close' } : {}) });
    res.end(JSON.stringify(body));
  }
  async function handle(req, res) {
    const health = req.url === '/secureshop/system/health';
    const systemMetrics = req.url === '/secureshop/system/metrics';
    if (!health && !systemMetrics && req.url !== '/secureshop/system/config-read') return false;
    const raw = req.headers.authorization;
    const actual = Buffer.from(typeof raw === 'string' ? raw : '');
    const authHeaders = (req.rawHeaders || []).filter((_, index) => index % 2 === 0).filter(key => key.toLowerCase() === 'authorization');
    if (authHeaders.length !== 1 || actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      respond(res, 401, { error: 'SYSTEM_UNAUTHORIZED' }); return true;
    }
    if (req.method !== (health || systemMetrics ? 'GET' : 'POST')) { respond(res, 405, { error: 'SYSTEM_METHOD_NOT_ALLOWED' }); return true; }
    if (closing || active.size >= maxConcurrent) { respond(res, 503, { error: 'SYSTEM_CONFIG_BUSY' }); return true; }
    // Readiness calls the fixed executor's checked assets/helper namespace probe.
    // It cannot be replaced with a configured flag or an unconditional health row.
    try {
      const readiness = executor.assertReady();
      if (readiness && typeof readiness.then === 'function') {
        Promise.resolve(readiness).catch(() => {});
        throw new TypeError('Fixed synchronous System readiness required');
      }
    }
    catch { respond(res, 503, { error: 'SYSTEM_CONFIG_UNAVAILABLE' }); return true; }
    if (health) {
      respond(res, 200, { version: HTTP_VERSION, ready: true, isolation: ISOLATION, configReadCapability: CAPABILITY });
      return true;
    }
    if (systemMetrics) {
      try {
        const value = metrics.snapshot();
        if (value && typeof value.then === 'function') { Promise.resolve(value).catch(() => {}); throw new Error('Asynchronous metrics provider'); }
        respond(res, 200, validateOwnedSystemMetrics(value));
      }
      catch { respond(res, 503, { error: 'SYSTEM_METRICS_UNAVAILABLE' }); }
      return true;
    }
    const controller = new AbortController();
    let finish;
    const entry = { controller, done: new Promise(resolve => { finish = resolve; }) };
    active.add(entry);
    const disconnect = () => { if (!res.writableEnded) controller.abort(fail(499, 'SYSTEM_CLIENT_DISCONNECTED')); };
    res.once('close', disconnect);
    const timer = setTimeout(() => controller.abort(fail(408, 'SYSTEM_BODY_TIMEOUT')), bodyTimeoutMs);
    try {
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) throw fail(415, 'SYSTEM_JSON_REQUIRED');
      const size = req.headers['content-length'];
      if (size !== undefined && (!/^\d+$/.test(size) || Number(size) > MAX_BODY_BYTES)) throw fail(413, 'SYSTEM_BODY_TOO_LARGE');
      const chunks = []; let total = 0;
      const body = await new Promise((resolve, reject) => {
        const cleanup = () => { req.off('data', data); req.off('end', end); req.off('error', error); req.off('aborted', aborted); controller.signal.removeEventListener('abort', aborted); };
        const error = reason => { cleanup(); reject(reason); };
        const aborted = () => error(controller.signal.reason || fail(400, 'SYSTEM_BODY_ABORTED'));
        const data = chunk => { total += chunk.length; if (total > MAX_BODY_BYTES) error(fail(413, 'SYSTEM_BODY_TOO_LARGE')); else chunks.push(chunk); };
        const end = () => { cleanup(); resolve(Buffer.concat(chunks, total)); };
        req.on('data', data); req.once('end', end); req.once('error', error); req.once('aborted', aborted); controller.signal.addEventListener('abort', aborted, { once: true });
        if (controller.signal.aborted) aborted();
      });
      clearTimeout(timer);
      let request;
      try { request = normalizeRequest(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body))); }
      catch { throw fail(400, 'SYSTEM_INVALID_REQUEST'); }
      const result = await executor.read(request, { signal: controller.signal });
      controller.signal.throwIfAborted();
      respond(res, 200, validateSystemConfigReceipt(request, result));
    } catch (error) {
      respond(res, error.status || 503, { error: error.status ? error.code : 'SYSTEM_CONFIG_UNAVAILABLE' });
    } finally {
      clearTimeout(timer); res.off('close', disconnect); active.delete(entry); finish();
    }
    return true;
  }
  async function close() {
    closing = true;
    const pending = [...active];
    for (const entry of pending) entry.controller.abort(fail(503, 'SYSTEM_RENDER_SHUTDOWN'));
    await Promise.all(pending.map(entry => entry.done));
  }
  return Object.freeze({ handle, close });
}

module.exports = { createSystemConfigHttpHandler, MAX_BODY_BYTES };
