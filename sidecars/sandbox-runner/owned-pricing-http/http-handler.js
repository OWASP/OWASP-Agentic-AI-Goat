'use strict';

const crypto = require('node:crypto');
const {
  normalizeRequest,
  bindResult,
  VERSION: HTTP_VERSION
} = require('./wire');
const CAPABILITY = 'secureshop-owned-pricing-http.v1';
const ISOLATION = 'bwrap-owned-pricing-http-v1';
const MAX_BODY_BYTES = 128 * 1024;
const fail = (status, code) => Object.assign(new Error(code), {
  status,
  code
});

// Explicit opt-in factory only. No main service mounting or deployment changes.
function createPricingHttpHandler({
  enabled = false,
  token,
  executor,
  maxConcurrent = 2,
  bodyTimeoutMs = 3000
} = {}) {
  if (typeof enabled !== 'boolean') throw new TypeError('Explicit pricing feature flag required');
  if (!enabled) return Object.freeze({
    handle: async () => false,
    close: async () => {}
  });
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(token)) throw new TypeError('Private pricing bearer required');
  if (typeof executor?.execute !== 'function' || typeof executor?.assertReady !== 'function' || typeof executor?.checkReadiness !== 'function' || !Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16 || !Number.isInteger(bodyTimeoutMs) || bodyTimeoutMs < 100 || bodyTimeoutMs > 10000) throw new TypeError('Bounded pricing HTTP configuration required');
  const expected = Buffer.from(`Bearer ${token}`);
  const active = new Set();
  let closing = false;
  function respond(res, status, body) {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...(status >= 400 ? {
        connection: 'close'
      } : {})
    });
    res.end(JSON.stringify(body));
  }
  async function handle(req, res) {
    const health = req.url === '/secureshop/pricing/health';
    if (!health && req.url !== '/secureshop/pricing/observe') return false;
    const raw = req.headers.authorization;
    const actual = Buffer.from(typeof raw === 'string' ? raw : '');
    const authHeaders = (req.rawHeaders || []).filter((_, index) => index % 2 === 0).filter(key => key.toLowerCase() === 'authorization');
    if (authHeaders.length !== 1 || actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      respond(res, 401, {
        error: 'PRICING_UNAUTHORIZED'
      });
      return true;
    }
    if (req.method !== (health ? 'GET' : 'POST')) {
      respond(res, 405, {
        error: 'PRICING_METHOD_NOT_ALLOWED'
      });
      return true;
    }
    if (closing || active.size >= maxConcurrent) {
      respond(res, 503, {
        error: 'PRICING_HTTP_BUSY'
      });
      return true;
    }
    const controller = new AbortController();
    let finish;
    const entry = {
      controller,
      done: new Promise(resolve => {
        finish = resolve;
      })
    };
    active.add(entry);
    const disconnect = () => {
      if (!res.writableEnded) controller.abort(fail(499, 'PRICING_CLIENT_DISCONNECTED'));
    };
    res.once('close', disconnect);
    let timer;
    try {
      // Admission is held for readiness too; an async probe cannot bypass the cap.
      const readiness = await (health ? executor.assertReady({
        signal: controller.signal
      }) : executor.checkReadiness());
      if (readiness?.ready !== true) throw fail(503, 'PRICING_HTTP_UNAVAILABLE');
      controller.signal.throwIfAborted();
      if (health) {
        respond(res, 200, {
          version: HTTP_VERSION,
          ready: true,
          isolation: ISOLATION,
          pricingCapability: CAPABILITY
        });
        return true;
      }
      timer = setTimeout(() => controller.abort(fail(408, 'PRICING_BODY_TIMEOUT')), bodyTimeoutMs);
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) throw fail(415, 'PRICING_JSON_REQUIRED');
      const size = req.headers['content-length'];
      if (size !== undefined && (!/^\d+$/.test(size) || Number(size) > MAX_BODY_BYTES)) throw fail(413, 'PRICING_BODY_TOO_LARGE');
      const chunks = [];
      let total = 0;
      const body = await new Promise((resolve, reject) => {
        const cleanup = () => {
          req.off('data', data);
          req.off('end', end);
          req.off('error', error);
          req.off('aborted', aborted);
          controller.signal.removeEventListener('abort', aborted);
        };
        const error = reason => {
          cleanup();
          reject(reason);
        };
        const aborted = () => error(controller.signal.reason || fail(400, 'PRICING_BODY_ABORTED'));
        const data = chunk => {
          total += chunk.length;
          if (total > MAX_BODY_BYTES) error(fail(413, 'PRICING_BODY_TOO_LARGE'));else chunks.push(chunk);
        };
        const end = () => {
          cleanup();
          resolve(Buffer.concat(chunks, total));
        };
        req.on('data', data);
        req.once('end', end);
        req.once('error', error);
        req.once('aborted', aborted);
        controller.signal.addEventListener('abort', aborted, {
          once: true
        });
        if (controller.signal.aborted) aborted();
      });
      clearTimeout(timer);
      let request;
      try {
        request = normalizeRequest(JSON.parse(new TextDecoder('utf-8', {
          fatal: true
        }).decode(body)));
      } catch {
        throw fail(400, 'PRICING_INVALID_REQUEST');
      }
      const result = await executor.execute({
        input: request.input,
        signal: controller.signal
      });
      controller.signal.throwIfAborted();
      respond(res, 200, bindResult(request, result));
    } catch (error) {
      respond(res, error.status || 503, {
        error: error.status ? error.code : 'PRICING_HTTP_UNAVAILABLE'
      });
    } finally {
      clearTimeout(timer);
      res.off('close', disconnect);
      active.delete(entry);
      finish();
    }
    return true;
  }
  async function close() {
    closing = true;
    const pending = [...active];
    for (const entry of pending) entry.controller.abort(fail(503, 'PRICING_HTTP_SHUTDOWN'));
    await Promise.all(pending.map(entry => entry.done));
  }
  return Object.freeze({
    handle,
    close
  });
}
module.exports = {
  createPricingHttpHandler,
  MAX_BODY_BYTES
};
