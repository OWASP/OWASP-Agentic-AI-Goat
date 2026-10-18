'use strict';

const { normalizeRenderRequest, validateRenderResult, normalizeRenderExecution,
  validateRenderExecutionResult } = require('../../../server/services/secureshopPromptPolicyContract');
const MAX_BODY_BYTES = 128 * 1024;
const fail = (status, code) => Object.assign(new Error(code), { status, code });

// Dedicated endpoint; mounting and process lifecycle remain the caller's job.
function createPolicyRenderHttpHandler({ executor, maxConcurrent = 2, bodyTimeoutMs = 3000 } = {}) {
  if (typeof executor?.render !== 'function' || !Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16
      || !Number.isInteger(bodyTimeoutMs) || bodyTimeoutMs < 100 || bodyTimeoutMs > 10000) throw new TypeError('Bounded policy HTTP configuration required');
  const active = new Set();
  let closing = false;
  function respond(res, status, body) {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
      ...(status >= 400 ? { connection: 'close' } : {}) });
    res.end(JSON.stringify(body));
  }
  async function handle(req, res) {
    if (req.url !== '/secureshop/policy-render') return false;
    if (req.method !== 'POST') { respond(res, 405, { error: 'POLICY_METHOD_NOT_ALLOWED' }); return true; }
    if (closing || active.size >= maxConcurrent) { respond(res, 503, { error: 'POLICY_RENDER_BUSY' }); return true; }
    const controller = new AbortController();
    let finish;
    const entry = { controller, done: new Promise(resolve => { finish = resolve; }) };
    active.add(entry);
    const disconnect = () => { if (!res.writableEnded) controller.abort(fail(499, 'POLICY_CLIENT_DISCONNECTED')); };
    res.once('close', disconnect);
    const timer = setTimeout(() => controller.abort(fail(408, 'POLICY_BODY_TIMEOUT')), bodyTimeoutMs);
    try {
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) throw fail(415, 'POLICY_JSON_REQUIRED');
      const size = req.headers['content-length'];
      if (size !== undefined && (!/^\d+$/.test(size) || Number(size) > MAX_BODY_BYTES)) throw fail(413, 'POLICY_BODY_TOO_LARGE');
      const chunks = []; let total = 0;
      const body = await new Promise((resolve, reject) => {
        const cleanup = () => { req.off('data', data); req.off('end', end); req.off('error', error); req.off('aborted', aborted); controller.signal.removeEventListener('abort', aborted); };
        const error = reason => { cleanup(); reject(reason); };
        const aborted = () => error(controller.signal.reason || fail(400, 'POLICY_BODY_ABORTED'));
        const data = chunk => { total += chunk.length; if (total > MAX_BODY_BYTES) error(fail(413, 'POLICY_BODY_TOO_LARGE')); else chunks.push(chunk); };
        const end = () => { cleanup(); resolve(Buffer.concat(chunks, total)); };
        req.on('data', data); req.once('end', end); req.once('error', error); req.once('aborted', aborted); controller.signal.addEventListener('abort', aborted, { once: true });
        if (controller.signal.aborted) aborted();
      });
      clearTimeout(timer);
      let request;
      try { const raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
        request = raw?.version === 2 ? normalizeRenderExecution(raw) : normalizeRenderRequest(raw); }
      catch { throw fail(400, 'POLICY_INVALID_REQUEST'); }
      const result = await executor.render(request, { signal: controller.signal });
      controller.signal.throwIfAborted();
      respond(res, 200, request.version === 2 ? validateRenderExecutionResult(request, result)
        : validateRenderResult(request, result));
    } catch (error) {
      respond(res, error.status || 503, { error: error.status ? error.code : 'POLICY_RENDER_UNAVAILABLE' });
    } finally {
      clearTimeout(timer); res.off('close', disconnect); active.delete(entry); finish();
    }
    return true;
  }
  async function close() {
    closing = true;
    const pending = [...active];
    for (const entry of pending) entry.controller.abort(fail(503, 'POLICY_RENDER_SHUTDOWN'));
    await Promise.all(pending.map(entry => entry.done));
  }
  return Object.freeze({ handle, close });
}

module.exports = { createPolicyRenderHttpHandler, MAX_BODY_BYTES };
