'use strict';

const { normalizeListingTemplateExecution, validateListingTemplateExecutionResult }
  = require('../../../server/services/secureshopListingTemplateExecutorContract');
const { listingTemplateEffectWitnessFor } = require('./executor');
const MAX_BODY_BYTES = 128 * 1024;
const fail = (status, code) => Object.assign(new Error(code), { status, code });

function createListingTemplateHttpHandler({ executor, witnessFor = listingTemplateEffectWitnessFor,
  bodyTimeoutMs = 3000 } = {}) {
  if (typeof executor?.execute !== 'function' || typeof witnessFor !== 'function'
      || !Number.isInteger(bodyTimeoutMs) || bodyTimeoutMs < 100 || bodyTimeoutMs > 10000) throw new TypeError('Bounded template HTTP configuration required');
  const active = new Set();
  let closing = false;
  const respond = (res, status, body) => {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
      ...(status >= 400 ? { connection: 'close' } : {}) });
    res.end(JSON.stringify(body));
  };
  async function handle(req, res) {
    if (req.url !== '/secureshop/listing-template-render') return false;
    if (req.method !== 'POST') { respond(res, 405, { error: 'LISTING_TEMPLATE_METHOD_NOT_ALLOWED' }); return true; }
    if (closing || active.size >= 1) { respond(res, 503, { error: 'LISTING_TEMPLATE_BUSY' }); return true; }
    const controller = new AbortController();
    let finish;
    const entry = { controller, done: new Promise(resolve => { finish = resolve; }) };
    active.add(entry);
    const disconnect = () => { if (!res.writableEnded) controller.abort(fail(499, 'LISTING_TEMPLATE_CLIENT_DISCONNECTED')); };
    res.once('close', disconnect);
    const timer = setTimeout(() => controller.abort(fail(408, 'LISTING_TEMPLATE_BODY_TIMEOUT')), bodyTimeoutMs);
    try {
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) throw fail(415, 'LISTING_TEMPLATE_JSON_REQUIRED');
      const size = req.headers['content-length'];
      if (size !== undefined && (!/^\d+$/.test(size) || Number(size) > MAX_BODY_BYTES)) throw fail(413, 'LISTING_TEMPLATE_BODY_TOO_LARGE');
      const chunks = []; let total = 0;
      const body = await new Promise((resolve, reject) => {
        const cleanup = () => { req.off('data', data); req.off('end', end); req.off('error', error); req.off('aborted', aborted); controller.signal.removeEventListener('abort', aborted); };
        const error = reason => { cleanup(); reject(reason); };
        const aborted = () => error(controller.signal.reason || fail(400, 'LISTING_TEMPLATE_BODY_ABORTED'));
        const data = chunk => { total += chunk.length; if (total > MAX_BODY_BYTES) error(fail(413, 'LISTING_TEMPLATE_BODY_TOO_LARGE')); else chunks.push(chunk); };
        const end = () => { cleanup(); resolve(Buffer.concat(chunks, total)); };
        req.on('data', data); req.once('end', end); req.once('error', error); req.once('aborted', aborted); controller.signal.addEventListener('abort', aborted, { once: true });
        if (controller.signal.aborted) aborted();
      });
      clearTimeout(timer);
      let request;
      try { request = normalizeListingTemplateExecution(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body))); }
      catch { throw fail(400, 'LISTING_TEMPLATE_INVALID_REQUEST'); }
      const result = await executor.execute(request, { signal: controller.signal });
      controller.signal.throwIfAborted();
      const witness = witnessFor(result);
      if (!witness || witness.workerAttested !== result.workerAttested
          || witness.commandEffectObserved !== result.commandEffectObserved
          || witness.effectSha256 !== result.effectSha256) throw fail(503, 'LISTING_TEMPLATE_EXECUTION_UNAVAILABLE');
      respond(res, 200, validateListingTemplateExecutionResult(request, result));
    } catch (error) {
      respond(res, error.status || 503, { error: error.status ? error.code : 'LISTING_TEMPLATE_UNAVAILABLE' });
    } finally {
      clearTimeout(timer); res.off('close', disconnect); active.delete(entry); finish();
    }
    return true;
  }
  async function close() {
    closing = true;
    const pending = [...active];
    for (const entry of pending) entry.controller.abort(fail(503, 'LISTING_TEMPLATE_SHUTDOWN'));
    await Promise.all(pending.map(entry => entry.done));
  }
  return Object.freeze({ handle, close });
}

module.exports = { createListingTemplateHttpHandler, MAX_BODY_BYTES };
