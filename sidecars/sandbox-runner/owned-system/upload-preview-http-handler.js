'use strict';

const crypto = require('node:crypto');
const {normalizeUploadPreviewRequest,validateUploadPreviewReceipt,VERSION:HTTP_VERSION,ISOLATION}=require('./upload-preview-contract');
const {createUploadPreviewExecutor}=require('./upload-preview-executor');
const CAPABILITY='secureshop-upload-preview.v1';
const MAX_BODY_BYTES = 512 * 1024;
const fail = (status, code) => Object.assign(new Error(code), { status, code });

// Explicit opt-in factory only. No main service mounting or deployment changes.
function createUploadPreviewHttpHandler({ enabled = false, token, executor, maxConcurrent = 1, bodyTimeoutMs = 3000 } = {}) {
  if (typeof enabled !== 'boolean') throw new TypeError('Explicit System feature flag required');
  if (!enabled) return Object.freeze({ handle: async () => false, close: async () => {} });
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(token)) throw new TypeError('Private System bearer required');
  executor = executor || createUploadPreviewExecutor();
  if (typeof executor.preview !== 'function' || typeof executor.assertReady !== 'function'
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
    const health = req.url === '/secureshop/uploads/preview-health';
    if (!health && req.url !== '/secureshop/uploads/preview') return false;
    const raw = req.headers.authorization;
    const actual = Buffer.from(typeof raw === 'string' ? raw : '');
    const authHeaders = (req.rawHeaders || []).filter((_, index) => index % 2 === 0).filter(key => key.toLowerCase() === 'authorization');
    if (authHeaders.length !== 1 || actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      respond(res, 401, { error: 'UPLOAD_PREVIEW_UNAUTHORIZED' }); return true;
    }
    if (req.method !== (health ? 'GET' : 'POST')) { respond(res, 405, { error: 'UPLOAD_PREVIEW_METHOD_NOT_ALLOWED' }); return true; }
    if (closing || active.size >= maxConcurrent) { respond(res, 503, { error: 'UPLOAD_PREVIEW_BUSY' }); return true; }
    const controller = new AbortController();
    let finish;
    const entry = { controller, done: new Promise(resolve => { finish = resolve; }) };
    active.add(entry);
    const disconnect = () => { if (!res.writableEnded) controller.abort(fail(499, 'UPLOAD_PREVIEW_CLIENT_DISCONNECTED')); };
    res.once('close', disconnect);
    let timer;
    try {
      // Admission is held for readiness too; an async probe cannot bypass the cap.
      await executor.assertReady({signal:controller.signal});
      controller.signal.throwIfAborted();
      if(health){respond(res,200,{version:HTTP_VERSION,ready:true,isolation:ISOLATION,previewCapability:CAPABILITY});return true;}
      timer=setTimeout(()=>controller.abort(fail(408,'UPLOAD_PREVIEW_BODY_TIMEOUT')),bodyTimeoutMs);
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) throw fail(415, 'UPLOAD_PREVIEW_JSON_REQUIRED');
      const size = req.headers['content-length'];
      if (size !== undefined && (!/^\d+$/.test(size) || Number(size) > MAX_BODY_BYTES)) throw fail(413, 'UPLOAD_PREVIEW_BODY_TOO_LARGE');
      const chunks = []; let total = 0;
      const body = await new Promise((resolve, reject) => {
        const cleanup = () => { req.off('data', data); req.off('end', end); req.off('error', error); req.off('aborted', aborted); controller.signal.removeEventListener('abort', aborted); };
        const error = reason => { cleanup(); reject(reason); };
        const aborted = () => error(controller.signal.reason || fail(400, 'UPLOAD_PREVIEW_BODY_ABORTED'));
        const data = chunk => { total += chunk.length; if (total > MAX_BODY_BYTES) error(fail(413, 'UPLOAD_PREVIEW_BODY_TOO_LARGE')); else chunks.push(chunk); };
        const end = () => { cleanup(); resolve(Buffer.concat(chunks, total)); };
        req.on('data', data); req.once('end', end); req.once('error', error); req.once('aborted', aborted); controller.signal.addEventListener('abort', aborted, { once: true });
        if (controller.signal.aborted) aborted();
      });
      clearTimeout(timer);
      let request;
      try { request = normalizeUploadPreviewRequest(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body))); }
      catch { throw fail(400, 'UPLOAD_PREVIEW_INVALID_REQUEST'); }
      const result = await executor.preview(request, { signal: controller.signal });
      controller.signal.throwIfAborted();
      respond(res, 200, validateUploadPreviewReceipt(result, request));
    } catch (error) {
      respond(res, error.status || 503, { error: error.status ? error.code : 'UPLOAD_PREVIEW_UNAVAILABLE' });
    } finally {
      clearTimeout(timer); res.off('close', disconnect); active.delete(entry); finish();
    }
    return true;
  }
  async function close() {
    closing = true;
    const pending = [...active];
    for (const entry of pending) entry.controller.abort(fail(503, 'UPLOAD_PREVIEW_SHUTDOWN'));
    await Promise.all(pending.map(entry => entry.done));
  }
  return Object.freeze({ handle, close });
}

module.exports = { createUploadPreviewHttpHandler, MAX_BODY_BYTES };
