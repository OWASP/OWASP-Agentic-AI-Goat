'use strict';

// Private owned upload preview transport. Import only the pure contract,
// never executor code or sidecar filesystem/process privileges.
const {VERSION:HTTP_VERSION,ISOLATION,normalizeUploadPreviewRequest,validateUploadPreviewReceipt}=require('../../sidecars/sandbox-runner/owned-system/upload-preview-contract');
const CAPABILITY='secureshop-upload-preview.v1';
// Bounded private transport covers image decode plus the five-second owned
// execution deadline and confirmed process drain. It never retries a POST.
const MAX_RESPONSE_BYTES = 512 * 1024;
const uncertainErrors = new WeakSet();
function unavailable() {
  return Object.assign(new Error('Owned upload preview service unavailable'), { code: 'UPLOAD_PREVIEW_UNAVAILABLE', statusCode: 503 });
}
function uncertain() {
  const error = Object.assign(new Error('Upload preview outcome unknown; do not retry automatically'),
    { code: 'UPLOAD_PREVIEW_OUTCOME_UNCERTAIN', statusCode: 503, outcome: 'unknown', automaticRetry: false });
  uncertainErrors.add(error); return error;
}
function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
async function readBounded(response, signal) {
  const length = response.headers?.get?.('content-length');
  if (length != null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
    try { Promise.resolve(response.body?.cancel?.()).catch(() => {}); } catch {}
    throw unavailable();
  }
  const reader = response.body?.getReader?.();
  if (!reader) throw unavailable();
  const cancel = () => { Promise.resolve(reader.cancel()).catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  const chunks = []; let size = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) { cancel(); throw unavailable(); }
      chunks.push(Buffer.from(item.value));
    }
    signal.throwIfAborted();
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size)));
  } finally { signal.removeEventListener('abort', cancel); reader.releaseLock?.(); }
}
function createSecureShopUploadPreviewClient({ baseURL, token, fetchImpl = fetch, timeoutMs = 18000 } = {}) {
  let origin;
  try { origin = new URL(baseURL); } catch { throw new TypeError('Exact Upload preview service origin required'); }
  if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' || !/^[0-9]+$/.test(origin.port) || Number(origin.port)<1024 || Number(origin.port)>65535 || origin.username || origin.password || origin.search || origin.hash
      || origin.pathname !== '/' || typeof token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(token)
      || typeof fetchImpl !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 20000) throw new TypeError('Private bounded upload preview transport configuration required');
  async function transport(route, body, signal) {
    const controller = new AbortController(); let timer, onAbort;
    const interrupted = new Promise((_, reject) => {
      onAbort = () => { controller.abort(); reject(unavailable()); };
      signal?.addEventListener('abort', onAbort, { once: true });
      timer = setTimeout(onAbort, timeoutMs);
    });
    try {
      if (signal?.aborted) { onAbort(); return await interrupted; }
      const work = (async () => {
        const response = await fetchImpl(new URL(route, origin), {
          method: body === undefined ? 'GET' : 'POST', redirect: 'error', credentials: 'omit', signal: controller.signal,
          headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        if (controller.signal.aborted) { try { await response?.body?.cancel?.(); } catch {} throw unavailable(); }
        if (!response?.ok) { try { await response?.body?.cancel?.(); } catch {} throw unavailable(); }
        return readBounded(response, controller.signal);
      })();
      return await Promise.race([work, interrupted]);
    } finally { clearTimeout(timer); signal?.removeEventListener('abort', onAbort); }
  }
  async function assertReady({ signal } = {}) {
    try {
      const value = await transport('/secureshop/uploads/preview-health', undefined, signal);
      if (!exact(value, ['version','ready','isolation','previewCapability']) || value.version !== HTTP_VERSION
          || value.ready !== true || value.isolation !== ISOLATION || value.previewCapability !== CAPABILITY) throw unavailable();
      return true;
    } catch { throw unavailable(); }
  }
  return Object.freeze({ assertReady,
    async preview(raw, { signal, assertCurrent } = {}) {
      const request = normalizeUploadPreviewRequest(raw);
      if (typeof assertCurrent !== 'function') throw new TypeError('Trusted authority check required');
      signal?.throwIfAborted();
      // Authority exceptions before the diagnostic POST retain their original type.
      await assertCurrent?.();
      await assertReady({ signal });
      await assertCurrent?.(); signal?.throwIfAborted();
      try {
        const value = await transport('/secureshop/uploads/preview', request, signal);
        const receipt = validateUploadPreviewReceipt(value, request);
        await assertCurrent?.();
        return receipt;
      } catch { throw uncertain(); }
    },
  });
}
module.exports = { createSecureShopUploadPreviewClient, validateUploadPreviewReceipt,
  isUploadPreviewOutcomeUncertain: error => uncertainErrors.has(error), HTTP_VERSION, CAPABILITY, MAX_RESPONSE_BYTES };
