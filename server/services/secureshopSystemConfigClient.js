'use strict';

// Unmounted proposed protocol. Import only the frozen pure request contract,
// never executor code or sidecar filesystem/process privileges.
const { validateSystemConfigReceipt: validReceipt } = require('../../sidecars/sandbox-runner/owned-system/receipt');
const { VERSION, ISOLATION, hash, normalizeRequest, requestDigest }
  = require('../../sidecars/sandbox-runner/owned-system/contract');
const { validateOwnedSystemMetrics } = require('../../sidecars/sandbox-runner/owned-system/health-contract');
const HTTP_VERSION = 'secureshop-owned-system-http.v1';
const CAPABILITY = 'secureshop-owned-system-config-read.v1';
// JSON escaping may expand file text sixfold; allow bounded metadata overhead.
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const uncertainErrors = new WeakSet();
function unavailable() {
  return Object.assign(new Error('Owned System config service unavailable'), { code: 'SYSTEM_CONFIG_UNAVAILABLE', statusCode: 503 });
}
function uncertain() {
  const error = Object.assign(new Error('System config outcome unknown; do not retry automatically'),
    { code: 'SYSTEM_CONFIG_OUTCOME_UNCERTAIN', statusCode: 503, outcome: 'unknown', automaticRetry: false });
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
function createSecureShopSystemConfigClient({ baseURL, token, fetchImpl = fetch, timeoutMs = 3000 } = {}) {
  let origin;
  try { origin = new URL(baseURL); } catch { throw new TypeError('Exact System service origin required'); }
  if (!['http:','https:'].includes(origin.protocol) || origin.username || origin.password || origin.search || origin.hash
      || origin.pathname !== '/' || typeof token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(token)
      || typeof fetchImpl !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) throw new TypeError('Private bounded System transport configuration required');
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
      const value = await transport('/secureshop/system/health', undefined, signal);
      if (!exact(value, ['version','ready','isolation','configReadCapability']) || value.version !== HTTP_VERSION
          || value.ready !== true || value.isolation !== ISOLATION || value.configReadCapability !== CAPABILITY) throw unavailable();
      return true;
    } catch { throw unavailable(); }
  }
  return Object.freeze({ assertReady,
    async metrics({ signal } = {}) {
      try { return validateOwnedSystemMetrics(await transport('/secureshop/system/metrics', undefined, signal)); }
      catch { throw unavailable(); }
    },
    async read(raw, { signal, assertCurrent } = {}) {
      const request = normalizeRequest(raw);
      if (assertCurrent !== undefined && typeof assertCurrent !== 'function') throw new TypeError('Trusted authority check required');
      signal?.throwIfAborted();
      // Authority exceptions before the config POST retain their original type.
      await assertCurrent?.();
      await assertReady({ signal });
      await assertCurrent?.(); signal?.throwIfAborted();
      try {
        const value = await transport('/secureshop/system/config-read', request, signal);
        const receipt = validReceipt(request, value);
        await assertCurrent?.();
        return receipt;
      } catch { throw uncertain(); }
    },
  });
}
module.exports = { createSecureShopSystemConfigClient, validateSystemConfigReceipt: validReceipt,
  isSystemConfigOutcomeUncertain: error => uncertainErrors.has(error), HTTP_VERSION, CAPABILITY, MAX_RESPONSE_BYTES };
