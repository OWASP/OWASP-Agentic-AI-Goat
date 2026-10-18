'use strict';

const { normalizeRenderRequest, validateRenderResult, normalizeRenderExecution,
  validateRenderExecutionResult, ISOLATION }
  = require('./secureshopPromptPolicyContract');

const MAX_RESPONSE_BYTES = 512 * 1024;

function unavailable(message = 'Owned policy renderer unavailable') {
  return Object.assign(new Error(message), { code: 'POLICY_RENDER_UNAVAILABLE' });
}
async function readBoundedJson(response) {
  const length = response.headers?.get?.('content-length');
  if (length !== null && length !== undefined && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
    throw unavailable('Owned policy renderer response exceeded its bound');
  }
  const reader = response.body?.getReader?.();
  if (!reader) throw unavailable('Owned policy renderer returned an unreadable response');
  const chunks = []; let total = 0;
  while (true) {
    const item = await reader.read();
    if (item.done) break;
    total += item.value.byteLength;
    if (total > MAX_RESPONSE_BYTES) { await reader.cancel(); throw unavailable('Owned policy renderer response exceeded its bound'); }
    chunks.push(Buffer.from(item.value));
  }
  try { return JSON.parse(Buffer.concat(chunks, total).toString('utf8')); }
  catch { throw unavailable('Owned policy renderer returned invalid JSON'); }
}
function createSecureShopPolicySandboxRuntime({ baseUrl, fetchImpl = fetch, timeoutMs = 3000 } = {}) {
  if (typeof baseUrl !== 'string' || !/^https?:\/\/[^/]+$/.test(baseUrl)
      || typeof fetchImpl !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) {
    throw new TypeError('Owned policy renderer configuration required');
  }
  return Object.freeze({
    async checkReadiness() {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetchImpl(`${baseUrl}/health`, { signal: controller.signal, redirect: 'error' });
        if (!response?.ok) throw unavailable();
        const health = await readBoundedJson(response);
        controller.signal.throwIfAborted();
        if (health?.policyRenderer?.enabled !== true || health.policyRenderer.available !== true
            || health.policyRenderer.isolation !== ISOLATION) throw unavailable();
        return true;
      } catch { throw unavailable(); }
      finally { clearTimeout(timer); }
    },
    async render(request, { signal, executionMode } = {}) {
      const normalized = normalizeRenderRequest(request);
      const execution = executionMode === undefined ? null
        : normalizeRenderExecution({ version: 2, mode: executionMode, request: normalized });
      const controller = new AbortController();
      const abort = () => controller.abort(signal?.reason);
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
      const timer = setTimeout(() => controller.abort(new DOMException('Policy renderer timed out', 'TimeoutError')), timeoutMs);
      try {
        const response = await fetchImpl(`${baseUrl}/secureshop/policy-render`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify(execution || normalized), signal: controller.signal,
        });
        if (!response?.ok) throw unavailable(`Owned policy renderer HTTP ${response?.status || 0}`);
        try { const result = await readBoundedJson(response);
          return execution ? validateRenderExecutionResult(execution, result) : validateRenderResult(normalized, result); }
        catch (error) { if (error?.code === 'POLICY_RENDER_UNAVAILABLE') throw error; throw unavailable(error?.message); }
      } catch (error) {
        if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError');
        if (error?.code === 'POLICY_RENDER_UNAVAILABLE') throw error;
        throw unavailable(error?.message);
      } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
    },
  });
}

module.exports = { MAX_RESPONSE_BYTES, readBoundedPolicyRenderJson: readBoundedJson, createSecureShopPolicySandboxRuntime };
