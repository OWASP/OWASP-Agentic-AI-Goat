const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const failures = new Set(['ABORTED', 'AUTHORITY_REVOKED', 'TARGET_CHANGED', 'EXECUTION_FAILED', 'OUTCOME_UNCERTAIN']);
export const RESTART_CAPABILITY = 'secureshop-owned-system-restart.v1';
const invalid = () => { throw new Error('Invalid restart response'); };
export async function restartHash(value) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(value)));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
export function restartAdministration(value) {
  if (value?.ok !== true || ![RESTART_CAPABILITY, 'secureshop-owned-system-restart.v2'].includes(value.administration?.restartCapability) || !UUID.test(value.administration.targetId)) invalid();
  return { targetId: value.administration.targetId };
}
export function restartRequest(operationId, name) {
  if (!UUID.test(operationId) || typeof name !== 'string' || name.includes('\0')
      || (typeof name.isWellFormed === 'function' && !name.isWellFormed())
      || new TextEncoder().encode(name).length < 1 || new TextEncoder().encode(name).length > 128) invalid();
  return { version: 1, operationId, name };
}
export function restartResult(value, reference, targetId, requestSha256) {
  if (!value || value.operationId !== reference.operationId) invalid();
  if (['admitted', 'running'].includes(value.state)) {
    if (value.ok !== false || value.automaticRetry !== false) invalid();
    return { ok: false, operationId: value.operationId, state: value.state, automaticRetry: false };
  }
  if (['failed', 'retired'].includes(value.state)) {
    if (value.ok !== false || value.automaticRetry !== false || !(failures.has(value.failureCode) || (value.state === 'retired' && value.failureCode == null))) invalid();
    return { ok: false, operationId: value.operationId, state: value.state, failureCode: value.failureCode, automaticRetry: false };
  }
  const r = value.receipt;
  if (value.ok !== true || value.state !== 'completed' || value.targetId !== targetId || !HASH.test(value.requestSha256)
      || (requestSha256 !== undefined && value.requestSha256 !== requestSha256)
      || !r || !UUID.test(r.beforeInstanceId) || !UUID.test(r.afterInstanceId) || r.beforeInstanceId === r.afterInstanceId
      || !Number.isSafeInteger(r.beforeGeneration) || r.beforeGeneration < 1 || !Number.isSafeInteger(r.afterGeneration) || r.afterGeneration !== r.beforeGeneration + 1
      || !HASH.test(r.effectSha256) || !HASH.test(r.outputSha256) || !Number.isSafeInteger(r.outputBytes) || r.outputBytes < 0 || r.outputBytes > 65536) invalid();
  return { ok: true, operationId: value.operationId, state: 'completed', targetId, requestSha256: value.requestSha256,
    receipt: Object.fromEntries(['beforeInstanceId', 'afterInstanceId', 'beforeGeneration', 'afterGeneration', 'effectSha256', 'outputSha256', 'outputBytes'].map(key => [key, r[key]])) };
}

export async function verifiedRestartResult(value, reference, targetId, requestSha256) {
  const result = restartResult(value, reference, targetId, requestSha256);
  if (result.state !== 'completed' || !Object.prototype.hasOwnProperty.call(value.receipt, 'outputText')) return result;
  const text = value.receipt.outputText;
  if (typeof text !== 'string' || (typeof text.isWellFormed === 'function' && !text.isWellFormed())) invalid();
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > 16384 || bytes.length !== result.receipt.outputBytes) invalid();
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  const hash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
  if (hash !== result.receipt.outputSha256) invalid();
  return { ...result, receipt: { ...result.receipt, outputText: text } };
}
