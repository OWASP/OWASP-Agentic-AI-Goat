export const POLICY_FINAL_HTML_KEY = 'secureshop.policy-final-html.reference.v1';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const keys = ['version', 'shopUserId', 'requestId', 'sessionId', 'assessmentStarted', 'startedAt'];
const fail = () => { throw Error('Invalid saved policy output request'); };
export function decodePolicyFinalHtmlReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 640) fail();
  let value; try { value = JSON.parse(raw); } catch { fail(); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',') || value.version !== 1
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1 || !UUID.test(value.requestId || '')
    || !(value.sessionId === null || UUID.test(value.sessionId || ''))
    || typeof value.assessmentStarted !== 'boolean' || value.assessmentStarted && value.sessionId === null
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) fail();
  return Object.freeze(value);
}
export function createPolicyFinalHtmlReferenceStore({ storage, flush } = {}) {
  if (![storage?.getItem, storage?.setItem, storage?.removeItem, flush].every(fn => typeof fn === 'function'))
    throw TypeError('Acknowledged policy output storage required');
  const raw = () => decodePolicyFinalHtmlReference(storage.getItem(POLICY_FINAL_HTML_KEY));
  const same = (left, right) => !!left && !!right && keys.every(key => left[key] === right[key]);
  const changed = () => { throw Error('Saved policy output request changed'); };
  return Object.freeze({
    read(shopUserId) {
      const value = raw();
      if (value && value.shopUserId !== shopUserId) fail();
      return value;
    },
    async save(reference, prior = null, current = () => true) {
      const value = decodePolicyFinalHtmlReference(JSON.stringify(reference));
      if (current() !== true || (prior === null ? raw() !== null : !same(raw(), prior))) changed();
      storage.setItem(POLICY_FINAL_HTML_KEY, JSON.stringify(value));
      await flush();
      if (current() !== true || !same(raw(), value)) changed();
      return value;
    },
    async clear(reference, current = () => true) {
      if (current() !== true || !same(raw(), reference)) changed();
      storage.removeItem(POLICY_FINAL_HTML_KEY);
      try { await flush(); if (current() !== true || raw() !== null) changed(); }
      catch (error) {
        storage.setItem(POLICY_FINAL_HTML_KEY, JSON.stringify(reference));
        try { await flush(); } catch { /* preserve original storage failure */ }
        throw error;
      }
    },
  });
}
