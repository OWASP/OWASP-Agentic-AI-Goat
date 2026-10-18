import { useCallback, useEffect, useRef, useState } from 'react';
import { productSimilarReferenceStore } from '../utils/productSimilarReference.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const MODES = ['products', 'manuals', 'mixed', 'catalog'];
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const invalid = () => { throw new Error('Similar products unavailable'); };
const productPath = id => `/api/secureshop/products/${id}/similar`;
const savedPath = ref => `${productPath(ref.productId)}/sessions/${ref.sessionId}/requests/${ref.requestId}`;

async function json(response) {
  if (!response.ok) { const error = new Error('Similar products unavailable'); error.status = response.status; throw error; }
  if (!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) invalid();
  return response.json();
}

async function savedJson(response) {
  if (response.status !== 404) return json(response);
  if (!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) invalid();
  const value = await response.json();
  if (!exact(value, ['status', 'sessionId', 'requestId']) || value.status !== 'not_found') invalid();
  return value;
}

export function decodeSavedProductSimilar(value, ref) {
  if (!exact(value, ['status', 'sessionId', 'requestId'])
    && !exact(value, ['status', 'result'])) invalid();
  if (value.status === 'pending' || value.status === 'not_found') {
    if (!exact(value, ['status', 'sessionId', 'requestId'])
      || value.sessionId !== ref.sessionId || value.requestId !== ref.requestId) invalid();
    return Object.freeze({ status: value.status, result: null });
  }
  if (value.status !== 'completed' || !exact(value, ['status', 'result'])) invalid();
  const result = value.result;
  const keys = ['results', 'count', 'mode', 'recommendation', 'seed', 'retrieved_context',
    'provider', 'model', 'sessionId', 'requestId'];
  if (!exact(result, keys) && !exact(result, [...keys, 'modeCapability'])) invalid();
  if (result.sessionId !== ref.sessionId || result.requestId !== ref.requestId
    || result.seed?.id !== ref.productId || typeof result.seed.name !== 'string'
    || !Array.isArray(result.results) || result.results.length > 100
    || !Number.isSafeInteger(result.count) || result.count !== result.results.length
    || result.results.some(row => !Number.isSafeInteger(row?.id) || row.id < 1
      || typeof row.name !== 'string' || !row.name)
    || !MODES.includes(result.mode) || !Array.isArray(result.retrieved_context)
    || typeof result.recommendation !== 'string' || !result.recommendation.trim()
    || new TextEncoder().encode(result.recommendation).byteLength > 8192
    || typeof result.provider !== 'string' || !result.provider
    || typeof result.model !== 'string' || !result.model
    || (result.modeCapability !== undefined
      && trustedTurnMode(result.modeCapability)?.featureId !== 'product_assist')) invalid();
  return Object.freeze({ status: 'completed', result: Object.freeze({ ...result }) });
}

export function useProductSimilar({ productId, shopUserId, authorityKey, transport,
  referenceStore = productSimilarReferenceStore } = {}) {
  const selected = Number(productId);
  const validProduct = Number.isSafeInteger(selected) && selected > 0 && selected <= 2147483647
    && String(selected) === String(productId);
  const [reference, setReference] = useState(null), [outcome, setOutcome] = useState(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(null);
  const [accessLost, setAccessLost] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), referenceRef = useRef(null);
  const mountedRef = useRef(false);
  const current = useCallback((epoch, controller) => mountedRef.current && epochRef.current === epoch
    && activeRef.current === controller && !controller.signal.aborted, []);
  const readSaved = useCallback(async (ref, controller, epoch) => {
    const response = await transport(savedPath(ref), { method: 'GET',
      headers: { accept: 'application/json' }, signal: controller.signal });
    const value = decodeSavedProductSimilar(await savedJson(response), ref);
    if (!current(epoch, controller)) return null;
    setOutcome(value); return value;
  }, [transport, current]);

  useEffect(() => {
    mountedRef.current = true; const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null; referenceRef.current = null;
    setReference(null); setOutcome(null); setBusy(false); setError(null); setAccessLost(false);
    try {
      if (Number.isSafeInteger(shopUserId) && shopUserId > 0 && typeof transport === 'function') {
        const saved = referenceStore.read(shopUserId);
        if (saved) {
          referenceRef.current = saved; setReference(saved);
          const controller = new AbortController(); activeRef.current = controller; setBusy(true);
          void readSaved(saved, controller, epoch).catch(cause => {
            if (current(epoch, controller)) { if ([401, 403].includes(cause.status)) setAccessLost(true);
              setError('Recommendations could not be read.'); }
          }).finally(() => { if (current(epoch, controller)) setBusy(false);
            if (activeRef.current === controller) activeRef.current = null; });
        }
      }
    } catch { setError('Recommendations are unavailable.'); }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [shopUserId, authorityKey, selected, transport, referenceStore, readSaved, current]);

  const check = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try { return !!await readSaved(referenceRef.current, controller, epoch); }
    catch (cause) { if (current(epoch, controller)) { if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError('Recommendations are unavailable.'); } return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [readSaved, current]);

  const start = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || referenceRef.current || !validProduct
      || !Number.isSafeInteger(shopUserId) || shopUserId < 1 || typeof transport !== 'function') return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const sessionResponse = await transport(`${productPath(selected)}/session`, {
        method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: '{}', signal: controller.signal });
      const session = await json(sessionResponse);
      if (!exact(session, ['sessionId']) || !UUID.test(session.sessionId)) invalid();
      if (!current(epoch, controller)) return false;
      const saved = await referenceStore.save({ shopUserId, productId: selected,
        sessionId: session.sessionId, requestId: crypto.randomUUID(), startedAt: Date.now() },
      () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = saved; setReference(saved);
      try { await transport(productPath(selected), { method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId }),
        signal: controller.signal }); }
      catch { /* A lost response is resolved only through the protected saved GET. */ }
      if (!current(epoch, controller)) return false;
      return !!await readSaved(saved, controller, epoch);
    } catch (cause) { if (current(epoch, controller)) {
      if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError(referenceRef.current ? 'Recommendations are unresolved. Check again.'
        : 'Similar products unavailable.');
    } return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [selected, validProduct, shopUserId, transport, referenceStore, readSaved, current]);

  const retryNotFound = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current
      || outcome?.status !== 'not_found' || accessLost) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const ref = referenceRef.current;
      const before = await readSaved(ref, controller, epoch);
      if (!current(epoch, controller) || !before) return false;
      if (before.status !== 'not_found') return before.status === 'completed';
      try { await transport(productPath(ref.productId), { method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({ sessionId: ref.sessionId, requestId: ref.requestId }),
        signal: controller.signal }); }
      catch { /* A lost response is resolved only through the protected saved GET. */ }
      if (!current(epoch, controller)) return false;
      return !!await readSaved(ref, controller, epoch);
    } catch (cause) { if (current(epoch, controller)) {
      if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError('Recommendations are unresolved. Check again.');
    } return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [outcome, accessLost, transport, readSaved, current]);

  const clearCompleted = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current
      || outcome?.status !== 'completed' || accessLost) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const ref = referenceRef.current;
      const saved = await readSaved(ref, controller, epoch);
      if (!current(epoch, controller) || saved?.status !== 'completed') return false;
      await referenceStore.clear(ref, () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = null; setReference(null); setOutcome(null); return true;
    } catch { if (current(epoch, controller)) setError('Recommendations could not be cleared.'); return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [outcome, accessLost, readSaved, referenceStore, current]);

  return { reference, outcome, busy, error, accessLost, validProduct,
    start, check, retryNotFound, clearCompleted };
}
