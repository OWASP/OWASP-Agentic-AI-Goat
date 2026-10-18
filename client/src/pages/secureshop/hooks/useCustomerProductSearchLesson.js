import { useCallback, useEffect, useRef, useState } from 'react';
import { productSearchReferenceStore } from '../utils/customerProductSearchReference.mjs';

const BASE = '/api/secureshop/customer/product-search';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const PRODUCT_COLUMNS = ['id', 'name', 'description', 'price', 'category', 'image_url',
  'stock_quantity', 'retailer_id', 'status', 'created_at', 'updated_at'];
const invalid = () => { throw new Error('Product-search lesson result unavailable'); };
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const bounded = (value, bytes) => typeof value === 'string' && value.isWellFormed()
  && !value.includes('\0') && new TextEncoder().encode(value).byteLength <= bytes;

async function readJson(response) {
  if (!response?.ok) {
    // Drain a small error response so the browser records the original HTTP
    // result. Cancel anything larger; error bytes never become lesson data.
    const reader = response?.body?.getReader?.();
    if (reader) {
      let bytes = 0;
      try {
        while (bytes <= 4096) {
          const part = await reader.read();
          if (part.done) break;
          bytes += part.value?.byteLength || 0;
        }
      } finally { try { await reader.cancel(); } catch {} }
    }
    invalid();
  }
  if (typeof response.json !== 'function'
    || !/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) invalid();
  return response.json();
}

export function decodeProductSearchResult(value, reference) {
  if (!value || value.sessionId !== reference.sessionId || value.requestId !== reference.requestId) invalid();
  if (exact(value, ['status', 'sessionId', 'requestId']) && value.status === 'unconfirmed')
    return Object.freeze({ status: 'unconfirmed' });
  if (!exact(value, ['status', 'sessionId', 'requestId', 'text', 'provider', 'model',
    'stopReason', 'searches', 'replayed']) || value.status !== 'completed'
    || value.stopReason !== 'end_turn' || typeof value.replayed !== 'boolean'
    || !bounded(value.text, 65536) || !bounded(value.provider, 256)
    || !bounded(value.model, 256) || !Array.isArray(value.searches) || value.searches.length > 8) invalid();
  const searches = value.searches.map(search => {
    if (!exact(search, ['results', 'count', 'query', 'echo_html', 'sql_error'])
      || !Array.isArray(search.results) || search.results.length > 50
      || !Number.isSafeInteger(search.count) || search.count !== search.results.length
      || !bounded(search.query, 1024) || !bounded(search.echo_html, 32768)
      || search.sql_error !== null) invalid();
    const rows = search.results.map(row => {
      if (!exact(row, PRODUCT_COLUMNS)
        || Object.values(row).some(item => item !== null && !['string', 'number', 'boolean'].includes(typeof item))
        || !bounded(JSON.stringify(row), 131072)) invalid();
      return Object.freeze({ ...row });
    });
    return Object.freeze({ query: search.query, count: search.count, results: Object.freeze(rows) });
  });
  return Object.freeze({ status: 'completed', text: value.text, provider: value.provider,
    model: value.model, searches: Object.freeze(searches) });
}

export function decodeProductSearchAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
    && value.modelEvaluated === false && ['unconfirmed', 'ineligible'].includes(value.status)) return value;
  if (!exact(value, ['completed', 'judgment', 'replayed'])
    || typeof value.completed !== 'boolean' || typeof value.replayed !== 'boolean'
    || !exact(value.judgment, ['evaluationId', 'verdict', 'canRetry'])
    || !UUID.test(value.judgment.evaluationId)
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    || typeof value.judgment.canRetry !== 'boolean') invalid();
  return value;
}

export function useCustomerProductSearchLesson({ shopUserId, authorityKey,
  transport = globalThis.fetch, referenceStore = productSearchReferenceStore } = {}) {
  const [ready, setReady] = useState(false);
  const [reference, setReference] = useState(null);
  const [result, setResult] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [status, setStatus] = useState('idle');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const epoch = useRef(0), active = useRef(null), mounted = useRef(false), savedRef = useRef(null);
  const current = useCallback((version, controller) => mounted.current && epoch.current === version
    && active.current === controller && !controller.signal.aborted, []);
  const request = useCallback((path, method, body, signal) => transport(BASE + path, {
    method, signal, headers: { accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }), [transport]);
  const savedRead = useCallback(async (saved, controller, version) => {
    const response = await request(`/operations/${saved.sessionId}/${saved.requestId}`, 'GET', undefined, controller.signal);
    const value = decodeProductSearchResult(await readJson(response), saved);
    if (!current(version, controller)) return false;
    setResult(value.status === 'completed' ? value : null); setStatus(value.status);
    return true;
  }, [request, current]);

  useEffect(() => {
    mounted.current = true; const version = ++epoch.current;
    active.current?.abort(); active.current = null; savedRef.current = null;
    setReady(false); setReference(null); setResult(null); setAssessment(null);
    setStatus('idle'); setError(null); setBusy(false);
    if (!Number.isSafeInteger(shopUserId) || shopUserId < 1 || typeof transport !== 'function') {
      setError('Product-search lesson unavailable.'); return () => { mounted.current = false; ++epoch.current; };
    }
    let saved;
    try { saved = referenceStore.read(shopUserId); } catch { setError('Saved lesson storage unavailable.'); }
    if (saved) { savedRef.current = saved; setReference(saved); setStatus('unconfirmed'); }
    const controller = new AbortController(); active.current = controller;
    void (async () => {
      try {
        const capability = await readJson(await request('/capabilities', 'GET', undefined, controller.signal));
        if (!exact(capability, ['ready']) || capability.ready !== true) invalid();
        if (!current(version, controller)) return;
        setReady(true);
        if (saved) await savedRead(saved, controller, version);
      } catch { if (current(version, controller)) setError(saved
        ? 'Check the saved search again.' : 'Product-search lesson unavailable.'); }
      finally { if (active.current === controller) active.current = null; }
    })();
    return () => { mounted.current = false; ++epoch.current; active.current?.abort(); active.current = null; };
  }, [shopUserId, authorityKey, transport, referenceStore, request, savedRead, current]);

  const recover = useCallback(async () => {
    const saved = savedRef.current;
    if (!saved || active.current || !mounted.current) return false;
    const controller = new AbortController(), version = epoch.current;
    active.current = controller; setBusy(true); setError(null);
    try { return await savedRead(saved, controller, version); }
    catch { if (current(version, controller)) setError('Saved search unavailable.'); return false; }
    finally { if (current(version, controller)) setBusy(false);
      if (active.current === controller) active.current = null; }
  }, [savedRead, current]);

  const run = useCallback(async message => {
    if (!ready || savedRef.current || active.current || !mounted.current
      || !bounded(message, 8192) || !message.trim()) return false;
    const controller = new AbortController(), version = epoch.current;
    active.current = controller; setBusy(true); setError(null);
    try {
      const session = await readJson(await request('/session', 'POST', {}, controller.signal));
      if (!exact(session, ['sessionId']) || !UUID.test(session.sessionId)) invalid();
      if (!current(version, controller)) return false;
      const saved = await referenceStore.save({ shopUserId, sessionId: session.sessionId,
        requestId: crypto.randomUUID(), startedAt: Date.now() }, () => current(version, controller));
      if (!current(version, controller)) return false;
      savedRef.current = saved; setReference(saved); setStatus('unconfirmed');
      try {
        const response = await request('/run', 'POST', { sessionId: saved.sessionId,
          requestId: saved.requestId, message }, controller.signal);
        const value = decodeProductSearchResult(await readJson(response), saved);
        if (!current(version, controller)) return false;
        if (value.status === 'completed') { setResult(value); setStatus('completed'); }
        return true;
      } catch { if (current(version, controller)) setError('Search status unknown. Check the saved search.'); return false; }
    } catch { if (current(version, controller)) setError('Product-search lesson unavailable.'); return false; }
    finally { if (current(version, controller)) setBusy(false);
      if (active.current === controller) active.current = null; }
  }, [ready, shopUserId, request, referenceStore, current]);

  const assess = useCallback(async () => {
    const saved = savedRef.current;
    if (!saved || !result || (assessment && !(assessment.completed === false
      && assessment.status === 'unconfirmed' && assessment.modelEvaluated === false))
      || active.current || !mounted.current) return false;
    const controller = new AbortController(), version = epoch.current;
    active.current = controller; setBusy(true); setError(null);
    try {
      const response = await request('/assess', 'POST', { sessionId: saved.sessionId,
        requestId: saved.requestId }, controller.signal);
      const value = decodeProductSearchAssessment(await readJson(response));
      if (!current(version, controller)) return false;
      setAssessment(value); return true;
    } catch { if (current(version, controller)) setError('Assessment status unknown. Check saved assessment.'); return false; }
    finally { if (current(version, controller)) setBusy(false);
      if (active.current === controller) active.current = null; }
  }, [result, assessment, request, current]);

  const recoverAssessment = useCallback(async () => {
    const saved = savedRef.current;
    if (!saved || active.current || !mounted.current) return false;
    const controller = new AbortController(), version = epoch.current;
    active.current = controller; setBusy(true); setError(null);
    try {
      const response = await request(`/assess/${saved.sessionId}/${saved.requestId}`, 'GET', undefined, controller.signal);
      const value = decodeProductSearchAssessment(await readJson(response));
      if (!current(version, controller)) return false;
      setAssessment(value); return true;
    } catch { if (current(version, controller)) setError('Saved assessment unavailable.'); return false; }
    finally { if (current(version, controller)) setBusy(false);
      if (active.current === controller) active.current = null; }
  }, [request, current]);

  const startNew = useCallback(async () => {
    const saved = savedRef.current;
    if (!saved || status !== 'completed' || active.current || !mounted.current) return false;
    const controller = new AbortController(), version = epoch.current;
    active.current = controller; setBusy(true); setError(null);
    try {
      await referenceStore.clear(saved, () => current(version, controller));
      if (!current(version, controller)) return false;
      savedRef.current = null; setReference(null); setResult(null); setAssessment(null); setStatus('idle');
      return true;
    } catch { if (current(version, controller)) setError('Saved search cannot be cleared.'); return false; }
    finally { if (current(version, controller)) setBusy(false);
      if (active.current === controller) active.current = null; }
  }, [status, referenceStore, current]);

  return { ready, reference, result, assessment, status, error, busy,
    run, recover, assess, recoverAssessment, startNew };
}
