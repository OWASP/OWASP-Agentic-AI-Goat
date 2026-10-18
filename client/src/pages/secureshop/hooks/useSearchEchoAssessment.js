import { useCallback, useEffect, useRef, useState } from 'react';
import { searchEchoAssessmentStore } from '../utils/customerSearchEchoAssessmentReference.mjs';

const BASE = '/api/secureshop/agents/customer';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const validSource = source => exact(source, ['sessionId', 'requestId', 'step'])
  && UUID.test(source.sessionId) && UUID.test(source.requestId)
  && Number.isInteger(source.step) && source.step >= 1 && source.step <= 4;
const sameSource = (a, b) => a?.sessionId === b?.sessionId && a?.requestId === b?.requestId
  && a?.step === b?.step;
const unavailable = () => { throw Error('Search assessment unavailable'); };

export function decodeSearchEchoAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
    && value.modelEvaluated === false && ['ineligible', 'unconfirmed'].includes(value.status))
    return Object.freeze({ completed: false, status: value.status, modelEvaluated: false });
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
    || typeof value.replayed !== 'boolean' || !exact(value.judgment, ['evaluationId', 'verdict', 'canRetry'])
    || !UUID.test(value.judgment.evaluationId || '')
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    || typeof value.judgment.canRetry !== 'boolean'
    || (value.completed && value.judgment.verdict !== 'pass')) unavailable();
  return Object.freeze({ completed: value.completed, replayed: value.replayed,
    judgment: Object.freeze({ ...value.judgment }) });
}

async function json(response) {
  if (!response.ok) { const error = Error('Search assessment unavailable'); error.status = response.status; throw error; }
  if (!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) unavailable();
  return response.json();
}

function savedPath(ref) {
  return `${BASE}/sessions/${ref.sessionId}/requests/${ref.requestId}/search-echo/${ref.step}/assessment`;
}

export function useSearchEchoAssessment({ shopUserId, authorityKey, transport,
  referenceStore = searchEchoAssessmentStore } = {}) {
  const [reference, setReference] = useState(null), [outcome, setOutcome] = useState(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(null);
  const [accessLost, setAccessLost] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), mountedRef = useRef(false), referenceRef = useRef(null);
  const current = useCallback((epoch, controller) => mountedRef.current && epochRef.current === epoch
    && activeRef.current === controller && !controller.signal.aborted, []);
  const readSaved = useCallback(async (ref, controller, epoch) => {
    const response = await transport(savedPath(ref), { method: 'GET', headers: { accept: 'application/json' },
      signal: controller.signal });
    const value = decodeSearchEchoAssessment(await json(response));
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
              setError('Saved search assessment could not be read.'); }
          }).finally(() => { if (current(epoch, controller)) setBusy(false);
            if (activeRef.current === controller) activeRef.current = null; });
        }
      }
    } catch { setError('Saved search assessment storage unavailable.'); }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [shopUserId, authorityKey, transport, referenceStore, readSaved, current]);

  const check = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try { return !!await readSaved(referenceRef.current, controller, epoch); }
    catch (cause) { if (current(epoch, controller)) { if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError('Saved search assessment unavailable.'); } return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [readSaved, current]);

  const start = useCallback(async source => {
    if (!mountedRef.current || activeRef.current || referenceRef.current || !validSource(source)
      || !Number.isSafeInteger(shopUserId) || shopUserId < 1) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const saved = await referenceStore.save({ shopUserId, ...source, startedAt: Date.now() },
        () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = saved; setReference(saved);
      try { await transport(`${BASE}/search-echo/assess`, { method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify(source), signal: controller.signal }); }
      catch { /* A lost response is resolved only by the saved GET. */ }
      if (!current(epoch, controller)) return false;
      return !!await readSaved(saved, controller, epoch);
    } catch (cause) { if (current(epoch, controller)) {
      if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError(referenceRef.current ? 'Search assessment unresolved. Check the saved result.'
        : 'Search assessment unavailable.');
    } return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [shopUserId, transport, referenceStore, readSaved, current]);

  const retryUnconfirmed = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current
      || outcome?.status !== 'unconfirmed' || accessLost) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const ref = referenceRef.current;
      const before = await readSaved(ref, controller, epoch);
      if (!current(epoch, controller) || !before) return false;
      if (before.status !== 'unconfirmed') return true;
      const source = { sessionId: ref.sessionId, requestId: ref.requestId, step: ref.step };
      try { await transport(`${BASE}/search-echo/assess`, { method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify(source), signal: controller.signal }); }
      catch { /* Resolve only through the protected saved GET. */ }
      if (!current(epoch, controller)) return false;
      return !!await readSaved(ref, controller, epoch);
    } catch (cause) { if (current(epoch, controller)) {
      if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError('Search assessment retry unresolved. Check the saved result.');
    } return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [outcome, accessLost, readSaved, current, transport]);

  const clearCompleted = useCallback(async nextSource => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current || !validSource(nextSource)
      || sameSource(referenceRef.current, nextSource) || !outcome
      || outcome.status === 'unconfirmed') return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const saved = await readSaved(referenceRef.current, controller, epoch);
      if (!saved || saved.status === 'unconfirmed') return false;
      await referenceStore.clear(referenceRef.current, () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = null; setReference(null); setOutcome(null); return true;
    } catch (cause) { if (current(epoch, controller)) {
      if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError('Saved search assessment could not be cleared.');
    } return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [referenceStore, readSaved, current, outcome]);

  return { reference, outcome, busy, error, accessLost,
    start, check, retryUnconfirmed, clearCompleted };
}
