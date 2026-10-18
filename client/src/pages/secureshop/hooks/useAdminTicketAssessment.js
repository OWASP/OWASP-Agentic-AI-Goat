import { useCallback, useEffect, useRef, useState } from 'react';
import { adminTicketAssessmentStore } from '../utils/adminTicketAssessmentReference.mjs';

const BASE = '/api/secureshop/admin/tickets';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const unavailable = () => { throw Error('Ticket assessment unavailable'); };

export function decodeAdminTicketAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
      && value.modelEvaluated === false && ['disabled', 'ineligible', 'unconfirmed', 'pending'].includes(value.status))
    return Object.freeze({ completed: false, status: value.status, modelEvaluated: false });
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
      || typeof value.replayed !== 'boolean' || !exact(value.judgment, ['evaluationId', 'verdict', 'canRetry'])
      || typeof value.judgment.evaluationId !== 'string' || !UUID.test(value.judgment.evaluationId)
      || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
      || typeof value.judgment.canRetry !== 'boolean'
      || value.completed && value.judgment.verdict !== 'pass') unavailable();
  return Object.freeze({ completed: value.completed, replayed: value.replayed,
    judgment: Object.freeze({ ...value.judgment }) });
}

async function json(response) {
  if (!response.ok) { const error = Error('Ticket assessment unavailable'); error.status = response.status; throw error; }
  if (!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) unavailable();
  return response.json();
}

export function useAdminTicketAssessment({ shopUserId, authorityKey, transport,
  referenceStore = adminTicketAssessmentStore } = {}) {
  const [reference, setReference] = useState(null), [outcome, setOutcome] = useState(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(null);
  const [accessLost, setAccessLost] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), mountedRef = useRef(false);
  const referenceRef = useRef(null);
  const current = useCallback((epoch, controller) => mountedRef.current
    && epochRef.current === epoch && activeRef.current === controller && !controller.signal.aborted, []);
  const readSaved = useCallback(async (saved, controller, epoch) => {
    const response = await transport(`${BASE}/${saved.ticketId}/assessment/${saved.requestId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
    const value = decodeAdminTicketAssessment(await json(response));
    if (!current(epoch, controller)) return null;
    setOutcome(value); return value;
  }, [transport, current]);

  useEffect(() => {
    mountedRef.current = true; const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    referenceRef.current = null; setReference(null); setOutcome(null); setBusy(false); setError(null);
    setAccessLost(false);
    try {
      const available = Number.isSafeInteger(shopUserId) && shopUserId > 0
        && typeof transport === 'function' && typeof referenceStore?.read === 'function'
        && typeof referenceStore?.save === 'function';
      const saved = available ? referenceStore.read(shopUserId) : null;
      if (saved) {
        referenceRef.current = saved; setReference(saved);
        const controller = new AbortController(); activeRef.current = controller; setBusy(true);
        void readSaved(saved, controller, epoch).catch(cause => {
          if (current(epoch, controller)) {
            if ([401, 403].includes(cause.status)) setAccessLost(true);
            setError('Saved ticket assessment could not be read.');
          }
        }).finally(() => { if (current(epoch, controller)) setBusy(false);
          if (activeRef.current === controller) activeRef.current = null; });
      }
    } catch { setError('Saved ticket assessment storage unavailable.'); }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [shopUserId, authorityKey, transport, referenceStore, readSaved, current]);

  const check = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try { return !!await readSaved(referenceRef.current, controller, epoch); }
    catch (cause) { if (current(epoch, controller)) {
      if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError('Saved ticket assessment unavailable.');
    } return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [readSaved, current]);

  const start = useCallback(async ticketId => {
    if (!mountedRef.current || activeRef.current || referenceRef.current
      || !Number.isSafeInteger(shopUserId) || shopUserId < 1
      || typeof ticketId !== 'string' || !/^[1-9]\d{0,18}$/.test(ticketId)
      || BigInt(ticketId) > 9223372036854775807n) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const saved = await referenceStore.save({ shopUserId, ticketId,
        requestId: crypto.randomUUID(), startedAt: Date.now() }, () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = saved; setReference(saved);
      // Acknowledged IDs precede the sole POST; all uncertain outcomes use GET.
      try { await transport(`${BASE}/${ticketId}/assessment`, { method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({ requestId: saved.requestId }), signal: controller.signal }); }
      catch { /* Resolve the admitted request through its protected saved GET. */ }
      if (!current(epoch, controller)) return false;
      return !!await readSaved(saved, controller, epoch);
    } catch (cause) {
      if (current(epoch, controller)) {
        if ([401, 403].includes(cause.status)) setAccessLost(true);
        setError(referenceRef.current
          ? 'Ticket assessment unresolved. Check the saved result.' : 'Ticket assessment unavailable.');
      }
      return false;
    } finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [shopUserId, transport, referenceStore, readSaved, current]);

  const clearCompleted = useCallback(async nextTicketId => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current || !outcome
      || outcome.status === 'unconfirmed' || outcome.status === 'pending'
      || typeof nextTicketId !== 'string' || !/^[1-9]\d{0,18}$/.test(nextTicketId)
      || nextTicketId === referenceRef.current.ticketId) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      await referenceStore.clear(referenceRef.current, () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = null; setReference(null); setOutcome(null); return true;
    } catch { if (current(epoch, controller)) setError('Saved ticket assessment could not be cleared.'); return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [referenceStore, current, outcome]);

  return { reference, outcome, busy, error, accessLost, start, check, clearCompleted };
}
