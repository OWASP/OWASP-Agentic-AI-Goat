import React, { useCallback, useEffect, useRef, useState } from 'react';
import { customerCouponProbeReferenceStore } from '../utils/customerCouponProbeReference.mjs';

const BASE = '/api/secureshop/customer/coupon-probe';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const unavailable = () => { throw new Error('Coupon assistant response unavailable'); };

const browserStore = customerCouponProbeReferenceStore;

function requestId() {
  if (typeof globalThis.crypto?.randomUUID === 'function') return globalThis.crypto.randomUUID();
  unavailable();
}
function validText(value, limit) {
  return typeof value === 'string' && value.isWellFormed() && !value.includes('\0')
    && encoder.encode(value).byteLength <= limit;
}
function json(response) {
  if (!response.ok || !/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) unavailable();
  return response.json();
}
export function decodeCouponProbeOutcome(value, reference) {
  if (exact(value, ['status', 'sessionId', 'requestId']) && value.status === 'unconfirmed'
    && value.sessionId === reference.sessionId && value.requestId === reference.requestId) {
    return Object.freeze({ status: 'unconfirmed' });
  }
  if (!exact(value, ['status', 'sessionId', 'requestId', 'text', 'provider', 'model', 'stopReason', 'probes', 'replayed'])
    || !['completed', 'incomplete'].includes(value.status) || value.sessionId !== reference.sessionId
    || value.requestId !== reference.requestId || value.replayed !== true
    || value.stopReason !== (value.status === 'incomplete' ? 'incomplete' : 'end_turn')
    || !validText(value.text, 65536) || !value.text.trim()
    || !validText(value.provider, 256) || !value.provider.trim()
    || !validText(value.model, 256) || !value.model.trim()
    || !Array.isArray(value.probes) || value.probes.length > 8) unavailable();
  for (const probe of value.probes) {
    if (!exact(probe, ['code', 'valid', 'discount_percent']) || !validText(probe.code, 1024)
      || typeof probe.valid !== 'boolean' || !Number.isInteger(probe.discount_percent)
      || probe.discount_percent < 0 || probe.discount_percent > 100) unavailable();
    if (!probe.valid && probe.discount_percent !== 0) unavailable();
  }
  // The panel deliberately does not project provider, model, probe codes, or
  // any receipt-like evidence. The terminal response is public chat text only.
  return Object.freeze({ status: value.status, text: value.text });
}
export function decodeCouponProbeAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
    && value.modelEvaluated === false && ['ineligible', 'unconfirmed'].includes(value.status)) return value;
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
    || typeof value.replayed !== 'boolean' || !exact(value.judgment, ['evaluationId', 'verdict', 'canRetry'])
    || !UUID.test(value.judgment.evaluationId || '')
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    || typeof value.judgment.canRetry !== 'boolean'
    || value.completed && value.judgment.verdict !== 'pass') unavailable();
  return value;
}

export function CouponProbePanel({ shopUserId, authorityKey, transport = globalThis.fetch,
  referenceStore = browserStore } = {}) {
  const [message, setMessage] = useState('');
  const [requestMode, setRequestMode] = useState('raw');
  const [reference, setReference] = useState(null);
  const [outcome, setOutcome] = useState(null);
  const [savedAssessment, setSavedAssessment] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const mountedRef = useRef(false), epochRef = useRef(0), activeRef = useRef(null);
  const referenceRef = useRef(null);
  const current = useCallback((epoch, controller) => mountedRef.current
    && epochRef.current === epoch && activeRef.current === controller && !controller.signal.aborted, []);

  const readOperation = useCallback(async (saved, controller, epoch) => {
    const response = await transport(`${BASE}/operations/${saved.sessionId}/${saved.requestId}`, {
      method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
    });
    const value = decodeCouponProbeOutcome(await json(response), saved);
    if (!current(epoch, controller)) return null;
    setOutcome(value); return value;
  }, [transport, current]);

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    referenceRef.current = null;
    setReference(null); setOutcome(null); setSavedAssessment(null); setBusy(false); setError(null);
    try {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1 || typeof transport !== 'function') unavailable();
      const saved = referenceStore.read(shopUserId);
      if (saved) {
        referenceRef.current = saved; setReference(saved); setBusy(true);
        const controller = new AbortController(); activeRef.current = controller;
        void readOperation(saved, controller, epoch).catch(() => {
          if (current(epoch, controller)) setError('Check the saved coupon conversation again.');
        }).finally(() => {
          if (current(epoch, controller)) setBusy(false);
          if (activeRef.current === controller) activeRef.current = null;
        });
      }
    } catch { setError('Saved coupon conversation unavailable.'); }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [shopUserId, authorityKey, transport, referenceStore, readOperation, current]);

  const checkSaved = useCallback(async () => {
    const saved = referenceRef.current;
    if (!saved || activeRef.current || !mountedRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try { return !!await readOperation(saved, controller, epoch); }
    catch { if (current(epoch, controller)) setError('Saved coupon conversation unavailable.'); return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [current, readOperation]);

  const submit = useCallback(async event => {
    event.preventDefault();
    if (activeRef.current || referenceRef.current || !message.trim() || !validText(message, 8192)) return;
    const controller = new AbortController(), epoch = epochRef.current, original = message;
    const protocol = ['guided-boolean-v1', 'guided-boolean-v2'].includes(requestMode)
      ? requestMode : undefined;
    const selectedMode = requestMode;
    activeRef.current = controller; setBusy(true); setError(null); setOutcome(null); setSavedAssessment(null);
    const unchanged = () => current(epoch, controller) && message === original
      && requestMode === selectedMode;
    try {
      const sessionResponse = await transport(`${BASE}/session`, { method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' }, body: '{}', signal: controller.signal });
      const session = await json(sessionResponse);
      if (!exact(session, ['sessionId']) || !UUID.test(session.sessionId || '') || !unchanged()) unavailable();
      const saved = await referenceStore.save({ shopUserId, sessionId: session.sessionId.toLowerCase(),
        requestId: requestId().toLowerCase(), startedAt: Date.now() }, unchanged);
      if (!current(epoch, controller)) return;
      referenceRef.current = saved; setReference(saved); setMessage('');
      // Once the IDs are durable, any loss is recovered only through the saved GET.
      try {
        const runResponse = await transport(`${BASE}/run`, { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId, message: original,
            ...(protocol ? { protocol } : {}) }), signal: controller.signal });
        // Drain success and error bodies under the bridge's existing byte/time
        // bounds so its credit loop reaches EOF. Only the saved GET supplies
        // the outcome; this response never authorizes a result or another POST.
        await runResponse.text();
      } catch { /* Do not repeat the model-bearing POST. */ }
      if (current(epoch, controller)) await readOperation(saved, controller, epoch);
    } catch {
      if (current(epoch, controller)) {
        try { const retained = referenceStore.read(shopUserId); if (retained) { referenceRef.current = retained; setReference(retained); } }
        catch { /* Missing durable IDs never authorize another run. */ }
        setError(referenceRef.current ? 'Coupon conversation is unresolved. Check the saved conversation.' : 'Coupon conversation unavailable.');
      }
    } finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [current, message, requestMode, readOperation, referenceStore, shopUserId, transport]);

  const assess = useCallback(async (run = false) => {
    const saved = referenceRef.current;
    if (!saved || outcome?.status !== 'completed' || activeRef.current || !mountedRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const response = await transport(run ? `${BASE}/assess` : `${BASE}/assess/${saved.sessionId}/${saved.requestId}`, {
        method: run ? 'POST' : 'GET', headers: { accept: 'application/json', ...(run ? { 'content-type': 'application/json' } : {}) },
        ...(run ? { body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId }) } : {}), signal: controller.signal,
      });
      const value = decodeCouponProbeAssessment(await json(response));
      if (!current(epoch, controller)) return false;
      setSavedAssessment(value); return true;
    } catch { if (current(epoch, controller)) setError('Saved coupon assessment unavailable.'); return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [current, outcome?.status, transport]);

  const clear = useCallback(async () => {
    const saved = referenceRef.current;
    if (!saved || !['completed', 'incomplete'].includes(outcome?.status) || activeRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller;
    try {
      await referenceStore.clear(saved, () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = null; setReference(null); setOutcome(null); setSavedAssessment(null); return true;
    } catch { if (current(epoch, controller)) setError('Saved coupon conversation could not be cleared.'); return false; }
    finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [current, outcome?.status, referenceStore]);

  return <section className="ss-card" aria-label="Coupon assistant" style={{ marginTop: 16, padding: 14 }}>
    <div className="ss-card__meta">COUPON ASSISTANT</div>
    <p style={{ margin: '8px 0' }}>Ask the customer assistant to check a coupon. The saved conversation can be checked after a reload.</p>
    {!reference && <form onSubmit={event => void submit(event)}>
      <label htmlFor="coupon-assistant-request-mode">Request mode</label>
      <select id="coupon-assistant-request-mode" className="ss-input" value={requestMode}
        disabled={busy} onChange={event => setRequestMode(event.target.value)}>
        <option value="raw">Raw message</option>
        <option value="guided-boolean-v1">Guided boolean investigation</option>
        <option value="guided-boolean-v2">Guided boolean investigation with calculator</option>
      </select>
      <label htmlFor="coupon-assistant-message">Message</label>
      <textarea id="coupon-assistant-message" className="ss-input" rows={3} maxLength={8192}
        value={message} onChange={event => setMessage(event.target.value)}
        placeholder="Ask the customer assistant to check a coupon." style={{ width: '100%', marginTop: 6 }} />
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="submit" disabled={busy || !message.trim()}>
        {busy ? 'Starting…' : 'Ask coupon assistant'}
      </button>
    </form>}
    {reference && !['completed', 'incomplete'].includes(outcome?.status) && <><p role="status">Coupon conversation is still being confirmed.</p>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy} onClick={() => void checkSaved()}>Check saved conversation</button></>}
    {outcome?.status === 'completed' && <><p role="status" style={{ whiteSpace: 'pre-wrap' }}>{outcome.text}</p>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy} onClick={() => void assess(false)}>Check saved assessment</button>
      {savedAssessment?.status === 'unconfirmed' && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy} onClick={() => void assess(true)}>Run saved assessment</button>}
      {savedAssessment?.status === 'ineligible' && <p role="status">This conversation is not eligible for objective credit.</p>}
      {savedAssessment?.judgment && <p role="status">{savedAssessment.judgment.verdict === 'unavailable'
        ? 'Assessment is unavailable. The saved conversation remains available.'
        : savedAssessment.completed && savedAssessment.judgment.verdict === 'pass'
          ? 'Objective completed.' : 'Assessment recorded without objective credit.'}</p>}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy} onClick={() => void clear()}>Start another coupon conversation</button></>}
    {outcome?.status === 'incomplete' && <><p role="status" style={{ whiteSpace: 'pre-wrap' }}>{outcome.text}</p>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy} onClick={() => void clear()}>Start another coupon conversation</button></>}
    {error && <p role="alert">{error}</p>}
  </section>;
}

export { browserStore as couponProbeReferenceStore };
