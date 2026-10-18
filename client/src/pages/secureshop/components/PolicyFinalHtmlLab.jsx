import React, { useEffect, useRef, useState } from 'react';
import Turn from './AgentLane/Turn.jsx';
import { shopStorage, flushShopStorage } from '../utils/shopStorage.mjs';
import { createPolicyFinalHtmlReferenceStore } from '../utils/policyFinalHtmlReference.mjs';

const BASE = '/api/secureshop/v2/controlled-ssrf/html';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const savedReferences = createPolicyFinalHtmlReferenceStore({ storage: shopStorage, flush: flushShopStorage });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function originalResponse(value, reference, recovered) {
  const mode = value?.modeCapability;
  if (!exact(value, ['sessionId', 'requestId', 'response', 'stopReason', 'replayed', 'modeCapability'])
    || !UUID.test(value.sessionId || '') || value.requestId !== reference.requestId
    || reference.sessionId !== null && value.sessionId !== reference.sessionId
    || value.stopReason !== 'end_turn' || value.replayed !== recovered
    || typeof value.response !== 'string' || !value.response.trim() || !value.response.isWellFormed()
    || value.response.includes('\0') || new TextEncoder().encode(value.response).byteLength > 20000
    || !exact(mode, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || mode.version !== 1 || mode.featureId !== 'controlled_ssrf'
    || mode.policyVersion !== 'owned-public-destination-v1' || !['fixed', 'vuln'].includes(mode.effectiveMode)
    || !exact(mode.scope, ['kind', 'id']) || mode.scope.kind !== 'launch_feature'
    || mode.scope.id !== mode.featureId) throw Error('Saved policy output is unavailable');
  return value;
}

export default function PolicyFinalHtmlLab({ enabled, personaKey, shopUserId,
  referenceStore = savedReferences, transport = globalThis.fetch }) {
  const epoch = useRef(0), active = useRef(null);
  const [ready, setReady] = useState(false), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [storageFailed, setStorageFailed] = useState(false);
  const [reference, setReference] = useState(null), [result, setResult] = useState(null);
  const [assessment, setAssessment] = useState(null), [policy, setPolicy] = useState('');
  const read = async (path, options = {}) => {
    const response = await transport(`${BASE}${path}`, options);
    const value = await response.json();
    if (!response.ok) throw Error(value.error || 'Policy output exercise unavailable');
    return value;
  };
  const recover = async (saved, signal, current) => {
    const value = originalResponse(await read(`/run/${saved.requestId}`, { signal }), saved, true);
    if (!current()) return;
    const acknowledged = saved.sessionId === null
      ? await referenceStore.save({ ...saved, sessionId: value.sessionId }, saved, current) : saved;
    if (!current()) return;
    setReference(acknowledged); setResult(value);
    if (acknowledged.assessmentStarted) {
      const outcome = await read(`/assessment/${acknowledged.sessionId}/${acknowledged.requestId}`, { signal });
      if (current()) setAssessment(outcome);
    }
  };
  useEffect(() => {
    const generation = ++epoch.current, controller = new AbortController();
    const current = () => epoch.current === generation && !controller.signal.aborted;
    active.current?.abort(); active.current = controller;
    setReady(false); setReference(null); setResult(null); setAssessment(null);
    setError(''); setStorageFailed(false); setPolicy('');
    if (!enabled || !Number.isSafeInteger(shopUserId) || shopUserId < 1) {
      setBusy(false); active.current = null; return () => controller.abort();
    }
    setBusy(true);
    void (async () => {
      let saved;
      try { saved = referenceStore.read(shopUserId); if (current()) setReference(saved); }
      catch (cause) { if (current()) { setStorageFailed(true); setError(cause.message); } return; }
      const results = await Promise.allSettled([
        read('/readiness', { signal: controller.signal }).then(value => {
          if (!exact(value, ['ready']) || typeof value.ready !== 'boolean') throw Error('Policy output availability is invalid');
          if (current()) setReady(value.ready);
        }),
        saved ? recover(saved, controller.signal, current) : Promise.resolve(),
      ]);
      if (current()) for (const item of results) if (item.status === 'rejected') setError(item.reason.message);
    })().finally(() => { if (current()) { active.current = null; setBusy(false); } });
    return () => { controller.abort(); if (active.current === controller) active.current = null; };
  }, [enabled, shopUserId, personaKey, referenceStore, transport]);

  async function perform(work) {
    if (active.current || busy || storageFailed) return;
    const generation = epoch.current, controller = new AbortController();
    const current = () => epoch.current === generation && !controller.signal.aborted;
    active.current = controller; setBusy(true); setError('');
    try { await work(controller.signal, current); }
    catch (cause) { if (current()) setError(cause.message); }
    finally { if (current()) { active.current = null; setBusy(false); } }
  }
  const run = () => perform(async (signal, current) => {
    if (!ready || reference || !policy.trim() || !policy.isWellFormed() || policy.includes('\0')
      || new TextEncoder().encode(policy).byteLength > 8192) throw Error('Enter a policy of at most 8192 bytes');
    const intent = { version: 1, shopUserId, requestId: crypto.randomUUID(), sessionId: null,
      assessmentStarted: false, startedAt: Date.now() };
    setReference(intent);
    await referenceStore.save(intent, null, current);
    if (!current()) return;
    const value = originalResponse(await read('/run', { method: 'POST', signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ request_id: intent.requestId, policy_html: policy }) }), intent, false);
    if (!current()) return;
    const acknowledged = await referenceStore.save({ ...intent, sessionId: value.sessionId }, intent, current);
    if (current()) { setReference(acknowledged); setResult(value); }
  });
  const check = () => perform((signal, current) => recover(reference, signal, current));
  const assess = () => perform(async (signal, current) => {
    if (!reference?.sessionId || !result || reference.assessmentStarted) return;
    const intent = { ...reference, assessmentStarted: true };
    setReference(intent); await referenceStore.save(intent, reference, current);
    if (!current()) return;
    const value = await read('/assess', { method: 'POST', signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ session_id: intent.sessionId, request_id: intent.requestId }) });
    if (current()) setAssessment(value);
  });
  const assessmentResolved = !reference?.assessmentStarted || assessment?.status === 'ineligible'
    || UUID.test(assessment?.judgment?.evaluationId || '');
  const startNew = () => perform(async (_signal, current) => {
    if (!result || !assessmentResolved) return;
    await referenceStore.clear(reference, current);
    if (current()) { setReference(null); setResult(null); setAssessment(null); }
  });
  if (!enabled || !ready && !reference && !error) return null;
  return <section aria-labelledby="policy-final-html-title" style={{ border: '1px solid var(--rule)', padding: 16, marginBottom: 32 }}>
    <div className="ss-card__meta">POLICY OUTPUT LAB</div>
    <h2 id="policy-final-html-title" className="ss-shelf__title" style={{ margin: '4px 0' }}>Policy answer rendering</h2>
    <p className="ss-mono" style={{ fontSize: 12, maxWidth: '78ch' }}>
      Supply a policy for the agent to fetch from your isolated practice source, then inspect its saved answer.
    </p>
    {error && <p role="alert" className="ss-mono" style={{ color: 'var(--rust)' }}>{error}</p>}
    <label className="ss-mono" style={{ display: 'block', fontSize: 12 }}>Policy HTML
      <textarea aria-label="Policy HTML" value={policy} onChange={event => setPolicy(event.target.value)}
        disabled={busy || !!reference || storageFailed} rows={4}
        style={{ width: '100%', boxSizing: 'border-box', margin: '6px 0 12px' }} />
    </label>
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {!reference && <button className="ss-btn" disabled={!ready || busy || storageFailed || !policy.trim()} onClick={run}>Fetch and explain policy</button>}
      {reference && <button className="ss-btn ss-btn--ghost" disabled={busy || storageFailed} onClick={check}>Check saved policy answer</button>}
      {result && !reference?.assessmentStarted && <button className="ss-btn" disabled={busy || storageFailed} onClick={assess}>Check policy output</button>}
      {result && <button className="ss-btn ss-btn--ghost" disabled={busy || storageFailed || !assessmentResolved} onClick={startNew}>New policy request</button>}
    </div>
    {busy && <p role="status" className="ss-mono">Waiting for the saved policy result…</p>}
    {result && <Turn role="customer" turn={{ user: '', hops: [], reply: result.response,
      status: 'done', modeCapability: result.modeCapability }} />}
    {assessment && <p role="status" className="ss-mono">Policy output assessment: {assessment.judgment?.verdict || assessment.status || 'unconfirmed'}{assessment.completed === true ? ' · Objective completed' : ''}</p>}
    <p className="ss-mono" style={{ fontSize: 11, opacity: .72, marginBottom: 0 }}>
      The assessment checks the original model answer and an isolated rendering witness. A displayed answer alone is not a pass.
    </p>
  </section>;
}
