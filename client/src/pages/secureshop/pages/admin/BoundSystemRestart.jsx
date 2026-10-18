import React, { useEffect, useRef, useState } from 'react';
import { readSystemRestartReferences, saveSystemRestartReference, forgetSystemRestartReference } from './systemRestartRecovery.js';
import { restartAdministration, restartHash, restartRequest, verifiedRestartResult } from './systemRestartOperation.mjs';

export default function BoundSystemRestart({ authToken, transport }) {
  const [name, setName] = useState('nginx');
  const [administration, setAdministration] = useState(null);
  const [references, setReferences] = useState([]);
  const [result, setResult] = useState(null);
  const [notice, setNotice] = useState('Checking restart availability…');
  const [busy, setBusy] = useState(false);
  const lifetime = useRef(null);
  const running = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    running.current = false;
    setAdministration(null); setReferences([]); setResult(null); setBusy(false);
    const current = () => lifetime.current === controller && !controller.signal.aborted && globalThis.fetch === transport;
    (async () => {
      try {
        const response = await transport('/api/secureshop/admin/system/restart', { signal: controller.signal });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const capability = restartAdministration(await response.json());
        const scopeKey = await restartHash({ restartTargetId: capability.targetId });
        if (!current()) return;
        const saved = readSystemRestartReferences();
        setAdministration({ ...capability, scopeKey }); setReferences(saved); setNotice(null);
      } catch (error) { if (current()) setNotice(`Restart unavailable: ${error.message}`); }
    })();
    return () => controller.abort();
  }, [authToken, transport]);

  async function operate(reference) {
    const controller = lifetime.current;
    const current = () => lifetime.current === controller && !controller?.signal.aborted && globalThis.fetch === transport;
    if (!administration || running.current || !current()) return;
    running.current = true; setBusy(true); setResult(null); setNotice(null);
    let saved = reference, dispatched = false;
    try {
      let response, expectedHash;
      if (reference) {
        response = await transport(`/api/secureshop/admin/system/restart-operations/${reference.operationId}`, { signal: controller.signal });
      } else {
        const request = restartRequest(globalThis.crypto.randomUUID(), name);
        expectedHash = await restartHash(request);
        if (!current()) return;
        saved = { scopeKey: administration.scopeKey, operationId: request.operationId, state: 'pending' };
        const next = await saveSystemRestartReference(saved);
        if (!current()) return;
        setReferences(next);
        dispatched = true;
        response = await transport('/api/secureshop/admin/system/restart', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request), signal: controller.signal });
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const outcome = await verifiedRestartResult(await response.json(), saved, administration.targetId, expectedHash);
      if (!current()) return;
      setResult(outcome);
      if (outcome.state === 'completed' && !reference) {
        const next = await saveSystemRestartReference({ ...saved, state: 'completed' });
        if (!current()) return;
        setReferences(next);
        setNotice('Owned service restarted. Receipt verified.');
      } else if (outcome.state === 'completed' || (['failed', 'retired'].includes(outcome.state) && outcome.failureCode !== 'OUTCOME_UNCERTAIN')) {
        const next = await forgetSystemRestartReference(saved);
        if (!current()) return;
        setReferences(next);
        setNotice(outcome.state === 'completed' ? 'Owned service restarted. Receipt verified.' : `Restart ${outcome.state}. No restart was repeated.`);
      } else setNotice('Outcome is pending or uncertain. Check the saved operation; no automatic retry will occur.');
    } catch (error) {
      if (!current()) return;
      if (dispatched && saved) {
        try {
          const next = await saveSystemRestartReference({ ...saved, state: 'unknown' });
          if (!current()) return;
          setReferences(next);
        } catch { /* The acknowledged pre-dispatch reference remains recoverable. */ }
      }
      if (current()) setNotice(`Restart unavailable: ${error.message}. Check any saved operation before retrying.`);
    } finally {
      if (current()) { running.current = false; setBusy(false); }
    }
  }

  async function forget(reference) {
    const controller = lifetime.current;
    if (running.current || !controller || controller.signal.aborted) return;
    running.current = true; setBusy(true);
    try {
      const next = await forgetSystemRestartReference(reference);
      if (lifetime.current === controller && !controller.signal.aborted && globalThis.fetch === transport) { setReferences(next); setNotice('Saved reference forgotten. This did not cancel or repeat the operation.'); }
    } catch (error) { if (lifetime.current === controller && !controller.signal.aborted) setNotice(error.message); }
    finally { if (lifetime.current === controller && !controller.signal.aborted) { running.current = false; setBusy(false); } }
  }

  return <section data-testid="system-restart-panel" style={{ marginBottom: 32 }}>
    <h2 className="ss-shelf__title">Restart service <span style={{ opacity: 0.55, fontFamily: 'var(--mono)', fontSize: 11 }}>· command injection sink</span></h2>
    <div className="ss-mono" style={{ padding: 10, marginBottom: 10, border: '1px solid var(--rust)', color: 'var(--rust)', background: 'color-mix(in srgb, var(--rust) 5%, transparent)', fontSize: 11 }}>
      Service name is interpolated into a shell command inside the isolated training service. The receipt records its instance and generation change.
    </div>
    <form className="ss-admin-system__action-form" onSubmit={event => { event.preventDefault(); void operate(); }}>
      <input className="ss-lane__input" value={name} onChange={event => setName(event.target.value)} placeholder="service name (try `nginx; whoami`)" style={{ flex: 1 }} aria-label="Service name" />
      <button className="ss-btn" type="submit" disabled={busy || !administration || references.some(row => row.scopeKey === administration.scopeKey)}>{busy ? 'checking…' : 'restart'}</button>
    </form>
    {notice && <p role="status" className="ss-mono">{notice}</p>}
    {references.map(reference => <div key={`${reference.scopeKey}:${reference.operationId}`} className="ss-mono">
      <span>Saved restart {reference.operationId} · {reference.state} </span>
      <button className="ss-btn" disabled={busy || reference.scopeKey !== administration?.scopeKey} onClick={() => void operate(reference)}>check restart outcome</button>{' '}
      <button className="ss-btn" disabled={busy} onClick={() => void forget(reference)}>forget reference</button>
    </div>)}
    {result && <pre className="ss-mono ss-admin-system__output" style={{ background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 12, border: '1px solid var(--rule)', fontSize: 11, margin: 0 }}>{JSON.stringify(result, null, 2)}</pre>}
  </section>;
}
