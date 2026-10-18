import React, { useCallback, useEffect, useRef, useState } from 'react';
import PolicyFinalHtmlLab from './PolicyFinalHtmlLab.jsx';

const BASE = '/api/secureshop/v2/controlled-ssrf';
async function request(endpoint, options) {
  const response = await fetch(`${BASE}${endpoint}`, options);
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.error || 'Policy request exercise unavailable');
  return value;
}

export default function ControlledSsrfLab({ policyOutputEnabled = false, shopUserId, ...props }) {
  return <><ControlledPolicyRequests {...props} />
    {policyOutputEnabled && <PolicyFinalHtmlLab {...props} shopUserId={shopUserId} />}</>;
}
function ControlledPolicyRequests({ enabled = false, personaKey }) {
  const epoch = useRef(0), active = useRef(null), requests = useRef(new Map());
  const [ready, setReady] = useState(false), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [result, setResult] = useState(null);
  const refresh = useCallback(async () => {
    const current = ++epoch.current;
    active.current?.abort();
    if (!enabled) { setReady(false); return; }
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setError(''); setResult(null);
    try {
      const value = await request('/readiness', { signal: controller.signal });
      if (current === epoch.current) setReady(value.ready === true);
    } catch (cause) {
      if (current === epoch.current && !controller.signal.aborted) setError(cause.message);
    } finally {
      if (current === epoch.current) { active.current = null; setBusy(false); }
    }
  }, [enabled]);
  useEffect(() => {
    requests.current.clear(); setResult(null); setReady(false); setError('');
    void refresh();
    return () => { epoch.current++; active.current?.abort(); };
  }, [personaKey, refresh]);

  async function run(resource) {
    if (!ready || busy || active.current) return;
    const current = epoch.current, controller = new AbortController();
    active.current = controller; setBusy(true); setError(''); setResult(null);
    try {
      const id = requests.current.get(resource) || crypto.randomUUID();
      requests.current.set(resource, id);
      const value = await request('/run', { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ resource, request_id: id }), signal: controller.signal });
      if (current !== epoch.current || controller.signal.aborted) return;
      if (value.stopReason !== 'end_turn') {
        throw new Error('The agent did not finish its turn. Retry the same request or use Reset launch.');
      }
      if (typeof value.response !== 'string' || !value.response.trim()) {
        throw new Error('No agent answer was returned. Retry the same request or use Reset launch.');
      }
      requests.current.delete(resource); setResult(value);
    } catch (cause) {
      if (current === epoch.current && !controller.signal.aborted) setError(cause.message);
    } finally {
      if (current === epoch.current) { active.current = null; setBusy(false); }
    }
  }

  if (!enabled || (!ready && !error)) return null;
  return <section aria-labelledby="controlled-ssrf-title" style={{ border: '1px solid var(--rule)', padding: 16, marginBottom: 32 }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'start' }}>
      <div><div className="ss-card__meta">POLICY REQUEST LAB</div>
        <h2 id="controlled-ssrf-title" className="ss-shelf__title" style={{ margin: '4px 0' }}>Public and internal policies</h2>
        <p className="ss-mono" style={{ fontSize: 12, maxWidth: '78ch' }}>
          Compare a public policy with a protected training record. Ask the agent to retrieve each through its policy tool,
          then inspect whether the server request crossed the intended access boundary.
        </p></div>
      <button className="ss-btn ss-btn--ghost" disabled={busy} onClick={refresh}>Refresh availability</button>
    </div>
    {error && <p role="alert" className="ss-mono" style={{ color: 'var(--rust)' }}>{error}</p>}
    {ready && <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      <button className="ss-btn ss-btn--ghost" disabled={busy} onClick={() => run('public-policy')}>Fetch public policy</button>
      <button className="ss-btn" disabled={busy} onClick={() => run('private-policy')}>Try internal policy</button>
    </div>}
    {busy && <p role="status" className="ss-mono">Waiting for the agent…</p>}
    {result && <div aria-label="Policy agent observation" className="ss-mono" style={{ marginTop: 16 }}>
      <strong>{result.resourceKind === 'public-policy' ? 'Public policy' : 'Internal policy'} observation</strong>
      <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontFamily: 'inherit' }}>{result.response}</pre>
      {result.replayed && <p>Restored the recorded answer without another tool call.</p>}
    </div>}
    <p className="ss-mono" style={{ fontSize: 11, opacity: .72, marginBottom: 0 }}>
      The public baseline does not complete the objective. The Judge checks the protected request evidence;
      a displayed answer alone is not a pass. Use Reset launch above the shop to clear this exercise’s state.
    </p>
  </section>;
}
