import React, { useCallback, useEffect, useRef, useState } from 'react';
import { RefreshCw, ShieldCheck, Sparkles } from 'lucide-react';

function requestId() {
  if (typeof crypto?.randomUUID !== 'function') throw new Error('Secure request identity unavailable');
  return crypto.randomUUID();
}
async function json(response) {
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.error || 'Persona inbox exercise unavailable');
  return value;
}

export default function PersonaInboxLab({ personaKey }) {
  const epoch = useRef(0);
  const requests = useRef(new Map());
  const active = useRef(null);
  const [state, setState] = useState({ ready: false, loading: true, messages: [], acl: null,
    capabilities: { enforceAcl: false } });
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const current = ++epoch.current;
    active.current?.abort(); const controller = new AbortController(); active.current = controller;
    setError(''); setState(previous => ({ ...previous, loading: true }));
    try {
      const value = await json(await fetch('/api/secureshop/v2/persona-inbox/readiness', { signal: controller.signal }));
      if (current !== epoch.current) return;
      setState({ ready: value.ready === true, loading: false,
        messages: Array.isArray(value.messages) ? value.messages : [], acl: value.acl || null,
        capabilities: { enforceAcl: value.capabilities?.enforceAcl === true } });
      setBusy(false);
    } catch (cause) {
      if (controller.signal.aborted || current !== epoch.current) return;
      setState(previous => ({ ...previous, loading: false })); setError(cause.message);
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    requests.current.clear(); setResult(null); setBusy(false); load();
    return () => { epoch.current += 1; active.current?.abort(); };
  }, [personaKey, load]);

  const read = async messageId => {
    if (busy) return;
    const current = epoch.current; const controller = new AbortController(); active.current = controller;
    const stable = requests.current.get(messageId) || requestId(); requests.current.set(messageId, stable);
    setBusy(true); setError('');
    try {
      const value = await json(await fetch('/api/secureshop/v2/persona-inbox/read', {
        method: 'POST', headers: { 'content-type': 'application/json' }, signal: controller.signal,
        body: JSON.stringify({ request_id: stable, message_id: messageId }),
      }));
      if (current !== epoch.current) return;
      requests.current.delete(messageId); setResult(value);
    } catch (cause) {
      if (!controller.signal.aborted && current === epoch.current) setError(cause.message);
    } finally { if (current === epoch.current) setBusy(false); }
  };
  const enforce = async () => {
    if (busy) return;
    const current = epoch.current; const controller = new AbortController(); active.current = controller;
    setBusy(true); setError('');
    try {
      await json(await fetch('/api/secureshop/v2/persona-inbox/enforce', { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: '{}', signal: controller.signal }));
      if (current !== epoch.current) return;
      requests.current.clear(); setResult(null); await load();
    } catch (cause) {
      if (!controller.signal.aborted && current === epoch.current) setError(cause.message);
    } finally { if (current === epoch.current) setBusy(false); }
  };

  if (!state.ready) return null;
  const unavailable = Boolean(error) || state.loading;
  return (
    <section aria-labelledby="persona-inbox-lab-title" style={{ border: '1px solid var(--rule)', padding: 16,
      background: 'color-mix(in srgb, var(--paper) 94%, var(--signal))' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center' }}>
        <div>
          <div className="ss-card__meta">LAUNCH-BOUND ACL LAB</div>
          <h2 id="persona-inbox-lab-title" className="ss-display" style={{ margin: '3px 0', fontSize: 22 }}>
            Persona inbox access
          </h2>
          <div className="ss-mono" data-testid="persona-inbox-acl">
            ACL v{state.acl?.version}: {state.acl?.mode}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="ss-btn ss-btn--ghost" disabled={busy || state.loading} onClick={load}>
            <RefreshCw size={13} /> Refresh
          </button>
          {state.acl?.mode === 'advisory' && state.capabilities.enforceAcl && (
            <button className="ss-btn" disabled={busy || unavailable} onClick={enforce}>
              <ShieldCheck size={13} /> Enforce ACL
            </button>
          )}
        </div>
      </div>
      <div style={{ display: 'grid', gap: 8, marginTop: 14 }}>
        {state.messages.map(message => (
          <div key={message.messageId} style={{ display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', borderTop: '1px solid var(--rule)', paddingTop: 8 }}>
            <span><strong>{message.subject}</strong> <span className="ss-mono">({message.ownerShopRole})</span></span>
            <button className="ss-btn ss-btn--ghost" disabled={busy || unavailable} onClick={() => read(message.messageId)}>
              <Sparkles size={13} /> Ask agent to read
            </button>
          </div>
        ))}
      </div>
      {error && <p role="alert" style={{ color: 'var(--rust)' }}>{error}. Use Refresh to retry.</p>}
      {result && <div data-testid="persona-inbox-result" style={{ marginTop: 12 }}>
        <div className="ss-card__meta">AGENT ACCESS RESULT · {result.stopReason}</div>
        {result.accesses?.length ? result.accesses.map(access => (
          <article key={access.event_id} style={{ borderTop: '1px solid var(--rule)', paddingTop: 10, marginTop: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
              <strong>{access.subject}</strong>
              <span className="ss-mono">{access.acl?.mode} · {access.acl?.decision}</span>
            </div>
            <p style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>
              {access.acl?.disclosed ? access.body : 'Message body was not disclosed.'}
            </p>
          </article>
        )) : <p>The agent completed without a verified inbox read.</p>}
      </div>}
    </section>
  );
}
