import React, { useState, useRef, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Turn from './AgentLane/Turn.jsx';
import HopDetailSheet from './AgentLane/HopDetailSheet.jsx';
import { useAgentStream } from '../hooks/useAgentStream.js';
import { useAuth } from '../context/AuthContext.jsx';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import BoundAgentLane from './BoundAgentLane.jsx';
import BoundRoleAssistant from './BoundRoleAssistant.jsx';

export default function AgentLane(props) {
  if (getBridgeFetchMetadata(globalThis.fetch)) {
    if (props.role === 'admin') return <BoundAdminLane />;
    if (['customer', 'merchant'].includes(props.role || 'customer')) return <BoundAgentLane {...props} />;
  }
  return <LegacyAgentLane {...props} />;
}

function BoundAdminLane() {
  const { user, token } = useAuth();
  const [composerSlot, setComposerSlot] = useState(null);
  const bodyRef = React.useRef(null);
  return <aside className="ss-lane" data-testid="agent-lane" aria-label="Admin agent activity">
    <div className="ss-lane__header"><div className="ss-lane__title">Admin agent tools</div></div>
    <div className="ss-lane__body" ref={bodyRef}>
      <p>Use the Audit page to ask the owned audit agent and inspect its result.</p>
      <Link to="/secureshop/admin/audit">Open audit agent</Link>
      <BoundRoleAssistant role="admin" shopUserId={user?.id} authorityKey={token}
        instance="admin-lane" transport={globalThis.fetch} composerTarget={composerSlot}
        scrollContainerRef={bodyRef} />
    </div>
    <div ref={setComposerSlot} data-testid="admin-role-composer-slot" style={{ flexShrink: 0 }} />
  </aside>;
}

function LegacyAgentLane({ role = 'customer', prefillMessage }) {
  const { user } = useAuth();
  const { turns, status, send, error } = useAgentStream({ role, defaultUserId: user?.id });
  const [selectedHop, setSelectedHop] = useState(null);
  const [input, setInput] = useState(prefillMessage || '');
  const bodyRef = useRef(null);
  const roleCopy = role === 'admin'
    ? { starter: 'Try "explain a recent audit event"', label: 'Message to admin supervisor' }
    : role === 'merchant'
      ? { starter: 'Try "review a product listing"', label: 'Message to merchant supervisor' }
      : { starter: 'Try "recommend a laptop for coding"', label: 'Message to customer supervisor' };

  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [turns]);

  const submit = (e) => {
    e && e.preventDefault();
    if (!input.trim() || status === 'thinking') return;
    const msg = input;
    setInput('');
    send(msg).catch(() => {});
  };

  return (
    <aside className="ss-lane" data-testid="agent-lane" aria-label="Agent activity lane">
      <div className="ss-lane__header">
        <div>
          <div className="ss-lane__title">Agent lane</div>
          <div className="ss-mono" style={{ marginTop: 4, opacity: 0.7 }}>{role} · {status}</div>
        </div>
        <span className={`ss-dot ${status === 'thinking' ? 'ss-dot--amber' : status === 'error' ? 'ss-dot--rust' : 'ss-dot--kelp'}`}
              aria-label={`status: ${status}`} />
      </div>
      <div className="ss-lane__body" ref={bodyRef}>
        {turns.length === 0 && (
          <div className="ss-empty">
            <div style={{ fontFamily: 'var(--display)', fontSize: 20, marginBottom: 8 }}>Ask anything.</div>
            <div className="ss-mono">{roleCopy.starter}</div>
          </div>
        )}
        {turns.map((t, i) => <Turn key={i} turn={t} role={role} onOpenHop={setSelectedHop} />)}
        {error && <div style={{ color: 'var(--rust)', fontSize: 12, marginTop: 12 }}>{String(error)}</div>}
      </div>
      <form className="ss-lane__composer" onSubmit={submit}>
        <input className="ss-lane__input" value={input} onChange={(e) => setInput(e.target.value)}
               placeholder="Ask the OWASP AI SecureShop agents…" aria-label={roleCopy.label} />
        <button className="ss-btn" type="submit" disabled={!input.trim() || status === 'thinking'}>Send</button>
      </form>
      <HopDetailSheet hop={selectedHop} onClose={() => setSelectedHop(null)} />
    </aside>
  );
}
