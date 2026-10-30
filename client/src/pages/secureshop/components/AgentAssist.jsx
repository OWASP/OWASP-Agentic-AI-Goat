import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Sparkles, X } from 'lucide-react';
import Button from './Button.jsx';
import Spinner from './Spinner.jsx';
import { useAgentStream } from '../hooks/useAgentStream.js';
import { useAuth } from '../context/AuthContext.jsx';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { useProductQuestion } from '../hooks/useProductQuestion.js';

/**
 * SecureShop v2 AgentAssist — small floating widget that can be embedded on
 * pages that don't have the full AgentLane. Bound product pages use the
 * selected product question operation; legacy pages retain their supervisor.
 */
export default function AgentAssist(props) {
  if (props.productId != null && getBridgeFetchMetadata(globalThis.fetch))
    return <BoundProductAssist {...props} />;
  return <LegacyAgentAssist {...props} />;
}

function BoundProductAssist({ productId, prompt: initialPrompt = '',
  placeholder = 'Ask about this product…', label = 'Ask about this product', position = 'inline' }) {
  const [open, setOpen] = useState(false);
  const [msg, setMsg] = useState(initialPrompt);
  useEffect(() => { setMsg(initialPrompt); }, [productId, initialPrompt]);
  const { user, token } = useAuth();
  const question = useProductQuestion({ productId, ownerKey: `${user?.id || ''}:${user?.role || ''}:${token || ''}` });
  const loading = question.status === 'thinking';
  const latest = question.turns.at(-1);
  const submit = async event => {
    event?.preventDefault?.();
    if (!msg.trim() || loading || !question.validProduct) return;
    await question.send(msg);
  };
  const body = <AgentAssistBody msg={msg} setMsg={setMsg} submit={submit}
    reply={!loading && !question.error ? latest?.reply : null} loading={loading}
    error={question.error} modeCapability={latest?.modeCapability} placeholder={placeholder} label={label} />;
  if (position === 'floating') return <>
    <button className="ss-fab" onClick={() => setOpen(value => !value)} aria-label={label} title={label} type="button">
      {open ? <X size={20} /> : <Sparkles size={20} />}
    </button>
    <AnimatePresence>{open && <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 12 }} transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
      style={{ position: 'fixed', right: 20, bottom: 90, width: 360, maxWidth: '92vw',
        background: 'var(--paper)', border: '1px solid var(--rule)', boxShadow: 'var(--shadow-lg)',
        padding: 16, zIndex: 40 }}>{body}</motion.div>}</AnimatePresence>
  </>;
  return <div style={{ border: '1px solid var(--rule)', padding: 16,
    background: 'color-mix(in srgb, var(--paper) 96%, var(--copper))' }}>{body}</div>;
}

function LegacyAgentAssist({
  role = 'customer',
  prompt: initialPrompt = '',
  placeholder = 'Ask the OWASP AI SecureShop agents…',
  label = 'Ask agents',
  position = 'inline', // 'inline' | 'floating'
}) {
  const [open, setOpen] = useState(false);
  const [msg, setMsg] = useState(initialPrompt);
  const { user } = useAuth();
  const { turns, status, error, send, createSession } = useAgentStream({ role, defaultUserId: user?.id });
  const loading = status === 'thinking';
  const latestTurn = turns.at(-1);
  const reply = !loading && !error ? latestTurn?.reply : null;
  const modeCapability = trustedTurnMode(latestTurn?.modeCapability);

  const submit = async (e) => {
    e?.preventDefault?.();
    if (!msg.trim() || loading) return;
    // Preserve this widget's existing one-shot conversation semantics.
    try {
      const session = await createSession();
      if (session) await send(msg);
    } catch { /* The shared hook exposes session failures through error state. */ }
  };

  if (position === 'floating') {
    return (
      <>
        <button
          className="ss-fab"
          onClick={() => setOpen((v) => !v)}
          aria-label={label}
          title={label}
          type="button"
        >
          {open ? <X size={20} /> : <Sparkles size={20} />}
        </button>
        <AnimatePresence>
          {open && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
              style={{
                position: 'fixed', right: 20, bottom: 90,
                width: 360, maxWidth: '92vw',
                background: 'var(--paper)', border: '1px solid var(--rule)',
                boxShadow: 'var(--shadow-lg)',
                padding: 16, zIndex: 40,
              }}
            >
              <AgentAssistBody
                msg={msg} setMsg={setMsg} submit={submit}
                reply={reply} loading={loading} error={error} modeCapability={modeCapability}
                placeholder={placeholder}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </>
    );
  }

  return (
    <div style={{
      border: '1px solid var(--rule)', padding: 16,
      background: 'color-mix(in srgb, var(--paper) 96%, var(--copper))',
    }}>
      <AgentAssistBody
        msg={msg} setMsg={setMsg} submit={submit}
        reply={reply} loading={loading} error={error} modeCapability={modeCapability}
        placeholder={placeholder}
        label={label}
      />
    </div>
  );
}

function AgentAssistBody({ msg, setMsg, submit, reply, loading, error, modeCapability, placeholder, label = 'Ask agents' }) {
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
        <Sparkles size={16} color="var(--signal)" />
        <div style={{ fontFamily: 'var(--display)', fontSize: 15, fontWeight: 600 }}>{label}</div>
      </div>
      <form onSubmit={submit} style={{ display: 'flex', gap: 8 }}>
        <input
          className="ss-lane__input"
          value={msg}
          onChange={(e) => setMsg(e.target.value)}
          placeholder={placeholder}
          aria-label={label}
        />
        <Button size="sm" type="submit" disabled={loading || !msg.trim()} loading={loading}>
          Ask
        </Button>
      </form>
      {loading && (
        <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center' }}>
          <Spinner size="sm" /> <span className="ss-mono" style={{ opacity: 0.7 }}>agents thinking…</span>
        </div>
      )}
      {reply && (
        <div style={{
          marginTop: 12, padding: 12, background: 'var(--carbon)', color: 'var(--paper)',
          fontFamily: 'var(--mono)', fontSize: 12, whiteSpace: 'pre-wrap',
        }}>
          {modeCapability && <div style={{ opacity: 0.75, marginBottom: 8 }}>
            {modeCapability.featureId} effect policy · {modeCapability.effectiveMode}
          </div>}
          {reply}
        </div>
      )}
      {error && (
        <div style={{ marginTop: 10, color: 'var(--rust)', fontSize: 12 }}>{error}</div>
      )}
    </div>
  );
}
