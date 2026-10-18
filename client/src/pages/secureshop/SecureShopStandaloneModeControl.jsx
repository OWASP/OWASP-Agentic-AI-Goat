import React, { useEffect, useRef, useState } from 'react';

export default function SecureShopStandaloneModeControl({ client, onModeChanged }) {
  const [current, setCurrent] = useState(null);
  const [status, setStatus] = useState('loading');
  const [error, setError] = useState('');
  const request = useRef({ sequence: 0, controller: null });

  const read = async (notice = '', changedFrom = null) => {
    request.current.controller?.abort();
    const controller = new AbortController();
    const sequence = ++request.current.sequence;
    request.current.controller = controller;
    setStatus('loading');
    setError(notice);
    try {
      const result = await client.getMode(controller.signal);
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setCurrent(result);
      setStatus('ready');
      setError(notice);
      if (changedFrom && (result.mode !== changedFrom.mode || result.revision !== changedFrom.revision)) {
        onModeChanged?.(result);
      }
    } catch (cause) {
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setCurrent(null);
      setStatus('error');
      setError(`${notice ? `${notice} ` : ''}${cause.message || 'Could not load shop mode.'}`);
    }
  };

  useEffect(() => {
    void read();
    return () => { request.current.sequence++; request.current.controller?.abort(); };
  }, [client]);

  const select = async nextMode => {
    if (!current || status !== 'ready' || current.mode === nextMode) return;
    request.current.controller?.abort();
    const controller = new AbortController();
    const sequence = ++request.current.sequence;
    request.current.controller = controller;
    setStatus('saving'); setError('');
    try {
      const result = await client.setMode(nextMode, current.revision, controller.signal);
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setCurrent(result);
      setStatus('ready');
      onModeChanged?.(result);
    } catch (cause) {
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setCurrent(null);
      await read(cause.status === 409
        ? 'Mode changed in another session. Current value reloaded.'
        : 'Mode change could not be confirmed. Current value reloaded.', current);
    }
  };

  return <div role="group" aria-label="Shop feature mode">
    <strong style={{ fontFamily: 'var(--display)', fontSize: 17 }}>Feature mode</strong>
    <p style={{ margin: '6px 0 12px', fontSize: 12, opacity: 0.72 }}>Applies to this SecureShop account.</p>
    {status === 'loading' && <p role="status" style={{ fontSize: 13 }}>Loading mode…</p>}
    {current && <>
      <p style={{ margin: '0 0 10px', fontSize: 13 }}>
        Current: <strong>{current.mode === 'vuln' ? 'Vulnerable' : 'Fixed'}</strong>
        <span className="ss-mono" style={{ opacity: 0.55, fontSize: 10 }}> · revision {current.revision}</span>
      </p>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {['vuln', 'fixed'].map(value => <button key={value} type="button"
          className="ss-btn ss-btn--ghost ss-btn--sm" aria-pressed={current.mode === value}
          disabled={status !== 'ready' || current.mode === value}
          onClick={() => select(value)}>{value === 'vuln' ? 'Vulnerable' : 'Fixed'}</button>)}
      </div>
      {status === 'saving' && <p role="status" style={{ fontSize: 12 }}>Updating mode…</p>}
    </>}
    {error && <p role="alert" style={{ color: 'var(--rust)', fontSize: 12, margin: '10px 0 0' }}>
      {error} {status === 'error' && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
        onClick={() => read()}>Retry mode</button>}
    </p>}
  </div>;
}
