import React, { useEffect, useRef, useState } from 'react';

const qualificationText = {
  'native-model': 'Qualified model workflow',
  'native-browser-judge': 'Qualified browser and Judge workflow',
  pending: 'Pending qualification — cannot enable yet',
};

export default function SecureShopStandaloneObjectivesControl({ client }) {
  const [rows, setRows] = useState(null);
  const [status, setStatus] = useState('loading');
  const [savingId, setSavingId] = useState(null);
  const [notice, setNotice] = useState('');
  const request = useRef({ sequence: 0, controller: null });

  const read = async (message = '') => {
    request.current.controller?.abort();
    const controller = new AbortController();
    const sequence = ++request.current.sequence;
    request.current.controller = controller;
    setRows(null);
    setStatus('loading');
    setSavingId(null);
    setNotice(message);
    try {
      const result = await client.getAssessmentObjectives(controller.signal);
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setRows(result);
      setStatus('ready');
    } catch (error) {
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setStatus('error');
      setNotice(`${message ? `${message} ` : ''}${error.status === 403
        ? 'Shop administrator access is required.'
        : error.message || 'Could not load objective settings.'}`);
    }
  };

  useEffect(() => {
    void read();
    return () => { request.current.sequence++; request.current.controller?.abort(); };
  }, [client]);

  const select = async row => {
    if (status !== 'ready' || !rows || (row.qualification === 'pending' && !row.enabled)) return;
    request.current.controller?.abort();
    const controller = new AbortController();
    const sequence = ++request.current.sequence;
    request.current.controller = controller;
    setStatus('saving');
    setSavingId(row.objectiveId);
    setNotice('');
    try {
      const result = await client.setAssessmentObjective(row.objectiveId, !row.enabled,
        row.revision, controller.signal);
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setRows(previous => previous.map(item => item.objectiveId === row.objectiveId
        ? { ...item, ...result } : item));
      setStatus('ready');
      setSavingId(null);
    } catch (error) {
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      await read(error.status === 409
        ? 'Objective setting changed or is not qualified. Current settings reloaded.'
        : 'Objective change could not be confirmed. Current settings reloaded.');
    }
  };

  return <section aria-label="Assessment objectives" style={{ borderTop: '1px solid var(--rule)',
    marginTop: 20, paddingTop: 16 }}>
    <strong style={{ fontFamily: 'var(--display)', fontSize: 17 }}>Assessment objectives</strong>
    <p style={{ margin: '6px 0 12px', fontSize: 12, opacity: 0.72 }}>
      Only qualified objectives can be enabled for this SecureShop account.
    </p>
    {status === 'loading' && <p role="status" style={{ fontSize: 13 }}>Loading objectives…</p>}
    {rows && <>
      {rows.length === 0 && <p style={{ fontSize: 13 }}>No assessment objectives are available.</p>}
      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {rows.map(row => <li key={row.objectiveId} style={{ borderTop: '1px solid var(--rule)',
          padding: '11px 0', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 13, lineHeight: 1.35 }}>{row.label}</div>
            <div className="ss-mono" style={{ fontSize: 10, opacity: 0.65, marginTop: 4 }}>
              {qualificationText[row.qualification]} · revision {row.revision}
            </div>
          </div>
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            aria-label={`${row.enabled ? 'Disable' : 'Enable'} ${row.label}`}
            aria-pressed={row.enabled}
            disabled={status !== 'ready' || (row.qualification === 'pending' && !row.enabled)}
            onClick={() => select(row)} style={{ flexShrink: 0 }}>
            {savingId === row.objectiveId ? 'Saving…' : row.enabled ? 'Enabled' : 'Disabled'}
          </button>
        </li>)}
      </ul>
    </>}
    {notice && <p role="alert" style={{ color: 'var(--rust)', fontSize: 12, margin: '10px 0 0' }}>
      {notice} {status === 'error' && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
        onClick={() => read()}>Retry objectives</button>}
    </p>}
  </section>;
}
