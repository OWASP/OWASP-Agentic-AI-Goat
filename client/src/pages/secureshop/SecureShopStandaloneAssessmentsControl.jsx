import React, { useEffect, useRef, useState } from 'react';

export default function SecureShopStandaloneAssessmentsControl({ client, focusEvaluationId = null }) {
  const [rows, setRows] = useState(null);
  const [status, setStatus] = useState('loading');
  const [notice, setNotice] = useState('');
  const [savingId, setSavingId] = useState(null);
  const request = useRef({ sequence: 0, controller: null });
  const mutationInFlight = useRef(false);
  const section = useRef(null);

  useEffect(() => {
    if (focusEvaluationId) section.current?.scrollIntoView?.({ block: 'nearest' });
  }, [focusEvaluationId]);

  const read = async (message = '', afterMutation = false) => {
    if (mutationInFlight.current && !afterMutation) return;
    request.current.controller?.abort();
    const controller = new AbortController();
    const sequence = ++request.current.sequence;
    request.current.controller = controller;
    setRows(null); setStatus('loading'); setSavingId(null); setNotice(message);
    try {
      const result = await client.getAssessments(controller.signal);
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setRows(result); setStatus('ready');
    } catch (error) {
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      setStatus('error');
      setNotice(`${message ? `${message} ` : ''}${error.message || 'Could not load saved assessments.'}`);
    }
  };

  useEffect(() => {
    void read();
    return () => { mutationInFlight.current = false; request.current.sequence++; request.current.controller?.abort(); };
  }, [client]);

  const retry = async row => {
    if (mutationInFlight.current || status !== 'ready' || !row.canRetry) return;
    mutationInFlight.current = true;
    request.current.controller?.abort();
    const controller = new AbortController();
    const sequence = ++request.current.sequence;
    request.current.controller = controller;
    setSavingId(row.evaluationId); setStatus('retrying'); setNotice('');
    try {
      const receipt = await client.retryAssessment(row.evaluationId, controller.signal);
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      await read(receipt.completed
        ? 'Saved evaluation completed. No shop action was repeated.'
        : `Saved evaluation returned ${receipt.verdict}; no objective completion was confirmed.`, true);
    } catch (error) {
      if (controller.signal.aborted || sequence !== request.current.sequence) return;
      await read(error.status === 409
        ? 'Evaluation retry is no longer available. Current assessments reloaded.'
        : 'Evaluation retry could not be confirmed. Current assessments reloaded; no action was repeated.', true);
    } finally {
      mutationInFlight.current = false;
    }
  };

  return <section ref={section} aria-label="Saved assessments" style={{ borderTop: '1px solid var(--rule)',
    marginTop: 20, paddingTop: 16 }}>
    <strong style={{ fontFamily: 'var(--display)', fontSize: 17 }}>Saved assessments</strong>
    <p style={{ margin: '6px 0 12px', fontSize: 12, opacity: 0.72 }}>
      Retry eligible grading from saved evidence. This does not repeat a shop action or browser effect.
    </p>
    {status === 'loading' && <p role="status" style={{ fontSize: 13 }}>Loading assessments…</p>}
    {rows && <>
      {rows.length === 0 && <p style={{ fontSize: 13 }}>No saved assessments are available.</p>}
      {focusEvaluationId && !rows.some(row => row.evaluationId === focusEvaluationId) &&
        <p role="status" style={{ fontSize: 12 }}>That evaluation is not in your recent saved assessments. No retry is available here.</p>}
      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {rows.map(row => <li key={row.evaluationId} style={{ borderTop: '1px solid var(--rule)',
          padding: '10px 0', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10,
          background: focusEvaluationId === row.evaluationId ? 'color-mix(in srgb, var(--paper) 88%, var(--copper))' : undefined }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 13 }}>{row.objectiveId}</div>
            <div className="ss-mono" style={{ fontSize: 10, opacity: 0.65, marginTop: 4,
              overflowWrap: 'anywhere' }}>
              {row.verdict || 'pending'} · {row.disposition || 'not yet evaluated'} · {row.evaluationId}
            </div>
          </div>
          {row.canRetry && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            disabled={status !== 'ready'} onClick={() => retry(row)} style={{ flexShrink: 0 }}>
            {savingId === row.evaluationId ? 'Retrying…' : 'Retry evaluation'}
          </button>}
        </li>)}
      </ul>
    </>}
    {notice && <p role="alert" style={{ color: 'var(--rust)', fontSize: 12, margin: '10px 0 0' }}>
      {notice} {status === 'error' && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
        onClick={() => read()}>Retry assessments list</button>}
    </p>}
    {status === 'ready' && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
      onClick={() => read()} style={{ marginTop: 8 }}>Refresh assessments</button>}
  </section>;
}
