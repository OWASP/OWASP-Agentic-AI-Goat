import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';

export default function JudgeRetryButton({ evaluationId, canRetry, onResult }) {
  const [state, setState] = useState('ready');
  const [errorMessage, setErrorMessage] = useState('');
  const mountedRef = useRef(true);
  const requestRef = useRef(null);
  const phaseRef = useRef('idle');
  useEffect(() => {
    mountedRef.current = true;
    requestRef.current = null;
    phaseRef.current = 'idle';
    setState('ready');
    setErrorMessage('');
    return () => {
      mountedRef.current = false;
      requestRef.current?.abort();
    };
  }, [evaluationId]);
  useEffect(() => {
    // Losing capability cancels a pending POST, but a successful receipt may
    // remove that capability while its own progress refresh is still running.
    if (canRetry !== true && phaseRef.current === 'request') {
      requestRef.current?.abort();
      requestRef.current = null;
      phaseRef.current = 'idle';
      setState('ready');
      setErrorMessage('');
    }
  }, [canRetry]);
  if (canRetry !== true || typeof evaluationId !== 'string' || !evaluationId) return null;
  const retry = async () => {
    if (state !== 'ready') return;
    setState('retrying');
    setErrorMessage('');
    const controller = new AbortController();
    requestRef.current = controller;
    phaseRef.current = 'request';
    let data;
    try {
      ({ data } = await axios.post(`/api/agent-runs/judgments/${encodeURIComponent(evaluationId)}/retry`, {}, { signal: controller.signal }));
      if (!mountedRef.current || controller.signal.aborted) return;
      phaseRef.current = 'callback';
      setState('done');
    } catch (error) {
      if (!mountedRef.current || controller.signal.aborted) return;
      phaseRef.current = 'idle';
      requestRef.current = null;
      setState(error.response?.data?.canRetry === false ? 'unavailable' : 'ready');
      setErrorMessage(error.response?.data?.message || error.response?.data?.error || error.response?.data?.code || 'Evaluation retry failed.');
      return;
    }
    try {
      await onResult?.(data, { signal: controller.signal });
    } catch {
      if (mountedRef.current && !controller.signal.aborted) {
        setErrorMessage('Evaluation finished, but progress could not be refreshed.');
      }
    } finally {
      if (requestRef.current === controller) {
        requestRef.current = null;
        phaseRef.current = 'completed';
      }
    }
  };
  return (
    <div>
      <button type="button" data-testid={`judge-retry-${evaluationId}`} onClick={retry} disabled={state !== 'ready'} style={{
        marginTop: '0.5rem', padding: '0.35rem 0.7rem', border: '1px solid currentColor', borderRadius: '6px',
        background: 'transparent', color: 'inherit', font: 'inherit', fontSize: '0.78rem', cursor: state === 'ready' ? 'pointer' : 'default',
      }}>
        {state === 'retrying' ? 'Retrying evaluation…' : state === 'done' ? 'Evaluation retried' : state === 'unavailable' ? 'Retry unavailable' : 'Retry evaluation'}
      </button>
      {errorMessage && <div role="status" style={{ marginTop: '0.35rem', fontSize: '0.75rem' }}>{errorMessage}</div>}
    </div>
  );
}
