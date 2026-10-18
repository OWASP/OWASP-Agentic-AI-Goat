import React, { useEffect, useRef, useState } from 'react';
import { requireAgentContentType } from '../utils/agentStreamProtocol.mjs';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const BASE = '/api/secureshop/agents/admin/assistant/system/diagnostic/assess';
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

export function decodeSystemDiagnosticAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
    && value.modelEvaluated === false && ['ineligible', 'unconfirmed'].includes(value.status)) return value;
  if (exact(value, ['completed', 'judgment', 'replayed']) && typeof value.completed === 'boolean'
    && typeof value.replayed === 'boolean'
    && exact(value.judgment, ['verdict', 'evaluationId', 'canRetry'])
    && ['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    && UUID.test(value.judgment.evaluationId || '')
    && typeof value.judgment.canRetry === 'boolean'
    && (!value.completed || value.judgment.verdict === 'pass')) return value;
  throw Error('Saved System diagnostic assessment unavailable.');
}

const savedPath = ref => `${BASE}/${ref.sessionId}/${ref.requestId}/${ref.proposalId}`;
const identity = ref => [ref?.sessionId, ref?.requestId, ref?.proposalId].join(':');
const admitted = ref => ref && [ref.sessionId, ref.requestId, ref.proposalId]
  .every(value => typeof value === 'string' && UUID.test(value));

export default function AdminSystemDiagnosticAssessment({ reference = null, ready = false,
  authorityKey, transport = globalThis.fetch, locked = false }) {
  const [outcome, setOutcome] = useState(null), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [accessLost, setAccessLost] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), submittedRef = useRef(false);
  const refKey = identity(reference);

  useEffect(() => {
    const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    submittedRef.current = false;
    setOutcome(null); setBusy(false); setError(''); setAccessLost(false);
    return () => { if (epochRef.current === epoch) epochRef.current++;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, transport, refKey, ready]);

  const check = async start => {
    if (!ready || !admitted(reference) || activeRef.current || accessLost
      || start && (locked || outcome?.status !== 'unconfirmed' || submittedRef.current)) return;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setBusy(true); setError('');
    const current = () => epochRef.current === epoch && activeRef.current === controller
      && !controller.signal.aborted;
    try {
      if (start) {
        submittedRef.current = true;
        // The saved diagnostic IDs are the entire grading request. Never resend its command.
        try { await transport(BASE, { method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId: reference.sessionId, requestId: reference.requestId,
            proposalId: reference.proposalId }), signal: controller.signal }); }
        catch { /* The protected saved GET resolves an uncertain acknowledgement. */ }
      }
      if (!current()) return;
      const response = await transport(savedPath(reference), { method: 'GET',
        headers: { accept: 'application/json' }, signal: controller.signal });
      if (!current()) return;
      if (!response.ok) { const cause = Error('Saved System diagnostic assessment unavailable.');
        cause.status = response.status; throw cause; }
      requireAgentContentType(response, 'application/json', 'Saved System diagnostic assessment');
      const value = decodeSystemDiagnosticAssessment(await response.json());
      if (current()) setOutcome(value);
    } catch (cause) {
      if (!current()) return;
      if ([401, 403].includes(cause.status)) { setAccessLost(true); setOutcome(null); }
      setError(cause.message || 'Saved System diagnostic assessment unavailable.');
    } finally {
      if (activeRef.current === controller) { activeRef.current = null; setBusy(false); }
    }
  };

  if (!ready || !admitted(reference)) return null;
  return <section className="ss-card" aria-label="Admin System diagnostic assessment"
    style={{ padding: 12, marginTop: 10, border: '1px solid var(--rule)' }}>
    <strong>System diagnostic assessment</strong>
    {!accessLost && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={busy} onClick={() => void check(false)}>Check saved System diagnostic assessment</button>}
    {!accessLost && outcome?.status === 'unconfirmed' && !submittedRef.current &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={busy || locked} onClick={() => void check(true)}>Check System diagnostic objective</button>}
    {outcome?.status === 'unconfirmed' && <p role="status">Assessment not confirmed.</p>}
    {outcome?.status === 'ineligible' && <p role="status">This diagnostic is not eligible for objective credit.</p>}
    {outcome?.judgment && <p role="status">{outcome.judgment.verdict === 'unavailable'
      ? 'Grading unavailable. The saved diagnostic remains available.'
      : outcome.completed ? 'Objective completed.' : 'Assessment completed without objective credit.'}</p>}
    {outcome?.judgment?.verdict === 'unavailable' && isStandaloneShopFrame() &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={() => openStandaloneAssessments(outcome.judgment.evaluationId)}>
        Open saved assessments</button>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
