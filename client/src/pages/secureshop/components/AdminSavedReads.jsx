import React, { useEffect, useRef, useState } from 'react';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';
import { requireAgentContentType } from '../utils/agentStreamProtocol.mjs';

const pre = { maxHeight: 280, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
  border: '1px solid var(--rule)', borderRadius: 8, padding: 12 };

const lookupBase = '/api/secureshop/agents/admin/assistant';
const lookupUuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exactLookup = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
export function decodeUserLookupAssessment(value) {
  if (exactLookup(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
    && value.modelEvaluated === false && ['ineligible', 'unconfirmed', 'pending'].includes(value.status)) return value;
  if (exactLookup(value, ['completed', 'judgment', 'replayed']) && typeof value.completed === 'boolean'
    && typeof value.replayed === 'boolean'
    && exactLookup(value.judgment, ['evaluationId', 'verdict', 'canRetry'])
    && lookupUuid.test(value.judgment.evaluationId || '')
    && ['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    && typeof value.judgment.canRetry === 'boolean'
    && (!value.completed || value.judgment.verdict === 'pass')) return value;
  throw Error('Saved user lookup assessment unavailable.');
}

export function AdminUserLookup({ read, reference, authorityKey, transport = globalThis.fetch, locked = false }) {
  const [outcome, setOutcome] = useState(null), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [accessLost, setAccessLost] = useState(false);
  const epoch = useRef(0), active = useRef(null), submitted = useRef(false);
  const sessionId = reference?.sessionId, requestId = reference?.requestId;
  const ready = read?.assessmentReady === true;
  useEffect(() => {
    ++epoch.current; active.current?.abort(); active.current = null; submitted.current = false;
    setOutcome(null); setBusy(false); setError(''); setAccessLost(false);
    return () => { ++epoch.current; active.current?.abort(); active.current = null; };
  }, [sessionId, requestId, authorityKey, transport, ready]);
  const check = async start => {
    if (!ready || active.current || accessLost || !lookupUuid.test(sessionId || '')
      || !lookupUuid.test(requestId || '') || start && (locked || submitted.current
        || outcome?.status !== 'unconfirmed')) return;
    const captured = epoch.current, controller = new AbortController(); active.current = controller;
    const current = () => epoch.current === captured && active.current === controller && !controller.signal.aborted;
    setBusy(true); setError('');
    try {
      if (start) {
        submitted.current = true;
        // A lost acknowledgement is recovered by GET, never by repeating the lookup or assessment POST.
        try { await transport(`${lookupBase}/user-lookup/assess`, { method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json' },
          body: JSON.stringify({ sessionId, requestId }), signal: controller.signal }); }
        catch { /* The exact protected GET resolves an uncertain acknowledgement. */ }
      }
      if (!current()) return;
      const response = await transport(`${lookupBase}/sessions/${sessionId}/requests/${requestId}/user-lookup/assessment`,
        { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!current()) return;
      if (!response.ok) {
        const cause = Error(`Saved user lookup assessment unavailable (HTTP ${response.status}).`);
        cause.status = response.status; throw cause;
      }
      requireAgentContentType(response, 'application/json', 'Saved user lookup assessment');
      const value = decodeUserLookupAssessment(await response.json());
      if (current()) setOutcome(value);
    } catch (cause) {
      if (!current()) return;
      setOutcome(null);
      if ([401, 403].includes(cause.status)) setAccessLost(true);
      setError(cause.message || 'Saved user lookup assessment unavailable.');
    } finally {
      if (active.current === controller) { active.current = null; setBusy(false); }
    }
  };
  if (!read) return null;
  return <section className="ss-card" aria-label="Admin user lookup result"
    style={{ padding: 12, marginTop: 10, overflowWrap: 'anywhere' }}>
    <strong>Saved user lookup · {read.username}</strong>
    <p>{read.status === 'complete' ? 'The isolated synthetic record was read. The original assistant reply is shown above.'
      : read.status === 'redacted' ? 'Sensitive teaching fields were withheld in Fixed mode.'
        : 'No matching teaching record was found.'}</p>
    {ready && !accessLost && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={busy} onClick={() => void check(false)}>Check saved user lookup assessment</button>}
    {ready && !accessLost && outcome?.status === 'unconfirmed' && !submitted.current &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy || locked}
        onClick={() => void check(true)}>Check user lookup objective</button>}
    {outcome?.status === 'unconfirmed' && <p role="status">Assessment not confirmed.</p>}
    {outcome?.status === 'pending' && <p role="status">Assessment is pending. Check its saved status without submitting it again.</p>}
    {outcome?.status === 'ineligible' && <p role="status">This saved lookup is not eligible for objective credit.</p>}
    {outcome?.judgment && <p role="status">{outcome.judgment.verdict === 'unavailable'
      ? 'Grading unavailable. The saved lookup remains available.'
      : outcome.completed ? 'User lookup objective completed.' : 'Assessment recorded without objective credit.'}</p>}
    {outcome?.judgment && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      onClick={() => openStandaloneAssessments(outcome.judgment.evaluationId)}>
      {isStandaloneShopFrame() ? 'Open saved assessments' : 'Saved assessment available'}</button>}
    {error && <p role="alert">{error}</p>}
  </section>;
}

export function AdminAuditSearch({ read }) {
  const [visible, setVisible] = useState(20);
  useEffect(() => setVisible(20), [read]);
  if (!read) return null;
  if (read.blocked) return <section className="ss-card" aria-label="Admin audit SQL result"
    style={{ padding: 12, marginTop: 10 }}><strong>Audit SQL read blocked</strong>
    <p>{read.reason}</p></section>;
  return <section className="ss-card" aria-label="Admin audit SQL result"
    style={{ padding: 12, marginTop: 10, overflowWrap: 'anywhere' }}>
    <strong>Saved audit SQL result</strong>
    <p>{read.ok ? 'Query completed.' : 'Query returned an error.'}
      {' '}Showing {Math.min(visible, read.events.length)} of {read.count} saved rows.</p>
    {read.error && <p role="status">{read.error}</p>}
    <details><summary>Saved query</summary><pre style={pre}>{read.sql}</pre></details>
    {read.events.slice(0, visible).map((row, index) => <pre key={index} style={pre}
      data-testid="saved-audit-sql-row">{JSON.stringify(row, null, 2)}</pre>)}
    {visible < read.events.length && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
      onClick={() => setVisible(current => Math.min(current + 20, read.events.length))}>
      Show more saved rows</button>}
  </section>;
}

export function AdminSystemHealth({ read }) {
  if (!read) return null;
  return <section className="ss-card" aria-label="Admin System health"
    style={{ padding: 12, marginTop: 10, overflowWrap: 'anywhere' }}>
    <strong>System health at {read.ts}</strong>
    <p>{read.hostname} · {read.platform} · Node {read.node}</p>
    <p>Uptime: {read.uptime_s} seconds · Free memory: {read.freemem_mb ?? 'Unavailable'} MB
      {' · '}Total memory: {read.totalmem_mb ?? 'Unavailable'} MB</p>
  </section>;
}

function SystemConfigAssessment({ reference, onCheck }) {
  const [state, setState] = useState({ kind: 'ready' });
  useEffect(() => { setState({ kind: 'ready' }); }, [reference?.sessionId, reference?.requestId, onCheck]);
  if (!reference || typeof onCheck !== 'function') return null;
  const check = async () => {
    if (state.kind === 'checking') return;
    setState({ kind: 'checking' });
    const result = await onCheck(reference);
    setState(result?.kind === 'stale' ? { kind: 'error', message: 'The saved System read changed. Check the current saved result.' }
      : result || { kind: 'error', message: 'Saved System assessment unavailable.' });
  };
  const judgment = state.kind === 'judgment' ? state.judgment : null;
  const unavailable = judgment?.verdict === 'unavailable';
  return <div style={{ marginTop: 10 }}>
    <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={check}
      disabled={state.kind === 'checking'}>
      {state.kind === 'checking' ? 'Checking saved System assessment…' : 'Check saved System assessment'}
    </button>
    {state.kind === 'ready' && <p role="status">Assessment pending. This checks the saved read without running chat or reading configuration again.</p>}
    {state.kind === 'ineligible' && <p role="status">This saved System read is not eligible for objective credit.</p>}
    {state.kind === 'error' && <p role="status">{state.message}</p>}
    {judgment && <p role="status">{unavailable
      ? 'Grading unavailable. The saved System read remains available.'
      : state.completed === true && judgment.verdict === 'pass' ? 'Objective completed.'
        : 'Assessment completed without awarding objective credit.'}</p>}
    {unavailable && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
      onClick={() => openStandaloneAssessments(judgment.evaluationId)}
      data-testid="open-saved-system-assessments">
      {isStandaloneShopFrame() ? 'Open saved assessments' : 'Saved assessment available'}
    </button>}
  </div>;
}

function PolicyInstructionAssessment({ reference, onCheck }) {
  const [state, setState] = useState({ kind: 'ready' });
  useEffect(() => { setState({ kind: 'ready' }); }, [reference?.sessionId, reference?.requestId, onCheck]);
  if (!reference || typeof onCheck !== 'function') return null;
  const check = async () => {
    if (state.kind === 'checking') return;
    setState({ kind: 'checking' });
    const result = await onCheck(reference);
    setState(result?.kind === 'stale' ? { kind: 'error', message: 'The saved policy instruction read changed. Check the current saved result.' }
      : result || { kind: 'error', message: 'Saved policy instruction assessment unavailable.' });
  };
  const judgment = state.kind === 'judgment' ? state.judgment : null;
  const unavailable = judgment?.verdict === 'unavailable';
  return <div style={{ marginTop: 10 }} aria-label="Saved policy instruction assessment">
    <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={check}
      disabled={state.kind === 'checking'}>
      {state.kind === 'checking' ? 'Checking saved policy instruction assessment…' : 'Check saved policy instruction assessment'}
    </button>
    {state.kind === 'ready' && <p role="status">Check whether this saved read has a policy instruction assessment. This does not rerun chat or read configuration again.</p>}
    {state.kind === 'ineligible' && <p role="status">This saved read is not eligible for policy instruction objective credit.</p>}
    {state.kind === 'error' && <p role="status">{state.message}</p>}
    {judgment && <p role="status">{unavailable
      ? 'Grading unavailable. The saved read remains available.'
      : state.completed === true && judgment.verdict === 'pass' ? 'Policy instruction objective completed.'
        : 'Policy instruction assessment completed without awarding objective credit.'}</p>}
    {unavailable && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
      onClick={() => openStandaloneAssessments(judgment.evaluationId)}>
      {isStandaloneShopFrame() ? 'Open saved assessments' : 'Saved assessment available'}
    </button>}
  </div>;
}

export function AdminSystemConfigRead({ read, reference = null, onCheck = null, onCheckPolicy = null }) {
  if (!read) return null;
  return <section className="ss-card" aria-label="Admin System config result"
    style={{ padding: 12, marginTop: 10, overflowWrap: 'anywhere' }}>
    <strong>Saved System config read</strong>
    {read.kind === 'content' ? <>
      <p>Read {read.size} bytes from the saved operation.</p>
      <pre style={pre} data-testid="saved-system-config-content">{read.content}</pre>
      <SystemConfigAssessment reference={reference} onCheck={onCheck} />
      <PolicyInstructionAssessment reference={reference} onCheck={onCheckPolicy} />
    </> : <p role="status">{read.kind === 'unavailable'
      ? 'System config read unavailable.' : read.error}</p>}
  </section>;
}
