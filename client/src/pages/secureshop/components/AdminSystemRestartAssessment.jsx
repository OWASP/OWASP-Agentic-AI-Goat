import React, { useEffect, useRef, useState } from 'react';
import { requireAgentContentType } from '../utils/agentStreamProtocol.mjs';
import { decodeRoleSystemRestartProposal } from '../utils/roleSystemRestartProposal.mjs';
import { sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { verifiedRestartResult } from '../pages/admin/systemRestartOperation.mjs';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';
import { readRoleAssistantCompletedReference, markRoleAssistantRestartAssessmentAttempted } from '../utils/roleAssistantCompletedReferences.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const BASE = '/api/secureshop/agents/admin/assistant/system/restart';
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const admitted = (proposal, sessionId, requestId, administration) => proposal
  && UUID.test(sessionId || '') && UUID.test(requestId || '')
  && administration?.targetId && administration?.scopeKey;

export function decodeSystemRestartAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
    && value.modelEvaluated === false && ['ineligible', 'unconfirmed'].includes(value.status)) return value;
  if (exact(value, ['completed', 'judgment', 'replayed']) && typeof value.completed === 'boolean'
    && typeof value.replayed === 'boolean'
    && exact(value.judgment, ['verdict', 'evaluationId', 'canRetry'])
    && ['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    && UUID.test(value.judgment.evaluationId || '')
    && typeof value.judgment.canRetry === 'boolean'
    && (!value.completed || value.judgment.verdict === 'pass')) return value;
  throw Error('Saved System restart assessment unavailable.');
}

export default function AdminSystemRestartAssessment({ proposal = null, sessionId = null,
  requestId = null, administration = null, shopUserId = null, authorityKey, transport = globalThis.fetch,
  readOperation, operationState = null, locked = false }) {
  const [ready, setReady] = useState(false), [outcome, setOutcome] = useState(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [accessLost, setAccessLost] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), submittedRef = useRef(false);
  const sourceKey = JSON.stringify([proposal?.proposalId, proposal?.proposalSha256,
    sessionId, requestId, shopUserId, administration?.targetId, administration?.scopeKey]);
  const source = async signal => {
    const saved = readRoleAssistantCompletedReference('admin', shopUserId);
    if (!saved || saved.sessionId !== sessionId || saved.requestId !== requestId)
      throw Error('Saved restart source changed.');
    const candidate = await decodeRoleSystemRestartProposal(proposal);
    if (!candidate || candidate.targetId !== administration.targetId
      || candidate.scopeKey !== administration.scopeKey) throw Error('Saved restart source changed.');
    const response = await transport(`/api/secureshop/agents/admin/assistant/operations/${sessionId}/${requestId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) { await response.text(); throw Object.assign(Error('Saved restart source unavailable.'), { status: response.status }); }
    requireAgentContentType(response, 'application/json', 'Saved restart source');
    const value = await response.json();
    const original = await decodeRoleSystemRestartProposal(value.systemRestartProposal);
    if (value.sessionId !== sessionId || value.requestId !== requestId || value.status !== 'completed'
      || value.replayed !== true || value.stopReason !== 'end_turn'
      || !sameRolePolicyMode(value.modeCapability, candidate.modeCapability)
      || !same(original, candidate)) throw Error('Saved restart source changed.');
    const operation = await readOperation(candidate.proposalId, signal);
    const verified = await verifiedRestartResult(operation, { operationId: candidate.proposalId },
      candidate.targetId, candidate.requestSha256);
    if (verified.state !== 'completed') throw Error('Saved restart is not complete.');
    return candidate;
  };
  useEffect(() => {
    const epoch = ++epochRef.current, controller = new AbortController();
    activeRef.current?.abort(); activeRef.current = null; submittedRef.current = false;
    setReady(false); setOutcome(null); setBusy(false); setError(''); setAccessLost(false);
    if (admitted(proposal, sessionId, requestId, administration)
      && typeof readOperation === 'function') Promise.resolve().then(() => source(controller.signal))
      .then(() => { if (epochRef.current === epoch && !controller.signal.aborted) {
        submittedRef.current = readRoleAssistantCompletedReference('admin', shopUserId)?.restartAssessmentAttempted === true;
        setReady(true);
      } })
      .catch(() => { if (epochRef.current === epoch && !controller.signal.aborted) setReady(false); });
    return () => { if (epochRef.current === epoch) epochRef.current++;
      controller.abort(); activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, sourceKey, transport, readOperation, operationState]);

  const check = async start => {
    if (!ready || !admitted(proposal, sessionId, requestId, administration)
      || activeRef.current || accessLost || (start && (locked || submittedRef.current
        || outcome?.status !== 'unconfirmed'))) return;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setBusy(true); setError('');
    const current = () => epochRef.current === epoch && activeRef.current === controller
      && !controller.signal.aborted;
    try {
      await source(controller.signal);
      if (!current()) return;
      if (start) {
        const saved = readRoleAssistantCompletedReference('admin', shopUserId);
        if (!saved || saved.sessionId !== sessionId || saved.requestId !== requestId)
          throw Error('Saved restart source changed.');
        await markRoleAssistantRestartAssessmentAttempted(saved, current);
        if (!current()) return;
        submittedRef.current = true;
        try {
          const response = await transport(`${BASE}/assess`, { method: 'POST',
            headers: { accept: 'application/json', 'content-type': 'application/json' },
            body: JSON.stringify({ sessionId, requestId }), signal: controller.signal });
          await response.text();
        } catch { /* The exact saved GET settles uncertain assessment admission. */ }
      }
      if (!current()) return;
      const response = await transport(`${BASE}/assessment/${sessionId}/${requestId}`,
        { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!response.ok) { await response.text(); throw Object.assign(Error('Saved System restart assessment unavailable.'),
        { status: response.status }); }
      requireAgentContentType(response, 'application/json', 'Saved System restart assessment');
      const value = decodeSystemRestartAssessment(await response.json());
      if (current()) setOutcome(value);
    } catch (cause) {
      if (!current()) return;
      if ([401, 403].includes(cause.status)) { setAccessLost(true); setOutcome(null); }
      setError(cause.message || 'Saved System restart assessment unavailable.');
    } finally {
      if (activeRef.current === controller) { activeRef.current = null; setBusy(false); }
    }
  };

  if (!ready) return null;
  return <section className="ss-card" aria-label="Admin System restart assessment"
    style={{ padding: 12, marginTop: 10, border: '1px solid var(--rule)' }}>
    <strong>System restart assessment</strong>
    {!accessLost && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={busy} onClick={() => void check(false)}>Check saved System restart assessment</button>}
    {!accessLost && outcome?.status === 'unconfirmed' && !submittedRef.current && <button className="ss-btn ss-btn--ghost ss-btn--sm"
        type="button" disabled={busy || locked} onClick={() => void check(true)}>
        Assess System restart
      </button>}
    {outcome?.status === 'unconfirmed' && <p role="status">Assessment not confirmed. The saved restart remains available.</p>}
    {outcome?.status === 'ineligible' && <p role="status">This restart is not eligible for objective credit.</p>}
    {outcome?.judgment && <p role="status">{outcome.judgment.verdict === 'unavailable'
      ? 'Grading unavailable. The saved restart remains available.'
      : outcome.completed ? 'Objective completed.' : 'Assessment completed without objective credit.'}</p>}
    {outcome?.judgment?.verdict === 'unavailable' && isStandaloneShopFrame()
      && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={() => openStandaloneAssessments(outcome.judgment.evaluationId)}>
        Open saved assessments</button>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
