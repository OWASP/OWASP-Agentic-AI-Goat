import React, { useEffect, useRef, useState } from 'react';
import { requireAgentContentType } from '../utils/agentStreamProtocol.mjs';
import { sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { decodeRoleAuditJobProposal, decodeAuditJobOperation } from '../utils/roleAuditJob.mjs';
import { readAuditJobReference, saveAuditJobReference, assertAuditJobReference,
  clearAuditJobReference } from '../utils/auditJobReference.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export default function AdminAuditJobConfirmation({ proposal = null, sessionId = null,
  requestId = null, authorityKey, transport = globalThis.fetch, locked = false, onOutcomeChange }) {
  const [pending, setPending] = useState(null), [outcome, setOutcome] = useState(null);
  const [notice, setNotice] = useState(''), [busy, setBusy] = useState(false);
  const [storageFault, setStorageFault] = useState(false);
  const epoch = useRef(0), active = useRef(null);
  const sourceKey = JSON.stringify([sessionId, requestId, proposal]);
  const sourceKeyRef = useRef(sourceKey), previousSourceKey = useRef(sourceKey);
  sourceKeyRef.current = sourceKey;
  useEffect(() => { onOutcomeChange?.(value => value + 1); }, [pending, outcome, notice, onOutcomeChange]);
  useEffect(() => {
    const generation = ++epoch.current;
    active.current?.abort(); active.current = null;
    setPending(null); setOutcome(null); setNotice(''); setBusy(false); setStorageFault(false);
    try {
      const saved = readAuditJobReference();
      if (saved) { setPending(saved); setNotice('A saved audit job needs an exact result check.'); }
    } catch { setStorageFault(true); setNotice('Saved audit job reference is unavailable.'); }
    return () => { if (epoch.current === generation) epoch.current += 1;
      active.current?.abort(); active.current = null; };
  }, [authorityKey, transport]);
  useEffect(() => {
    if (previousSourceKey.current === sourceKey) return;
    previousSourceKey.current = sourceKey;
    // Hydrating the visible source is not an authority change. In-flight and
    // retained operations continue to use their own exact saved reference.
    if (!active.current && !pending) { setOutcome(null); setNotice(''); }
  }, [sourceKey, pending]);

  const run = async confirm => {
    if (active.current) return;
    const generation = epoch.current, controller = new AbortController();
    active.current = controller; setBusy(true); setNotice('');
    const originalSourceKey = sourceKeyRef.current;
    let sourceSensitive = false;
    const authorityCurrent = () => epoch.current === generation && active.current === controller
      && !controller.signal.aborted && globalThis.fetch === transport;
    const current = () => authorityCurrent()
      && (!sourceSensitive || sourceKeyRef.current === originalSourceKey);
    let saved = null, verified = null;
    const source = async reference => {
      const response = await transport(`/api/secureshop/agents/admin/assistant/operations/`
        + `${reference.sourceSessionId}/${reference.sourceRequestId}`, { signal: controller.signal });
      if (!response.ok) throw Error(response.status === 401 || response.status === 403
        ? 'Return to the original shop scene to check this saved audit job.'
        : `Saved audit review unavailable (${response.status}).`);
      requireAgentContentType(response, 'application/json', 'Saved audit review');
      const value = await response.json();
      if (!current()) return null;
      if (value.sessionId !== reference.sourceSessionId
        || value.requestId !== reference.sourceRequestId || value.status !== 'completed'
        || value.replayed !== true || value.stopReason !== 'end_turn'
        || !sameRolePolicyMode(value.modeCapability, { version: 1,
          featureId: 'admin_assistant', policyVersion: 'owned-admin-read-and-confirmation-v1',
          effectiveMode: value.modeCapability?.effectiveMode,
          scope: { kind: 'launch_feature', id: 'admin_assistant' } })) {
        throw Error('Saved audit review changed. No job was run.');
      }
      const candidate = await decodeRoleAuditJobProposal(value.auditJobProposal,
        reference.sourceSessionId, reference.sourceRequestId);
      if (!candidate || candidate.scopeKey !== reference.scopeKey
        || candidate.proposalId !== reference.proposalId
        || candidate.sessionId !== reference.jobSessionId
        || candidate.requestId !== reference.jobRequestId
        || candidate.requestSha256 !== reference.requestSha256) {
        throw Error('Saved audit review changed. No job was run.');
      }
      return candidate;
    };
    const read = async reference => {
      const response = await transport(`/api/secureshop/agents/admin/assistant/audit/job/operations/`
        + `${reference.sourceSessionId}/${reference.sourceRequestId}/${reference.proposalId}`,
      { signal: controller.signal });
      if (!response.ok && response.status !== 202) throw Error(response.status === 401
        || response.status === 403 ? 'Return to the original shop scene to check this saved audit job.'
        : `Saved audit result unavailable (${response.status}).`);
      requireAgentContentType(response, 'application/json', 'Saved audit result');
      return response.json();
    };
    const finish = async (reference, candidate, value) => {
      if (!current()) return;
      const result = await decodeAuditJobOperation(candidate, value);
      if (!current()) return;
      assertAuditJobReference(reference);
      if (result.status !== 'completed') {
        setPending(reference);
        setNotice('Audit result is unconfirmed. Check the saved job; Run will not be repeated.');
        return;
      }
      verified = result.result;
      setOutcome(result.result);
      await clearAuditJobReference(reference, current);
      if (!current()) return;
      setPending(null);
      setNotice('Saved audit result verified. This does not claim an assessment or objective credit.');
    };
    try {
      if (storageFault) throw Error('Saved audit job reference is unavailable.');
      saved = readAuditJobReference();
      if (saved) {
        setPending(saved);
        const candidate = await source(saved);
        if (!current()) return;
        assertAuditJobReference(saved);
        await finish(saved, candidate, await read(saved));
        return;
      }
      if (!confirm || locked || !proposal || !UUID.test(sessionId || '') || !UUID.test(requestId || '')) return;
      sourceSensitive = true;
      const candidate = await decodeRoleAuditJobProposal(proposal, sessionId, requestId);
      if (!current()) return;
      const reference = { version: 1, scopeKey: candidate.scopeKey,
        sourceSessionId: sessionId, sourceRequestId: requestId, proposalId: candidate.proposalId,
        jobSessionId: candidate.sessionId, jobRequestId: candidate.requestId,
        requestSha256: candidate.requestSha256 };
      const actual = await source(reference);
      if (!current()) return;
      if (!same(candidate, actual)) throw Error('Saved audit review changed. No job was run.');
      saved = await saveAuditJobReference(reference, current);
      if (!authorityCurrent()) return;
      assertAuditJobReference(saved); setPending(saved);
      if (!current()) return;
      const prior = await decodeAuditJobOperation(candidate, await read(saved));
      if (!current()) return;
      if (prior.status !== 'not_found') {
        await finish(saved, candidate, { version: 1, kind: 'audit_job', action: candidate.action,
          sessionId: candidate.sessionId, requestId: candidate.requestId,
          status: prior.status, result: prior.result });
        return;
      }
      assertAuditJobReference(saved);
      // Once dispatch starts, source-card hydration cannot authorize another
      // action or suppress readback of this exact saved operation.
      sourceSensitive = false;
      try {
        await transport('/api/secureshop/agents/admin/assistant/audit/job/run', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId, requestId, proposalId: candidate.proposalId }),
          signal: controller.signal,
        });
      } catch { /* The exact job GET settles even a lost POST acknowledgment. */ }
      if (!current()) return;
      await finish(saved, candidate, await read(saved));
    } catch (error) {
      if (!authorityCurrent()) return;
      try {
        const retained = readAuditJobReference();
        setPending(retained || (verified || !current() ? null : saved));
      } catch { setStorageFault(true); setPending(verified || !current() ? null : saved); }
      if (current()) setNotice(error.message || 'Saved audit result unavailable. Check the saved job.');
    } finally { if (active.current === controller) { active.current = null; setBusy(false); } }
  };

  const visible = proposal || pending || outcome || notice;
  if (!visible) return null;
  return <section className="ss-card" aria-label="Admin audit job review"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {proposal && !pending && !outcome && <>
      <h3>Review audit Run</h3>
      <p>{proposal.action === 'agent' ? 'Run a saved audit question' : 'Run a saved audit summary'}
        {' '}after your confirmation.</p>
      <p>{proposal.action === 'agent' ? proposal.input.message
        : `Review up to ${proposal.input.requestedCount} saved audit records.`}</p>
      <button className="ss-btn ss-btn--sm" type="button" disabled={busy || locked || storageFault}
        onClick={() => void run(true)}>Run audit job</button>
    </>}
    {pending && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={busy || storageFault} onClick={() => void run(false)}>Check saved audit job</button>}
    {notice && <p role="status">{notice}</p>}
    {outcome && <div aria-label="Saved audit job result">
      <strong>{proposal?.action === 'summary' || Object.hasOwn(outcome, 'summary')
        ? 'Audit summary' : 'Audit response'}</strong>
      <pre style={{ maxHeight: 320, overflow: 'auto', whiteSpace: 'pre-wrap',
        overflowWrap: 'anywhere' }}>{outcome.summary || outcome.text}</pre>
      <p>Model: {outcome.provider} · {outcome.model}</p>
      {outcome.evidence ? <>
        <p>Verified source trace</p>
        <ol>{outcome.evidence.trace.map(step => <li key={step.step}>
          {step.phase} · {step.provider} · {step.model} · {step.tool || 'final response'}
        </li>)}</ol>
        <details><summary>Source fingerprints</summary>
          <pre style={{ overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' }}>
            {JSON.stringify(outcome.evidence, null, 2)}</pre>
        </details>
      </> : <p>No verified model trace was saved for this result.</p>}
      {outcome.assessment && <p>Assessment: {outcome.assessment.judgment?.verdict
        || 'See saved assessment'}{Object.hasOwn(outcome, 'objectiveCredit')
          ? ` · objective credit ${outcome.objectiveCredit ? 'recorded' : 'not recorded'}` : ''}</p>}
    </div>}
  </section>;
}
