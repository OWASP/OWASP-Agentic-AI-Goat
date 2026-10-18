import React, { useEffect, useRef, useState } from 'react';
import { requireAgentContentType } from '../utils/agentStreamProtocol.mjs';
import { decodeRoleSystemDiagnosticProposal } from '../utils/roleSystemDiagnosticProposal.mjs';
import { decodeRoleSystemDiagnosticOutcome } from '../utils/roleSystemDiagnosticOutcome.mjs';
import { sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { adminSystemDiagnosticReferenceStore } from '../utils/adminSystemDiagnosticReference.mjs';
import AdminSystemDiagnosticAssessment from './AdminSystemDiagnosticAssessment.jsx';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const BASE = '/api/secureshop/agents/admin/assistant/system/diagnostic/confirm';
const sourcePath = (sessionId, requestId) =>
  `/api/secureshop/agents/admin/assistant/operations/${sessionId}/${requestId}`;
const savedPath = reference => `${BASE}/${reference.sessionId}/${reference.requestId}/${reference.proposalId}`;
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const sameReference = (left, right) => !!left && !!right
  && ['version', 'shopUserId', 'sessionId', 'requestId', 'proposalId', 'scopeKey',
    'proposalSha256', 'startedAt'].every(key => left[key] === right[key]);

function administration(value) {
  const item = value?.administration;
  if (value?.ok !== true || !item || Object.keys(item).sort().join(',')
    !== 'diagnosticCapability,modeCapability,scopeKey'
    || item.diagnosticCapability !== 'secureshop-owned-system-diagnostic.v1'
    || !/^[a-f0-9]{64}$/.test(item.scopeKey || '')
    || !sameRolePolicyMode(item.modeCapability, { version: 1,
      featureId: 'system_diagnostic', policyVersion: 'owned-system-diagnostic-shell-v1',
      effectiveMode: item.modeCapability?.effectiveMode,
      scope: { kind: 'launch_feature', id: 'system_diagnostic' } })
    || !['vuln', 'fixed'].includes(item.modeCapability?.effectiveMode)) {
    throw Error('System diagnostic authority unavailable.');
  }
  return item;
}

export default function AdminSystemDiagnosticConfirmation({ proposal = null,
  sessionId = null, requestId = null, shopUserId = null, authorityKey,
  transport = globalThis.fetch, locked = false,
  referenceStore = adminSystemDiagnosticReferenceStore }) {
  const [scope, setScope] = useState(null);
  const [pending, setPending] = useState(null);
  const [review, setReview] = useState(null);
  const [outcome, setOutcome] = useState(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [storageFault, setStorageFault] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), administrationSeqRef = useRef(0);
  const proposalKey = JSON.stringify([proposal?.proposalId || null,
    proposal?.proposalSha256 || null, sessionId, requestId]);
  const proposalKeyRef = useRef(proposalKey), lastProposalKeyRef = useRef(proposalKey);
  proposalKeyRef.current = proposalKey;

  useEffect(() => {
    const epoch = ++epochRef.current, controller = new AbortController();
    const administrationSeq = ++administrationSeqRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    setScope(null); setPending(null); setReview(null); setOutcome(null);
    setNotice(''); setBusy(false); setStorageFault(false);
    const current = () => epochRef.current === epoch && !controller.signal.aborted;
    Promise.resolve().then(async () => {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) return;
      const saved = referenceStore.read(shopUserId);
      if (!current()) return;
      if (saved) { setPending(saved); setNotice('A System diagnostic is saved. Check its exact outcome before another command.'); }
      const response = await transport('/api/secureshop/admin/system/diagnostic', { signal: controller.signal });
      if (!response.ok) throw Error('System diagnostic authority unavailable.');
      requireAgentContentType(response, 'application/json', 'System diagnostic authority');
      const currentScope = administration(await response.json());
      if (current() && administrationSeqRef.current === administrationSeq) setScope(currentScope);
    }).catch(error => {
      if (!current() || administrationSeqRef.current !== administrationSeq) return;
      if (/saved|storage/i.test(error.message)) setStorageFault(true);
      setNotice(error.message || 'System diagnostic authority unavailable.');
    });
    return () => { if (epochRef.current === epoch) epochRef.current++;
      controller.abort(); activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, shopUserId, transport, referenceStore]);

  useEffect(() => {
    if (lastProposalKeyRef.current === proposalKey) return;
    lastProposalKeyRef.current = proposalKey;
    if (!proposal) return;
    const epoch = epochRef.current, controller = new AbortController();
    const administrationSeq = ++administrationSeqRef.current;
    setScope(null);
    Promise.resolve().then(async () => {
      const response = await transport('/api/secureshop/admin/system/diagnostic',
        { signal: controller.signal });
      if (!response.ok) throw Error('System diagnostic authority unavailable.');
      requireAgentContentType(response, 'application/json', 'System diagnostic authority');
      const currentScope = administration(await response.json());
      if (!controller.signal.aborted && epochRef.current === epoch
        && administrationSeqRef.current === administrationSeq) setScope(currentScope);
    }).catch(error => {
      if (!controller.signal.aborted && epochRef.current === epoch
        && administrationSeqRef.current === administrationSeq)
        setNotice(error.message || 'System diagnostic authority unavailable.');
    });
    return () => controller.abort();
  }, [proposalKey, transport]);

  const readSource = async (reference, signal) => {
    const response = await transport(sourcePath(reference.sessionId, reference.requestId), { signal });
    if (!response.ok) throw Error('Saved diagnostic proposal unavailable. No command was sent.');
    requireAgentContentType(response, 'application/json', 'Saved diagnostic proposal');
    const value = await response.json();
    const candidate = await decodeRoleSystemDiagnosticProposal(value.systemDiagnosticProposal);
    if (!candidate || value.sessionId !== reference.sessionId || value.requestId !== reference.requestId
      || value.status !== 'completed' || value.replayed !== true || value.stopReason !== 'end_turn'
      || candidate.proposalId !== reference.proposalId
      || candidate.scopeKey !== reference.scopeKey
      || candidate.proposalSha256 !== reference.proposalSha256) {
      throw Error('Saved diagnostic proposal changed. No command was sent.');
    }
    return candidate;
  };

  const readOperation = async (reference, candidate, signal) => {
    const response = await transport(savedPath(reference), { signal });
    if (![200, 202].includes(response.status)) throw Error(`Saved diagnostic lookup failed (${response.status})`);
    requireAgentContentType(response, 'application/json', 'Saved diagnostic outcome');
    const value = await response.json();
    const original = await decodeRoleSystemDiagnosticProposal(value.proposal);
    if (!original || original.proposalId !== reference.proposalId
      || original.scopeKey !== reference.scopeKey
      || original.proposalSha256 !== reference.proposalSha256
      || (candidate && !same(original, candidate))) {
      throw Error('Saved diagnostic source changed. No command was sent.');
    }
    const { proposal: ignored, ...operation } = value;
    return { proposal: original, outcome: await decodeRoleSystemDiagnosticOutcome(operation, original) };
  };

  const run = async confirm => {
    if (activeRef.current || !Number.isSafeInteger(shopUserId) || shopUserId < 1) return;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setBusy(true); setNotice('');
    const sourceKey = proposalKeyRef.current;
    let sourceUncommitted = false;
    const authorityCurrent = () => epochRef.current === epoch && activeRef.current === controller
      && !controller.signal.aborted;
    const current = () => authorityCurrent()
      && (!sourceUncommitted || proposalKeyRef.current === sourceKey);
    let saved;
    try {
      if (storageFault) throw Error('Saved System diagnostic state is unavailable.');
      saved = referenceStore.read(shopUserId);
      if (!current()) return;
      if (saved && confirm) {
        setPending(saved);
        confirm = false;
      }
      if (!saved) {
        if (!confirm || locked || !proposal || !scope || !UUID.test(sessionId || '')
          || !UUID.test(requestId || '')) return;
        sourceUncommitted = true;
        const candidate = await decodeRoleSystemDiagnosticProposal(proposal);
        if (!current()) return;
        if (candidate.scopeKey !== scope.scopeKey
          || !sameRolePolicyMode(candidate.modeCapability, scope.modeCapability)) {
          throw Error('Diagnostic mode or shop scene changed. Request a fresh review.');
        }
        saved = { shopUserId, sessionId, requestId, proposalId: candidate.proposalId,
          scopeKey: candidate.scopeKey, proposalSha256: candidate.proposalSha256,
          startedAt: Date.now() };
        const original = await readSource(saved, controller.signal);
        if (!current() || !same(original, candidate)) return;
        saved = await referenceStore.save(saved, current);
        if (!authorityCurrent()) return;
        setPending(saved); setReview(candidate);
        if (!current()) return;
      }
      if (!scope || scope.scopeKey !== saved.scopeKey) {
        throw Error('Saved System diagnostic belongs to another shop scene.');
      }
      if (!sameReference(referenceStore.read(shopUserId), saved)) {
        throw Error('Saved System diagnostic reference changed. No command was sent.');
      }
      let candidate = null;
      if (confirm) {
        candidate = await readSource(saved, controller.signal);
        if (!current()) return;
        if (!sameRolePolicyMode(candidate.modeCapability, scope.modeCapability)) {
          throw Error('Diagnostic mode changed. The saved command will not be repeated.');
        }
      }
      let readback = await readOperation(saved, candidate, controller.signal);
      if (!current()) return;
      candidate = readback.proposal;
      setReview(candidate);
      let result = readback.outcome;
      if (result.state === 'not_found' && confirm) {
        if (!sameReference(referenceStore.read(shopUserId), saved)) {
          throw Error('Saved System diagnostic reference changed. No command was sent.');
        }
        let fixedDenied = false;
        try {
          const response = await transport(BASE, { method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId,
              proposalId: saved.proposalId }), signal: controller.signal });
          if (response.status === 403) {
            requireAgentContentType(response, 'application/json', 'Fixed diagnostic denial');
            const denied = await response.json();
            fixedDenied = denied?.code === 'SYSTEM_DIAGNOSTIC_FIXED_DENIED';
          }
        } catch { /* Only protected saved GET settles a possibly committed command. */ }
        if (!current()) return;
        readback = await readOperation(saved, candidate, controller.signal);
        if (!current()) return;
        result = readback.outcome;
        if (fixedDenied && result.state === 'not_found') {
          await referenceStore.clear(saved, current);
          if (!current()) return;
          setPending(null); setOutcome(null);
          setNotice('Fixed mode denied this diagnostic before execution.');
          return;
        }
      }
      setOutcome(result);
      setNotice(result.state === 'completed' ? 'System diagnostic completed. The saved receipt was verified.'
        : result.state === 'not_executed' ? 'Diagnostic was not executed. No command was repeated.'
          : 'Diagnostic outcome is unresolved. Check the saved operation; no command was repeated.');
    } catch (error) {
      if (authorityCurrent()) {
        try { setPending(referenceStore.read(shopUserId) || (current() ? saved : null)); }
        catch { setStorageFault(true); }
        if (current()) setNotice(error.message || 'System diagnostic outcome unavailable.');
      }
    } finally {
      if (activeRef.current === controller) { activeRef.current = null; setBusy(false); }
    }
  };

  const dismiss = async () => {
    if (busy || storageFault || !['completed', 'not_executed'].includes(outcome?.state)
      || !Number.isSafeInteger(shopUserId) || shopUserId < 1) return;
    const epoch = epochRef.current;
    try {
      const saved = referenceStore.read(shopUserId);
      if (!sameReference(saved, pending)) throw Error('Saved System diagnostic reference changed.');
      await referenceStore.clear(saved, () => !activeRef.current
        && epochRef.current === epoch);
      if (epochRef.current !== epoch) return;
      setPending(null); setReview(null); setOutcome(null); setNotice('');
    } catch (error) { setStorageFault(true); setNotice(error.message); }
  };

  if (!proposal && !pending && !outcome && !notice) return null;
  return <section className="ss-card" aria-label="Admin System diagnostic confirmation"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {!pending && proposal && <>
      <h3 style={{ fontFamily: 'var(--display)', margin: '4px 0 10px' }}>Review proposed System diagnostic</h3>
      <p>The assistant proposed this exact isolated command. Inspect both fields before confirming. Nothing ran during preparation.</p>
      <p>Command template</p><pre className="ss-mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{proposal.cmd_template}</pre>
      <p>Arguments</p><pre className="ss-mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{proposal.args}</pre>
      <p>Constructed command</p><pre className="ss-mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{`${proposal.cmd_template} ${proposal.args}`}</pre>
      <button className="ss-btn ss-btn--sm" type="button"
        disabled={busy || locked || storageFault || !scope || scope.scopeKey !== proposal.scopeKey}
        onClick={() => void run(true)}>Confirm System diagnostic</button>
    </>}
    {pending && <>
      {review && <p>Saved command: <code>{`${review.cmd_template} ${review.args}`}</code></p>}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={busy || storageFault || !scope} onClick={() => void run(false)}>
        Check saved System diagnostic
      </button>
    </>}
    {outcome?.state === 'completed' && <>
      <p>Exit code: {outcome.exitCode === null ? `signal ${outcome.signal}` : outcome.exitCode}</p>
      <p>Standard output</p><pre className="ss-mono" style={{ maxHeight: 240, overflow: 'auto',
        whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{outcome.stdout}</pre>
      <p>Standard error</p><pre className="ss-mono" style={{ maxHeight: 240, overflow: 'auto',
        whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{outcome.stderr}</pre>
    </>}
    <AdminSystemDiagnosticAssessment reference={pending}
      ready={outcome?.state === 'completed'} authorityKey={authorityKey}
      transport={transport} locked={locked || busy || storageFault} />
    {pending && ['completed', 'not_executed'].includes(outcome?.state) &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={busy || storageFault} onClick={() => void dismiss()}>Close saved diagnostic</button>}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
