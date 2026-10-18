import React, { useEffect, useRef, useState } from 'react';
import { requireAgentContentType } from '../utils/agentStreamProtocol.mjs';
import AdminSystemRestartAssessment from './AdminSystemRestartAssessment.jsx';
import { decodeRoleSystemRestartProposal } from '../utils/roleSystemRestartProposal.mjs';
import { sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { restartAdministration, restartHash, verifiedRestartResult } from '../pages/admin/systemRestartOperation.mjs';
import { readSystemRestartReferences, saveSystemRestartReference,
  forgetSystemRestartReference } from '../pages/admin/systemRestartRecovery.js';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const sameRef = (left, right) => left?.scopeKey === right?.scopeKey
  && left?.operationId === right?.operationId && left?.state === right?.state;

// The callbacks keep the RoleChat transport separate from the existing System
// operation journal. Both must use the original parent-owned authority.
export default function AdminSystemRestartConfirmation({ proposal = null, sessionId = null,
  requestId = null, shopUserId = null, authorityKey, transport = globalThis.fetch, locked = false,
  confirmOperation, readOperation }) {
  const [administration, setAdministration] = useState(null);
  const [pending, setPending] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [storageFault, setStorageFault] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), recoveryOperationRef = useRef(null);
  const proposalIdentityRef = useRef(null);
  const [proposalRevision, setProposalRevision] = useState(0);

  useEffect(() => {
    const epoch = ++epochRef.current, controller = new AbortController();
    activeRef.current?.abort(); activeRef.current = null; recoveryOperationRef.current = null;
    setAdministration(null); setPending(null); setReceipt(null); setNotice(''); setBusy(false);
    setStorageFault(false);
    const current = () => epochRef.current === epoch && !controller.signal.aborted;
    Promise.resolve().then(async () => {
      const references = readSystemRestartReferences();
      if (!current()) return;
      if (references.length) {
        recoveryOperationRef.current = references[0].operationId;
        setPending(references[0]);
        setNotice('A System restart is saved. Check its exact outcome before another restart.');
      }
      const response = await transport('/api/secureshop/admin/system/restart', { signal: controller.signal });
      if (!response.ok) throw Error('System restart availability is unavailable.');
      requireAgentContentType(response, 'application/json', 'System restart availability');
      const capability = restartAdministration(await response.json());
      const scopeKey = await restartHash({ restartTargetId: capability.targetId });
      if (current()) setAdministration({ ...capability, scopeKey });
    }).catch(error => {
      if (!current()) return;
      if (/saved System operation/i.test(error.message)) setStorageFault(true);
      setNotice(error.message || 'System restart availability is unavailable.');
    });
    return () => { if (epochRef.current === epoch) epochRef.current += 1;
      controller.abort(); activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, transport, proposalRevision]);

  useEffect(() => {
    const next = { proposalId: proposal?.proposalId || null, sessionId: sessionId || null,
      requestId: requestId || null };
    const prior = proposalIdentityRef.current;
    proposalIdentityRef.current = next;
    if (!prior || (prior.proposalId === next.proposalId && prior.sessionId === next.sessionId
      && prior.requestId === next.requestId)) return;
    if (prior.proposalId === null && prior.sessionId === null && prior.requestId === null
      && next.proposalId === recoveryOperationRef.current) return;
    setProposalRevision(value => value + 1);
  }, [proposal?.proposalId, requestId, sessionId]);

  const assertSaved = saved => {
    const references = readSystemRestartReferences();
    if (references.length !== 1 || !sameRef(references[0], saved)) {
      throw Error('Saved System restart reference changed. No restart was submitted.');
    }
  };

  const run = async confirm => {
    if (activeRef.current) return;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setBusy(true); setNotice('');
    const current = () => epochRef.current === epoch && activeRef.current === controller
      && !controller.signal.aborted;
    let saved = null;
    const finish = async (reference, value, expectedHash) => {
      if (!current()) return;
      if (!administration || reference.scopeKey !== administration.scopeKey) {
        throw Error('Saved System restart belongs to another shop session.');
      }
      if (value.state === 'not_found' || value.state === 'unconfirmed') {
        setPending(reference); setNotice('Restart outcome is unconfirmed. Check the saved operation; no restart was repeated.');
        return;
      }
      const outcome = await verifiedRestartResult(value, reference, administration.targetId, expectedHash);
      if (!current()) return;
      if (['admitted', 'running'].includes(outcome.state)) {
        setPending(reference); setNotice('Restart is still running. Check the saved operation; no restart was repeated.');
        return;
      }
      if (outcome.state === 'failed' && outcome.failureCode === 'OUTCOME_UNCERTAIN') {
        setPending(reference);
        setNotice('Restart outcome is uncertain. Check the saved operation; no restart was repeated.');
        return;
      }
      assertSaved(reference);
      try {
        await forgetSystemRestartReference(reference);
        if (!current()) return;
        if (readSystemRestartReferences().some(row => row.scopeKey === reference.scopeKey
          && row.operationId === reference.operationId)) throw Error('Saved System restart reference did not clear.');
      } catch (error) {
        if (current() && !readSystemRestartReferences().some(row => row.scopeKey === reference.scopeKey
          && row.operationId === reference.operationId)) await saveSystemRestartReference(reference);
        throw error;
      }
      if (!current()) return;
      setPending(null); setReceipt(outcome);
      setNotice(outcome.state === 'completed' ? 'Owned service restarted. Saved receipt verified.'
        : `Restart ${outcome.state}. No restart was repeated.`);
    };
    try {
      if (storageFault) throw Error('Saved System restart state is unavailable.');
      const references = readSystemRestartReferences();
      if (!current()) return;
      if (references.length) {
        saved = references[0]; setPending(saved);
        if (!administration) throw Error('System restart availability is unavailable.');
        if (saved.scopeKey !== administration.scopeKey) throw Error('Saved restart belongs to another shop session.');
        assertSaved(saved);
        await finish(saved, await readOperation(saved.operationId, controller.signal), undefined);
        return;
      }
      if (!confirm || locked || !proposal || !administration || !UUID.test(sessionId || '')
        || !UUID.test(requestId || '') || typeof confirmOperation !== 'function'
        || typeof readOperation !== 'function') return;
      const candidate = await decodeRoleSystemRestartProposal(proposal);
      if (!current()) return;
      if (candidate.scopeKey !== administration.scopeKey
        || candidate.targetId !== administration.targetId) throw Error('Restart target changed. Request a fresh review.');
      const response = await transport(`/api/secureshop/agents/admin/assistant/operations/${sessionId}/${requestId}`,
        { signal: controller.signal });
      if (!response.ok) throw Error('Saved assistant proposal unavailable. No restart was submitted.');
      requireAgentContentType(response, 'application/json', 'Saved restart proposal');
      const source = await response.json();
      if (!current()) return;
      const actual = await decodeRoleSystemRestartProposal(source.systemRestartProposal);
      if (!current()) return;
      if (source.sessionId !== sessionId || source.requestId !== requestId
        || source.status !== 'completed' || source.replayed !== true
        || source.stopReason !== 'end_turn'
        || !sameRolePolicyMode(source.modeCapability, candidate.modeCapability)
        || !same(actual, candidate)) throw Error('Saved restart proposal changed. No restart was submitted.');
      saved = { scopeKey: candidate.scopeKey, operationId: candidate.proposalId, state: 'pending' };
      await saveSystemRestartReference(saved);
      if (!current()) return;
      assertSaved(saved); setPending(saved);
      const prior = await readOperation(saved.operationId, controller.signal);
      if (!current()) return;
      if (prior.state !== 'not_found') { await finish(saved, prior, candidate.requestSha256); return; }
      assertSaved(saved);
      try { await confirmOperation({ sessionId, requestId, proposalId: candidate.proposalId }, controller.signal); }
      catch { /* The exact saved operation GET, never the POST response, settles this operation. */ }
      if (!current()) return;
      await finish(saved, await readOperation(saved.operationId, controller.signal), candidate.requestSha256);
    } catch (error) {
      if (!current()) return;
      try {
        const retained = readSystemRestartReferences();
        setPending(retained[0] || saved);
      } catch { setStorageFault(true); if (saved) setPending(saved); }
      setNotice(error.message || 'Restart outcome unavailable. Check the saved operation.');
    } finally { if (current()) { activeRef.current = null; setBusy(false); } }
  };

  if (!proposal && !pending && !receipt && !notice) return null;
  return <section className="ss-card" aria-label="Admin System restart review"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {proposal && !pending && !receipt && <>
      <h3 style={{ fontFamily: 'var(--display)', margin: '4px 0 10px' }}>Review System restart</h3>
      <p>Restart the owned service named <strong>{proposal.name}</strong>. The restart runs only after confirmation.</p>
      <button className="ss-btn ss-btn--sm" type="button" disabled={busy || locked || storageFault
        || !administration || administration.scopeKey !== proposal.scopeKey
        || typeof confirmOperation !== 'function' || typeof readOperation !== 'function'}
        onClick={() => void run(true)}>Confirm System restart</button>
    </>}
    {pending && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={busy || storageFault || !administration || typeof readOperation !== 'function'}
      onClick={() => void run(false)}>Check saved System restart</button>}
    {receipt?.state === 'completed' && <p role="status">{notice}</p>}
    {receipt?.receipt?.outputText && <pre style={{ maxHeight: 240, overflow: 'auto',
      whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{receipt.receipt.outputText}</pre>}
    {notice && receipt?.state !== 'completed' && <p role="status">{notice}</p>}
    <AdminSystemRestartAssessment proposal={proposal} sessionId={sessionId}
      requestId={requestId} administration={administration} shopUserId={shopUserId} authorityKey={authorityKey}
      transport={transport} readOperation={readOperation} operationState={receipt?.state || null} locked={locked || busy || storageFault} />
  </section>;
}
