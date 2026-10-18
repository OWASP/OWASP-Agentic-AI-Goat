import React, { useEffect, useRef, useState } from 'react';
import { shopStorage, SHOP_USER_ADMIN_KEY } from '../utils/shopStorage.mjs';
import { decodePending, savePending, assertSaved, clearPending, assertReceipt,
  readOperation, acknowledgeRegisteredSelfChange,
  requestReauthenticationForUnresolvedSelfChange } from '../pages/admin/userAdminOperation.js';
import { decodeUserAdministrationProposal,
  sameUserAdministrationProposal } from '../utils/userAdministrationProposal.mjs';
import { isStandaloneShopFrame } from '../bridge/assessmentPanelIntent.mjs';

const sourcePath = (sessionId, requestId) =>
  `/api/secureshop/agents/admin/assistant/operations/${sessionId}/${requestId}`;
const confirmPath = '/api/secureshop/agents/admin/assistant/user/confirm';
const sameMode = (left, right) => left?.version === right?.version
  && left?.featureId === right?.featureId && left?.policyVersion === right?.policyVersion
  && left?.effectiveMode === right?.effectiveMode
  && left?.scope?.kind === right?.scope?.kind && left?.scope?.id === right?.scope?.id;
const referenceFor = proposal => ({ scopeKey: proposal.scopeKey,
  targetId: proposal.target.userId, action: proposal.action,
  ...(proposal.action === 'ban' ? { reason: proposal.reason } : { role: proposal.role }),
  operationId: proposal.proposalId, expectedVersion: proposal.expectedVersion });

export default function AdminUserConfirmation({ proposal = null, sessionId = null, requestId = null,
  shopUserId, authorityKey, transport = globalThis.fetch, locked = false }) {
  const [pending, setPending] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [completed, setCompleted] = useState(false);
  const [authLossEpoch, setAuthLossEpoch] = useState(null);
  const epochRef = useRef(0), lockRef = useRef(false);
  useEffect(() => {
    const epoch = ++epochRef.current;
    setPending(null); setBusy(false); setError(null); setCompleted(false); setAuthLossEpoch(null);
    try { setPending(decodePending(shopStorage.getItem(SHOP_USER_ADMIN_KEY))); }
    catch { setError('Saved user change is unavailable. No new change can be sent.'); }
    return () => { if (epochRef.current === epoch) ++epochRef.current; };
  }, [authorityKey, transport, sessionId, requestId, proposal?.requestSha256]);
  const current = epoch => epochRef.current === epoch && globalThis.fetch === transport;
  const recover = async () => {
    if (lockRef.current || !pending) return;
    const epoch = epochRef.current;
    lockRef.current = true; setBusy(true); setError(null); setAuthLossEpoch(null);
    try {
      const saved = assertSaved(pending);
      await readOperation(saved, transport);
      if (!current(epoch)) return;
      await clearPending(saved, undefined, undefined, () => current(epoch));
      if (!current(epoch)) return;
      setPending(null); setCompleted(true);
    } catch (caught) {
      if (current(epoch)) {
        setAuthLossEpoch(caught.code === 'ADMIN_AUTH_CHANGED' ? epoch : null);
        setError(caught.message || 'Saved user change remains unresolved');
      }
    } finally { lockRef.current = false; if (current(epoch)) setBusy(false); }
  };
  const confirm = async () => {
    if (lockRef.current || locked || pending || !proposal || !sessionId || !requestId || error) return;
    const epoch = epochRef.current;
    lockRef.current = true; setBusy(true); setError(null); setAuthLossEpoch(null);
    let saved = null;
    try {
      const decoded = await decodeUserAdministrationProposal(proposal);
      if (!current(epoch)) return;
      const sourceResponse = await transport(sourcePath(sessionId, requestId));
      if (!sourceResponse.ok) throw Error(`Saved admin assistant turn unavailable (${sourceResponse.status})`);
      const source = await sourceResponse.json();
      if (!current(epoch)) return;
      if (source.sessionId !== sessionId || source.requestId !== requestId
        || source.status !== 'completed' || source.replayed !== true
        || source.stopReason !== 'end_turn' || !sameMode(source.modeCapability, decoded.modeCapability)
        || !sameUserAdministrationProposal(await decodeUserAdministrationProposal(source.userAdministrationProposal), decoded)) {
        throw Error('Saved administrator change differs from this review');
      }
      saved = await savePending(referenceFor(decoded), undefined, undefined, () => current(epoch));
      if (!current(epoch)) return;
      assertSaved(saved);
      setPending(saved);
      const response = await transport(confirmPath, { method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ sessionId, requestId, proposalId: decoded.proposalId }) });
      if (!current(epoch)) return;
      if (!response.ok) throw Error(`User change is not confirmed (${response.status}). Check the saved operation.`);
      const body = await response.json();
      if (!current(epoch)) return;
      if (body?.ok !== true) throw Error('User change is not confirmed. Check the saved operation.');
      const receipt = assertReceipt(body.receipt, saved);
      const selfChange = isStandaloneShopFrame() && decoded.target.identityKind === 'registered_account'
        && decoded.target.userId === shopUserId
        && (saved.action === 'ban' || saved.role !== 'admin');
      if (selfChange) {
        await acknowledgeRegisteredSelfChange(saved, receipt, shopUserId, () => current(epoch));
      } else {
        await readOperation(saved, transport);
        if (!current(epoch)) return;
        await clearPending(saved, undefined, undefined, () => current(epoch));
      }
      if (!current(epoch)) return;
      setPending(null); setCompleted(true);
    } catch (caught) {
      if (current(epoch)) {
        try {
          const retained = decodePending(shopStorage.getItem(SHOP_USER_ADMIN_KEY));
          if (retained) setPending(retained);
          else if (saved) setPending(saved);
        } catch { /* The error below keeps confirmation disabled. */ }
        setError(caught.message || 'User change outcome is uncertain. Check the saved operation.');
      }
    } finally { lockRef.current = false; if (current(epoch)) setBusy(false); }
  };
  if (!proposal && !pending && !error && !completed) return null;
  return <section className="ss-card" aria-label="Admin user change review" style={{ padding: 14, marginTop: 12 }}>
    <strong>Review user change</strong>
    {proposal && !pending && !completed && <>
      <p><strong>{proposal.target.username}</strong> · {proposal.target.identityKind === 'registered_account'
        ? 'Shop account' : 'Teaching persona'}</p>
      <p>Current role: {proposal.target.currentRole}{proposal.target.bannedAt ? ' · currently banned' : ''}</p>
      {proposal.action === 'set_role'
        ? <p>New role: <strong>{proposal.role}</strong></p>
        : <p>Ban reason: <strong>{proposal.reason}</strong></p>}
      <button className="ss-btn" type="button" disabled={locked || busy || !!error}
        onClick={() => void confirm()}>{proposal.action === 'ban' ? 'Confirm user ban' : 'Confirm role change'}</button>
    </>}
    {pending && <><p>This user change may have completed. Check its saved result before another change.</p>
      <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
        onClick={() => void recover()}>Check saved user change</button></>}
    {pending && authLossEpoch !== null && isStandaloneShopFrame() && pending.targetId === shopUserId
      && (pending.action === 'ban' || pending.role !== 'admin') &&
      <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
        onClick={() => {
          try { requestReauthenticationForUnresolvedSelfChange(pending, shopUserId,
            () => current(authLossEpoch)); }
          catch (caught) { setError(caught.message); }
        }}>Sign in again</button>}
    {completed && <p role="status">User change confirmed.</p>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
