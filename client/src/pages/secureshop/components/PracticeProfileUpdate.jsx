import React, { useEffect, useRef, useState } from 'react';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import {
  clearProfileReference, decodeProfileForm, decodeProfileOperation, decodeProfileProposal,
  normalizeEditedProfileFields, profileFieldsDigest, profileRequestDigest,
  readProfileReference, sameProfileReference, saveProfileReference,
} from '../utils/profileOperation.mjs';

const FIELDS = [['fullName', 'Full name'], ['email', 'Email'], ['phone', 'Phone']];
const shown = value => value === null || value === '' ? 'Not set' : value;
const message = error => error instanceof Error ? error.message : 'Saved profile outcome unavailable.';
const sameProposal = (left, right) => left && right &&
  JSON.stringify(left) === JSON.stringify(right);

export default function PracticeProfileUpdate({ proposal = null, entryPoint = 'chat',
  sourceSessionId = null, sourceRequestId = null, authorityKey,
  transport = globalThis.fetch, onConfirmed }) {
  if (!['chat', 'account'].includes(entryPoint)) throw new TypeError('Trusted profile entry point required');
  let reviewProposal = null, proposalError = false;
  try { reviewProposal = decodeProfileProposal(proposal); } catch { proposalError = true; }
  const proposalKey = JSON.stringify(reviewProposal);
  const [form, setForm] = useState(null);
  const [fields, setFields] = useState(null);
  const [review, setReview] = useState(false);
  const [reference, setReference] = useState(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [storageFault, setStorageFault] = useState(false);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const epochRef = useRef(0), activeRef = useRef(null), mountedRef = useRef(false);

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    setForm(null); setFields(null); setReview(false); setReference(null);
    setNotice(''); setBusy(false); setCompleted(false); setStorageFault(false);
    try {
      const saved = readProfileReference();
      if (saved) { setReference(saved); setNotice('A profile change is saved. Check its exact outcome before another update.'); }
    } catch { setStorageFault(true); setNotice('Saved profile state is unavailable. Updating is blocked.'); }
    if (entryPoint === 'account') {
      const controller = new AbortController(); activeRef.current = controller;
      const current = () => mountedRef.current && epochRef.current === epoch
        && activeRef.current === controller && !controller.signal.aborted;
      setBusy(true);
      Promise.resolve().then(async () => {
        const response = await transport('/api/secureshop/customer/commerce/profile-form',
          { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
        if (!response.ok) throw Error(`Current profile unavailable (${response.status}).`);
        const value = decodeProfileForm(await response.json());
        if (!current()) return;
        setForm(value); setFields({ ...value.fields });
      }).catch(error => { if (current()) setNotice(message(error)); })
        .finally(() => { if (current()) { setBusy(false); activeRef.current = null; } });
    }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, transport, entryPoint, proposalKey, refreshNonce]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/customer/commerce/operations/${saved.operationId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) throw Error(`Saved profile lookup failed (${response.status}).`);
    return decodeProfileOperation(await response.json(), saved);
  };
  const finish = async (saved, outcome, current) => {
    if (!current()) return;
    if (outcome.status === 'not_found') {
      setReference(saved);
      setNotice('Profile outcome is not recorded yet. Check the saved profile; the update will not be retried.');
      return;
    }
    await clearProfileReference(saved, current);
    if (!current()) return;
    setReference(null); setCompleted(true); setReview(false);
    if (outcome.status === 'stale') {
      setForm(null); setFields(null);
      setNotice('Your profile changed before confirmation. No update was saved. Start a fresh review.');
      return;
    }
    setNotice('Profile updated.');
    Promise.resolve().then(() => onConfirmed?.()).catch(() => {
      // The receipt remains authoritative even if the display refresh fails.
    });
  };
  const readSourceProposal = async (expected, signal) => {
    const response = await transport(`/api/secureshop/agents/customer/operations/${sourceSessionId}/${sourceRequestId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) throw Error(`Saved profile review unavailable (${response.status}).`);
    const turn = await response.json();
    const current = decodeProfileProposal(turn.profileProposal);
    if (turn.sessionId !== sourceSessionId || turn.requestId !== sourceRequestId
      || turn.status !== 'completed' || turn.replayed !== true
      || turn.stopReason !== 'end_turn' || !trustedTurnMode(turn.modeCapability)
      || !sameProposal(current, expected)
      || await profileRequestDigest(current.proposalId,
        current.expectedSnapshotSha256, current.after) !== current.requestSha256)
      throw Error('Saved profile review changed. Start a fresh chat request.');
  };
  const run = async (recover = false) => {
    if (activeRef.current) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted;
    activeRef.current = controller; setBusy(true); setNotice('');
    let saved = null;
    try {
      saved = readProfileReference();
      if (saved || recover) {
        if (!saved) throw Error('Saved profile reference is unavailable.');
        setReference(saved);
        await finish(saved, await readExact(saved, controller.signal), current);
        return;
      }
      if (storageFault || completed || proposalError || (entryPoint === 'account' && !review)) return;
      const account = entryPoint === 'account';
      if (account && (!form || !fields)) return;
      if (!account && (!reviewProposal || !sourceSessionId || !sourceRequestId)) return;
      const after = account ? normalizeEditedProfileFields(fields, form.fields) : reviewProposal.after;
      const operationId = account ? globalThis.crypto.randomUUID().toLowerCase() : reviewProposal.proposalId;
      const expectedSnapshotSha256 = account ? form.expectedSnapshotSha256 : reviewProposal.expectedSnapshotSha256;
      const fieldsSha256 = await profileFieldsDigest(after);
      const requestSha256 = await profileRequestDigest(operationId, expectedSnapshotSha256, after);
      if (!current()) return;
      if (!account && (requestSha256 !== reviewProposal.requestSha256
        || !sameProposal(reviewProposal, decodeProfileProposal(proposal))))
        throw Error('Saved profile review changed. Start a fresh chat request.');
      saved = { version: 1, operationId, scopeKey: account ? form.scopeKey : reviewProposal.scopeKey,
        expectedSnapshotSha256, fieldsSha256, requestSha256,
        sessionId: account ? null : sourceSessionId, requestId: account ? null : sourceRequestId };
      await saveProfileReference(saved);
      if (!current()) return;
      if (!sameProfileReference(readProfileReference(), saved)) throw Error('Saved profile reference changed. No update was submitted.');
      setReference(saved);
      const prior = await readExact(saved, controller.signal);
      if (!current()) return;
      if (prior.status !== 'not_found') { await finish(saved, prior, current); return; }
      if (!sameProfileReference(readProfileReference(), saved)) throw Error('Saved profile reference changed. No update was submitted.');
      if (!account) await readSourceProposal(reviewProposal, controller.signal);
      if (!current()) return;
      if (!sameProfileReference(readProfileReference(), saved)) throw Error('Saved profile reference changed. No update was submitted.');
      try {
        await transport(account ? '/api/secureshop/customer/commerce/profile'
          : '/api/secureshop/agents/customer/profile/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify(account
            ? { operationId, expectedSnapshotSha256, fields: after }
            : { sessionId: sourceSessionId, requestId: sourceRequestId, proposalId: operationId }),
          signal: controller.signal,
        });
      } catch { /* Resolve the uncertain effect only through exact GET. */ }
      if (!current()) return;
      await finish(saved, await readExact(saved, controller.signal), current);
    } catch (error) {
      if (current()) {
        if (saved) setReference(saved);
        setNotice(message(error));
      }
    } finally {
      if (current()) { setBusy(false); activeRef.current = null; }
    }
  };

  if (entryPoint === 'chat' && !reviewProposal && !reference && !completed
    && !proposalError && !storageFault) return null;
  const before = entryPoint === 'account' ? form?.fields : reviewProposal?.before;
  const after = entryPoint === 'account' && form && fields
    ? (() => { try { return normalizeEditedProfileFields(fields, form.fields); } catch { return null; } })()
    : reviewProposal?.after;
  return <section className="ss-card" aria-label="Profile update review" style={{ padding: 14, marginTop: 12 }}>
    <h3 style={{ margin: '0 0 10px' }}>Profile</h3>
    {entryPoint === 'account' && fields && !completed && <div className="ss-form" style={{ display: 'grid', gap: 10 }}>
      {FIELDS.map(([key, label]) => <label key={key}>{label}
        <input aria-label={label} className="ss-lane__input" type={key === 'email' ? 'email' : 'text'}
          value={fields[key] ?? ''} disabled={busy || !!reference}
          onChange={event => { setFields({ ...fields, [key]: event.target.value }); setReview(false); }} />
      </label>)}
      <button className="ss-btn ss-btn--ghost" type="button" disabled={busy || !!reference || !after}
        onClick={() => setReview(true)}>Review profile</button>
    </div>}
    {(entryPoint === 'chat' && reviewProposal || review && before && after) && <div aria-label="Profile changes to confirm">
      {FIELDS.map(([key, label]) => <p key={key} style={{ overflowWrap: 'anywhere' }}>
        <strong>{label}:</strong> {shown(before[key])} → {shown(after[key])}
      </p>)}
      {!completed && !reference && <button className="ss-btn" type="button"
        disabled={busy || storageFault || proposalError}
        onClick={() => void run()}>Confirm profile update</button>}
    </div>}
    {reference && <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
      onClick={() => void run(true)}>Check saved profile</button>}
    {entryPoint === 'account' && completed && <button className="ss-btn ss-btn--ghost" type="button"
      onClick={() => setRefreshNonce(value => value + 1)}>Review current profile</button>}
    {notice && <p role="status">{notice}</p>}
    {proposalError && <p role="alert">Saved profile review is unavailable.</p>}
  </section>;
}
