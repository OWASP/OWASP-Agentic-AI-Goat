import React, { useEffect, useRef, useState } from 'react';
import { clearListingCreateReference, decodeListingCreateOperation, decodeListingCreateProposal,
  readListingCreateReference, sameListingCreateProposal, saveListingCreateReference } from '../pages/merchant/listingCreateOperation.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { assessListingCreate, readListingCreateAssessment } from '../pages/merchant/listingCreateAssessment.mjs';
import { getJudgeFeedback } from '../../../utils/judgeFeedback.mjs';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const display = value => value === null || value === '' ? 'Not provided' : value;
const rawV2Receipt = receipt => receipt?.version === 2 && receipt.source?.execution?.mode === 'vuln';
const assessmentMessage = assessment => {
  if (!assessment) return '';
  if (assessment.status === 'unconfirmed') return 'Listing created from the saved result. Assessment is not confirmed yet; the listing remains saved.';
  if (assessment.status === 'ineligible') return 'Listing created from the saved result. This listing is not eligible for objective credit.';
  if (assessment.completed === true && assessment.judgment?.verdict === 'pass') return 'Objective completed.';
  return getJudgeFeedback({ judgment: assessment.judgment })[0]?.content || 'The saved assessment did not award objective credit.';
};

function DraftReview({ preview }) {
  const { listing } = preview, isHtml = preview.version === 2;
  return <section aria-label="Listing create review" style={{ marginTop: 10 }}>
    <div className="ss-card" style={{ padding: 10 }}>
      <strong style={{ display: 'block', minWidth: 0, overflowWrap: 'anywhere' }}>{listing.name}</strong>
      <p style={{ margin: '6px 0', minWidth: 0, overflowWrap: 'anywhere' }}>{display(listing.description)}</p>
      {isHtml && <div className="ss-mono" style={{ fontSize: 11, minWidth: 0, overflowWrap: 'anywhere' }}>
        <span>Presentation: HTML · Execution mode: {preview.source.execution.mode}</span>
        <strong style={{ display: 'block', marginTop: 8 }}>Authored HTML source</strong>
        <pre aria-label="Authored HTML source" style={{ margin: '4px 0', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{preview.source.authoredHtml}</pre>
        <strong style={{ display: 'block', marginTop: 8 }}>Stored presentation</strong>
        <pre aria-label="Stored listing presentation" style={{ margin: '4px 0', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{preview.source.storedHtml}</pre>
      </div>}
      <div className="ss-mono" style={{ fontSize: 11, display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 8 }}>
        <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>Category: {display(listing.category)}</span>
        <span>Price: {preview.currency} {listing.price.toFixed(2)}</span>
        <span>Initial stock: {preview.initialStock}</span>
        <span>Status: {preview.status}</span>
      </div>
    </div>
    <p className="ss-mono" style={{ fontSize: 11 }}>This creates an active listing with zero stock. Manage stock separately after confirmation.</p>
  </section>;
}

export default function MerchantListingCreateConfirmation({ proposal, sessionId, requestId, authorityKey,
  transport = globalThis.fetch }) {
  const [reference, setReference] = useState(null), [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState(''), [assessment, setAssessment] = useState(null), [storageFault, setStorageFault] = useState(false), [busy, setBusy] = useState(false);
  const activeRef = useRef(null), epochRef = useRef(0), mountedRef = useRef(false);
  const proposalKey = JSON.stringify([proposal?.proposalId || null,
    proposal?.preview?.requestSha256 || null, sessionId, requestId]);
  const proposalKeyRef = useRef(proposalKey), presentedKeyRef = useRef(proposalKey);
  proposalKeyRef.current = proposalKey;
  useEffect(() => {
    mountedRef.current = true; const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    setReference(null); setReceipt(null); setNotice(''); setAssessment(null); setBusy(false); setStorageFault(false);
    const controller = new AbortController();
    try { const saved = readListingCreateReference(); if (saved) {
      setReference(saved); setNotice('A listing draft is saved. Check its exact outcome before confirming another.');
      Promise.resolve().then(() => readListingCreateAssessment(transport, saved.operationId, controller.signal)).then(value => {
        if (mountedRef.current && epochRef.current === epoch && !controller.signal.aborted) {
          setAssessment(value); setNotice(assessmentMessage(value));
        }
      }).catch(() => { /* The saved create receipt remains recoverable even if assessment status is unavailable. */ });
    } }
    catch { setStorageFault(true); setNotice('Saved listing draft state is unavailable. Confirmation is blocked.'); }
    return () => { mountedRef.current = false; epochRef.current += 1; controller.abort(); activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, transport]);

  useEffect(() => {
    if (!proposal || presentedKeyRef.current === proposalKey) return;
    if (reference?.operationId === proposal.proposalId || receipt?.operationId === proposal.proposalId) {
      presentedKeyRef.current = proposalKey;
      return;
    }
    if (activeRef.current || reference) return;
    try { if (readListingCreateReference()) return; } catch { return; }
    presentedKeyRef.current = proposalKey;
    setReceipt(null); setAssessment(null); setNotice('');
  }, [proposalKey, proposal, reference, receipt, busy]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/agents/merchant/assistant/listing-create/operations/${saved.operationId}`, { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) throw Error(`Saved listing lookup failed (${response.status}).`);
    return await decodeListingCreateOperation(await response.json(), saved);
  };
  const showOutcome = async (saved, outcome, current, assess = false, signal) => {
    if (!current()) return;
    if (outcome.status === 'not_found') { setReference(saved); setNotice('Listing outcome is not recorded yet. Check the saved draft; confirmation will not be retried.'); return; }
    if (!rawV2Receipt(outcome)) {
      await clearListingCreateReference(saved, current); if (!current()) return;
      setReference(null); setReceipt(outcome); setNotice('Listing created from the saved result.'); return;
    }
    setReference(saved); setReceipt(outcome); setNotice('Listing created from the saved result.');
    try {
      const value = assess ? await assessListingCreate(transport, saved.operationId, signal) : await readListingCreateAssessment(transport, saved.operationId, signal);
      if (!current()) return;
      setAssessment(value); setNotice(assessmentMessage(value));
    } catch {
      if (current()) setNotice('Listing created from the saved result. Assessment status is unavailable; check the saved listing.');
    }
  };
  const run = async confirm => {
    if (activeRef.current) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const sourceKey = proposalKeyRef.current;
    let sourceBound = false;
    const authorityCurrent = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted;
    const current = () => authorityCurrent() && (!sourceBound || proposalKeyRef.current === sourceKey);
    activeRef.current = controller; setBusy(true); setNotice(''); let saved = null;
    try {
      saved = readListingCreateReference();
      if (saved) { if (current()) setReference(saved); await showOutcome(saved, await readExact(saved, controller.signal), current, false, controller.signal); return; }
      if (!confirm || !proposal || storageFault || !UUID.test(sessionId || '') || !UUID.test(requestId || '')) return;
      sourceBound = true;
      const candidate = await decodeListingCreateProposal(proposal);
      const source = await transport(`/api/secureshop/agents/merchant/assistant/operations/${sessionId}/${requestId}`, { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!source.ok) throw Error('Saved assistant draft unavailable. No listing was created.');
      const sourceValue = await source.json(); if (!current()) return;
      const currentProposal = await decodeListingCreateProposal(sourceValue.listingCreateProposal ?? null); if (!current()) return;
      if (sourceValue.sessionId !== sessionId || sourceValue.requestId !== requestId || sourceValue.status !== 'completed'
        || sourceValue.replayed !== true || sourceValue.stopReason !== 'end_turn'
        || trustedTurnMode(sourceValue.modeCapability)?.featureId !== 'merchant_assistant'
        || !sameListingCreateProposal(currentProposal, candidate)) throw Error('Saved listing draft changed. Request a fresh draft.');
      saved = { version: 1, scopeKey: candidate.preview.scopeKey, operationId: candidate.proposalId, requestSha256: candidate.preview.requestSha256 };
      if (!current()) return; await saveListingCreateReference(saved);
      if (authorityCurrent()) setReference(saved);
      if (!current()) return;
      const persisted = readListingCreateReference();
      if (!persisted || JSON.stringify(persisted) !== JSON.stringify(saved)) throw Error('Saved listing draft changed. No listing was created.');
      const prior = await readExact(saved, controller.signal); if (!current()) return;
      if (prior.status !== 'not_found') { await showOutcome(saved, prior, current, false, controller.signal); return; }
      const beforePost = readListingCreateReference();
      if (!beforePost || JSON.stringify(beforePost) !== JSON.stringify(saved)) throw Error('Saved listing draft changed. No listing was created.');
      try { await transport('/api/secureshop/agents/merchant/assistant/listing-create/confirm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sessionId, requestId, proposalId: saved.operationId }), signal: controller.signal }); }
      catch { /* Parent-acknowledged operation is recovered only through the exact GET. */ }
      if (!current()) return; await showOutcome(saved, await readExact(saved, controller.signal), current, true, controller.signal);
    } catch (error) {
      if (!authorityCurrent()) return;
      try { saved = readListingCreateReference(); } catch { setStorageFault(true); }
      if (saved) setReference(saved);
      if (current()) setNotice(error instanceof Error ? error.message : 'Listing outcome unavailable.');
    } finally { if (activeRef.current === controller) { activeRef.current = null; setBusy(false); } }
  };
  const assessSaved = async () => {
    if (activeRef.current || !reference || !rawV2Receipt(receipt)) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const current = () => mountedRef.current && epochRef.current === epoch && activeRef.current === controller && !controller.signal.aborted;
    activeRef.current = controller; setBusy(true);
    try {
      const value = await assessListingCreate(transport, reference.operationId, controller.signal);
      if (!current()) return;
      setAssessment(value); setNotice(assessmentMessage(value));
    } catch (error) { if (current()) setNotice(error instanceof Error ? error.message : 'Saved listing assessment is unavailable.'); }
    finally { if (current()) { activeRef.current = null; setBusy(false); } }
  };
  if (!proposal && !reference && !receipt && !notice) return null;
  return <section className="ss-card" aria-label="Merchant listing create confirmation" style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {proposal && <><div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>SAVED LISTING DRAFT · REVIEW BEFORE CREATING</div>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review new listing</h3><DraftReview preview={proposal.preview} /></>}
    {receipt && <p role="status">Listing created from the saved result.</p>}{notice && <p role="status">{notice}</p>}
    {reference ? <button className="ss-btn ss-btn--ghost" type="button" disabled={busy} onClick={() => void run(false)}>Check saved listing</button>
      : proposal && !receipt && <button className="ss-btn" type="button" disabled={busy || storageFault} onClick={() => void run(true)}>Create listing</button>}
    {rawV2Receipt(receipt) && assessment?.status === 'unconfirmed' && <button className="ss-btn ss-btn--ghost" type="button"
      disabled={busy} onClick={() => void assessSaved()}>{busy ? 'Assessing saved listing…' : 'Assess saved listing'}</button>}
    {assessment?.judgment?.verdict === 'unavailable' && assessment.judgment.canRetry === true
      && (isStandaloneShopFrame() ? <button className="ss-btn ss-btn--ghost" type="button"
        onClick={() => openStandaloneAssessments(assessment.judgment.evaluationId)}>Open saved assessments</button>
        : <p role="status">A saved assessment is available in the SecureShop assessments panel.</p>)}
  </section>;
}
