import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { clearManualPending, readManualPending, saveManualPending } from '../utils/manualReviewOperation.mjs';
import { shopStorage, SHOP_REVIEW_DECISION_KEY } from '../utils/shopStorage.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { decodeMerchantReviewDetail, decodeMerchantReviewProposal, merchantReviewSelection,
  sameMerchantReviewProposal, verifyMerchantReviewReceipt } from '../utils/merchantReviewChat.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

function savedReviewReference() {
  const raw = shopStorage.getItem(SHOP_REVIEW_DECISION_KEY);
  if (raw === null) return null;
  const scopeKey = JSON.parse(raw)?.scopeKey;
  if (typeof scopeKey !== 'string') throw Error('Saved review decision is invalid.');
  return readManualPending(scopeKey);
}

function isChatReference(value) {
  return value && UUID.test(value.sourceSessionId || '') && UUID.test(value.sourceRequestId || '')
    && /^[a-f0-9]{64}$/.test(value.expectedSnapshotSha256 || '');
}

export default function MerchantReviewChat({ cards = [], detail = null, page = null,
  proposal = null, sessionId = null, requestId = null, authorityKey,
  locked = false, onSelect, transport = globalThis.fetch }) {
  const [reference, setReference] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [storageFault, setStorageFault] = useState(false);
  const [dismissedProposalId, setDismissedProposalId] = useState(null);
  const epochRef = useRef(0), mountedRef = useRef(false), activeRef = useRef(null);
  const proposalId = proposal?.proposalId || null;

  useEffect(() => {
    mountedRef.current = true;
    ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    setReference(null); setReceipt(null); setNotice(''); setBusy(false); setStorageFault(false);
    setDismissedProposalId(null);
    try {
      const saved = savedReviewReference();
      if (saved) {
        setReference(saved);
        setNotice(isChatReference(saved)
          ? 'A review decision is saved. Check its exact outcome before confirming another.'
          : 'A review decision is saved on the Reviews page. Resolve it there before confirming another.');
      }
    } catch { setStorageFault(true); setNotice('Saved review state is unavailable. Confirmation is blocked.'); }
    return () => {
      mountedRef.current = false; ++epochRef.current;
      activeRef.current?.abort(); activeRef.current = null;
    };
  }, [authorityKey, proposalId, requestId, sessionId, transport]);

  const choose = (card, intent) => {
    if (locked || busy || typeof onSelect !== 'function') return;
    onSelect(merchantReviewSelection(card.choiceId, intent));
  };

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/merchant/reviews/operations/${saved.operationId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (response.status === 404) return null;
    if (!response.ok) throw Error('Saved review decision is unavailable.');
    const value = await response.json();
    if (value?.ok !== true) throw Error('Saved review response is invalid.');
    return verifyMerchantReviewReceipt(value.receipt, saved, value.executionScopeKey);
  };

  const run = async confirm => {
    if (activeRef.current) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted;
    activeRef.current = controller; setBusy(true); setNotice('');
    let saved = null;
    try {
      saved = savedReviewReference();
      if (saved && !isChatReference(saved)) {
        setReference(saved); setNotice('Resolve the saved decision on the Reviews page first.'); return;
      }
      if (!saved && (!confirm || !proposal || storageFault || !UUID.test(sessionId || '')
        || !UUID.test(requestId || ''))) return;
      const capabilityResponse = await transport('/api/secureshop/merchant/reviews?status=pending&per_page=1',
        { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!capabilityResponse.ok) throw Error('Review authority is unavailable.');
      const capability = (await capabilityResponse.json())?.manual_decisions;
      if (!current()) return;
      const expectedScope = saved?.scopeKey ?? proposal.scopeKey;
      if (capability?.available !== true || capability.scopeKey !== expectedScope)
        throw Error('Review authority changed. The saved decision is retained.');
      if (!saved) {
        const candidate = decodeMerchantReviewProposal(proposal);
        const source = await transport(`/api/secureshop/agents/merchant/assistant/operations/${sessionId}/${requestId}`,
          { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
        if (!source.ok) throw Error('Saved assistant proposal unavailable. No review decision was submitted.');
        const sourceValue = await source.json();
        if (!current()) return;
        if (sourceValue.sessionId !== sessionId || sourceValue.requestId !== requestId
          || sourceValue.status !== 'completed' || sourceValue.replayed !== true
          || sourceValue.stopReason !== 'end_turn'
          || trustedTurnMode(sourceValue.modeCapability)?.featureId !== 'merchant_assistant'
          || !sameMerchantReviewProposal(sourceValue.reviewProposal, candidate))
          throw Error('Saved review proposal changed. Request a fresh proposal.');
        saved = { scopeKey: candidate.scopeKey, operationId: candidate.proposalId,
          reviewId: candidate.review.reviewId, action: candidate.decision, reason: candidate.reason,
          expectedSnapshotSha256: candidate.expectedSnapshotSha256,
          sourceSessionId: sessionId, sourceRequestId: requestId };
        const prior = await readExact(saved, controller.signal);
        if (!current()) return;
        if (prior) {
          setReceipt(prior); setNotice('A saved review result already exists. No confirmation was sent.'); return;
        }
        if (savedReviewReference())
          throw Error('Another review decision was saved. No confirmation was submitted.');
        await saveManualPending(saved);
        if (!current()) return;
        if (JSON.stringify(savedReviewReference()) !== JSON.stringify(saved))
          throw Error('Saved review decision changed. No confirmation was submitted.');
        setReference(saved);
        // The saved operation is acknowledged before its sole confirmation POST.
        try {
          await transport('/api/secureshop/agents/merchant/assistant/review/confirm', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ sessionId, requestId, proposalId: saved.operationId }), signal: controller.signal,
          });
        } catch { /* Exact GET resolves an uncertain response; never replay POST. */ }
      }
      if (!current()) return;
      const outcome = await readExact(saved, controller.signal);
      if (!current()) return;
      if (!outcome) {
        setReference(saved); setNotice('Review outcome is unconfirmed. Check the saved decision; confirmation will not be retried.');
        return;
      }
      setReceipt(outcome);
      await clearManualPending(saved);
      if (!current()) return;
      setReference(null); setReceipt(outcome);
      setNotice(outcome.applied ? 'Review decision confirmed from the saved result.'
        : 'The saved decision completed without changing the review.');
    } catch (error) {
      if (!current()) return;
      try { saved = savedReviewReference(); } catch { setStorageFault(true); }
      if (saved) setReference(saved);
      setNotice(error instanceof Error ? error.message : 'Review outcome unavailable.');
    } finally { if (current()) { activeRef.current = null; setBusy(false); } }
  };

  const reviewCards = cards.filter(card => card?.kind === 'merchant_review');
  let selectedDetail = null, selectedProposal = null;
  try {
    selectedDetail = decodeMerchantReviewDetail(detail);
    selectedProposal = proposalId === dismissedProposalId ? null : decodeMerchantReviewProposal(proposal);
  } catch { /* Invalid protected data is never presented as actionable. */ }
  if (!reviewCards.length && !selectedDetail && !selectedProposal && !reference && !notice) return null;
  return <section aria-label="Merchant review assistant" style={{ marginTop: 12 }}>
    {reviewCards.length > 0 && <div role="group" aria-label="Merchant review choices">
      {page && <p className="ss-mono">Review page {page.page} · {page.total} matching review(s)
        {page.nextPage ? ` · More available on page ${page.nextPage}` : ''}</p>}
      {reviewCards.map(card => <div className="ss-card" data-choice-id={card.choiceId} key={card.choiceId} style={{ padding: 12, marginTop: 8 }}>
        <strong>{card.title}</strong>
        <p className="ss-mono">{card.detail}</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="ss-btn ss-btn--ghost" type="button" disabled={locked || busy}
            onClick={() => choose(card, 'review_details')}>View review</button>
          <button className="ss-btn ss-btn--ghost" type="button" disabled={locked || busy}
            onClick={() => choose(card, 'review_approve')}>Approve</button>
          <button className="ss-btn ss-btn--ghost" type="button" disabled={locked || busy}
            onClick={() => choose(card, 'review_reject')}>Reject</button>
        </div>
      </div>)}
    </div>}
    {selectedDetail && <section className="ss-card" aria-label="Selected merchant review"
      style={{ padding: 12, marginTop: 10 }}>
      <strong>Selected review</strong>
      <p>Rating: {selectedDetail.rating} of 5 · Status: {selectedDetail.status}</p>
      {selectedDetail.oversized
        ? <p>This review is too long for chat. Open Reviews to inspect and decide it.</p>
        : <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{selectedDetail.body}</p>}
      {selectedDetail.oversized && <Link to="/secureshop/merchant/reviews">Open Reviews</Link>}
    </section>}
    {selectedProposal && <section className="ss-card" aria-label="Merchant review decision confirmation"
      style={{ padding: 12, marginTop: 10 }}>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>SAVED REVIEW PROPOSAL · NO DECISION APPLIED</div>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>
        {selectedProposal.decision === 'approve' ? 'Approve this review?' : 'Reject this review?'}
      </h3>
      <p>Rating: {selectedProposal.review.rating} of 5</p>
      <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{selectedProposal.review.body}</p>
      {selectedProposal.reason && <p>Reason: {selectedProposal.reason}</p>}
      <p className="ss-mono">The review remains pending until you confirm this saved proposal.</p>
      {!reference && !receipt && <button className="ss-btn" type="button" disabled={busy || locked || storageFault}
        onClick={() => void run(true)}>Confirm {selectedProposal.decision === 'approve' ? 'approval' : 'rejection'}</button>}
      {!reference && !receipt && <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
        onClick={() => { setDismissedProposalId(proposalId); setNotice('Proposal dismissed. No review decision was submitted. Ask for a new proposal to continue.'); }}>
        Cancel proposal</button>}
    </section>}
    {reference && isChatReference(reference) && <button className="ss-btn ss-btn--ghost" type="button"
      disabled={busy || storageFault} onClick={() => void run(false)}>Check saved review decision</button>}
    {receipt && <p role="status">{receipt.applied ? 'Review decision applied.' : 'No review change was applied.'}</p>}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
