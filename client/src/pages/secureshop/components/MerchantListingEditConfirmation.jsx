import React, { useEffect, useRef, useState } from 'react';
import { clearListingEditReference, decodeListingEditOperation, decodeListingEditProposal,
  readListingEditReference, sameListingEditProposal, saveListingEditReference } from '../pages/merchant/listingEditOperation.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const textValue = value => value === null ? '(empty)' : String(value);
const fields = Object.freeze([
  ['name', 'Name'], ['description', 'Description'], ['price', 'Price'], ['category', 'Category'],
  ['templateSource', 'Template source'], ['imageUrl', 'Image URL'],
]);
const changedValue = (field, value) => field === 'templateSource' ? '(updated — see technical values)'
  : textValue(value);

function ListingReview({ preview }) {
  const changed = fields.filter(([field]) => preview.before[field] !== preview.after[field]);
  return <section aria-label="Listing edit review" style={{ marginTop: 10 }}>
    <div className="ss-mono" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
      gap: 10, fontSize: 11 }}>
      <strong>Current listing</strong><strong>Proposed listing</strong>
      <span data-testid="listing-current listing-name" style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
        {textValue(preview.before.name)}
      </span>
      <span data-testid="listing-proposed listing-name" style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
        {textValue(preview.after.name)}
      </span>
    </div>
    {changed.map(([field, label]) => <div key={field} className="ss-card" style={{ marginTop: 8, padding: 9 }}>
      <strong>{label}</strong>
      <div className="ss-mono" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
        gap: 10, marginTop: 4, fontSize: 11 }}>
        <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>{changedValue(field, preview.before[field])}</span>
        <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>{changedValue(field, preview.after[field])}</span>
      </div>
    </div>)}
    <details style={{ marginTop: 10 }}>
      <summary>Technical listing values</summary>
      <div className="ss-mono" style={{ marginTop: 8, fontSize: 11, overflowWrap: 'anywhere' }}>
        <strong>Current generated HTML</strong><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{textValue(preview.before.descriptionHtml)}</pre>
        <strong>Proposed generated HTML</strong><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{textValue(preview.after.descriptionHtml)}</pre>
        <strong>Current template source</strong><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{textValue(preview.before.templateSource)}</pre>
        <strong>Proposed template source</strong><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{textValue(preview.after.templateSource)}</pre>
      </div>
    </details>
  </section>;
}

export default function MerchantListingEditConfirmation({ proposal, sessionId, requestId, authorityKey,
  transport = globalThis.fetch }) {
  const [reference, setReference] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState('');
  const [storageFault, setStorageFault] = useState(false);
  const [busy, setBusy] = useState(false);
  const activeRef = useRef(null), epochRef = useRef(0), mountedRef = useRef(false);
  const proposalKey = JSON.stringify([proposal?.proposalId || null,
    proposal?.preview?.requestSha256 || null, sessionId, requestId]);
  const proposalKeyRef = useRef(proposalKey), presentedKeyRef = useRef(proposalKey);
  proposalKeyRef.current = proposalKey;

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    setReference(null); setReceipt(null); setNotice(''); setBusy(false); setStorageFault(false);
    try {
      const saved = readListingEditReference();
      if (saved) { setReference(saved); setNotice('A listing edit is saved. Check its exact outcome before confirming another.'); }
    } catch { setStorageFault(true); setNotice('Saved listing edit state is unavailable. Confirmation is blocked.'); }
    return () => { mountedRef.current = false; epochRef.current += 1; activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, transport]);

  useEffect(() => {
    if (!proposal || presentedKeyRef.current === proposalKey) return;
    if (reference?.operationId === proposal.proposalId || receipt?.operationId === proposal.proposalId) {
      presentedKeyRef.current = proposalKey;
      return;
    }
    if (activeRef.current || reference) return;
    try { if (readListingEditReference()) return; } catch { return; }
    presentedKeyRef.current = proposalKey;
    setReceipt(null); setNotice('');
  }, [proposalKey, proposal, reference, receipt, busy]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/agents/merchant/assistant/listing/operations/${saved.operationId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) throw Error(`Saved listing edit lookup failed (${response.status}).`);
    return decodeListingEditOperation(await response.json(), saved);
  };

  const showOutcome = async (saved, outcome, current) => {
    if (!current()) return;
    if (outcome.status === 'not_found') {
      setReference(saved); setNotice('Listing edit outcome is not recorded yet. Check the saved edit; confirmation will not be retried.');
      return;
    }
    await clearListingEditReference(saved, current);
    if (!current()) return;
    setReference(null); setReceipt(outcome); setNotice('Listing edit confirmed from the saved result.');
  };

  const run = async confirm => {
    if (activeRef.current) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const sourceKey = proposalKeyRef.current;
    let sourceBound = false;
    const authorityCurrent = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted;
    const current = () => authorityCurrent() && (!sourceBound || proposalKeyRef.current === sourceKey);
    activeRef.current = controller; setBusy(true); setNotice('');
    let saved = null;
    try {
      saved = readListingEditReference();
      if (saved) {
        if (current()) setReference(saved);
        await showOutcome(saved, await readExact(saved, controller.signal), current);
        return;
      }
      if (!confirm || !proposal || storageFault || !UUID.test(sessionId || '') || !UUID.test(requestId || '')) return;
      sourceBound = true;
      const candidate = await decodeListingEditProposal(proposal);
      const source = await transport(`/api/secureshop/agents/merchant/assistant/operations/${sessionId}/${requestId}`,
        { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!source.ok) throw Error('Saved assistant proposal unavailable. No listing edit was submitted.');
      const sourceValue = await source.json();
      if (!current()) return;
      const currentProposal = await decodeListingEditProposal(sourceValue.listingProposal ?? null);
      if (!current()) return;
      if (sourceValue.sessionId !== sessionId || sourceValue.requestId !== requestId
        || sourceValue.status !== 'completed' || sourceValue.replayed !== true
        || sourceValue.stopReason !== 'end_turn'
        || trustedTurnMode(sourceValue.modeCapability)?.featureId !== 'merchant_assistant'
        || !sameListingEditProposal(currentProposal, candidate))
        throw Error('Saved listing proposal changed. Request a fresh proposal.');
      saved = { version: 1, scopeKey: candidate.preview.scopeKey, operationId: candidate.proposalId,
        productId: candidate.preview.productId, catalogRevision: candidate.preview.catalogRevision,
        requestSha256: candidate.preview.requestSha256,
        expectedSnapshotSha256: candidate.preview.expectedSnapshotSha256 };
      await saveListingEditReference(saved);
      if (authorityCurrent()) setReference(saved);
      if (!current()) return;
      const persisted = readListingEditReference();
      if (!persisted || JSON.stringify(persisted) !== JSON.stringify(saved))
        throw Error('Saved listing edit changed. No update was submitted.');
      const prior = await readExact(saved, controller.signal);
      if (!current()) return;
      if (prior.status !== 'not_found') { await showOutcome(saved, prior, current); return; }
      const beforePost = readListingEditReference();
      if (!beforePost || JSON.stringify(beforePost) !== JSON.stringify(saved))
        throw Error('Saved listing edit changed. No update was submitted.');
      // A parent-acknowledged proposal has exactly one confirmation POST. Recovery is GET-only.
      try {
        await transport('/api/secureshop/agents/merchant/assistant/listing/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId, requestId, proposalId: saved.operationId }), signal: controller.signal,
        });
      } catch { /* The exact operation GET resolves a lost response. */ }
      if (!current()) return;
      await showOutcome(saved, await readExact(saved, controller.signal), current);
    } catch (error) {
      if (!authorityCurrent()) return;
      try { saved = readListingEditReference(); } catch { setStorageFault(true); }
      if (saved) setReference(saved);
      if (current()) setNotice(error instanceof Error ? error.message : 'Listing edit outcome unavailable.');
    } finally { if (activeRef.current === controller) { activeRef.current = null; setBusy(false); } }
  };

  if (!proposal && !reference && !receipt && !notice) return null;
  return <section className="ss-card" aria-label="Merchant listing edit confirmation"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {proposal && <>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>
        SAVED LISTING EDIT PROPOSAL · REVIEW BEFORE APPLYING
      </div>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review listing edit</h3>
      <p><strong>{proposal.product.name}</strong></p>
      <ListingReview preview={proposal.preview} />
      <p className="ss-mono" style={{ fontSize: 11 }}>The listing remains unchanged until you confirm.</p>
    </>}
    {receipt && <p role="status">Listing edit applied from the saved result.</p>}
    {notice && <p role="status">{notice}</p>}
    {reference
      ? <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
          onClick={() => void run(false)}>Check saved listing edit</button>
      : proposal && !receipt && <button className="ss-btn" type="button" disabled={busy || storageFault}
          onClick={() => void run(true)}>Confirm listing edit</button>}
  </section>;
}
