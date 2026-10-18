import React, { useEffect, useRef, useState } from 'react';
import { SafeChatBody } from '../../../components/workshop/WorkshopExperience.js';
import { decodePricingProposal, pricingBlockedResult, pricingRequestDigest, pricingResult,
  samePricingProposal } from '../pages/merchant/pricingOperation.mjs';
import { clearPricingReference, readPricingReferences,
  savePricingReference } from '../pages/merchant/pricingRecovery.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import PricingComparisonCard from './PricingComparisonCard.jsx';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;

export default function MerchantPricingConfirmation({ proposal, sessionId, requestId, authorityKey,
  transport = globalThis.fetch }) {
  const [reference, setReference] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState('');
  const [readyScope, setReadyScope] = useState(null);
  const [storageFault, setStorageFault] = useState(false);
  const [busy, setBusy] = useState(false);
  const activeRef = useRef(null), epochRef = useRef(0), mountedRef = useRef(false);
  const proposalId = proposal?.proposalId || null;

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current, controller = new AbortController();
    activeRef.current?.abort(); activeRef.current = null;
    setReference(null); setReceipt(null); setNotice(''); setReadyScope(null);
    setStorageFault(false); setBusy(false);
    let rows = null;
    try { rows = readPricingReferences(); } catch {
      setStorageFault(true); setNotice('Saved Pricing state is unavailable. Confirmation is blocked.');
    }
    const cleanup = () => { mountedRef.current = false; epochRef.current += 1;
      controller.abort(); activeRef.current?.abort(); activeRef.current = null; };
    if (rows === null || (!proposal && rows.length === 0)) return cleanup;
    Promise.resolve().then(() => transport('/api/secureshop/merchant/pricing/run', {
      method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
    })).then(async response => {
      if (!response.ok) {
        try { await response.body?.cancel(); } catch { /* Preserve the availability error. */ }
        throw Error('Pricing availability unavailable.');
      }
      const value = await response.json();
      if (value?.ok !== true || value.administration?.versionedPricing !== true
        || !SHA.test(value.administration.scopeKey)) throw Error('Pricing availability unavailable.');
      if (!mountedRef.current || epochRef.current !== epoch || controller.signal.aborted) return;
      const scopeKey = value.administration.scopeKey;
      setReadyScope(scopeKey);
      const saved = readPricingReferences().find(row => row.scopeKey === scopeKey) || null;
      if (saved) {
        setReference(saved);
        setNotice('A Pricing operation is saved. Check its exact outcome before confirming another.');
      }
    }).catch(error => {
      if (mountedRef.current && epochRef.current === epoch && !controller.signal.aborted)
        setNotice(error?.message || 'Pricing availability unavailable.');
    });
    return cleanup;
  }, [authorityKey, proposalId, requestId, sessionId, transport]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/merchant/pricing/operations/${saved.operationId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok && ![202, 404].includes(response.status))
      throw Error(`Saved Pricing lookup failed (${response.status})`);
    const value = await response.json();
    const result = value.state === 'blocked'
      ? await pricingBlockedResult(value, saved,
        proposal?.proposalId === saved.operationId ? proposal.competitorUrl : undefined)
      : pricingResult(value, saved);
    if (result.state === 'completed' && value.modeCapability
      && trustedTurnMode(value.modeCapability)?.featureId !== 'pricing')
      throw Error('Saved Pricing mode is invalid.');
    return result;
  };

  const showOutcome = async (saved, result, current) => {
    if (!current()) return;
    if (result.state !== 'completed' && result.state !== 'not_executed' && result.state !== 'blocked') {
      setReference(saved);
      setNotice(`Pricing outcome is ${result.state}. Check the saved operation; confirmation will not be retried.`);
      return;
    }
    await clearPricingReference(saved, current);
    if (!current()) return;
    setReference(null); setReceipt(result);
    setNotice(result.state === 'blocked'
      ? 'Comparison blocked by fixed-mode policy. No competitor request was made.'
      : result.state === 'completed'
        ? 'Pricing analysis completed from the saved result. No product price was applied.'
        : 'Saved Pricing request was not executed. No product price was changed.');
  };

  const run = async confirm => {
    if (activeRef.current) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted;
    activeRef.current = controller; setBusy(true); setNotice('');
    let saved = null;
    try {
      const rows = readPricingReferences();
      if (!readyScope || storageFault) throw Error('Pricing availability or saved state is unavailable.');
      saved = rows.find(row => row.scopeKey === readyScope) || null;
      if (saved) {
        if (current()) setReference(saved);
        await showOutcome(saved, await readExact(saved, controller.signal), current);
        return;
      }
      if (!confirm || !proposal || !UUID.test(sessionId || '') || !UUID.test(requestId || '')) return;
      const candidate = decodePricingProposal(proposal);
      if (candidate.scopeKey !== readyScope) throw Error('Pricing scene changed. Request a fresh proposal.');
      const capability = await transport('/api/secureshop/merchant/pricing/run', {
        method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
      });
      if (!capability.ok) {
        try { await capability.body?.cancel(); } catch { /* Preserve the availability error. */ }
        throw Error('Pricing availability unavailable. No analysis was submitted.');
      }
      const available = await capability.json();
      if (!current()) return;
      if (available?.ok !== true || available.administration?.versionedPricing !== true
        || available.administration.scopeKey !== candidate.scopeKey)
        throw Error('Pricing scene changed. Request a fresh proposal.');
      const source = await transport(`/api/secureshop/agents/merchant/assistant/operations/${sessionId}/${requestId}`,
        { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!source.ok) throw Error('Saved assistant proposal unavailable. No analysis was submitted.');
      const sourceValue = await source.json();
      if (!current()) return;
      if (sourceValue.sessionId !== sessionId || sourceValue.requestId !== requestId
        || sourceValue.status !== 'completed' || sourceValue.replayed !== true
        || sourceValue.stopReason !== 'end_turn'
        || trustedTurnMode(sourceValue.modeCapability)?.featureId !== 'merchant_assistant'
        || !samePricingProposal(sourceValue.pricingProposal, candidate))
        throw Error('Saved Pricing proposal changed. Request a fresh proposal.');
      const request = { operationId: candidate.proposalId, productId: candidate.productId,
        message: candidate.message, ...(candidate.experiment ? { experiment: candidate.experiment } : {}),
        ...(candidate.action === 'compare' ? { competitorUrl: candidate.competitorUrl } : {}) };
      if (await pricingRequestDigest(request) !== candidate.requestSha256)
        throw Error('Saved Pricing request digest changed. No analysis was submitted.');
      if (!current()) return;
      saved = { scopeKey: candidate.scopeKey, operationId: candidate.proposalId,
        productId: candidate.productId, action: candidate.action,
        requestSha256: candidate.requestSha256 };
      await savePricingReference(saved);
      if (!current()) return;
      const persisted = readPricingReferences().find(row => row.scopeKey === saved.scopeKey);
      if (!persisted || !Object.keys(saved).every(key => persisted[key] === saved[key]))
        throw Error('Saved Pricing reference changed. No analysis was submitted.');
      setReference(saved);
      const prior = await readExact(saved, controller.signal);
      if (!current()) return;
      if (prior.state !== 'not_found') {
        await showOutcome(saved, prior, current);
        return;
      }
      const beforePost = readPricingReferences().find(row => row.scopeKey === saved.scopeKey);
      if (!beforePost || !Object.keys(saved).every(key => beforePost[key] === saved[key]))
        throw Error('Saved Pricing reference changed. No analysis was submitted.');
      // Only this parent-acknowledged proposal ID can be confirmed. Unknown responses use GET only.
      try {
        await transport('/api/secureshop/agents/merchant/assistant/pricing/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId, requestId, proposalId: saved.operationId }),
          signal: controller.signal,
        });
      } catch { /* The exact Pricing operation GET determines the outcome. */ }
      if (!current()) return;
      await showOutcome(saved, await readExact(saved, controller.signal), current);
    } catch (error) {
      if (!current()) return;
      try {
        saved = readPricingReferences().find(row => row.scopeKey === readyScope) || null;
        setReference(saved);
      } catch {
        // Unreadable storage is never evidence that the request was removed.
        setStorageFault(true);
        if (saved) setReference(saved);
      }
      setNotice(error instanceof Error ? error.message : 'Pricing outcome unavailable.');
    } finally {
      if (current()) { activeRef.current = null; setBusy(false); }
    }
  };

  if (!proposal && !reference && !receipt && !notice) return null;
  return <section className="ss-card" aria-label="Merchant pricing confirmation"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {proposal && <>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>
        SAVED PRICING PROPOSAL · REVIEW BEFORE RUNNING
      </div>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review pricing analysis</h3>
      <p><strong>{proposal.product.name}</strong> · {proposal.action === 'experiment'
        ? `${proposal.experiment?.strategy} experiment for ${proposal.experiment?.durationDays} days`
        : proposal.action === 'compare' ? 'competitor comparison' : 'price suggestion'}</p>
      <p className="ss-mono" data-testid="pricing-proposal-message"
        style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
        {proposal.message}
      </p>
      {proposal.action === 'compare' && <p className="ss-mono" style={{ overflowWrap: 'anywhere' }}>
        Competitor URL: {proposal.competitorUrl}
      </p>}
      <p className="ss-mono" style={{ fontSize: 11 }}>
        This runs analysis only. It does not apply a product price.
      </p>
    </>}
    {receipt?.state === 'completed' && <div role="status">
      <strong>Saved Pricing analysis</strong>
      {receipt.modelComparison
        ? <PricingComparisonCard comparison={receipt.modelComparison} />
        : <SafeChatBody content={receipt.response} />}
      {receipt.modelComparison && typeof receipt.observation?.competitor_response === 'string'
        && <details><summary>Competitor response (verbatim)</summary>
          <pre className="ss-mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
            {receipt.observation.competitor_response}
          </pre>
        </details>}
    </div>}
    {receipt?.state === 'blocked' && <div role="status" aria-label="Blocked pricing comparison">
      The saved comparison was blocked by fixed-mode policy. No competitor request was made.
    </div>}
    {notice && <p role="status">{notice}</p>}
    {reference
      ? <button className="ss-btn ss-btn--ghost" type="button" disabled={busy || !readyScope}
          onClick={() => void run(false)}>Check saved pricing operation</button>
      : proposal && !receipt && <button className="ss-btn" type="button"
          disabled={busy || storageFault || readyScope !== proposal.scopeKey}
          onClick={() => void run(true)}>Confirm pricing analysis</button>}
  </section>;
}
