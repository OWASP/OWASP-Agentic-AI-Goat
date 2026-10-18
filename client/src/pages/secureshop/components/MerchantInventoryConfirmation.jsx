import React, { useEffect, useRef, useState } from 'react';
import { decodeInventoryProposal, readInventoryReference, saveInventoryReference,
  replaceInventoryReference, clearInventoryReference, sameInventoryProposal,
  sameInventoryReference } from '../pages/merchant/inventoryReference.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const sameMode = (a, b) => !!a && !!b && a.version === b.version
  && a.featureId === b.featureId && a.policyVersion === b.policyVersion
  && a.effectiveMode === b.effectiveMode && a.scope?.kind === b.scope?.kind
  && a.scope?.id === b.scope?.id;
const digest = async message => [...new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',
  new TextEncoder().encode(message)))].map(byte => byte.toString(16).padStart(2, '0')).join('');

export default function MerchantInventoryConfirmation({ proposal, sessionId, requestId, authorityKey,
  transport = globalThis.fetch }) {
  const [reference, setReference] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState('');
  const [readySource, setReadySource] = useState(null);
  const [storageFault, setStorageFault] = useState(false);
  const [busy, setBusy] = useState(false);
  const activeRef = useRef(null);
  const epochRef = useRef(0), sourceEpochRef = useRef(0), activeKindRef = useRef(null);
  const mountedRef = useRef(false);
  const sourceKey = JSON.stringify([proposal, sessionId, requestId]);

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null; activeKindRef.current = null;
    setReference(null); setReceipt(null); setNotice(''); setReadySource(null);
    setStorageFault(false); setBusy(false);
    try {
      const saved = readInventoryReference();
      if (saved) { setReference(saved); setNotice('A stock request is saved. Check its exact outcome before confirming another.'); }
    } catch {
      setStorageFault(true); setNotice('Saved inventory state is unavailable. Confirmation is blocked.');
    }
    return () => {
      mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; activeKindRef.current = null;
    };
  }, [authorityKey, transport]);

  useEffect(() => {
    const sourceEpoch = ++sourceEpochRef.current, controller = new AbortController();
    setReadySource(null);
    if (activeKindRef.current === 'confirm') {
      activeRef.current?.abort(); activeRef.current = null; activeKindRef.current = null;
      setBusy(false);
    }
    if (!activeRef.current) try {
      const saved = readInventoryReference();
      if (saved) setReference(saved);
      else { setReceipt(null); setNotice(''); }
    } catch { setStorageFault(true); }
    if (proposal) {
      Promise.resolve().then(() => decodeInventoryProposal(proposal)).then(() =>
        transport('/api/secureshop/merchant/inventory/readiness', { signal: controller.signal }))
        .then(async response => {
          if (!response.ok) {
            try { await response.body?.cancel(); } catch { /* Preserve the readiness error. */ }
            throw Error('Inventory readiness unavailable.');
          }
          const value = await response.json();
          if (mountedRef.current && sourceEpochRef.current === sourceEpoch && !controller.signal.aborted) {
            setReadySource(value.ready === true && value.scopeKey === proposal.scopeKey
              && sameMode(value.modeCapability, proposal.modeCapability) ? sourceKey : null);
          }
        }).catch(() => {
          if (mountedRef.current && sourceEpochRef.current === sourceEpoch && !controller.signal.aborted)
            setNotice('Inventory readiness unavailable. Confirmation is blocked.');
        });
    }
    return () => controller.abort();
  }, [authorityKey, sourceKey, transport]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/merchant/inventory/operations/${saved.requestId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) throw Error(`Saved inventory lookup failed (${response.status})`);
    const value = await response.json();
    if (value?.requestId !== saved.requestId
      || !['not_found', 'pending', 'uncertain', 'completed'].includes(value.status)
      || (value.status === 'completed' && (value.ok !== true || typeof value.answer !== 'string'
        || !Array.isArray(value.operations) || value.operations.length > 20))) {
      throw Error('Saved inventory receipt is invalid.');
    }
    return value;
  };

  const showOutcome = async (saved, outcome, current) => {
    if (!current()) return;
    if (outcome.status !== 'completed') {
      setNotice('Stock outcome is unconfirmed. Check the saved request; confirmation will not be retried.');
      return;
    }
    const judgment = outcome.grading?.judgment;
    if (judgment?.verdict === 'unavailable' && judgment.canRetry === true) {
      const next = saved.evaluationId === judgment.evaluationId ? saved
        : { ...saved, evaluationId: judgment.evaluationId,
          retryRequestId: globalThis.crypto.randomUUID() };
      if (next !== saved) await replaceInventoryReference(saved, next);
      if (!current()) return;
      setReference(next); setReceipt(outcome);
      setNotice('Stock result saved. Grading is unavailable; open Inventory to review retry eligibility.');
      return;
    }
    if (outcome.grading?.status === 'disabled' && saved.evaluationId) {
      setReference(saved); setReceipt(outcome);
      setNotice('Stock result saved. Open Inventory to review its saved grading request.');
      return;
    }
    await clearInventoryReference(saved, current);
    if (!current()) return;
    setReference(null); setReceipt(outcome);
    const effect = outcome.operations.find(row => row?.action === 'set_stock');
    setNotice(effect?.result?.applied === true
      ? 'Stock change confirmed from the saved result.'
      : 'Saved inventory result found. No stock change was applied.');
  };

  const run = async confirm => {
    if (activeRef.current) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const sourceEpoch = sourceEpochRef.current;
    let recovering = !confirm;
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted
      && (recovering || sourceEpochRef.current === sourceEpoch);
    activeRef.current = controller; activeKindRef.current = confirm ? 'confirm' : 'read';
    setBusy(true); setNotice('');
    let saved = null;
    try {
      saved = readInventoryReference();
      if (saved) {
        recovering = true; activeKindRef.current = 'read';
        if (current()) setReference(saved);
        await showOutcome(saved, await readExact(saved, controller.signal), current);
        return;
      }
      if (!confirm || !proposal || readySource !== sourceKey || storageFault || !UUID.test(sessionId || '')
        || !UUID.test(requestId || '')) return;
      decodeInventoryProposal(proposal);
      const readiness = await transport('/api/secureshop/merchant/inventory/readiness',
        { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!readiness.ok) {
        try { await readiness.body?.cancel(); } catch { /* Preserve the readiness error. */ }
        throw Error('Inventory readiness unavailable. No stock change was submitted.');
      }
      const available = await readiness.json();
      if (!current()) return;
      if (available.ready !== true || available.scopeKey !== proposal.scopeKey
        || !sameMode(available.modeCapability, proposal.modeCapability)) {
        throw Error('Inventory mode or scene changed. Request a fresh proposal.');
      }
      const source = await transport(`/api/secureshop/agents/merchant/assistant/operations/${sessionId}/${requestId}`,
        { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!source.ok) throw Error('Saved assistant proposal unavailable. No stock change was submitted.');
      const sourceValue = await source.json();
      if (!current()) return;
      const currentProposal = decodeInventoryProposal(sourceValue.inventoryProposal ?? null);
      if (sourceValue.sessionId !== sessionId || sourceValue.requestId !== requestId
        || sourceValue.status !== 'completed' || sourceValue.replayed !== true
        || sourceValue.stopReason !== 'end_turn'
        || trustedTurnMode(sourceValue.modeCapability)?.featureId !== 'merchant_assistant'
        || !sameInventoryProposal(currentProposal, proposal)) {
        throw Error('Saved stock proposal changed. Request a fresh proposal.');
      }
      const prior = await readExact({ requestId: proposal.proposalId }, controller.signal);
      if (!current()) return;
      if (prior.status !== 'not_found') {
        setNotice('A saved stock outcome already exists. Open Inventory to check it; no confirmation was sent.');
        return;
      }
      const stockChange = { productId: proposal.stockChange.productId,
        quantity: proposal.stockChange.quantity };
      saved = { version: 3, scopeKey: proposal.scopeKey, requestId: proposal.proposalId,
        digest: await digest(JSON.stringify({ version: 3, message: proposal.message,
          access: 'write', stockChange })),
        access: 'write', stockChange };
      if (!current()) return;
      await saveInventoryReference(saved);
      if (!current()) return;
      if (!sameInventoryReference(readInventoryReference(), saved)) {
        throw Error('Saved inventory request changed. No stock change was submitted.');
      }
      setReference(saved);
      // One parent-acknowledged POST; all uncertainty is resolved with exact GET.
      try {
        await transport('/api/secureshop/agents/merchant/assistant/inventory/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId, requestId, proposalId: saved.requestId }), signal: controller.signal,
        });
      } catch { /* The saved operation GET decides the outcome. */ }
      if (!current()) return;
      await showOutcome(saved, await readExact(saved, controller.signal), current);
    } catch (error) {
      if (!current()) return;
      try { saved = readInventoryReference(); } catch { /* Storage unreadability is never absence. */ }
      if (saved) setReference(saved);
      setNotice(error instanceof Error ? error.message : 'Stock outcome unavailable.');
    } finally {
      if (current()) { activeRef.current = null; activeKindRef.current = null; setBusy(false); }
    }
  };

  if (!proposal && !reference && !receipt && !notice) return null;
  return <section className="ss-card" aria-label="Merchant inventory confirmation"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {proposal && <>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>
        SAVED STOCK PROPOSAL · REVIEW BEFORE APPLYING
      </div>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review stock change</h3>
      <p><strong>{proposal.product.name}</strong> · new absolute stock quantity: {proposal.stockChange.quantity}</p>
      <p className="ss-mono" style={{ fontSize: 11 }}>Stock is unchanged until you confirm.</p>
    </>}
    {receipt && <p role="status">{receipt.operations.some(row => row?.action === 'set_stock'
      && row.result?.applied === true) ? 'Stock change applied.' : 'No stock change was applied.'}</p>}
    {notice && <p role="status">{notice}</p>}
    {reference
      ? <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
          onClick={() => void run(false)}>Check saved stock change</button>
      : proposal && !receipt && <button className="ss-btn" type="button"
          disabled={busy || storageFault || readySource !== sourceKey} onClick={() => void run(true)}>
          Confirm stock change</button>}
  </section>;
}
