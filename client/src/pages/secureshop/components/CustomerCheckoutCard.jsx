import React, { useCallback, useEffect, useRef, useState } from 'react';
import { readCheckoutReference, saveCheckoutReference,
  clearCheckoutReference } from '../utils/checkoutReference.mjs';
import { decodeCheckoutOperation, decodeCheckoutProposal } from '../utils/customerTurnOperations.mjs';

const SHA = /^[a-f0-9]{64}$/;
const dollars = cents => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' })
  .format(cents / 100);

export default function CustomerCheckoutCard({ proposal, authorityKey, transport = globalThis.fetch,
  onChooseAnotherPayment }) {
  const [reference, setReference] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState('');
  const [storageFault, setStorageFault] = useState(false);
  const [busy, setBusy] = useState(false);
  const activeRef = useRef(null);
  const activeIntentRef = useRef(null);
  const epochRef = useRef(0);
  const mountedRef = useRef(false);
  const proposalId = proposal?.proposalId || null;
  const previousProposalIdRef = useRef(proposalId);

  const readExact = useCallback(async (saved, signal) => {
    const response = await transport(`/api/secureshop/customer/commerce/operations/${saved.operationId}`, {
      method: 'GET', headers: { accept: 'application/json' }, signal,
    });
    if (!response.ok) throw new Error(`Saved checkout lookup failed (${response.status})`);
    const value = await response.json();
    return decodeCheckoutOperation(value, saved);
  }, [transport]);

  useEffect(() => {
    mountedRef.current = true;
    epochRef.current += 1;
    activeRef.current?.abort();
    activeRef.current = null;
    activeIntentRef.current = null;
    setReference(null); setReceipt(null); setNotice(''); setBusy(false); setStorageFault(false);
    let saved;
    try { saved = readCheckoutReference(); }
    catch (error) {
      setStorageFault(true);
      setNotice('Saved checkout storage is unavailable. Confirmation is blocked.');
      return () => { mountedRef.current = false; epochRef.current += 1; };
    }
    if (saved) {
      setReference(saved);
      setNotice('A checkout request is saved. Check its exact outcome before confirming another.');
    }
    return () => {
      mountedRef.current = false;
      epochRef.current += 1;
      activeRef.current?.abort();
      activeRef.current = null;
      activeIntentRef.current = null;
    };
  }, [authorityKey, transport]);

  useEffect(() => {
    const changed = previousProposalIdRef.current !== proposalId;
    previousProposalIdRef.current = proposalId;
    // The exact saved operation, rather than the late chat card, owns recovery.
    // A different proposal still cancels an uncommitted confirmation preflight.
    if (changed && activeRef.current) {
      if (activeIntentRef.current?.kind === 'saved'
        && activeIntentRef.current.operationId === proposalId) return;
      activeRef.current.abort(); activeRef.current = null;
      activeIntentRef.current = null; epochRef.current += 1;
      setBusy(false);
      if (reference) setNotice('A checkout request is saved. Check its exact outcome before confirming another.');
    }
    if (activeRef.current || reference) return;
    if (changed || (receipt && proposalId && receipt.operationId !== proposalId)) {
      setReceipt(null); setNotice('');
    }
  }, [proposalId, reference, receipt, busy]);

  const run = async (confirm) => {
    if (activeRef.current) return;
    const controller = new AbortController();
    const epoch = epochRef.current;
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted;
    activeRef.current = controller;
    activeIntentRef.current = { kind: 'confirm', operationId: proposalId };
    setBusy(true); setNotice('');
    let saved = null;
    try {
      saved = readCheckoutReference();
      if (saved) {
        activeIntentRef.current = { kind: 'saved', operationId: saved.operationId };
        if (current()) setReference(saved);
        const outcome = await readExact(saved, controller.signal);
        if (!current()) return;
        if (outcome.status !== 'completed') {
          setNotice('This saved checkout is still unconfirmed. No confirmation was sent again.');
          return;
        }
        await clearCheckoutReference(saved);
        if (!current()) return;
        setReference(null); setReceipt(outcome.receipt);
        setNotice(outcome.receipt.status === 'approved' ? 'Order confirmed from the saved receipt.'
          : 'This practice checkout did not place an order. Request a fresh quote before trying again.');
        return;
      }
      if (!confirm || !proposal) return;
      decodeCheckoutProposal(proposal);
      const preflight = await transport(`/api/secureshop/customer/commerce/operations/${proposal.proposalId}`, {
        method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
      });
      if (!preflight.ok) throw new Error('Checkout quote could not be verified. No confirmation was sent.');
      const value = await preflight.json();
      if (!current()) return;
      if (!SHA.test(value?.scopeKey || '') || value.operationId !== proposal.proposalId
        || value.proposal?.quoteSha256 !== proposal.quoteSha256) {
        throw new Error('Checkout quote changed. Request a fresh quote.');
      }
      saved = { operationId: proposal.proposalId, intentDigest: proposal.quoteSha256,
        scopeKey: value.scopeKey };
      const checked = decodeCheckoutOperation(value, saved);
      if (checked.proposal.totalCents !== proposal.totalCents) {
        throw new Error('Checkout quote changed. Request a fresh quote.');
      }
      if (checked.status === 'completed') {
        setReceipt(checked.receipt);
        setNotice(checked.receipt.status === 'approved'
          ? 'Order confirmed from the saved receipt. No confirmation was sent again.'
          : 'This practice checkout did not place an order. No confirmation was sent again.');
        return;
      }
      await saveCheckoutReference(saved);
      if (!current()) return;
      const acknowledged = readCheckoutReference();
      if (!acknowledged || acknowledged.operationId !== saved.operationId
        || acknowledged.intentDigest !== saved.intentDigest
        || acknowledged.scopeKey !== saved.scopeKey) {
        throw new Error('Saved checkout changed before confirmation. No order was submitted.');
      }
      setReference(saved);
      // The exact parent-acknowledged reference precedes this single commit.
      // Any transport failure after dispatch is resolved only by GET.
      try {
        await transport('/api/secureshop/customer/commerce/checkout/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ proposalId: proposal.proposalId }), signal: controller.signal,
        });
      } catch { /* exact readback below decides the outcome */ }
      if (!current()) return;
      const outcome = await readExact(saved, controller.signal);
      if (!current()) return;
      if (outcome.status !== 'completed') {
        setNotice('Checkout outcome is unconfirmed. Check the saved checkout; no confirmation will be retried.');
        return;
      }
      await clearCheckoutReference(saved);
      if (!current()) return;
      setReference(null); setReceipt(outcome.receipt);
      setNotice(outcome.receipt.status === 'approved' ? 'Order confirmed from the saved receipt.'
        : 'This practice checkout did not place an order. Request a fresh quote before trying again.');
    } catch (error) {
      if (!current()) return;
      try { saved = readCheckoutReference(); } catch { /* no absence inference */ }
      if (saved) setReference(saved);
      setNotice(error instanceof Error ? error.message : 'Checkout outcome unavailable');
    } finally {
      if (current()) { activeRef.current = null; activeIntentRef.current = null; setBusy(false); }
    }
  };

  const chooseAnotherPayment = () => {
    if (activeRef.current || reference || busy || storageFault || receipt?.status !== 'declined'
      || receipt.operationId !== proposalId || typeof onChooseAnotherPayment !== 'function') return;
    try {
      const saved = readCheckoutReference();
      if (saved) {
        setReference(saved);
        setNotice('A checkout request is saved. Check its exact outcome before continuing.');
        return;
      }
    } catch {
      setStorageFault(true);
      setNotice('Saved checkout storage is unavailable. Check its exact outcome before continuing.');
      return;
    }
    onChooseAnotherPayment();
  };

  if (!proposal && !reference && !notice && !receipt) return null;
  return <section className="ss-card" aria-label="Customer checkout confirmation"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>SERVER QUOTE · PRACTICE CHECKOUT</div>
    {proposal && <>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review your order</h3>
      <ul>{proposal.items.map((item, index) => <li key={`${item.productId}:${index}`}>
        {item.name} · {item.quantity} × {dollars(item.unitPriceCents)} = {dollars(item.lineTotalCents)}
      </li>)}</ul>
      <p>Subtotal {dollars(proposal.subtotalCents)} · Discount {dollars(proposal.discountCents)}</p>
      <strong>Total {dollars(proposal.totalCents)}</strong>
      <p>Address: {proposal.address.title} · {proposal.address.detail}</p>
      <p>Practice payment: {proposal.paymentMethod.title} · {proposal.paymentMethod.detail}</p>
    </>}
    {receipt && <p role="status">{receipt.status === 'approved'
      ? `Order placed · ${dollars(receipt.totalCents)}`
      : receipt.status === 'declined' ? 'Practice payment declined. No order was placed.'
        : 'Quote changed. No order was placed.'}</p>}
    {notice && <p role="status">{notice}</p>}
    {receipt?.status === 'declined' && receipt.operationId === proposalId && !reference
      && !busy && !storageFault && typeof onChooseAnotherPayment === 'function' &&
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={chooseAnotherPayment}>Choose another payment method</button>}
    {reference
      ? <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
          onClick={() => void run(false)}>Check saved checkout</button>
      : proposal && !receipt && <button className="ss-btn" type="button" disabled={busy || storageFault}
          onClick={() => void run(true)}>Confirm this practice order</button>}
  </section>;
}
