import React, { useEffect, useRef, useState } from 'react';
import { readChatCartReference, saveChatCartReference,
  clearChatCartReference } from '../utils/chatCartReference.mjs';
import { decodeCartProposal, decodeCartOperation } from '../utils/customerTurnOperations.mjs';

const SHA = /^[a-f0-9]{64}$/;
const ACTION = Object.freeze({ 'cart.add': 'Add to cart', 'cart.update': 'Set cart quantity',
  'cart.remove': 'Remove from cart' });

export default function CustomerCartConfirmation({ proposal, authorityKey,
  onCartApplied, transport = globalThis.fetch }) {
  const [reference, setReference] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState('');
  const [storageFault, setStorageFault] = useState(false);
  const [busy, setBusy] = useState(false);
  const activeRef = useRef(null);
  const epochRef = useRef(0), sourceEpochRef = useRef(0), activeKindRef = useRef(null);
  const mountedRef = useRef(false);
  const sourceKey = JSON.stringify(proposal);

  useEffect(() => {
    mountedRef.current = true;
    epochRef.current += 1;
    activeRef.current?.abort(); activeRef.current = null; activeKindRef.current = null;
    setReference(null); setReceipt(null); setNotice(''); setStorageFault(false); setBusy(false);
    try {
      const saved = readChatCartReference();
      if (saved) {
        setReference(saved);
        setNotice('A cart change is saved. Check its exact outcome before confirming another.');
      }
    } catch {
      setStorageFault(true);
      setNotice('Saved cart state is unavailable. Confirmation is blocked.');
    }
    return () => {
      mountedRef.current = false;
      epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; activeKindRef.current = null;
    };
  }, [authorityKey, transport]);

  useEffect(() => {
    sourceEpochRef.current += 1;
    if (activeKindRef.current === 'confirm') {
      activeRef.current?.abort(); activeRef.current = null; activeKindRef.current = null;
      setBusy(false);
    }
    if (!activeRef.current) try {
      const saved = readChatCartReference();
      if (saved) setReference(saved);
      else { setReceipt(null); setNotice(''); }
    } catch { setStorageFault(true); }
  }, [authorityKey, sourceKey, transport]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/customer/commerce/operations/${saved.operationId}`, {
      method: 'GET', headers: { accept: 'application/json' }, signal,
    });
    if (!response.ok) throw new Error(`Saved cart lookup failed (${response.status})`);
    return decodeCartOperation(await response.json(), saved);
  };

  const run = async confirm => {
    if (activeRef.current) return;
    const controller = new AbortController();
    const epoch = epochRef.current;
    const sourceEpoch = sourceEpochRef.current;
    let recovering = !confirm;
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted
      && (recovering || sourceEpochRef.current === sourceEpoch);
    activeRef.current = controller; activeKindRef.current = confirm ? 'confirm' : 'read';
    setBusy(true); setNotice('');
    let saved = null;
    try {
      saved = readChatCartReference();
      if (saved) {
        recovering = true; activeKindRef.current = 'read';
        if (current()) setReference(saved);
        const outcome = await readExact(saved, controller.signal);
        if (!current()) return;
        if (outcome.status !== 'completed') {
          setNotice('The saved cart change is still unconfirmed. No confirmation was sent again.');
          return;
        }
        await clearChatCartReference(saved);
        if (!current()) return;
        setReference(null); setReceipt(outcome.receipt);
        if (outcome.receipt.status === 'completed') {
          let refreshed = false;
          try { refreshed = !!(await onCartApplied?.()); } catch { /* receipt remains authoritative */ }
          if (!current()) return;
          setNotice(refreshed ? 'Cart change confirmed from the saved receipt.'
            : 'Cart change applied, but the cart view could not refresh. Open Cart to check the latest items.');
        } else setNotice('Cart changed since this proposal. No change was applied; request a fresh proposal.');
        return;
      }
      if (!confirm || !proposal) return;
      decodeCartProposal(proposal);
      const preflight = await transport(`/api/secureshop/customer/commerce/operations/${proposal.proposalId}`, {
        method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
      });
      if (!preflight.ok) throw new Error('Cart proposal could not be verified. No change was submitted.');
      const value = await preflight.json();
      if (!current()) return;
      if (!SHA.test(value?.scopeKey || '') || value.operationId !== proposal.proposalId
        || value.proposal?.quoteSha256 !== proposal.quoteSha256) {
        throw new Error('Cart proposal changed. Request a fresh proposal.');
      }
      saved = { operationId: proposal.proposalId, intentDigest: proposal.quoteSha256,
        scopeKey: value.scopeKey };
      const checked = decodeCartOperation(value, saved);
      if (checked.proposal.kind !== proposal.kind || checked.proposal.choice.choiceId !== proposal.choice.choiceId
        || checked.proposal.quantity !== proposal.quantity) {
        throw new Error('Cart proposal changed. Request a fresh proposal.');
      }
      if (checked.status === 'completed') {
        setReceipt(checked.receipt);
        if (checked.receipt.status === 'completed') {
          let refreshed = false;
          try { refreshed = !!(await onCartApplied?.()); } catch { /* receipt remains authoritative */ }
          if (!current()) return;
          setNotice(refreshed ? 'This cart change already has a saved receipt. No confirmation was sent.'
            : 'Cart change was already applied, but the cart view could not refresh. Open Cart to check it.');
        } else setNotice('This cart proposal is stale. No confirmation was sent.');
        return;
      }
      await saveChatCartReference(saved);
      if (!current()) return;
      const acknowledged = readChatCartReference();
      if (!acknowledged || acknowledged.operationId !== saved.operationId
        || acknowledged.intentDigest !== saved.intentDigest || acknowledged.scopeKey !== saved.scopeKey) {
        throw new Error('Saved cart confirmation changed before submission. No change was sent.');
      }
      setReference(saved);
      // This is the only mutation attempt. An unknown response always uses
      // the saved operation GET and never replays the POST.
      try {
        await transport('/api/secureshop/customer/commerce/cart/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ proposalId: saved.operationId }), signal: controller.signal,
        });
      } catch { /* exact GET below decides the saved outcome */ }
      if (!current()) return;
      const outcome = await readExact(saved, controller.signal);
      if (!current()) return;
      if (outcome.status !== 'completed') {
        setNotice('Cart outcome is unconfirmed. Check the saved change; confirmation will not be retried.');
        return;
      }
      await clearChatCartReference(saved);
      if (!current()) return;
      setReference(null); setReceipt(outcome.receipt);
      if (outcome.receipt.status === 'completed') {
        let refreshed = false;
        try { refreshed = !!(await onCartApplied?.()); } catch { /* receipt remains authoritative */ }
        if (!current()) return;
        setNotice(refreshed ? 'Cart change confirmed from the saved receipt.'
          : 'Cart change applied, but the cart view could not refresh. Open Cart to check the latest items.');
      } else setNotice('Cart changed since this proposal. No change was applied; request a fresh proposal.');
    } catch (error) {
      if (!current()) return;
      try { saved = readChatCartReference(); } catch { /* never infer no pending operation */ }
      if (saved) setReference(saved);
      setNotice(error instanceof Error ? error.message : 'Cart outcome unavailable');
    } finally {
      if (current()) { activeRef.current = null; activeKindRef.current = null; setBusy(false); }
    }
  };

  if (!proposal && !reference && !receipt && !notice) return null;
  return <section className="ss-card" aria-label="Customer cart confirmation"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>SAVED CART PROPOSAL · REVIEW BEFORE APPLYING</div>
    {proposal && <>
      <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review cart change</h3>
      <p><strong>{ACTION[proposal.kind]}</strong>: {proposal.choice.title}</p>
      <p>{proposal.choice.detail}</p>
      <p>{proposal.kind === 'cart.remove' ? 'Remove this item from your cart.'
        : proposal.kind === 'cart.update' ? `New absolute quantity: ${proposal.quantity}`
          : `Quantity to add: ${proposal.quantity}`}</p>
      <p className="ss-mono" style={{ fontSize: 11 }}>Your cart is unchanged until you confirm.</p>
    </>}
    {receipt && <p role="status">{receipt.status === 'completed'
      ? 'Cart change applied.' : 'The proposal is stale. No cart change was applied.'}</p>}
    {notice && <p role="status">{notice}</p>}
    {reference
      ? <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
          onClick={() => void run(false)}>Check saved cart change</button>
      : proposal && !receipt && <button className="ss-btn" type="button" disabled={busy || storageFault}
          onClick={() => void run(true)}>Confirm cart change</button>}
  </section>;
}
