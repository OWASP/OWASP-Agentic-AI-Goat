import React, { useEffect, useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { Check, ArrowLeft, ArrowRight, Sparkles, PartyPopper, CreditCard, Home } from 'lucide-react';

import Button from '../components/Button.jsx';
import Card from '../components/Card.jsx';
import Input from '../components/Input.jsx';
import Spinner from '../components/Spinner.jsx';
import { useCart } from '../context/CartContext.jsx';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext.jsx';
import { shopStorage } from '../utils/shopStorage.mjs';
import { readCheckoutReference, saveCheckoutReference, clearCheckoutReference, checkoutIntentDigest } from '../utils/checkoutReference.mjs';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { decodeCheckoutOperation } from '../utils/customerTurnOperations.mjs';
import PracticePaymentSetup from '../components/PracticePaymentSetup.jsx';
import PracticeAddressSetup from '../components/PracticeAddressSetup.jsx';
import { decodeAddressCards } from '../utils/addressSetupOperation.mjs';

const STEPS = ['Shipping', 'Payment', 'Review'];
const SHA = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CARD_KINDS = new Set(['address', 'payment_method']);
const cardChoice = value => value && Object.getPrototypeOf(value) === Object.prototype
  && value.version === 1 && CARD_KINDS.has(value.kind) && UUID.test(value.choiceId || '')
  && typeof value.title === 'string' && value.title.trim() && value.title.length <= 256
  && typeof value.detail === 'string' && value.detail.trim() && value.detail.length <= 512;
const proposalChoice = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === 'choiceId,detail,title'
  && UUID.test(value.choiceId || '') && typeof value.title === 'string' && value.title.trim()
  && value.title.length <= 256 && typeof value.detail === 'string' && value.detail.trim()
  && value.detail.length <= 512;
const cardsPayload = (value, kind) => value && Object.getPrototypeOf(value) === Object.prototype
  && SHA.test(value.scopeKey || '') && Array.isArray(value.cards)
  && value.cards.length <= (kind === 'address' ? 32 : 12)
  && value.cards.every(card => cardChoice(card) && card.kind === kind) ? value : null;
const proposalPayload = value => value && Object.getPrototypeOf(value) === Object.prototype
  && SHA.test(value.scopeKey || '') && value.version === 1 && UUID.test(value.proposalId || '')
  && value.status === 'prepared' && value.currency === 'USD' && SHA.test(value.quoteSha256 || '')
  && proposalChoice(value.address) && proposalChoice(value.paymentMethod) ? value : null;
const confirmationPayload = value => value && Object.getPrototypeOf(value) === Object.prototype
  && SHA.test(value.scopeKey || '') && value.version === 1 && UUID.test(value.operationId || '')
  && value.kind === 'checkout.confirm' && ['approved', 'declined', 'stale'].includes(value.status)
  && value.currency === 'USD' && Number.isSafeInteger(value.totalCents) && value.totalCents >= 0
  && typeof value.replayed === 'boolean' ? value : null;
const money = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
function validReceipt(value, operationId, scopeKey) {
  const order = value?.order;
  if (value?.scopeKey !== scopeKey || value?.operationId !== operationId || value?.status !== 'completed'
      || !Number.isSafeInteger(order?.id) || order.id < 1 || !money(order.total)
      || !money(order.subtotal) || !money(order.discount)) throw Error('Saved order receipt unavailable');
  return order;
}

export default function Checkout() {
  const { items, subtotal, total, coupon, discount, clear, reload, loading, error } = useCart();
  const { user, token } = useAuth();
  const toast = useToast();
  const nav = useNavigate();
  const reduce = useReducedMotion();
  const bound = Boolean(getBridgeFetchMetadata(window.fetch));
  const checkoutRequestRef = useRef(null);
  const activeRequest = useRef(null);
  const mounted = useRef(false);
  const identity = JSON.stringify([user?.id, token]);
  const currentIdentity = useRef(identity);
  currentIdentity.current = identity;
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; activeRequest.current?.abort(); };
  }, []);
  useEffect(() => {
    checkoutRequestRef.current = null;
    activeRequest.current?.abort();
    activeRequest.current = null;
    setPlacing(false);
    setPayPhase(null);
    setPlaced(null);
    setHistoricalReceipt(null);
    setPreparedProposal(null);
    setConfirmEligible(false);
    setShowAddressSetup(false);
  }, [identity]);

  const [step, setStep] = useState(0);
  const [placing, setPlacing] = useState(false);
  const [placed, setPlaced] = useState(null);
  const [payPhase, setPayPhase] = useState(null); // null | 'authorizing' | 'approved'

  const [ship, setShip] = useState({
    full_name: user?.full_name || '',
    address: '', city: '', state: '', zip: '', phone: '',
  });
  const currentShipping = useRef(ship);
  currentShipping.current = ship;
  const [showAddressSetup, setShowAddressSetup] = useState(false);
  const [pay, setPay] = useState({ name: '', number: '', expiry: '', cvv: '', save: true, choiceId: '', title: '', detail: '' });
  const [boundChoices, setBoundChoices] = useState({ status: bound ? 'idle' : 'ready', scopeKey: null, addresses: [], payments: [], error: null });
  const [choicesRefresh, setChoicesRefresh] = useState(0);
  const [summary, setSummary] = useState(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [history, setHistory] = useState({ status: bound ? 'loading' : 'ready', scopeKey: null, operations: [], reference: null, error: null });
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [historicalReceipt, setHistoricalReceipt] = useState(null);
  const [preparedProposal, setPreparedProposal] = useState(null);
  const [confirmEligible, setConfirmEligible] = useState(false);

  useEffect(() => {
    if (!bound || step !== 1) return undefined;
    const controller = new AbortController();
    const requestFetch = window.fetch;
    const current = () => !controller.signal.aborted && mounted.current
      && currentIdentity.current === identity && window.fetch === requestFetch;
    setBoundChoices(value => ({ ...value, status: 'loading', error: null }));
    (async () => {
      try {
        const headers = { Authorization: `Bearer ${token}` };
        const [addressesResponse, paymentsResponse] = await Promise.all([
          requestFetch('/api/secureshop/customer/commerce/addresses', { signal: controller.signal, headers }),
          requestFetch('/api/secureshop/customer/commerce/payment-methods', { signal: controller.signal, headers }),
        ]);
        const [addressesValue, paymentsValue] = await Promise.all([
          addressesResponse.json(), paymentsResponse.json(),
        ]);
        const addressesPayload = addressesResponse.ok && cardsPayload(addressesValue, 'address');
        const paymentsPayload = paymentsResponse.ok && cardsPayload(paymentsValue, 'payment_method');
        if (!addressesPayload || !paymentsPayload || addressesPayload.scopeKey !== paymentsPayload.scopeKey)
          throw Error('Practice payment choices are unavailable');
        if (!current()) return;
        const addresses = addressesPayload.cards, payments = paymentsPayload.cards;
        setBoundChoices({ status: 'ready', scopeKey: addressesPayload.scopeKey, addresses, payments, error: null });
        setPay(value => {
          const payment = payments.find(card => card.choiceId === value.choiceId) || payments[0];
          const address = addresses.find(card => card.choiceId === value.addressChoiceId);
          return { ...value, choiceId: payment?.choiceId || '', title: payment?.title || '', detail: payment?.detail || '',
            addressChoiceId: address?.choiceId || '', addressTitle: address?.title || '', addressDetail: address?.detail || '' };
        });
      } catch (cause) {
        if (current()) setBoundChoices({ status: 'error', scopeKey: null, addresses: [], payments: [],
          error: cause?.message || 'Practice payment choices are unavailable' });
      }
    })();
    return () => controller.abort();
  }, [bound, step, identity, token, choicesRefresh]);

  useEffect(() => {
    if (!bound) {
      setHistory({ status: 'ready', scopeKey: null, operations: [], reference: null, error: null });
      return undefined;
    }
    // Bound checkout recovery is intentionally an exact operation GET, never an
    // orders-list fallback. The persisted reference already carries its scope.
    try {
      const reference = readCheckoutReference();
      setHistory({ status: 'ready', scopeKey: reference?.scopeKey || null, operations: [], reference, error: null });
    } catch (cause) {
      setHistory({ status: 'error', scopeKey: null, operations: [], reference: null,
        error: cause?.message || 'Saved checkout unavailable' });
    }
    return undefined;
  }, [bound, identity, historyRefresh]);


  const readReceipt = async (operationId, scopeKey, requestFetch = window.fetch, signal) => {
    const response = await requestFetch(`/api/secureshop/orders/operations/${operationId}`, {
      signal, headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw Error('Checkout outcome is not confirmed. Your saved reference is retained.');
    return validReceipt(await response.json(), operationId, scopeKey);
  };

  const checkSavedOrder = async () => {
    if (activeRequest.current || history.status !== 'ready' || !history.reference || !mounted.current) return;
    if (history.reference.scopeKey !== history.scopeKey) {
      toast.error('This saved checkout belongs to another shop practice. Its reference is retained.'); return;
    }
    const controller = new AbortController();
    const requestFetch = window.fetch;
    activeRequest.current = controller;
    setPlacing(true);
    try {
      let boundOperation = null;
      let legacyBoundReceipt = false;
      let order = null;
      if (bound) {
        try {
          boundOperation = await readBoundOperation(history.reference.operationId, history.reference,
            requestFetch, controller.signal);
        } catch (cause) {
          // Old bound references used the original orders receipt endpoint. Its
          // exact GET remains supported, but only after the new typed operation
          // endpoint explicitly says this operation does not exist.
          if (cause?.code !== 'BOUND_CHECKOUT_NOT_FOUND') throw cause;
          order = await readReceipt(history.reference.operationId, history.scopeKey, requestFetch, controller.signal);
          legacyBoundReceipt = true;
        }
        if (boundOperation?.status === 'completed') {
          const receipt = boundOperation.receipt;
          if (receipt?.status === 'declined' || receipt?.status === 'stale') {
            if (controller.signal.aborted || currentIdentity.current !== identity || window.fetch !== requestFetch) return;
            await clearCheckoutReference(history.reference);
            if (!controller.signal.aborted && currentIdentity.current === identity) {
              checkoutRequestRef.current = null;
              setHistory(value => ({ ...value, reference: null }));
              setPreparedProposal(null);
              setConfirmEligible(false);
              toast.error(receipt.status === 'declined'
                ? 'This synthetic practice payment was declined. Your cart is unchanged.'
                : 'This checkout quote is stale. Request a fresh quote before trying again.');
            }
            return;
          }
          order = receipt?.status === 'approved' ? receipt.order : null;
        }
        if (boundOperation?.status === 'prepared') {
          setPreparedProposal(boundOperation.proposal);
          setConfirmEligible(false);
          return;
        }
      } else {
        order = await readReceipt(history.reference.operationId, history.scopeKey, requestFetch, controller.signal);
      }
      const orderId = legacyBoundReceipt || !bound ? order?.id : order?.orderId;
      if (!order || !Number.isSafeInteger(orderId) || !money(order.total))
        throw Error('Checkout outcome is not confirmed. Your saved reference is retained.');
      if (controller.signal.aborted || currentIdentity.current !== identity || window.fetch !== requestFetch) return;
      try { await clearCheckoutReference(history.reference); }
      catch {
        if (!controller.signal.aborted) {
          setHistory(value => ({ ...value, receiptConfirmed: true }));
          toast.error('Order receipt confirmed, but the saved reference could not be cleared. Check it again.');
        }
        return;
      }
      if (controller.signal.aborted || currentIdentity.current !== identity) return;
      checkoutRequestRef.current = null;
      setHistory(value => ({ ...value, reference: null }));
      setPreparedProposal(null);
      setConfirmEligible(false);
      setPlaced({ order_id: orderId, total: order.total, recovered: true });
    } catch (cause) {
      if (!controller.signal.aborted) toast.error(cause.message || 'Saved order receipt unavailable');
    } finally {
      if (activeRequest.current === controller) activeRequest.current = null;
      if (mounted.current) setPlacing(false);
    }
  };

  const readHistoricalOrder = async operationId => {
    if (activeRequest.current || history.status !== 'ready' || !UUID.test(operationId)) return;
    const controller = new AbortController();
    const requestFetch = window.fetch;
    activeRequest.current = controller;
    try {
      const order = await readReceipt(operationId, history.scopeKey, requestFetch, controller.signal);
      if (!controller.signal.aborted && currentIdentity.current === identity && window.fetch === requestFetch)
        setHistoricalReceipt({ id: order.id, total: order.total });
    } catch (cause) {
      if (!controller.signal.aborted) toast.error(cause.message || 'Saved order receipt unavailable');
    } finally { if (activeRequest.current === controller) activeRequest.current = null; }
  };

  useEffect(() => {
    if (!items.length && !placed && !loading && !error && history.status === 'ready'
      && (!bound || (!history.reference && history.operations.length === 0))) {
      const t = setTimeout(() => { if (!items.length && !placed) nav('/secureshop/cart', { replace: true }); }, 400);
      return () => clearTimeout(t);
    }
  }, [items.length, placed, loading, error, history, bound, nav]);

  const nextStep = () => setStep((s) => Math.min(STEPS.length - 1, s + 1));
  const prevStep = () => setStep((s) => Math.max(0, s - 1));
  const continueShipping = async () => {
    if (!bound) return nextStep();
    const required = ['full_name', 'address', 'city', 'state', 'zip'];
    if (required.some(key => !String(ship[key] || '').trim())) {
      toast.error('Complete the delivery address before continuing.'); return;
    }
    try {
      const requestFetch = window.fetch;
      const headers = { 'content-type': 'application/json', Authorization: `Bearer ${token}` };
      const existingResponse = await requestFetch('/api/secureshop/customer/commerce/addresses', { headers });
      const existing = existingResponse.ok && decodeAddressCards(await existingResponse.json());
      if (!mounted.current || currentIdentity.current !== identity || window.fetch !== requestFetch
        || currentShipping.current !== ship) return;
      if (!existing) throw Error('Saved practice addresses are unavailable');
      // Display cards are not enough to identify typed delivery details. Use the
      // protected structured rows and preserve the server-issued choice ID.
      const delivery = { line1: ship.address, line2: null, city: ship.city,
        state: ship.state, zip: ship.zip, phone: ship.phone };
      const field = value => typeof value === 'string' && value.trim() ? value : null;
      const match = existing.addresses.find(row => Object.entries(delivery)
        .every(([key, value]) => row.fields[key] === field(value)));
      const selected = existing.cards.find(card => card.choiceId === match?.choiceId);
      setPay(value => ({ ...value, addressChoiceId: selected?.choiceId || '',
        addressTitle: selected?.title || '', addressDetail: selected?.detail || '' }));
      if (!selected) {
        setShowAddressSetup(true);
        return;
      }
      setShowAddressSetup(false);
      setStep(1);
    } catch (cause) { toast.error(cause?.message || 'Saved practice addresses are unavailable'); }
  };

  useEffect(() => {
    if (step !== 2) return;
    const controller = new AbortController();
    const requestFetch = window.fetch;
    let storedToken;
    setSummary(null);
    setSummaryLoading(true);
    try { storedToken = shopStorage.getItem('secureshop_v2_token'); }
    catch { setSummaryLoading(false); return; }
    const current = () => {
      if (controller.signal.aborted || currentIdentity.current !== identity ||
          window.fetch !== requestFetch) return false;
      try { return shopStorage.getItem('secureshop_v2_token') === storedToken; }
      catch { return false; }
    };
    if (bound && storedToken !== token) { setSummaryLoading(false); return; }
    requestFetch('/api/secureshop/orders/summary', {
      method: 'POST', signal: controller.signal,
      headers: { 'content-type': 'application/json', ...(bound && token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(bound ? {} : { user_id: user?.id || 1 }),
    })
      .then(r => { if (!r.ok) throw new Error('Summary unavailable'); return r.json(); })
      .then(value => { if (current()) setSummary(value); })
      .catch(() => {})
      .finally(() => { if (current()) setSummaryLoading(false); });
    return () => controller.abort();
  }, [step, identity, bound, token]);

  // Wave 5B U5 — build a masked payment method identifier from the card fields
  // and send it with the order. We NEVER transmit or persist the raw PAN/CVV —
  // only "Card ending 4242" and the derived brand.
  const _brandFromNumber = (num) => {
    const s = String(num || '').replace(/\D/g, '');
    if (/^4/.test(s)) return 'Visa';
    if (/^(5[1-5]|2[2-7])/.test(s)) return 'Mastercard';
    if (/^3[47]/.test(s)) return 'Amex';
    if (/^6/.test(s)) return 'Discover';
    return 'Card';
  };
  const buildPaymentMethod = () => {
    if (bound) return pay.title || 'Synthetic practice payment';
    const digits = String(pay.number || '').replace(/\D/g, '');
    if (!digits) return 'card';
    const last4 = digits.slice(-4);
    const brand = _brandFromNumber(digits);
    return `${brand} ending ${last4}`;
  };

  const readBoundOperation = async (operationId, expectedReference, requestFetch, signal) => {
    const response = await requestFetch(`/api/secureshop/customer/commerce/operations/${operationId}`, {
      signal, headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw Error('Checkout outcome is not confirmed. Your saved reference is retained.');
    const value = await response.json();
    if (value && Object.getPrototypeOf(value) === Object.prototype
      && Object.keys(value).sort().join(',') === 'operationId,scopeKey,status'
      // Legacy checkout history and conversational checkout use different
      // authority-bound scope digest algorithms. The authenticated typed
      // absence proves only that the new protocol has no operation; the
      // legacy exact receipt GET below still validates the persisted scope.
      && SHA.test(value.scopeKey || '') && value.operationId === operationId
      && value.status === 'not_found') {
      const error = Error('Checkout operation was not found');
      error.code = 'BOUND_CHECKOUT_NOT_FOUND';
      throw error;
    }
    try { return decodeCheckoutOperation(value, expectedReference); }
    catch { throw Error('Checkout outcome is not confirmed. Your saved reference is retained.'); }
  };

  const placeBoundOrder = async ({ controller, requestFetch, current, confirmedHere = false }) => {
    if (boundChoices.status !== 'ready' || !boundChoices.scopeKey || !pay.addressChoiceId || !pay.choiceId)
      throw Error('Choose a saved delivery address and a practice payment first.');
    let reference = readCheckoutReference() || history.reference;
    if (reference) {
      const operation = await readBoundOperation(reference.operationId, reference, requestFetch, controller.signal);
      if (!current()) return;
      if (operation.status === 'prepared') {
        const sameRenderedProposal = preparedProposal?.proposalId === operation.proposal.proposalId
          && preparedProposal?.quoteSha256 === operation.proposal.quoteSha256;
        if (!sameRenderedProposal) {
          setPreparedProposal(operation.proposal);
          setConfirmEligible(false);
          setHistory(value => ({ ...value, scopeKey: reference.scopeKey, reference }));
          return;
        }
        if (!confirmEligible) {
          throw Error('Checkout outcome is unconfirmed. Use the saved receipt before starting a fresh quote.');
        }
        // Saving the reference is asynchronous across the parent bridge. Read
        // it again immediately before the sole confirmation POST so a foreign
        // replacement cannot authorize this quote.
        const acknowledged = readCheckoutReference();
        if (!acknowledged || acknowledged.operationId !== reference.operationId
          || acknowledged.intentDigest !== reference.intentDigest
          || acknowledged.scopeKey !== reference.scopeKey) {
          throw Error('Saved checkout changed before confirmation. No order was submitted.');
        }
        // This latch changes before dispatch. A lost/unknown response can only
        // be resolved by the exact operation GET, never another confirmation.
        setConfirmEligible(false);
        const confirmedResponse = await requestFetch('/api/secureshop/customer/commerce/checkout/confirm', {
          signal: controller.signal, method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ proposalId: reference.operationId }),
        });
        const confirmation = confirmedResponse.ok && confirmationPayload(await confirmedResponse.json());
        if (!confirmation || confirmation.scopeKey !== reference.scopeKey || confirmation.operationId !== reference.operationId)
          throw Error('Checkout outcome is unconfirmed. Your saved reference is retained; check saved order.');
        if (!current()) return;
        if (confirmation.status === 'declined' || confirmation.status === 'stale') {
          await clearCheckoutReference(reference);
          if (!current()) return;
          checkoutRequestRef.current = null;
          setHistory(value => ({ ...value, reference: null }));
          setPreparedProposal(null);
          setConfirmEligible(false);
          toast.error(confirmation.status === 'declined'
            ? 'This synthetic practice payment was declined. Your cart is unchanged.'
            : 'This checkout quote is stale. Request a fresh quote before trying again.');
          return;
        }
        if (confirmation.status !== 'approved') throw Error('Checkout outcome is unconfirmed. Your saved reference is retained; check saved order.');
        return placeBoundOrder({ controller, requestFetch, current, confirmedHere: true });
      }
      if (operation.status === 'completed' && ['declined', 'stale'].includes(operation.receipt?.status)
        && operation.receipt?.operationId === reference.operationId) {
        await clearCheckoutReference(reference);
        if (!current()) return;
        checkoutRequestRef.current = null;
        setHistory(value => ({ ...value, reference: null }));
        setPreparedProposal(null);
        setConfirmEligible(false);
        toast.error(operation.receipt.status === 'declined'
          ? 'This synthetic practice payment was declined. Your cart is unchanged.'
          : 'This checkout quote is stale. Request a fresh quote before trying again.');
        return;
      }
      if (operation.status !== 'completed' || operation.receipt?.status !== 'approved'
        || operation.receipt?.operationId !== reference.operationId) {
        throw Error('Checkout outcome is not confirmed. Your saved reference is retained.');
      }
      const order = operation.receipt.order;
      if (!Number.isSafeInteger(order?.orderId) || order.orderId < 1 || !money(order.total))
        throw Error('Checkout outcome is not confirmed. Your saved reference is retained.');
      await clearCheckoutReference(reference);
      if (!current()) return;
      checkoutRequestRef.current = null;
      setHistory(value => ({ ...value, reference: null }));
      setPreparedProposal(null);
      setConfirmEligible(false);
      if (!confirmedHere) {
        setPlaced({ order_id: order.orderId, total: order.total, recovered: true });
        return;
      }
      setPayPhase('approved');
      setPlaced({ order_id: order.orderId, total: order.total, payment_method: pay.title });
      clear();
      try { if (!await reload()) throw Error('Cart refresh unavailable'); }
      catch { if (current()) toast.error('Order placed, but cart refresh failed.'); }
      if (current()) toast.success(`Order #${order.orderId} placed`);
      return;
    }
    const operationId = globalThis.crypto.randomUUID().toLowerCase();
    const preparedResponse = await requestFetch('/api/secureshop/customer/commerce/checkout/prepare', {
      signal: controller.signal, method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ operationId, addressChoiceId: pay.addressChoiceId, paymentChoiceId: pay.choiceId }),
    });
    const prepared = preparedResponse.ok && proposalPayload(await preparedResponse.json());
    if (!prepared || prepared.scopeKey !== boundChoices.scopeKey) throw Error('Checkout preparation unavailable');
    if (!current()) return;
    reference = { operationId: prepared.proposalId, intentDigest: prepared.quoteSha256, scopeKey: prepared.scopeKey };
    await saveCheckoutReference(reference);
    if (!current()) return;
    const acknowledged = readCheckoutReference();
    if (!acknowledged || acknowledged.operationId !== reference.operationId
      || acknowledged.intentDigest !== reference.intentDigest || acknowledged.scopeKey !== reference.scopeKey) {
      throw Error('Saved checkout changed before confirmation. No order was submitted.');
    }
    checkoutRequestRef.current = { ...reference, identity, fetchImpl: requestFetch };
    setHistory(value => ({ ...value, scopeKey: reference.scopeKey, reference }));
    setPreparedProposal(prepared);
    setConfirmEligible(true);
  };

  const placeOrder = async () => {
    if (activeRequest.current || !mounted.current) return;
    if (bound && history.status !== 'ready') {
      toast.error('Saved checkout status is unavailable. Retry before placing an order.'); return;
    }
    let storedToken;
    try { storedToken = shopStorage.getItem('secureshop_v2_token'); } catch { return; }
    if (bound && storedToken !== token) return;
    const controller = new AbortController();
    activeRequest.current = controller;
    const requestFetch = window.fetch;
    const current = () => {
      if (!mounted.current || controller.signal.aborted ||
          currentIdentity.current !== identity || window.fetch !== requestFetch) return false;
      try { return shopStorage.getItem('secureshop_v2_token') === storedToken; }
      catch { return false; }
    };
    setPlacing(true);
    setPayPhase('authorizing');
    if (bound) {
      try { await placeBoundOrder({ controller, requestFetch, current }); }
      catch (cause) { if (current()) { setPayPhase(null); toast.error(cause.message || 'Checkout unavailable'); } }
      finally {
        if (activeRequest.current === controller) {
          activeRequest.current = null;
          if (mounted.current) { setPlacing(false); setPayPhase(null); }
        }
      }
      return;
    }
    let submitted = false;
    let receiptConfirmed = false;
    try {
      const shippingAddress = `${ship.full_name}\n${ship.address}\n${ship.city}, ${ship.state} ${ship.zip}\n${ship.phone}`;
      const paymentMethod = buildPaymentMethod();
      let operationId;
      let reference;
      if (bound) {
        const digest = await checkoutIntentDigest(shippingAddress, paymentMethod);
        if (!current()) return;
        reference = readCheckoutReference() || history.reference;
        if (reference && (reference.scopeKey !== history.scopeKey || reference.intentDigest !== digest))
          throw Error('A saved checkout needs its exact receipt checked before another order.');
        if (reference) {
          // A confirmed receipt is authoritative. Missing readback is never proof that a POST did not run.
          try {
            const order = await readReceipt(reference.operationId, history.scopeKey, requestFetch, controller.signal);
            if (!current()) return;
            receiptConfirmed = true;
            await clearCheckoutReference(reference);
            if (!current()) return;
            checkoutRequestRef.current = null;
            setHistory(value => ({ ...value, reference: null }));
            setPlaced({ order_id: order.id, total: order.total, recovered: true });
            return;
          } catch (cause) {
            if (cause.message !== 'Checkout outcome is not confirmed. Your saved reference is retained.') throw cause;
          }
          const admitted = checkoutRequestRef.current;
          if (!admitted || admitted.operationId !== reference.operationId || admitted.intentDigest !== digest
            || admitted.scopeKey !== history.scopeKey || admitted.identity !== identity || admitted.fetchImpl !== requestFetch)
            throw Error('Checkout outcome is unconfirmed. Check the saved order; this page will not submit it again.');
        } else {
          operationId = globalThis.crypto.randomUUID().toLowerCase();
          reference = { operationId, intentDigest: digest, scopeKey: history.scopeKey };
          await saveCheckoutReference(reference);
          if (!current()) return;
          checkoutRequestRef.current = { ...reference, identity, fetchImpl: requestFetch };
          setHistory(value => ({ ...value, reference }));
        }
        operationId = reference.operationId;
      }
      // Simulate an authorization delay so the "Authorizing…" UI reads.
      await new Promise((res) => setTimeout(res, 600));
      if (!current()) return;
      submitted = true;
      const r = await requestFetch('/api/secureshop/orders', {
        signal: controller.signal,
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(bound && token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({
          ...(bound ? {operationId} : { user_id: user?.id || 1 }),
          shipping_address: shippingAddress,
          payment_method: paymentMethod,
        }),
      });
      const j = await r.json();
      if (!current()) return;
      if (!r.ok || !j.ok) throw new Error(j.error || 'order failed');
      if (bound) {
        if (!Number.isSafeInteger(j.order_id) || j.order_id < 1 || !money(j.total)) throw Error('Order response was incomplete. Check the saved receipt.');
        const order = await readReceipt(operationId, history.scopeKey, requestFetch, controller.signal);
        if (!current()) return;
        if (order.id !== j.order_id || order.total !== j.total) throw Error('Order receipt did not match. The saved reference is retained.');
        receiptConfirmed = true;
        await clearCheckoutReference(reference);
        if (!current()) return;
        setHistory(value => ({ ...value, reference: null }));
      }
      checkoutRequestRef.current = null;
      setPayPhase('approved');
      // Brief "Approved" beat before the success screen swaps in.
      await new Promise((res) => setTimeout(res, 300));
      if (!current()) return;
      setPlaced({ order_id: j.order_id, total: j.total, payment_method: paymentMethod });
      clear();
      try {
        const refreshed = await reload();
        if (bound && !refreshed) throw new Error('Cart refresh unavailable');
      } catch {
        if (current()) toast.error('Order placed, but cart refresh failed.');
      }
      if (!current()) return;
      toast.success(`Order #${j.order_id} placed`);
    } catch (e) {
      if (!current()) return;
      setPayPhase(null);
      if (bound && receiptConfirmed) {
        setHistory(value => ({ ...value, receiptConfirmed: true }));
        toast.error('Order receipt confirmed, but the saved reference could not be cleared. Check it again.');
      } else if (bound && submitted) {
        toast.error('Checkout outcome is unconfirmed. Your saved reference is retained; check saved order.');
      } else toast.error(e.message || 'Checkout unavailable');
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
        if (mounted.current) { setPlacing(false); setPayPhase(null); }
      }
    }
  };

  if (placed) {
    return (
      <div style={{ textAlign: 'center', padding: '60px 20px', maxWidth: 640, margin: '0 auto', position: 'relative' }}>
        <ConfettiBurst />
        <motion.div
          initial={reduce ? { opacity: 0 } : { scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.4, ease: [0.34, 1.56, 0.64, 1] }}
          style={{ marginBottom: 24 }}
        >
          <PartyPopper size={64} color="var(--kelp)" />
        </motion.div>
        <h1 className="ss-display" style={{ fontSize: 48, margin: '0 0 12px 0' }}>Order placed.</h1>
        <div style={{ fontSize: 16, opacity: 0.75, marginBottom: 24 }}>
          Your order <strong>#{placed.order_id}</strong> is confirmed for ${Number(placed.total).toFixed(2)}.
          {placed.recovered ? ' This receipt was confirmed from saved orders.' : ' A confirmation is on its way.'}
        </div>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
          <Button as={Link} to="/secureshop/orders">View orders</Button>
          <Button as={Link} to="/secureshop/catalog" variant="ghost">Keep shopping</Button>
        </div>
      </div>
    );
  }

  const savedOrders = bound && <Card style={{ padding: 20, marginBottom: 20 }}>
    <div className="ss-card__meta" style={{ marginBottom: 8 }}>Saved orders</div>
    {history.status === 'loading' && <p role="status">Checking saved orders…</p>}
    {history.status === 'error' && <div role="alert">
      <p>{history.error}. Checkout is paused until saved orders can be checked.</p>
      <Button onClick={() => setHistoryRefresh(value => value + 1)}>Retry saved orders</Button>
    </div>}
    {history.status === 'ready' && history.reference && <div role="alert">
      <p>{history.receiptConfirmed
        ? 'Order receipt confirmed, but saved checkout storage still needs checking.'
        : history.reference.scopeKey === history.scopeKey
        ? 'A checkout result is not confirmed yet. Check its saved receipt before starting another order.'
        : 'A saved checkout belongs to another shop practice. It remains unresolved.'}</p>
      {history.reference.scopeKey === history.scopeKey &&
        <Button onClick={checkSavedOrder} disabled={placing}>Check saved order</Button>}
    </div>}
    {history.status === 'ready' && history.operations.length > 0 && <div>
      <p>Completed orders in this shop practice</p>
      {historicalReceipt && <p role="status">Saved receipt: order #{historicalReceipt.id}, ${historicalReceipt.total.toFixed(2)}.</p>}
      {history.operations.map(row => <div key={row.operationId} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
        <span>Order #{row.orderId}</span>
        <Button variant="ghost" onClick={() => readHistoricalOrder(row.operationId)}>Read receipt</Button>
      </div>)}
    </div>}
    {history.status === 'ready' && !history.reference && history.operations.length === 0 &&
      <span className="ss-mono" style={{ fontSize: 12 }}>No completed saved orders in this shop practice.</span>}
  </Card>;

  if (!items.length) {
    return (
      <div style={{ padding: '80px 0', textAlign: 'center', opacity: 0.65 }}>
        {savedOrders}
        {error ? <>
          <p role="alert">Could not load your cart: {error}</p>
          <Button onClick={reload}>Retry cart</Button>
        </> : <><Spinner /> Loading cart…</>}
      </div>
    );
  }

  return (
    <div>
      <h1 className="ss-display" style={{ fontSize: 36, marginBottom: 24 }}>Checkout</h1>

      {savedOrders}

      <Stepper current={step} />

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 32, marginTop: 24 }}>
        <div>
          <AnimatePresence mode="wait">
            {step === 0 && <StepShipping key="ship" bound={bound} ship={ship} setShip={setShip} onNext={continueShipping} />}
            {step === 1 && <StepPayment key="pay" bound={bound} pay={pay} setPay={setPay}
              choices={boundChoices} authorityKey={token} transport={window.fetch}
              onPaymentConfirmed={() => setChoicesRefresh(value => value + 1)}
              onNext={nextStep} onPrev={prevStep} />}
            {step === 2 && <StepReview key="review" bound={bound} ship={ship} pay={pay} summary={summary} summaryLoading={summaryLoading} onPrev={prevStep} onPlace={placeOrder} placing={placing} payPhase={payPhase} proposal={preparedProposal} confirmEligible={confirmEligible} />}
          </AnimatePresence>
          {bound && step === 0 && <PracticeAddressSetup key={showAddressSetup ? 'checkout-create' : 'checkout-recovery'}
            entryPoint={showAddressSetup ? 'checkout' : 'chat'} setup={null}
            initialFields={showAddressSetup ? { label: 'Checkout delivery', line1: ship.address,
              line2: null, city: ship.city, state: ship.state, zip: ship.zip, phone: ship.phone } : null}
            authorityKey={identity} transport={window.fetch}
            onStale={() => setShowAddressSetup(false)}
            onConfirmed={async () => {
              const requestFetch = window.fetch;
              if (currentIdentity.current !== identity) return;
              const response = await requestFetch('/api/secureshop/customer/commerce/addresses',
                { method: 'GET', headers: { accept: 'application/json' } });
              if (currentIdentity.current !== identity || window.fetch !== requestFetch) return;
              const current = response.ok && cardsPayload(await response.json(), 'address');
              if (currentIdentity.current !== identity || window.fetch !== requestFetch) return;
              if (!current?.cards.length) throw Error('Saved delivery address is unavailable');
              // The shared save callback deliberately carries no choice identity.
              // Require a physical selection from refreshed protected cards.
              setPay(value => ({ ...value, addressChoiceId: '', addressTitle: '', addressDetail: '' }));
              setShowAddressSetup(false); nextStep();
            }} />}
        </div>

        <Card style={{ padding: 24, height: 'fit-content', position: 'sticky', top: 100 }}>
          <div className="ss-card__meta" style={{ marginBottom: 16 }}>Order</div>
          {items.map((it) => (
            <div key={it.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', fontSize: 13, opacity: 0.85 }}>
              <span>{it.quantity}× {it.name}</span>
              <span style={{ fontVariantNumeric: 'tabular-nums' }}>${(Number(it.price) * it.quantity).toFixed(2)}</span>
            </div>
          ))}
          <div style={{ borderTop: '1px solid var(--rule)', marginTop: 12, paddingTop: 12 }}>
            <Row label="Subtotal" value={`$${Number(subtotal).toFixed(2)}`} />
            {coupon && <Row label={`Coupon (${coupon.code})`} value={`-$${discount.toFixed(2)}`} />}
            <Row label="Total" value={`$${Number(total).toFixed(2)}`} bold />
          </div>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, value, bold }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', fontSize: 14, fontWeight: bold ? 700 : 400 }}>
      <span>{label}</span>
      <span style={{ fontVariantNumeric: 'tabular-nums' }}>{value}</span>
    </div>
  );
}

function Stepper({ current }) {
  return (
    <div className="ss-stepper">
      {STEPS.map((label, i) => {
        const status = i < current ? 'done' : i === current ? 'active' : '';
        const cls = ['ss-stepper__step', status && `ss-stepper__step--${status}`].filter(Boolean).join(' ');
        return (
          <div key={label} className={cls}>
            <span className="ss-stepper__num">{i < current ? <Check size={12} /> : i + 1}</span>
            {label}
          </div>
        );
      })}
    </div>
  );
}

function StepShipping({ bound = false, ship, setShip, onNext }) {
  const submit = (e) => { e.preventDefault(); onNext(); };
  const set = (k) => (e) => setShip((s) => ({ ...s, [k]: e.target.value }));
  return (
    <motion.form onSubmit={submit} initial={{ opacity: 0, x: 6 }} animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -6 }} transition={{ duration: 0.22 }}
      style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 560 }}>
      <h2 className="ss-display" style={{ fontSize: 22, margin: 0 }}>{bound ? 'Delivery address' : 'Where should we ship it?'}</h2>
      {bound && <p className="ss-mono" style={{ fontSize: 12, opacity: 0.65, margin: 0 }}>Save your delivery address, then choose a practice payment.</p>}
      <Input label="Full name" value={ship.full_name} onChange={set('full_name')} required autoComplete="name" />
      <Input label="Address" value={ship.address} onChange={set('address')} required autoComplete="street-address" />
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: 12 }}>
        <Input label="City" value={ship.city} onChange={set('city')} required autoComplete="address-level2" />
        <Input label="State" value={ship.state} onChange={set('state')} required autoComplete="address-level1" />
        <Input label="ZIP" value={ship.zip} onChange={set('zip')} required autoComplete="postal-code" />
      </div>
      <Input label="Phone" value={ship.phone} onChange={set('phone')} type="tel" autoComplete="tel" />
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
        <Button type="submit" iconRight={<ArrowRight size={16} />}>Continue to payment</Button>
      </div>
    </motion.form>
  );
}

export function StepPayment({ bound = false, pay, setPay, choices, authorityKey,
  transport = globalThis.fetch, onPaymentConfirmed, onNext, onPrev }) {
  const canReview = !bound || (choices.status === 'ready'
    && choices.addresses.some(card => card.choiceId === pay.addressChoiceId)
    && choices.payments.some(card => card.choiceId === pay.choiceId));
  const submit = (e) => { e.preventDefault(); if (canReview) onNext(); };
  const set = (k) => (e) => setPay((p) => ({ ...p, [k]: e.target.value }));
  const selectChoice = card => setPay(value => ({ ...value, choiceId: card.choiceId,
    title: card.title, detail: card.detail }));
  return (
    <motion.form
      onSubmit={submit}
      initial={{ opacity: 0, x: 6 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -6 }}
      transition={{ duration: 0.22 }}
      style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 560 }}
    >
      <h2 className="ss-display" style={{ fontSize: 22, margin: 0 }}>Payment</h2>
      {bound ? <>
        <p className="ss-mono" style={{ fontSize: 11, opacity: 0.65, margin: 0 }}>
          Choose a synthetic practice payment. This checkout never collects card details.
        </p>
        {choices.status === 'loading' && <p role="status">Loading practice payment choices…</p>}
        {choices.status === 'error' && <p role="alert">{choices.error}</p>}
        <PracticePaymentSetup entryPoint="checkout" authorityKey={authorityKey}
          transport={transport} onConfirmed={onPaymentConfirmed} />
        {choices.status === 'ready' && choices.payments.length === 0 && <p role="alert">No practice payment choices are available. Add a named synthetic choice to continue.</p>}
        {choices.status === 'ready' && choices.addresses.length > 0 && <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="ss-card__meta" style={{ marginBottom: 8 }}>Saved delivery address</legend>
          {choices.addresses.map(card => <label key={card.choiceId} style={{ display: 'flex', gap: 10, padding: '10px 0', cursor: 'pointer' }}>
            <input type="radio" name="practice-address" value={card.choiceId} checked={pay.addressChoiceId === card.choiceId}
              onChange={() => setPay(value => ({ ...value, addressChoiceId: card.choiceId, addressTitle: card.title, addressDetail: card.detail }))} />
            <span><strong>{card.title}</strong><br /><span style={{ fontSize: 13, opacity: 0.7 }}>{card.detail}</span></span>
          </label>)}
        </fieldset>}
        {choices.status === 'ready' && choices.payments.length > 0 && <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="ss-card__meta" style={{ marginBottom: 8 }}>Synthetic practice payment</legend>
          {choices.payments.map(card => <label key={card.choiceId} style={{ display: 'flex', gap: 10, padding: '10px 0', cursor: 'pointer' }}>
            <input type="radio" name="practice-payment" value={card.choiceId}
              checked={pay.choiceId === card.choiceId} onChange={() => selectChoice(card)} />
            <span><strong>{card.title}</strong><br /><span style={{ fontSize: 13, opacity: 0.7 }}>{card.detail}</span></span>
          </label>)}
        </fieldset>}
      </> : <>
        <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55 }}>
          Mock only — do not enter real payment details.
        </div>
        <Input label="Name on card" value={pay.name} onChange={set('name')} required autoComplete="cc-name" icon={<CreditCard size={16} />} />
        <Input label="Card number" value={pay.number} onChange={set('number')} required placeholder="4242 4242 4242 4242" autoComplete="cc-number" />
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <Input label="Expiry" value={pay.expiry} onChange={set('expiry')} required placeholder="MM/YY" autoComplete="cc-exp" />
          <Input label="CVV" value={pay.cvv} onChange={set('cvv')} required autoComplete="cc-csc" />
        </div>
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}>
          <input type="checkbox" checked={pay.save} onChange={(e) => setPay((p) => ({ ...p, save: e.target.checked }))} />
          Save this card for next time
        </label>
      </>}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
        <Button variant="ghost" type="button" onClick={onPrev} icon={<ArrowLeft size={16} />}>Back</Button>
        <Button type="submit" disabled={!canReview} iconRight={<ArrowRight size={16} />}>Review order</Button>
      </div>
    </motion.form>
  );
}

function orderSummaryText(summary, bound) {
  if (!bound) return typeof summary?.summary === 'string' && summary.summary ? summary.summary : '(no summary)';
  const details = summary?.summary;
  const amount = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
  if (!details || !Number.isSafeInteger(details.item_count) || details.item_count < 0 ||
      !amount(details.subtotal) || !amount(summary.total) ||
      (details.discount !== undefined && !amount(details.discount))) return '(no summary)';
  return [
    `Items: ${details.item_count}`,
    `Subtotal: $${details.subtotal.toFixed(2)}`,
    ...(details.discount !== undefined ? [`Discount: -$${details.discount.toFixed(2)}`] : []),
    `Total: $${summary.total.toFixed(2)}`,
  ].join('\n');
}

export function StepReview({ bound = false, ship, pay, summary, summaryLoading, onPrev, onPlace, placing, payPhase, proposal, confirmEligible = false }) {
  const shippingTitle = proposal?.address?.title || pay.addressTitle || 'Practice address';
  const shippingDetail = proposal?.address?.detail || pay.addressDetail || 'Server-owned address choice';
  const cardMask = bound ? (proposal?.paymentMethod?.title || pay.title || '(no practice payment selected)')
    : pay.number ? `•••• •••• •••• ${String(pay.number).slice(-4)}` : '(no card entered)';
  const paymentDetail = proposal?.paymentMethod?.detail || pay.detail || 'Synthetic practice payment';
  return (
    <motion.div
      initial={{ opacity: 0, x: 6 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -6 }}
      transition={{ duration: 0.22 }}
      style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
    >
      <h2 className="ss-display" style={{ fontSize: 22, margin: 0 }}>Review your order</h2>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Card padded style={{ padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <Home size={14} color="var(--copper)" />
            <div className="ss-card__meta">Shipping to</div>
          </div>
          <div style={{ fontSize: 14, lineHeight: 1.5 }}>
            {bound ? <><div>{shippingTitle}</div>
              <div style={{ opacity: 0.65, fontSize: 12 }}>{shippingDetail}</div></>
              : <><div>{ship.full_name}</div><div>{ship.address}</div>
                <div>{ship.city}, {ship.state} {ship.zip}</div>
                <div style={{ opacity: 0.65, fontSize: 12 }}>{ship.phone}</div></>}
          </div>
        </Card>
        <Card padded style={{ padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <CreditCard size={14} color="var(--copper)" />
            <div className="ss-card__meta">Payment</div>
          </div>
          <div className="ss-mono" style={{ fontSize: 14 }}>{cardMask}</div>
          <div style={{ fontSize: 12, opacity: 0.65 }}>{bound ? paymentDetail : `Expires ${pay.expiry || '—'}`}</div>
        </Card>
      </div>

      <Card padded style={{ padding: 20, background: 'color-mix(in srgb, var(--paper) 92%, var(--copper))' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <Sparkles size={14} color="var(--signal)" />
          <div className="ss-card__meta" style={{ margin: 0 }}>{bound ? 'Order summary' : 'AI-generated order summary · summarizer agent'}</div>
        </div>
        {proposal ? (
          <pre className="ss-mono" style={{ fontSize: 12, background: 'transparent', margin: 0, whiteSpace: 'pre-wrap' }}>
            {[...proposal.items.map(item => `${item.quantity}× ${item.name} · $${(item.lineTotalCents / 100).toFixed(2)}`),
              `Subtotal: $${(proposal.subtotalCents / 100).toFixed(2)}`,
              `Discount: -$${(proposal.discountCents / 100).toFixed(2)}`,
              `Total: $${(proposal.totalCents / 100).toFixed(2)}`,
              `Quote: ${proposal.quoteSha256}`].join('\n')}
          </pre>
        ) : summaryLoading ? (
          <>
            <div className="ss-skel" style={{ width: '100%', height: 14, marginBottom: 6 }} />
            <div className="ss-skel" style={{ width: '82%', height: 14, marginBottom: 6 }} />
            <div className="ss-skel" style={{ width: '90%', height: 14 }} />
          </>
        ) : (
          <pre className="ss-mono" style={{ fontSize: 12, background: 'transparent', margin: 0, whiteSpace: 'pre-wrap' }}>
            {orderSummaryText(summary, bound)}
          </pre>
        )}
      </Card>

      {payPhase && (
        <div
          className="ss-mono"
          style={{
            padding: 12, fontSize: 13,
            background: payPhase === 'approved'
              ? 'color-mix(in srgb, var(--kelp) 15%, transparent)'
              : 'color-mix(in srgb, var(--amber) 15%, transparent)',
            border: `1px solid ${payPhase === 'approved' ? 'var(--kelp)' : 'var(--amber)'}`,
          }}
          role="status"
          aria-live="polite"
        >
          {payPhase === 'authorizing' && `Authorizing ${cardMask}…`}
          {payPhase === 'approved'    && `Approved — issuer confirmed ${cardMask}`}
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <Button variant="ghost" onClick={onPrev} disabled={placing} icon={<ArrowLeft size={16} />}>Back</Button>
        <Button onClick={onPlace} loading={placing} disabled={placing || (Boolean(proposal) && !confirmEligible)} iconRight={<ArrowRight size={16} />} size="lg">
          {placing
            ? (payPhase === 'approved' ? 'Placing order…' : 'Authorizing…')
            : proposal ? 'Confirm exact quote' : 'Place order'}
        </Button>
      </div>
      {proposal && !confirmEligible && <p role="alert">This saved checkout must be recovered by its exact receipt before another confirmation.</p>}
    </motion.div>
  );
}

function ConfettiBurst() {
  const reduce = useReducedMotion();
  const pieces = 24;
  if (reduce) return null;
  return (
    <div aria-hidden="true" style={{ position: 'absolute', inset: 0, pointerEvents: 'none', overflow: 'hidden' }}>
      {Array.from({ length: pieces }).map((_, i) => {
        const angle = (i / pieces) * Math.PI * 2;
        const dx = Math.cos(angle) * 240;
        const dy = Math.sin(angle) * 240;
        const colors = ['var(--signal)', 'var(--copper)', 'var(--kelp)', 'var(--amber)'];
        return (
          <motion.span
            key={i}
            initial={{ opacity: 1, x: 0, y: 0, scale: 0.6 }}
            animate={{ opacity: 0, x: dx, y: dy, scale: 1.2, rotate: 360 }}
            transition={{ duration: 1.4, ease: [0.16, 1, 0.3, 1] }}
            style={{
              position: 'absolute',
              top: '30%', left: '50%',
              width: 8, height: 12,
              background: colors[i % colors.length],
              display: 'inline-block',
            }}
          />
        );
      })}
    </div>
  );
}
