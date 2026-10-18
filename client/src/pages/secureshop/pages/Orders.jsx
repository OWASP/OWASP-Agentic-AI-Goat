import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { Package, ArrowRight, RefreshCw, Eye } from 'lucide-react';

import Button from '../components/Button.jsx';
import EmptyState from '../components/EmptyState.jsx';
import OrderStatusChip from '../components/OrderStatusChip.jsx';
import Dialog from '../components/Dialog.jsx';
import Spinner from '../components/Spinner.jsx';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext.jsx';
import { requestRefundTicket } from '../utils/refundRequest.mjs';
import { readRefundReferences, saveRefundReference } from '../utils/refundReferences.mjs';
import { decodeRefundSetup } from '../utils/refundSetup.mjs';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';

const STATUS_OPTIONS = ['all', 'pending', 'confirmed', 'shipped', 'delivered', 'cancelled'];
const refundCopy = (result) => {
  if (!result) return '';
  if (result.status === 'pending') return 'Requesting a refund ticket…';
  if (result.status === 'checking') return 'Checking the saved refund request…';
  if (result.status === 'confirmed') return `Refund request filed · ticket #${result.ticketId}`;
  if (result.status === 'not_confirmed') return 'No refund ticket was confirmed in this run. Check support before another request.';
  if (result.status === 'uncertain' || result.status === 'unconfirmed') return 'Refund outcome unconfirmed. Check the saved request before another for this order.';
  return 'Refund service was unavailable before the agent request was sent. You can retry.';
};
const TICKET = /^[1-9][0-9]{0,18}$/;

async function readRefundOutcome(reference, requestFetch) {
  const response = await requestFetch(`/api/secureshop/agents/customer/refund/operations/${reference.sessionId}/${reference.requestId}`);
  if (!response.ok) throw Error('Saved refund outcome is unavailable');
  const value = await response.json();
  if (value?.requestId !== reference.requestId) throw Error('Saved refund reference mismatch');
  if (value.status !== 'saved') return { status: 'unconfirmed' };
  if (String(value.orderId) !== String(reference.orderId) || typeof value.ticketId !== 'string'
      || !TICKET.test(value.ticketId) || BigInt(value.ticketId) > 9223372036854775807n) {
    throw Error('Saved refund ticket mismatch');
  }
  return { status: 'confirmed', ticketId: value.ticketId };
}

export default function Orders() {
  const { user, token } = useAuth();
  const toast = useToast();
  const reduce = useReducedMotion();
  const location = useLocation();

  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [reload, setReload] = useState(0);
  const [filter, setFilter] = useState('all');
  const [dateRange, setDateRange] = useState('any');
  const [selected, setSelected] = useState(null);
  const [selectedLoading, setSelectedLoading] = useState(false);
  const [refundReason, setRefundReason] = useState('');
  const [refundResults, setRefundResults] = useState({ identity: '', byOrder: {} });
  const [refundRecovery, setRefundRecovery] = useState({ identity: '', status: 'loading', references: [] });
  const [refundReload, setRefundReload] = useState(0);
  const [handoffNotice, setHandoffNotice] = useState('');

  const detailRequest = useRef(null);
  const reviewedHandoff = useRef(null);
  const refundInFlight = useRef(new Map());
  const mounted = useRef(true);
  const uid = user?.id || 1;
  const identity = `${uid}:${token || ""}`;
  const currentOwner = useRef(identity);
  currentOwner.current = identity;
  const bound = Boolean(getBridgeFetchMetadata(window.fetch)?.boundReviews);
  const refundReferenceFor = (orderId) => refundRecovery.identity === identity
    ? refundRecovery.references.find(row => String(row.orderId) === String(orderId)) : null;
  const refundFor = (orderId) => {
    const result = refundResults.identity === identity ? refundResults.byOrder[String(orderId)] : null;
    return result || (refundReferenceFor(orderId) ? { status: 'unconfirmed' } : null);
  };

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => {
    refundInFlight.current = new Map();
    setRefundResults({ identity, byOrder: {} });
    setRefundReason('');
  }, [identity]);

  useEffect(() => {
    try {
      const references = bound ? readRefundReferences() : [];
      setRefundRecovery({ identity, status: 'ready', references });
    } catch {
      setRefundRecovery({ identity, status: 'error', references: [] });
    }
  }, [identity, bound, refundReload]);

  useEffect(() => {
    let cancelled = false;
    detailRequest.current = null;
    setSelected(null);
    setSelectedLoading(false);
    setOrders([]);
    setLoading(true);
    setLoadError(false);
    const controller = new AbortController();
    fetch(`/api/secureshop/orders${bound ? '' : `?user_id=${uid}`}`, { signal: controller.signal })
      .then(r => { if (!r.ok) throw new Error('Orders unavailable'); return r.json(); })
      .then(j => { if (!Array.isArray(j.orders)) throw new Error('Invalid orders response'); if (!cancelled && currentOwner.current === identity) setOrders(j.orders); })
      .catch(() => { if (!cancelled && currentOwner.current === identity) setLoadError(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; controller.abort(); detailRequest.current = null; };
  }, [uid, token, bound, reload]);

  useEffect(() => {
    if (!bound || loading || loadError || !location.state) return;
    let handoff;
    try {
      if (Object.getPrototypeOf(location.state) !== Object.prototype
        || Object.keys(location.state).join(',') !== 'refundSetup') throw Error('Invalid refund review link');
      handoff = decodeRefundSetup(location.state.refundSetup);
      if (!handoff) throw Error('Invalid refund review link');
    } catch { setHandoffNotice('Refund review link is unavailable. Choose an order from your list.'); return; }
    const key = `${identity}:${location.key}:${handoff.choiceId}`;
    if (reviewedHandoff.current === key) return;
    reviewedHandoff.current = key;
    const owned = orders.find(row => Number(row.id) === handoff.orderId);
    if (!owned) { setHandoffNotice('The selected order is not in your current orders.'); return; }
    const request = {}, requestFetch = window.fetch;
    detailRequest.current = request;
    const current = () => mounted.current && currentOwner.current === identity
      && window.fetch === requestFetch && detailRequest.current === request;
    setHandoffNotice('Checking your selected order…');
    requestFetch(`/api/secureshop/orders/${handoff.orderId}`, { method: 'GET', headers: { accept: 'application/json' } })
      .then(async response => {
        if (!response.ok) throw Error('Selected order unavailable');
        const value = await response.json();
        if (!value?.order || Number(value.order.id) !== handoff.orderId || !Array.isArray(value.items))
          throw Error('Selected order mismatch');
        if (!current()) return;
        setRefundReason('');
        setSelected({ ...value.order, items: value.items });
        setSelectedLoading(false);
        setHandoffNotice('Review this order and enter a reason to request a refund.');
      }).catch(() => { if (current()) setHandoffNotice('The selected order could not be verified. Choose it from your list.'); });
    return () => {
      if (detailRequest.current === request) detailRequest.current = null;
      if (reviewedHandoff.current === key) reviewedHandoff.current = null;
    };
  }, [bound, loading, loadError, orders, location.key, location.state, identity]);

  const filtered = useMemo(() => {
    let f = orders;
    if (filter !== 'all') f = f.filter(o => String(o.status).toLowerCase() === filter);
    if (dateRange !== 'any') {
      const now = Date.now();
      const cutoff = dateRange === '30d' ? now - 30 * 86400000
                   : dateRange === '90d' ? now - 90 * 86400000
                   : dateRange === '1y'  ? now - 365 * 86400000 : 0;
      if (cutoff) f = f.filter(o => new Date(o.order_date).getTime() >= cutoff);
    }
    return f;
  }, [orders, filter, dateRange]);

  const closeDetail = () => {
    detailRequest.current = null;
    setSelected(null);
    setSelectedLoading(false);
    setRefundReason('');
  };

  const openDetail = async (order) => {
    const request = {};
    detailRequest.current = request;
    const isCurrent = () => detailRequest.current === request && currentOwner.current === identity;
    setRefundReason('');
    setSelected({ ...order, items: [], loading: true });
    setSelectedLoading(true);
    try {
      const r = await fetch(`/api/secureshop/orders/${order.id}`);
      if (!r.ok) throw new Error('Order details unavailable');
      const j = await r.json();
      if (j.order && String(j.order.id) !== String(order.id)) throw new Error('Order response mismatch');
      if (isCurrent()) setSelected({ ...(j.order || order), items: j.items || [] });
    } catch { if (isCurrent()) setSelected(order); }
    finally { if (isCurrent()) setSelectedLoading(false); }
  };

  const requestRefund = async (order) => {
    const orderId = String(order.id);
    const reason = refundReason.trim();
    const prior = refundFor(order.id);
    if (!reason || reason.length > 500 || refundInFlight.current.has(orderId)
        || (bound && (refundRecovery.identity !== identity || refundRecovery.status !== 'ready'
          || refundReferenceFor(order.id))) || (prior && prior.status !== 'failed')) return;
    const marker = {};
    const inFlight = refundInFlight.current;
    inFlight.set(orderId, marker);
    const requestFetch = window.fetch;
    const isCurrent = () => mounted.current && currentOwner.current === identity && window.fetch === requestFetch;
    const record = (result) => {
      if (isCurrent()) setRefundResults(previous => ({
        identity,
        byOrder: { ...(previous.identity === identity ? previous.byOrder : {}), [orderId]: result },
      }));
    };
    record({ status: 'pending' });
    toast.info(`Requesting refund for #${order.id}…`);
    let reference = null;
    try {
      const requestId = bound ? globalThis.crypto.randomUUID().toLowerCase() : undefined;
      const result = await requestRefundTicket({ fetchImpl: requestFetch, userId: uid, orderId: order.id, reason,
        ...(bound ? { requestId, beforeChat: async (sessionId) => {
          if (!isCurrent()) throw Error('Refund identity changed');
          let saved;
          try { saved = await saveRefundReference({ sessionId, requestId, orderId: Number(order.id) }); }
          catch (error) {
            if (isCurrent()) setRefundRecovery(previous => previous.identity === identity
              ? { ...previous, status: 'error' } : previous);
            throw error;
          }
          reference = saved;
          if (!isCurrent()) throw Error('Refund identity changed');
          setRefundRecovery(previous => previous.identity === identity
            ? { ...previous, references: [...previous.references, saved] } : previous);
        }, verifyBeforeChat: (sessionId) => {
          if (!isCurrent() || !reference || reference.sessionId !== sessionId
            || reference.requestId !== requestId || String(reference.orderId) !== orderId)
            throw Error('Refund identity changed');
          const current = readRefundReferences().find(row => row.orderId === reference.orderId);
          if (!current || current.sessionId !== reference.sessionId
            || current.requestId !== reference.requestId || current.orderId !== reference.orderId)
            throw Error('Saved refund reference changed');
        } } : {}) });
      if (bound) {
        if (!reference || !isCurrent()) return;
        const outcome = await readRefundOutcome(reference, requestFetch);
        if (!isCurrent()) return;
        record(outcome);
        if (outcome.status === 'confirmed') toast.success(`Refund request filed for #${order.id} · ticket #${outcome.ticketId}.`);
        else toast.error(`Refund outcome unconfirmed for #${order.id}. Check the saved request.`);
        return;
      }
      if (String(result?.orderId) !== orderId || !result?.ticketId)
        throw Object.assign(new Error('Refund response mismatch'), { code: 'uncertain' });
      record({ status: 'confirmed', ticketId: result.ticketId });
      if (isCurrent()) toast.success(`Refund request filed for #${order.id} · ticket #${result.ticketId}.`);
    } catch (e) {
      if (bound && reference) {
        try {
          const outcome = await readRefundOutcome(reference, requestFetch);
          if (!isCurrent()) return;
          record(outcome);
          if (outcome.status === 'confirmed') toast.success(`Refund request filed for #${order.id} · ticket #${outcome.ticketId}.`);
          else toast.error(`Refund outcome unconfirmed for #${order.id}. Check the saved request.`);
        } catch {
          if (isCurrent()) {
            record({ status: 'uncertain' });
            toast.error(`Refund outcome unconfirmed for #${order.id}. Check the saved request.`);
          }
        }
        return;
      }
      const status = e?.code === 'not_confirmed' ? 'not_confirmed'
        : e?.code === 'failed' ? 'failed' : 'uncertain';
      record({ status });
      if (!isCurrent()) return;
      if (e?.code === 'not_confirmed') {
        toast.error(`No refund ticket was confirmed for #${order.id}.`);
      } else if (status === 'uncertain') {
        toast.error(`Could not confirm refund request for #${order.id}. Check support before retrying.`);
      } else {
        toast.error(`Refund service was unavailable for #${order.id}.`);
      }
    } finally {
      if (inFlight.get(orderId) === marker) inFlight.delete(orderId);
    }
  };

  const checkSavedRefund = async (order) => {
    const reference = refundReferenceFor(order.id);
    const orderId = String(order.id);
    if (!reference || refundInFlight.current.has(orderId)) return;
    const marker = {};
    const inFlight = refundInFlight.current;
    inFlight.set(orderId, marker);
    const requestFetch = window.fetch;
    const isCurrent = () => mounted.current && currentOwner.current === identity && window.fetch === requestFetch
      && refundReferenceFor(order.id)?.requestId === reference.requestId;
    if (isCurrent()) setRefundResults(previous => ({ identity,
      byOrder: { ...(previous.identity === identity ? previous.byOrder : {}), [orderId]: { status: 'checking' } },
    }));
    try {
      const result = await readRefundOutcome(reference, requestFetch);
      if (isCurrent()) setRefundResults(previous => ({ identity,
        byOrder: { ...(previous.identity === identity ? previous.byOrder : {}), [orderId]: result },
      }));
    } catch {
      if (isCurrent()) setRefundResults(previous => ({ identity,
        byOrder: { ...(previous.identity === identity ? previous.byOrder : {}), [orderId]: { status: 'uncertain' } },
      }));
    } finally {
      if (inFlight.get(orderId) === marker) inFlight.delete(orderId);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 24, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 className="ss-display" style={{ fontSize: 40, margin: 0 }}>Orders</h1>
          <div style={{ opacity: 0.65, fontSize: 13 }}>{loading ? 'Loading…' : loadError ? 'Orders unavailable' : `${filtered.length} of ${orders.length} orders`}</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}
                  style={{ padding: '8px 12px', border: '1px solid var(--rule)', borderRadius: 6, background: 'transparent' }}
                  aria-label="Filter by status">
            {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={dateRange} onChange={(e) => setDateRange(e.target.value)}
                  style={{ padding: '8px 12px', border: '1px solid var(--rule)', borderRadius: 6, background: 'transparent' }}
                  aria-label="Date range">
            <option value="any">Any date</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="1y">Last year</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div style={{ padding: '60px 0', textAlign: 'center' }}><Spinner size="lg" /></div>
      ) : loadError ? (
        <div role="alert">
          <p>Could not load orders. Please try again.</p>
          <Button variant="ghost" onClick={() => setReload(value => value + 1)}>Retry</Button>
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<Package size={40} />}
          title={orders.length === 0 ? 'No orders yet' : 'No orders match'}
          description={orders.length === 0
            ? 'When you place an order, it will show up here with tracking, invoices, and refund options.'
            : 'Try widening the filter or date range.'}
          action={orders.length === 0
            ? <Button as={Link} to="/secureshop/catalog" iconRight={<ArrowRight size={16} />}>Start shopping</Button>
            : <Button variant="ghost" onClick={() => { setFilter('all'); setDateRange('any'); }}>Clear filters</Button>}
        />
      ) : (
        <table className="ss-table" aria-label="Orders list">
          <thead>
            <tr>
              <th style={{ width: 100 }}>Order #</th>
              <th>Date</th>
              <th style={{ width: 130 }}>Total</th>
              <th style={{ width: 130 }}>Status</th>
              <th style={{ width: 140 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((o, i) => (
              <motion.tr
                key={o.id}
                initial={reduce ? {} : { opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.22, delay: Math.min(i, 12) * 0.03 }}
              >
                <td><span className="ss-mono" style={{ fontWeight: 600 }}>#{o.id}</span></td>
                <td>{new Date(o.order_date).toLocaleString()}</td>
                <td style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>${Number(o.total_amount).toFixed(2)}</td>
                <td><OrderStatusChip status={o.status} /></td>
                <td>
                  <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                    <Button size="sm" variant="ghost" onClick={() => openDetail(o)} icon={<Eye size={14} />}>View</Button>
                  </div>
                  {refundFor(o.id) && <div role="status" style={{ fontSize: 11, marginTop: 6, textAlign: 'right', opacity: 0.7 }}>
                    {refundCopy(refundFor(o.id))}
                  </div>}
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      )}

      {bound && refundRecovery.identity === identity && refundRecovery.status === 'error' && <div role="alert" style={{ marginTop: 16 }}>
        <p>Saved refund status is unavailable. New refund requests are paused until it can be checked.</p>
        <Button variant="ghost" onClick={() => setRefundReload(value => value + 1)}>Retry saved refunds</Button>
      </div>}
      {handoffNotice && <p role="status">{handoffNotice}</p>}

      <Dialog
        open={Boolean(selected)}
        onClose={closeDetail}
        title={selected ? `Order #${selected.id}` : ''}
        size="lg"
      >
        {selected && (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
              <div>
                <div className="ss-card__meta">Placed</div>
                <div>{new Date(selected.order_date).toLocaleString()}</div>
                <div className="ss-card__meta" style={{ marginTop: 14 }}>Status</div>
                <OrderStatusChip status={selected.status} />
              </div>
              <div>
                <div className="ss-card__meta">Total</div>
                <div style={{ fontSize: 22, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
                  ${Number(selected.total_amount).toFixed(2)}
                </div>
                {selected.coupon_code && <div className="ss-card__meta">Coupon ({selected.coupon_code}): −${Number(selected.discount_amount || 0).toFixed(2)}</div>}
                <div className="ss-card__meta" style={{ marginTop: 14 }}>Payment</div>
                <div>{selected.payment_method || '—'}</div>
              </div>
            </div>

            <div style={{ marginBottom: 20 }}>
              <div className="ss-card__meta">Shipping to</div>
              <pre style={{ fontFamily: 'var(--body)', fontSize: 14, whiteSpace: 'pre-wrap', margin: '4px 0 0 0' }}>
                {selected.shipping_address || '(no address recorded)'}
              </pre>
            </div>

            <div className="ss-card__meta" style={{ marginBottom: 8 }}>Line items</div>
            {selectedLoading ? (
              <Spinner />
            ) : (
              <table className="ss-table">
                <thead>
                  <tr>
                    <th>Product</th>
                    <th style={{ width: 80 }}>Qty</th>
                    <th style={{ width: 110, textAlign: 'right' }}>Unit</th>
                    <th style={{ width: 110, textAlign: 'right' }}>Total</th>
                  </tr>
                </thead>
                <tbody>
                  {(selected.items || []).map((it) => (
                    <tr key={it.id}>
                      <td>{it.name || `product #${it.product_id}`}</td>
                      <td>{it.quantity}</td>
                      <td style={{ textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>${Number(it.price).toFixed(2)}</td>
                      <td style={{ textAlign: 'right', fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>
                        ${Number(it.total_amount ?? Number(it.price) * it.quantity).toFixed(2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            <div style={{ marginTop: 24, padding: 16, border: '1px solid var(--rule)', background: 'color-mix(in srgb, var(--paper) 94%, var(--carbon))' }}>
              <div className="ss-card__meta">Tracking</div>
              <div className="ss-mono" style={{ fontSize: 12, opacity: 0.6, marginTop: 4 }}>
                (mock) — carrier updates land here when the shipper flips shipped_date.
              </div>
            </div>

            <div className="ss-input-wrap" style={{ marginTop: 24 }}>
              <label className="ss-input-label" htmlFor="ss-refund-reason">Reason for refund</label>
              <textarea id="ss-refund-reason" className="ss-input" rows={3} maxLength={500}
                        value={refundReason} onChange={event => setRefundReason(event.target.value)}
                        disabled={Boolean(refundFor(selected.id) && refundFor(selected.id).status !== 'failed')}
                        placeholder="Tell support why you are requesting a refund"
                        style={{ width: '100%', resize: 'vertical' }} />
              <div className="ss-input-helper">Required before sending the request to the support agent.</div>
            </div>
            {refundFor(selected.id) && <p role="status" style={{ margin: '12px 0 0', fontSize: 13 }}>
              {refundCopy(refundFor(selected.id))}
            </p>}
            {refundReferenceFor(selected.id) && <Button variant="ghost" onClick={() => checkSavedRefund(selected)}
              disabled={refundFor(selected.id)?.status === 'checking' || refundFor(selected.id)?.status === 'pending'}>
              Check saved refund
            </Button>}

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 24 }}>
              <Button variant="ghost" onClick={closeDetail}>Close</Button>
              <Button variant="danger" onClick={() => requestRefund(selected)} icon={<RefreshCw size={14} />}
                      disabled={!refundReason.trim() || (bound && (refundRecovery.identity !== identity
                        || refundRecovery.status !== 'ready' || Boolean(refundReferenceFor(selected.id))))
                        || Boolean(refundFor(selected.id) && refundFor(selected.id).status !== 'failed')}>
                {refundFor(selected.id)?.status === 'failed' ? 'Retry request' : 'Request refund'}
              </Button>
            </div>
          </div>
        )}
      </Dialog>
    </div>
  );
}
