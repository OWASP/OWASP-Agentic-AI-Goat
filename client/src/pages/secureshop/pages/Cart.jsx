import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { Trash2, Tag, ArrowRight, ShoppingBag } from 'lucide-react';

import Button from '../components/Button.jsx';
import EmptyState from '../components/EmptyState.jsx';
import Card from '../components/Card.jsx';
import Badge from '../components/Badge.jsx';
import { CouponProbePanel } from '../components/CouponProbePanel.jsx';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { useAuth } from '../context/AuthContext.jsx';
import { useCart } from '../context/CartContext.jsx';

export default function Cart() {
  const { items, subtotal, total, discount, coupon, couponAvailable, updateQty, remove, applyCoupon, loading, error, cartReady } = useCart();
  const { user, token } = useAuth();
  const reduce = useReducedMotion();

  const [couponCode, setCouponCode] = useState('');
  const [applying, setApplying] = useState(false);
  const [couponProbeCapability, setCouponProbeCapability] = useState({ key: null, ready: false });

  const submitCoupon = async (e) => {
    e.preventDefault();
    if (!couponReady || !couponCode.trim() || applying) return;
    setApplying(true);
    try {
      await applyCoupon(couponCode);
      setCouponCode('');
    } catch { /* handled by toast */ }
    finally { setApplying(false); }
  };

  const bound = Boolean(getBridgeFetchMetadata(window.fetch));
  const couponReady = !bound || couponAvailable === true;
  const couponProbeKey = bound && Number.isSafeInteger(user?.id) && user.id > 0
    ? `${user.id}:${token || ''}` : null;

  useEffect(() => {
    const controller = new AbortController();
    let closed = false;
    setCouponProbeCapability({ key: couponProbeKey, ready: false });
    if (!couponProbeKey || typeof globalThis.fetch !== 'function') {
      return () => { closed = true; controller.abort(); };
    }
    void globalThis.fetch('/api/secureshop/customer/coupon-probe/capabilities', {
      method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
    }).then(async response => {
      const contentType = response.headers?.get?.('content-type') || '';
      if (!response.ok || !/^application\/json(?:;|$)/i.test(contentType)) throw new Error('Unavailable');
      const value = await response.json();
      if (!value || Object.getPrototypeOf(value) !== Object.prototype
        || Object.keys(value).length !== 1 || value.ready !== true) throw new Error('Unavailable');
      if (!closed) setCouponProbeCapability({ key: couponProbeKey, ready: true });
    }).catch(() => {
      if (!closed) setCouponProbeCapability({ key: couponProbeKey, ready: false });
    });
    return () => { closed = true; controller.abort(); };
  }, [couponProbeKey]);

  const couponProbeReady = couponProbeCapability.key === couponProbeKey && couponProbeCapability.ready;
  const tax = bound ? 0 : Math.max(0, total * 0.08);
  const shipping = !bound && items.length ? (subtotal > 75 ? 0 : 6.99) : 0;
  const grandTotal = total + tax + shipping;

  if (cartReady === false) return <div>
    <h1 className="ss-display" style={{ fontSize: 40, marginBottom: 8 }}>Cart</h1>
    <p role={error ? 'alert' : 'status'}>{error || 'Restoring your cart…'}</p>
  </div>;

  if (!loading && error && items.length === 0) {
    return (
      <div>
        <h1 className="ss-display" style={{ fontSize: 40, marginBottom: 8 }}>Cart</h1>
        <p role="alert" style={{ color: 'var(--rust)' }}>{error}</p>
        <EmptyState
          icon={<ShoppingBag size={40} />}
          title="Cart unavailable"
          description="We couldn't verify the current contents of your cart."
        />
      </div>
    );
  }

  if (!loading && items.length === 0) {
    return (
      <div>
        <h1 className="ss-display" style={{ fontSize: 40, marginBottom: 8 }}>Cart</h1>
        {error && <p role="alert" style={{ color: 'var(--rust)' }}>{error}</p>}
        <EmptyState
          icon={<ShoppingBag size={40} />}
          title="Your cart is empty"
          description="Once you add products, they'll show up here."
          action={<Button as={Link} to="/secureshop/catalog" iconRight={<ArrowRight size={16} />}>Browse the catalog</Button>}
        />
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 24 }}>
        <h1 className="ss-display" style={{ fontSize: 40, margin: 0 }}>Cart</h1>
        <div className="ss-mono" style={{ opacity: 0.65, fontSize: 12 }}>
          {items.length} item{items.length === 1 ? '' : 's'}
        </div>
      </div>
      {error && <p role="alert" style={{ color: 'var(--rust)' }}>{error}</p>}

      <div className="ss-cart-layout">
        <div>
          <table className="ss-table ss-cart-table" aria-label="Cart items">
            <thead>
              <tr>
                <th style={{ width: 80 }}></th>
                <th>Product</th>
                <th style={{ width: 130 }}>Qty</th>
                <th style={{ width: 100, textAlign: 'right' }}>Unit</th>
                <th style={{ width: 110, textAlign: 'right' }}>Subtotal</th>
                <th style={{ width: 50 }}></th>
              </tr>
            </thead>
            <tbody>
              <AnimatePresence>
                {items.map((it) => (
                  <motion.tr
                    key={it.id}
                    layout
                    initial={reduce ? { opacity: 0 } : { opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={reduce ? { opacity: 0 } : { opacity: 0, x: -20 }}
                    transition={{ duration: 0.22 }}
                  >
                    <td data-label="Product image">
                      <div style={{ width: 60, height: 74, background: 'var(--carbon)' }} />
                    </td>
                    <td data-label="Product">
                      <Link to={`/secureshop/product/${it.product_id}`} style={{ color: 'inherit', textDecoration: 'none' }}>
                        <div style={{ fontFamily: 'var(--display)', fontSize: 16, fontWeight: 600 }}>{it.name}</div>
                      </Link>
                    </td>
                    <td data-label="Quantity">
                      <div className="ss-qty" aria-label={`Quantity for ${it.name}`}>
                        <button className="ss-qty__btn" onClick={() => updateQty(it.id, Math.max(1, it.quantity - 1))}
                          aria-label={`Decrease quantity for ${it.name}`} disabled={it.quantity <= 1}>−</button>
                        <input
                          className="ss-qty__val"
                          type="number" min="1" max="99" step="1" inputMode="numeric"
                          aria-label={`Quantity for ${it.name}`}
                          value={it.quantity}
                          onChange={(e) => {
                            const quantity = Number(e.target.value);
                            if (Number.isSafeInteger(quantity) && quantity >= 1 && quantity <= 99) {
                              updateQty(it.id, quantity);
                            }
                          }}
                        />
                        <button className="ss-qty__btn" onClick={() => updateQty(it.id, it.quantity + 1)}
                          aria-label={`Increase quantity for ${it.name}`} disabled={it.quantity >= 99}>+</button>
                      </div>
                    </td>
                    <td data-label="Unit price" style={{ textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>${Number(it.price).toFixed(2)}</td>
                    <td data-label="Subtotal" style={{ textAlign: 'right', fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>
                      ${(Number(it.price) * it.quantity).toFixed(2)}
                    </td>
                    <td data-label="Remove">
                      <button
                        onClick={() => remove(it.id)}
                        aria-label={`Remove ${it.name}`}
                        style={{ background: 'transparent', border: 0, cursor: 'pointer', color: 'var(--rust)', padding: 8 }}
                        title="Remove"
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </AnimatePresence>
            </tbody>
          </table>
        </div>

        <div>
          <Card className="ss-cart-summary" style={{ padding: 24 }}>
            <div className="ss-card__meta" style={{ marginBottom: 16 }}>Order summary</div>
            <SummaryRow label="Subtotal" value={`$${Number(subtotal).toFixed(2)}`} />
            {coupon && (
              <SummaryRow
                label={<span>Discount <Badge variant="kelp">{coupon.code}</Badge></span>}
                value={`-$${Number(discount).toFixed(2)}`}
                variant="kelp"
              />
            )}
            <SummaryRow label={bound ? "Shipping (not charged)" : "Shipping"} value={shipping === 0 ? 'Free' : `$${shipping.toFixed(2)}`} />
            <SummaryRow label={bound ? "Tax (not charged)" : "Tax (est.)"} value={`$${tax.toFixed(2)}`} />
            <div style={{ borderTop: '1px solid var(--rule)', marginTop: 12, paddingTop: 12 }}>
              <SummaryRow label={<strong>Total</strong>} value={<strong style={{ fontSize: 20, fontVariantNumeric: 'tabular-nums' }}>${grandTotal.toFixed(2)}</strong>} />
            </div>

            <form className="ss-cart-coupon-form" onSubmit={submitCoupon} style={{ marginTop: 20, display: 'flex', gap: 8 }}>
              <div style={{ flex: 1, position: 'relative' }}>
                <Tag size={14} style={{ position: 'absolute', left: 12, top: 14, opacity: 0.5, pointerEvents: 'none' }} />
                <input
                  className="ss-input"
                  placeholder="Coupon code"
                  value={couponCode}
                  onChange={(e) => setCouponCode(e.target.value)}
                  style={{ paddingLeft: 34, width: '100%' }}
                  aria-label="Coupon code"
                  disabled={!couponReady}
                />
              </div>
              <Button size="md" type="submit" loading={applying} disabled={!couponReady || !couponCode.trim()}>Apply</Button>
            </form>
            <div className="ss-mono" role={couponReady ? undefined : 'status'} style={{ marginTop: 8, opacity: 0.5, fontSize: 11 }}>
              {couponReady
                ? 'Try: WELCOME10 — or the coupon field also accepts SQL fragments (intentional).'
                : 'Coupons are unavailable in this shop setup.'}
            </div>
            {couponProbeReady && <CouponProbePanel shopUserId={user.id}
              authorityKey={token} transport={globalThis.fetch} />}

            <Button
              as={Link}
              to="/secureshop/checkout"
              fullWidth
              size="lg"
              style={{ marginTop: 20 }}
              iconRight={<ArrowRight size={16} />}
              disabled={!items.length}
            >
              Proceed to checkout
            </Button>

            <div style={{ marginTop: 12, fontSize: 12, opacity: 0.65, textAlign: 'center' }}>
              {bound ? 'Total matches your order checkout' : 'Free shipping over $75 · secure checkout'}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function SummaryRow({ label, value, variant }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', fontSize: 14, color: variant === 'kelp' ? 'var(--kelp)' : undefined }}>
      <span>{label}</span>
      <span style={{ fontVariantNumeric: 'tabular-nums' }}>{value}</span>
    </div>
  );
}
