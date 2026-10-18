import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, Package, Zap } from 'lucide-react';

import { useAuth } from '../context/AuthContext';
import { useCart } from '../context/CartContext.jsx';
import ProductCard from '../components/ProductCard.jsx';
import Card from '../components/Card.jsx';
import Button from '../components/Button.jsx';
import OrderStatusChip from '../components/OrderStatusChip.jsx';
import EmptyState from '../components/EmptyState.jsx';
import ControlledSsrfLab from '../components/ControlledSsrfLab.jsx';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';

/**
 * Home.jsx — authed dashboard-y home at /secureshop/home.
 */
export default function Home() {
  const { user } = useAuth();
  const { addItem } = useCart();
  const reduce = useReducedMotion();

  const [recommended, setRecommended] = useState([]);
  const [deals, setDeals] = useState([]);
  const [beauty, setBeauty] = useState([]);
  const [books, setBooks] = useState([]);
  const [orders, setOrders] = useState([]);
  const [trace, setTrace] = useState([]);
  const [traceError, setTraceError] = useState('');
  const [loadErrors, setLoadErrors] = useState({});
  const [loading, setLoading] = useState(true);

  const uid = user?.id || 1;
  const bound = Boolean(getBridgeFetchMetadata(window.fetch));

  useEffect(() => {
    let cancelled = false;
    async function loadAll() {
      setLoading(true);
      setTrace([]);
      setTraceError('');
      try {
        const outcomes = await Promise.all([
          loadSection(`/api/secureshop/recommended${bound ? '' : `?user_id=${uid}`}`, 'recommendations', body => (
            Array.isArray(body?.feed) ? body.feed : body?.products
          )),
          loadSection('/api/secureshop/products?limit=7&sort=deals', 'deals', body => body?.products),
          loadSection('/api/secureshop/products?category=Beauty&limit=6', 'Beauty products', body => body?.products),
          loadSection('/api/secureshop/products?category=Books&limit=6', 'Books', body => body?.products),
          loadSection(`/api/secureshop/orders${bound ? '' : `?user_id=${uid}`}`, 'recent orders', body => body?.orders),
          loadSection('/api/secureshop/agents/customer/trace/latest?limit=5', 'recent agent activity', body => body?.rows),
        ]);
        if (cancelled) return;
        const [rec, dl, be, bk, ord, activity] = outcomes;
        setRecommended(rec.items);
        setDeals(dl.items);
        setBeauty(be.items);
        setBooks(bk.items);
        setOrders(ord.items);
        setTrace(activity.items);
        setTraceError(activity.error);
        setLoadErrors({
          recommended: rec.error,
          deals: dl.error,
          beauty: be.error,
          books: bk.error,
          orders: ord.error,
        });
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    loadAll();
    return () => { cancelled = true; };
  }, [uid, bound]);

  const handleAdd = (p) => addItem(p.id, 1, { name: p.name, price: p.price });

  return (
    <div>
      <motion.section
        initial={reduce ? { opacity: 0 } : { opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
        style={{ marginBottom: 32 }}
      >
        <div style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--copper)' }}>
          {new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })}
        </div>
        <h1 className="ss-display" style={{ fontSize: 44, margin: '8px 0 4px 0' }}>
          Welcome back, {user?.full_name || user?.username || 'friend'}.
        </h1>
        <p style={{ maxWidth: '52ch', opacity: 0.72, fontSize: 15 }}>
          {bound
            ? 'Explore products selected from your shopping activity, recent orders, and current deals.'
            : "The customer supervisor has been quietly organizing your feed since your last visit. Here's what we found worth showing you today."}
        </p>
      </motion.section>

      <ControlledSsrfLab enabled={Boolean(getBridgeFetchMetadata(window.fetch))}
        policyOutputEnabled={Boolean(getBridgeFetchMetadata(window.fetch))} shopUserId={user?.id}
        personaKey={`${user?.id || 0}:${user?.role || ''}`} />

      <section style={{ marginBottom: 40 }}>
        <SectionHeader
          title="Recommended for you"
          hint={bound ? 'Based on your shopping activity · no AI model used' : 'from product-search.personalized_feed'}
          viewAllTo="/secureshop/catalog"
        />
        <div className="ss-shelf__row">
          {loading && Array.from({ length: 4 }).map((_, i) => <SkelCard key={i} />)}
          {!loading && recommended.slice(0, 6).map((p, i) => (
            <ProductCard key={p.id} product={p} index={i} onAdd={handleAdd} />
          ))}
          {!loading && loadErrors.recommended && (
            <SectionUnavailable section="Recommendations" message={loadErrors.recommended} />
          )}
          {!loading && !loadErrors.recommended && !recommended.length && (
            <EmptyState title="No recommendations yet" description="Browse a bit, and the feed will personalize." />
          )}
        </div>
      </section>

      <section style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 30, marginBottom: 40 }}>
        <Card padded style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <Package size={18} color="var(--copper)" />
            <div className="ss-card__meta">Recent orders</div>
          </div>
          {loading ? (
            <div style={{ padding: '20px 0', opacity: 0.6, fontSize: 14 }}>
              Loading recent orders…
            </div>
          ) : loadErrors.orders ? (
            <SectionUnavailable section="Recent orders" message={loadErrors.orders} compact />
          ) : orders.slice(0, 3).length === 0 ? (
            <div style={{ padding: '20px 0', opacity: 0.6, fontSize: 14 }}>
              No orders yet. Try adding a product to your cart.
            </div>
          ) : orders.slice(0, 3).map((o) => (
            <div key={o.id} style={{ padding: '10px 0', borderBottom: '1px solid var(--rule)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <div style={{ fontFamily: 'var(--display)', fontSize: 15 }}>#{o.id}</div>
                <div className="ss-card__price" style={{ fontSize: 14 }}>${Number(o.total_amount).toFixed(2)}</div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 6, fontSize: 12, opacity: 0.7 }}>
                <span className="ss-mono">{new Date(o.order_date).toLocaleDateString()}</span>
                <OrderStatusChip status={o.status} />
              </div>
            </div>
          ))}
          <div style={{ marginTop: 12 }}>
            <Link to="/secureshop/orders" style={{ color: 'var(--signal)', fontSize: 13, textDecoration: 'none' }}>
              All orders →
            </Link>
          </div>
        </Card>

        <Card padded style={{ padding: 24, background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <Zap size={18} color="var(--signal)" />
            <div className="ss-card__meta">Deals of the day</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
            {loading && Array.from({ length: 3 }).map((_, i) => (
              <div key={i}><div className="ss-skel" style={{ aspectRatio: '4/5', marginBottom: 8 }} /><div className="ss-skel" style={{ height: 16 }} /></div>
            ))}
            {!loading && deals.slice(0, 6).map((p, i) => (
              <Link
                key={p.id}
                to={`/secureshop/product/${p.id}`}
                style={{
                  display: 'flex', flexDirection: 'column', gap: 6,
                  textDecoration: 'none', color: 'inherit',
                  padding: 10, border: '1px solid var(--rule)', background: 'var(--paper)',
                }}
              >
                <div style={{ aspectRatio: '4/5', background: 'var(--carbon)', minHeight: 80 }} />
                <div style={{ fontSize: 13, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {p.name}
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                  <span style={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>${Number(p.price).toFixed(2)}</span>
                </div>
              </Link>
            ))}
            {!loading && loadErrors.deals && (
              <SectionUnavailable section="Deals" message={loadErrors.deals} compact />
            )}
            {!loading && !loadErrors.deals && !deals.length && (
              <EmptyState title="No deals today" description="Check the catalog for current products." />
            )}
          </div>
        </Card>
      </section>

      <section style={{ marginBottom: 40 }}>
        <SectionHeader title="Beauty" viewAllTo="/secureshop/catalog?category=Beauty" />
        <div className="ss-shelf__row">
          {loading && Array.from({ length: 4 }).map((_, i) => <SkelCard key={i} />)}
          {!loading && beauty.map((p, i) => <ProductCard key={p.id} product={p} index={i} onAdd={handleAdd} />)}
          {!loading && loadErrors.beauty && (
            <SectionUnavailable section="Beauty" message={loadErrors.beauty} />
          )}
          {!loading && !loadErrors.beauty && !beauty.length && (
            <EmptyState title="No Beauty products available" description="Try another catalog category." />
          )}
        </div>
      </section>

      <section style={{ marginBottom: 40 }}>
        <SectionHeader title="Books" viewAllTo="/secureshop/catalog?category=Books" />
        <div className="ss-shelf__row">
          {loading && Array.from({ length: 4 }).map((_, i) => <SkelCard key={i} />)}
          {!loading && books.map((p, i) => <ProductCard key={p.id} product={p} index={i} onAdd={handleAdd} />)}
          {!loading && loadErrors.books && (
            <SectionUnavailable section="Books" message={loadErrors.books} />
          )}
          {!loading && !loadErrors.books && !books.length && (
            <EmptyState title="No Books available" description="Try another catalog category." />
          )}
        </div>
      </section>

      <section aria-label="Recent agent activity" style={{ marginBottom: 40 }}>
        <Card padded style={{ padding: 24 }}>
          <div className="ss-card__meta" style={{ marginBottom: 14 }}>RECENT AGENT ACTIVITY</div>
          {loading ? (
            <div role="status" style={{ opacity: 0.65, fontSize: 14 }}>Loading recent activity…</div>
          ) : traceError ? (
            <div role="alert" style={{ opacity: 0.72, fontSize: 14 }}>
              <strong>Recent activity unavailable.</strong> {traceError}
            </div>
          ) : trace.length === 0 ? (
            <div style={{ opacity: 0.65, fontSize: 14 }}>
              No agent activity yet. Start a task in the agent lane to see its recorded steps here.
            </div>
          ) : (
            <ol style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: 10 }}>
              {trace.map((row, index) => (
                <li key={row.id || `${row.session_id || 'activity'}-${row.ts || index}`} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 16,
                  borderTop: '1px solid var(--rule)', paddingTop: 10,
                }}>
                  <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
                    <span style={{ fontWeight: 600 }}>{boundedText(row.actor) || 'Agent'}</span>
                    {' · '}{boundedText(row.tool_name || row.kind) || 'Recorded step'}
                  </span>
                  {row.ts && <time className="ss-mono" dateTime={row.ts} style={{ opacity: 0.62, fontSize: 11, flexShrink: 0 }}>
                    {formatTraceTime(row.ts)}
                  </time>}
                </li>
              ))}
            </ol>
          )}
        </Card>
      </section>

      <section style={{
        padding: '40px 32px',
        background: 'var(--carbon)', color: 'var(--paper)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 20,
      }}>
        <div>
          <div style={{ fontFamily: 'var(--display)', fontSize: 26, marginBottom: 6 }}>Ask the agents anything.</div>
          <div style={{ opacity: 0.75 }}>Every product has a summarizer. Every review has a moderator. Every price has an advisor.</div>
        </div>
        <Button as={Link} to="/secureshop/catalog" variant="ghost" iconRight={<ArrowRight size={16} />}
                style={{ color: 'var(--paper)', borderColor: 'var(--paper)' }}>
          Browse the catalog
        </Button>
      </section>
    </div>
  );
}

async function loadSection(url, section, selectItems) {
  try {
    const response = await fetch(url);
    let body;
    try {
      body = await response.json();
    } catch {
      throw new Error(`${section} returned an unreadable response.`);
    }
    if (!response.ok) {
      throw new Error(boundedText(body?.error) || `${section} are temporarily unavailable.`);
    }
    const items = selectItems(body);
    if (!Array.isArray(items)) {
      throw new Error(`${section} returned an unreadable response.`);
    }
    return { items, error: '' };
  } catch (error) {
    return {
      items: [],
      error: boundedText(error?.message) || `${section} are temporarily unavailable.`,
    };
  }
}

function boundedText(value) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, 200);
}

function formatTraceTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString();
}

function SectionUnavailable({ section, message, compact = false }) {
  return (
    <div
      role="alert"
      style={{ padding: compact ? '14px 0' : 20, opacity: 0.72, fontSize: 14 }}
    >
      <strong>{section} unavailable.</strong> {message}
    </div>
  );
}

function SectionHeader({ title, hint, viewAllTo }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 18 }}>
      <div>
        <h2 className="ss-shelf__title" style={{ margin: 0 }}>{title}</h2>
        {hint && <div className="ss-mono" style={{ opacity: 0.55, fontSize: 11, marginTop: 2 }}>{hint}</div>}
      </div>
      {viewAllTo && (
        <Link to={viewAllTo} style={{ color: 'var(--signal)', fontSize: 13, textDecoration: 'none' }}>
          View all →
        </Link>
      )}
    </div>
  );
}

function SkelCard() {
  return (
    <div className="ss-product-card">
      <div className="ss-skel" style={{ aspectRatio: '4/5' }} />
      <div style={{ padding: 14 }}>
        <div className="ss-skel" style={{ width: '60%', height: 10, marginBottom: 8 }} />
        <div className="ss-skel" style={{ width: '90%', height: 18, marginBottom: 12 }} />
        <div className="ss-skel" style={{ width: '30%', height: 14 }} />
      </div>
    </div>
  );
}
