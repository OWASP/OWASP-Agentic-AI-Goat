import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import {
  ArrowUpRight, ArrowDownRight, TrendingUp, ShoppingBag,
  Package, DollarSign, Sparkles, MessageSquareText, LineChart as LineIcon,
  Activity, PlusCircle, ShieldCheck, FlaskConical,
} from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip,
  AreaChart, Area, CartesianGrid,
} from 'recharts';
import InventoryPanel from './InventoryPanel.jsx';
import { useAuth } from '../../context/AuthContext.jsx';

/**
 * Merchant Overview — M8 Wave 2B.
 *
 * The Overview is the merchant's operations dashboard:
 *   - Four KPI cards with delta indicators + tiny sparklines
 *   - Big sales chart (last-30-day revenue area chart)
 *   - Live agent activity feed polling agent_trace scoped to merchant sessions
 *   - Quick-action panel — links to Listings / Reviews / Pricing
 *
 * Every panel has an explicit empty state and the whole page respects
 * prefers-reduced-motion.
 */
export default function MerchantOverview() {
  const { user, token } = useAuth() || {};
  const retailerId = user?.id || 2;
  const requestFetch = window.fetch;
  const reduced = useReducedMotion();

  const [kpis, setKpis] = useState(null);
  const [salesData, setSalesData] = useState([]);
  const [trace, setTrace] = useState([]);
  const [products, setProducts] = useState([]);
  const [pendingReviews, setPendingReviews] = useState(null);
  const [activeListings, setActiveListings] = useState(null);
  const [loadErrors, setLoadErrors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [traceError, setTraceError] = useState(null);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setKpis(null); setSalesData([]); setProducts([]); setPendingReviews(null);
    setActiveListings(null); setLoadErrors([]);
    const read = (url, valid) => readOverviewJson(requestFetch, url, controller.signal, valid);
    Promise.allSettled([
      read(`/api/secureshop/merchant/overview/kpis?retailer_id=${retailerId}`, j =>
        ['revenue','orders','aov'].every(key => Number.isFinite(j?.[key]?.value) && j[key].value >= 0)),
      read(`/api/secureshop/merchant/overview/sales-chart?retailer_id=${retailerId}&days=30`, j => Array.isArray(j?.series)),
      read(`/api/secureshop/merchant/products?retailer_id=${retailerId}&status=active&per_page=6`, j =>
        Array.isArray(j?.products) && Number.isSafeInteger(j.total) && j.total >= 0),
      read('/api/secureshop/merchant/reviews?status=pending&per_page=1', j =>
        Array.isArray(j?.reviews) && Number.isSafeInteger(j.total) && j.total >= 0),
    ]).then(([kpiRes, salesRes, prodRes, revRes]) => {
      if (cancelled) return;
      if (kpiRes.status === 'fulfilled') setKpis(kpiRes.value);
      if (salesRes.status === 'fulfilled') setSalesData(salesRes.value?.series || []);
      if (prodRes.status === 'fulfilled') { setProducts(prodRes.value.products); setActiveListings(prodRes.value.total); }
      if (revRes.status === 'fulfilled') setPendingReviews(revRes.value.total);
      setLoadErrors([kpiRes,salesRes,prodRes,revRes].flatMap((result,index) =>
        result.status === 'rejected' ? [['Metrics','Sales chart','Listings','Review count'][index]] : []));
      setLoading(false);
    });
    return () => { cancelled = true; controller.abort(); };
  }, [retailerId, token, requestFetch, reload]);

  useEffect(() => {
    let cancelled = false;
    let timer;
    const controller = new AbortController();
    setTrace([]); setTraceError(null);
    async function pullTrace() {
      try {
        const j = await readOverviewJson(requestFetch, '/api/secureshop/agents/merchant/trace/latest?limit=10',
          controller.signal, value => Array.isArray(value?.rows));
        if (cancelled) return;
        setTrace(j.rows || []);
        setTraceError(j.degraded || null);
      } catch (e) {
        if (!cancelled) setTraceError(e.message);
      } finally {
        if (!cancelled) timer = setTimeout(pullTrace, 5000);
      }
    }
    pullTrace();
    return () => { cancelled = true; controller.abort(); clearTimeout(timer); };
  }, [retailerId, token, requestFetch]);

  const displayName = user?.username || user?.full_name || 'merchant';

  return (
    <motion.div
      initial={reduced ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
      style={{ display: 'flex', flexDirection: 'column', gap: 40 }}
    >
      <header>
        <div className="ss-card__meta">MERCHANT LENS · {displayName.toUpperCase()}</div>
        <h1 className="ss-display" style={{ fontSize: 46, margin: '8px 0 10px 0', letterSpacing: '-0.015em' }}>
          Your store, watched by five agents.
        </h1>
        <p style={{ maxWidth: '68ch', opacity: 0.75, fontSize: 15, lineHeight: 1.55 }}>
          Every product summary you approve is written by an LLM. Every review is moderated by one.
          Every price suggestion carries a hidden retrieval chain. The lane on the right is the
          transparent seam of that machine — read it before you trust it.
        </p>
      </header>

      <section aria-label="key performance indicators">
        {loadErrors.length > 0 && <div role="alert">{loadErrors.join(', ')} unavailable.{' '}
          <button type="button" className="ss-btn ss-btn--sm" onClick={() => setReload(value => value + 1)}>Retry dashboard</button>
        </div>}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 16,
        }}>
          <KpiCard
            icon={<DollarSign size={18} />}
            label="30-DAY REVENUE"
            value={loading ? null : kpis ? `$${kpis.revenue.value.toFixed(2)}` : '—'}
            delta={kpis?.revenue?.delta_pct}
            spark={kpis?.revenue?.spark || []}
            reduced={reduced}
          />
          <KpiCard
            icon={<ShoppingBag size={18} />}
            label="ORDERS (30D)"
            value={loading ? null : kpis ? String(kpis.orders.value) : '—'}
            delta={kpis?.orders?.delta_pct}
            spark={kpis?.orders?.spark || []}
            reduced={reduced}
          />
          <KpiCard
            icon={<TrendingUp size={18} />}
            label="AVG ORDER VALUE"
            value={loading ? null : kpis ? `$${kpis.aov.value.toFixed(2)}` : '—'}
            delta={kpis?.aov?.delta_pct}
            reduced={reduced}
          />
          <KpiCard
            icon={<Package size={18} />}
            label="TOP PRODUCT"
            value={loading ? null : (kpis?.top_product?.name || '—')}
            sub={kpis?.top_product ? `$${Number(kpis.top_product.revenue || 0).toFixed(2)}` : kpis ? 'no orders yet' : undefined}
            small
            reduced={reduced}
          />
        </div>
      </section>

      <InventoryPanel token={token} transport={requestFetch} onComplete={()=>setReload(value=>value+1)} />

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 1fr)', gap: 32 }}>
        <section aria-label="sales chart" style={panelStyle}>
          <div style={panelHeader}>
            <div>
              <div className="ss-card__meta">DAILY REVENUE · LAST 30 DAYS</div>
              <div className="ss-display" style={{ fontSize: 22, marginTop: 4 }}>Sales trend</div>
            </div>
            <div style={{ display: 'inline-flex', gap: 8, alignItems: 'center', color: 'var(--kelp)' }}>
              <LineIcon size={16} />
              <span className="ss-mono" style={{ fontSize: 12, opacity: 0.75 }}>{salesData.length} days</span>
            </div>
          </div>

          {loading ? (
            <div style={{ height: 260, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div className="ss-mono" style={{ opacity: 0.5 }}>loading…</div>
            </div>
          ) : loadErrors.includes('Sales chart') ? (
            <div role="status">Sales chart unavailable.</div>
          ) : salesData.length === 0 ? (
            <EmptyState
              icon={<LineIcon size={28} />}
              title="No sales yet"
              body="Once orders start rolling in this chart will fill out with daily revenue."
            />
          ) : (
            <div style={{ height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={salesData} margin={{ top: 10, right: 10, left: 0, bottom: 4 }}>
                  <defs>
                    <linearGradient id="salesFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--signal)" stopOpacity={0.28} />
                      <stop offset="100%" stopColor="var(--signal)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--rule)" strokeDasharray="3 3" strokeOpacity={0.4} vertical={false} />
                  <XAxis
                    dataKey="day"
                    tick={{ fontSize: 10, fill: 'var(--ink)', opacity: 0.6 }}
                    tickFormatter={(d) => d?.slice(5)}
                    interval={4}
                  />
                  <YAxis
                    tick={{ fontSize: 10, fill: 'var(--ink)', opacity: 0.6 }}
                    tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v)}
                    width={44}
                  />
                  <Tooltip
                    contentStyle={{
                      background: 'var(--carbon)', color: 'var(--paper)', border: '1px solid var(--rule)',
                      fontFamily: 'var(--mono)', fontSize: 12,
                    }}
                    labelStyle={{ color: 'var(--paper)' }}
                    formatter={(v, name) => [`$${Number(v).toFixed(2)}`, name]}
                  />
                  <Area
                    type="monotone" dataKey="revenue"
                    stroke="var(--signal)" strokeWidth={2}
                    fill="url(#salesFill)"
                    isAnimationActive={!reduced}
                    animationDuration={reduced ? 0 : 400}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section aria-label="agent activity" style={panelStyle}>
          <div style={panelHeader}>
            <div>
              <div className="ss-card__meta">AGENT ACTIVITY</div>
              <div className="ss-display" style={{ fontSize: 22, marginTop: 4 }}>What agents did</div>
            </div>
            <Activity size={16} style={{ color: 'var(--copper)' }} />
          </div>

          {traceError && (
            <div className="ss-mono" style={{ fontSize: 12, opacity: 0.55, marginBottom: 8 }}>
              (trace store: {traceError})
            </div>
          )}

          {trace.length === 0 ? (
            <EmptyState
              icon={<Sparkles size={24} />}
              title="No agent activity yet"
              body="Ask the merchant supervisor a question and hops will show up here in real time."
            />
          ) : (
            <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 10 }}>
              <AnimatePresence initial={false}>
                {trace.slice(0, 10).map((row, idx) => (
                  <motion.li
                    key={row.id}
                    initial={reduced ? false : { opacity: 0, x: 8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ delay: reduced ? 0 : idx * 0.035, duration: 0.24 }}
                    style={{
                      border: '1px solid var(--rule)',
                      padding: 10,
                      background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))',
                    }}
                  >
                    <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6, display: 'flex', justifyContent: 'space-between' }}>
                      <span>{row.kind}</span>
                      <span>{formatRelative(row.ts)}</span>
                    </div>
                    <div style={{ marginTop: 4, fontSize: 13 }}>
                      <span className="ss-mono" style={{ color: 'var(--kelp)' }}>{row.agent_ns || 'supervisor'}</span>
                      {row.tool_name && (
                        <>
                          <span style={{ opacity: 0.4 }}> · </span>
                          <span className="ss-mono" style={{ color: 'var(--copper)' }}>{row.tool_name}</span>
                        </>
                      )}
                    </div>
                    {row.latency_ms != null && (
                      <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55, marginTop: 2 }}>
                        {row.latency_ms}ms · {row.provider || 'n/a'}
                      </div>
                    )}
                  </motion.li>
                ))}
              </AnimatePresence>
            </ul>
          )}
        </section>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 2fr)', gap: 32 }}>
        <section aria-label="quick actions" style={panelStyle}>
          <div style={panelHeader}>
            <div>
              <div className="ss-card__meta">QUICK ACTIONS</div>
              <div className="ss-display" style={{ fontSize: 22, marginTop: 4 }}>Do next</div>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <QuickAction to="/secureshop/merchant/listings#new" icon={<PlusCircle size={16} />} title="Add product" sub="Nunjucks template + AI description" reduced={reduced} />
            <QuickAction to="/secureshop/merchant/reviews" icon={<ShieldCheck size={16} />} title="Moderate reviews" sub={pendingReviews === null ? 'review count unavailable' : pendingReviews > 0 ? `${pendingReviews} pending` : 'no pending'} badge={pendingReviews > 0 ? pendingReviews : null} reduced={reduced} />
            <QuickAction to="/secureshop/merchant/pricing" icon={<FlaskConical size={16} />} title="Run pricing experiment" sub="undercut / premium / bundle" reduced={reduced} />
            <QuickAction to="/secureshop/merchant/analytics" icon={<MessageSquareText size={16} />} title="Ask analytics" sub="natural language → SQL → chart" reduced={reduced} />
          </div>
        </section>

        <section aria-label="latest listings" style={panelStyle}>
          <div style={panelHeader}>
            <div>
              <div className="ss-card__meta">LATEST LISTINGS</div>
              <div className="ss-display" style={{ fontSize: 22, marginTop: 4 }}>{activeListings ?? '—'} active</div>
            </div>
            <Link to="/secureshop/merchant/listings" className="ss-mono"
                  style={{ fontSize: 12, opacity: 0.75, textDecoration: 'none', color: 'var(--kelp)' }}>
              See all →
            </Link>
          </div>

          {loading ? (
            <div role="status">Loading listings…</div>
          ) : loadErrors.includes('Listings') ? (
            <div role="status">Listings unavailable.</div>
          ) : products.length === 0 ? (
            <EmptyState
              icon={<Package size={28} />}
              title="No listings yet"
              body="Head to Listings and create your first product."
              cta={{ to: '/secureshop/merchant/listings', label: 'Create listing' }}
            />
          ) : (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
              gap: 12,
            }}>
              {products.slice(0, 6).map((p, idx) => (
                <motion.div
                  key={p.id}
                  initial={reduced ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: reduced ? 0 : idx * 0.035, duration: 0.28 }}
                >
                  <Link to={`/secureshop/merchant/listings#p${p.id}`}
                        style={{ textDecoration: 'none', color: 'inherit', display: 'block',
                                 border: '1px solid var(--rule)', padding: 12, minHeight: 96 }}>
                    <div className="ss-card__meta" style={{ fontSize: 10 }}>
                      #{p.id} · {p.status}
                    </div>
                    <div style={{ fontFamily: 'var(--display)', fontSize: 15, margin: '4px 0', lineHeight: 1.2 }}>
                      {truncate(p.name, 42)}
                    </div>
                    <div className="ss-mono" style={{ fontSize: 12, opacity: 0.75, display: 'flex', justifyContent: 'space-between' }}>
                      <span>${Number(p.price).toFixed(2)}</span>
                      <span>stock: {p.stock_quantity}</span>
                    </div>
                  </Link>
                </motion.div>
              ))}
            </div>
          )}
        </section>
      </div>

      <section className="ss-editorial" style={{ marginBottom: 20 }}>
        <h2>What the agents did this hour.</h2>
        <p>
          Ask the agent lane about your store: "what did the review moderator do today?",
          "which product needs a reorder?", "top 5 SKUs by revenue this week". The supervisor
          writes SQL, runs it, and shows you every hop. When it makes a call you didn't
          sanction — you'll see the hop.
        </p>
      </section>
    </motion.div>
  );
}

async function readOverviewJson(requestFetch, url, signal, valid) {
  const response = await requestFetch(url, { signal });
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  const body = await response.json();
  if (!valid(body)) throw new Error('Invalid response');
  return body;
}

function KpiCard({ icon, label, value, delta, sub, spark = [], small, reduced }) {
  const positive = typeof delta === 'number' && delta > 0;
  const negative = typeof delta === 'number' && delta < 0;
  return (
    <motion.div
      initial={reduced ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
      style={{
        border: '1px solid var(--rule)',
        padding: 20,
        background: 'color-mix(in srgb, var(--paper) 92%, var(--carbon))',
        display: 'flex', flexDirection: 'column', gap: 6,
        minHeight: 140,
        position: 'relative',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, opacity: 0.65 }}>
        {icon}
        <div className="ss-card__meta">{label}</div>
      </div>
      {value === null ? (
        <div className="ss-skel" style={{ height: 26, marginTop: 6 }} />
      ) : (
        <div
          className="ss-display"
          style={{
            fontSize: small ? 20 : 30,
            margin: '2px 0 2px 0',
            fontVariantNumeric: 'tabular-nums',
            lineHeight: 1.1,
          }}
        >
          {value}
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', minHeight: 20 }}>
        {typeof delta === 'number' ? (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12,
            color: positive ? 'var(--kelp)' : negative ? 'var(--rust)' : 'var(--copper)',
            fontFamily: 'var(--mono)',
          }}>
            {positive ? <ArrowUpRight size={12} /> : negative ? <ArrowDownRight size={12} /> : null}
            {positive ? '+' : ''}{delta}%
            <span style={{ opacity: 0.6, marginLeft: 2 }}>vs prev period</span>
          </span>
        ) : (
          <span className="ss-mono" style={{ opacity: 0.5, fontSize: 12 }}>{sub || ''}</span>
        )}

        {spark && spark.length > 1 && (
          <div style={{ width: 72, height: 22, opacity: 0.85 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={spark.map((v, i) => ({ i, v }))}>
                <Line dataKey="v" stroke="var(--signal)" strokeWidth={1.5} dot={false}
                      isAnimationActive={!reduced} animationDuration={reduced ? 0 : 400} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </motion.div>
  );
}

function QuickAction({ to, icon, title, sub, badge, reduced }) {
  return (
    <motion.div
      whileHover={reduced ? undefined : { x: 3 }}
      transition={{ duration: 0.18 }}
    >
      <Link to={to} style={{
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '12px 14px',
        border: '1px solid var(--rule)',
        textDecoration: 'none', color: 'inherit',
        background: 'color-mix(in srgb, var(--paper) 94%, var(--carbon))',
      }}>
        <div style={{
          width: 32, height: 32, display: 'grid', placeItems: 'center',
          background: 'var(--carbon)', color: 'var(--paper)', flexShrink: 0,
        }}>
          {icon}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: 'var(--display)', fontSize: 15, lineHeight: 1.2 }}>{title}</div>
          <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6 }}>{sub}</div>
        </div>
        {badge != null && (
          <div style={{
            padding: '2px 8px', background: 'var(--signal)', color: 'var(--paper)',
            fontFamily: 'var(--mono)', fontSize: 11, letterSpacing: '0.05em',
          }}>{badge}</div>
        )}
      </Link>
    </motion.div>
  );
}

function EmptyState({ icon, title, body, cta }) {
  return (
    <div style={{
      padding: '32px 20px', textAlign: 'center',
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8,
      color: 'var(--ink)', opacity: 0.75,
    }}>
      <div style={{ opacity: 0.5 }}>{icon}</div>
      <div style={{ fontFamily: 'var(--display)', fontSize: 16 }}>{title}</div>
      <div style={{ fontSize: 13, maxWidth: '38ch', lineHeight: 1.4 }}>{body}</div>
      {cta && (
        <Link to={cta.to} className="ss-btn ss-btn--sm" style={{ marginTop: 8 }}>{cta.label}</Link>
      )}
    </div>
  );
}

const panelStyle = {
  border: '1px solid var(--rule)',
  padding: 20,
  display: 'flex', flexDirection: 'column', gap: 16,
  background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))',
};

const panelHeader = {
  display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12,
};

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function formatRelative(ts) {
  if (!ts) return 'just now';
  try {
    const d = new Date(ts).getTime();
    const diff = Date.now() - d;
    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  } catch {
    return '';
  }
}
