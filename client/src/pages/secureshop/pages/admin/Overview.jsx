import React, { useEffect, useMemo, useState, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import PageTransition from '../../components/PageTransition.jsx';

/**
 * Admin — Overview.jsx (Wave 2C).
 *
 * The platform-health cockpit. Six sections:
 *   1. KPI cards row (users, products, revenue, sessions)
 *   2. Agent Host status card (polls /admin/agent-host/health every 5s)
 *   3. MCP registry status card (server count + rug-pull detection)
 *   4. Provider status card (per-role active_provider from agent_provider_state)
 *   5. DB size card (secureshop.db + secureshop_agents.db)
 *   6. Recent security-relevant events (top 20 filtered audit rows)
 *   7. Live agent trace strip (last 5 supervisor turns across roles)
 */

const SECURITY_ACTIONS = ['set_role', 'ban', 'update_policy', 'register_mcp', 'reset_password', 'remove_mcp'];
const POLL_MS = 5000;
const READ_TIMEOUT_MS = 10000;
const READS = [
  ['kpis', '/api/secureshop/admin/overview/kpis'],
  ['host', '/api/secureshop/admin/agent-host/health'],
  ['servers', '/api/secureshop/admin/mcp/servers'],
  ['history', '/api/secureshop/admin/mcp/schema-history'],
  ['providers', '/api/secureshop/admin/provider-state'],
  ['dbSizes', '/api/secureshop/admin/db-sizes'],
  ['audit', '/api/secureshop/admin/audit?limit=200'],
  ['trace', '/api/secureshop/agents/admin/trace/latest?limit=5'],
];

async function readJsonResponse(url, signal) {
  const response = await fetch(url, { signal });
  let body = null;
  try {
    body = await response.json();
  } catch {
    // Status remains the useful, non-sensitive error when the response is not JSON.
  }
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.ok === false) {
    throw new Error('Invalid response');
  }
  return body;
}

function readJson(url, parentSignal) {
  const controller = new AbortController();
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      parentSignal.removeEventListener('abort', cancelled);
      if (error) reject(error);
      else resolve(value);
    };
    const cancelled = () => {
      finish(Object.assign(new Error('Request cancelled'), { name: 'AbortError' }));
      controller.abort();
    };
    if (parentSignal.aborted) { cancelled(); return; }
    parentSignal.addEventListener('abort', cancelled, { once: true });
    timer = setTimeout(() => {
      finish(new Error('Request timed out'));
      controller.abort();
    }, READ_TIMEOUT_MS);
    // Settlement is fenced even if fetch/body parsing ignores cancellation.
    readJsonResponse(url, controller.signal).then(
      value => finish(null, value),
      error => finish(error),
    );
  });
}

export default function AdminOverview() {
  const [kpis, setKpis] = useState(null);
  const [host, setHost] = useState(null);
  const [servers, setServers] = useState(null);
  const [history, setHistory] = useState(null);
  const [providers, setProviders] = useState(null);
  const [dbSizes, setDbSizes] = useState(null);
  const [audit, setAudit] = useState(null);
  const [trace, setTrace] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [readErrors, setReadErrors] = useState({});
  const mountedRef = useRef(false);
  const inFlightRef = useRef(false);
  const generationRef = useRef(0);
  const abortRef = useRef(null);

  const refreshAll = useCallback(async () => {
    if (!mountedRef.current || inFlightRef.current) return;
    inFlightRef.current = true;
    const generation = ++generationRef.current;
    const controller = new AbortController();
    abortRef.current = controller;
    const results = await Promise.allSettled(
      READS.map(([, url]) => readJson(url, controller.signal)),
    );

    if (!mountedRef.current || generation !== generationRef.current) return;
    const nextErrors = {};
    const setters = [setKpis, setHost, setServers, setHistory, setProviders, setDbSizes, setAudit, setTrace];
    results.forEach((result, index) => {
      const key = READS[index][0];
      if (result.status === 'fulfilled') setters[index](result.value);
      else if (result.reason?.name !== 'AbortError') nextErrors[key] = result.reason?.message || 'request failed';
    });
    setReadErrors(nextErrors);
    setLoading(false);
    if (Object.keys(nextErrors).length === 0) setLastRefresh(new Date());
    inFlightRef.current = false;
    abortRef.current = null;
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    refreshAll();
    const t = setInterval(refreshAll, POLL_MS);
    return () => {
      mountedRef.current = false;
      generationRef.current += 1;
      abortRef.current?.abort();
      abortRef.current = null;
      inFlightRef.current = false;
      clearInterval(t);
    };
  }, [refreshAll]);

  // Compute MCP rug-pull count from schema history.
  const mcpRugPullCount = useMemo(() => {
    if (!history?.history?.length) return 0;
    const byName = new Map();
    let changed = 0;
    for (const h of history.history) {
      const prev = byName.get(h.name);
      if (prev && prev !== h.schema_hash) changed += 1;
      byName.set(h.name, h.schema_hash);
    }
    return changed;
  }, [history]);

  const mcpLastActivity = useMemo(() => {
    if (!history?.history?.length) return null;
    return history.history[history.history.length - 1]?.ts || null;
  }, [history]);

  const securityEvents = useMemo(() => {
    const filtered = (audit?.events || []).filter(e => SECURITY_ACTIONS.includes(String(e.action)));
    return filtered.slice(0, 20);
  }, [audit]);

  const failedReads = Object.keys(readErrors);
  const mcpError = readErrors.servers || readErrors.history;
  const mcpStatus = mcpError
    ? (servers || history ? 'STALE' : 'UNAVAILABLE')
    : (servers && history ? (mcpRugPullCount > 0 ? 'ALERT' : (servers?.basis === 'persisted_launch_discovery' ? 'RECORDED' : 'OK')) : undefined);

  return (
    <PageTransition>
      <header style={{ marginBottom: 32 }}>
        <div className="ss-card__meta">ADMIN LENS</div>
        <h1 className="ss-display" style={{ fontSize: 40, margin: '6px 0 8px 0' }}>The seam of the whole platform.</h1>
        <p style={{ opacity: 0.75, fontSize: 15, lineHeight: 1.55, maxWidth: '60ch' }}>
          Every task agent — user, audit, system, policy, MCP registry — answers to a single LLM
          turn away. The lane on the right can call them all. Watch this page for the hop that walks off.
        </p>
        <div className="ss-mono" style={{ opacity: 0.55, fontSize: 11, marginTop: 8 }}>
          auto-refresh every {POLL_MS / 1000}s{lastRefresh ? ` · last complete update ${_fmtClock(lastRefresh)}` : ''}
        </div>
        {failedReads.length > 0 && (
          <div role="alert" className="ss-mono" style={{ marginTop: 10, padding: '8px 10px', border: '1px solid var(--rust)', color: 'var(--rust)', fontSize: 11 }}>
            incomplete refresh · unavailable: {failedReads.join(', ')}
          </div>
        )}
      </header>

      {/* KPI row */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 40 }}>
        <StaggerKpi delay={0.00} label="TOTAL USERS"    value={kpis?.total_users ?? '…'}    sub={kpis ? `${kpis.admin_count} admin · ${kpis.banned_count} banned` : (readErrors.kpis ? 'unavailable' : 'loading…')} stale={Boolean(readErrors.kpis && kpis)} />
        <StaggerKpi delay={0.04} label="TOTAL PRODUCTS" value={kpis?.total_products ?? '…'} sub={kpis ? `${kpis.total_orders} orders` : (readErrors.kpis ? 'unavailable' : 'loading…')} stale={Boolean(readErrors.kpis && kpis)} />
        <StaggerKpi delay={0.08} label="TOTAL REVENUE"  value={kpis ? `$${_fmtMoney(kpis.total_revenue)}` : '…'} sub={kpis ? (kpis.revenue_basis === 'gross_order_total' ? 'gross order total' : 'all-time') : (readErrors.kpis ? 'unavailable' : 'loading…')} stale={Boolean(readErrors.kpis && kpis)} />
        <StaggerKpi delay={0.12} label="ACTIVE SESSIONS" value={kpis?.active_sessions ?? '…'} sub={kpis ? 'last 15 minutes' : (readErrors.kpis ? 'unavailable' : 'loading…')} stale={Boolean(readErrors.kpis && kpis)} />
      </section>

      {/* Status cards grid */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 40 }}>
        <StatusCard title={host?.runtime || "Agent Host"} onlineOverride={readErrors.host ? (host ? 'STALE' : 'UNAVAILABLE') : host?.status}>
          <StatusRow label="status">
            <StatusDot online={['ONLINE','SERVICE_READY'].includes(host?.status)} />
            <b style={{ color: ['ONLINE','SERVICE_READY'].includes(host?.status) ? 'var(--ink)' : 'var(--rust)' }}>
              {host?.status || (loading ? 'checking…' : 'UNKNOWN')}
            </b>
          </StatusRow>
          {host?.model_execution === 'not_tested' && <div className="ss-mono" style={{fontSize:11,opacity:0.65}}>Scoped service checks only; model execution not tested.</div>}
          {(host?.providers || []).map(p => <StatusRow key={p.provider} label={p.provider}>{p.availability}</StatusRow>)}
          <StatusRow label="port">{host?.port ?? '—'}</StatusRow>
          <StatusRow label="agents">{host?.agents ?? '—'}</StatusRow>
          {host?.error && (
            <div className="ss-mono" style={{ fontSize: 11, opacity: 0.65, marginTop: 8, color: 'var(--rust)' }}>
              {host.error}
            </div>
          )}
          <ReadFailure error={readErrors.host} retained={Boolean(host)} />
        </StatusCard>

        <StatusCard title="MCP Registry" onlineOverride={mcpStatus}>
          {servers?.basis === 'persisted_launch_discovery' && <div className="ss-mono" style={{fontSize:11,opacity:0.65}}>Persisted launch discoveries; network health is not measured.</div>}
          <StatusRow label={servers?.basis === 'persisted_launch_discovery' ? 'observed targets' : 'registered'}>{servers?.servers?.length ?? '—'}</StatusRow>
          <StatusRow label="schema mismatches">
            <span style={{ color: mcpRugPullCount > 0 ? 'var(--rust)' : 'var(--ink)', fontWeight: 600 }}>
              {history ? mcpRugPullCount : '—'}
            </span>
          </StatusRow>
          <StatusRow label="last activity">{mcpLastActivity ? _fmtTs(mcpLastActivity) : '—'}</StatusRow>
          <Link to="/secureshop/admin/mcp" className="ss-mono" style={{ display: 'inline-block', marginTop: 8, fontSize: 11, opacity: 0.75 }}>
            registry →
          </Link>
          <ReadFailure error={mcpError} retained={Boolean((readErrors.servers && servers) || (readErrors.history && history))} />
        </StatusCard>

        <StatusCard title="Provider State">
          {!providers && !readErrors.providers && (
            <div className="ss-mono" style={{ opacity: 0.55, fontSize: 12 }}>checking provider state…</div>
          )}
          {providers && (providers.providers || []).length === 0 && (
            <div className="ss-mono" style={{ opacity: 0.55, fontSize: 12 }}>no provider state yet — trigger a supervisor turn</div>
          )}
          {(providers?.providers || []).map(p => (
            <StatusRow key={p.role} label={p.role}>
              <span className="ss-mono" style={{ fontSize: 12 }}>
                {p.active_provider || 'unset'}
              </span>
            </StatusRow>
          ))}
          <ReadFailure error={readErrors.providers} retained={Boolean(providers)} />
        </StatusCard>

        <StatusCard title={dbSizes?.basis === 'selected_launch_json_row_bytes' ? 'Selected launch data' : 'Database Files'}>
          {!dbSizes && !readErrors.dbSizes && <div className="ss-mono" style={{ opacity: 0.55, fontSize: 12 }}>checking database files…</div>}
          {dbSizes?.basis === 'selected_launch_json_row_bytes' && <div className="ss-mono" style={{fontSize:11,opacity:0.65}}>Logical JSON row bytes; selected sources only, not physical disk usage.</div>}
          {(dbSizes?.files || []).map(f => (
            <StatusRow key={f.path} label={_basename(f.path)}>
              <span className="ss-mono" style={{ fontSize: 12 }}>
                {f.size_mb != null ? `${f.size_mb} MB` : (f.error || '—')}
              </span>
            </StatusRow>
          ))}
          <ReadFailure error={readErrors.dbSizes} retained={Boolean(dbSizes)} />
        </StatusCard>
      </section>

      {/* Security-relevant events */}
      <section style={{ marginBottom: 40 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
          <h2 className="ss-shelf__title">Recent security-relevant events</h2>
          <Link to="/secureshop/admin/audit" className="ss-mono" style={{ opacity: 0.7 }}>
            all events →
          </Link>
        </div>
        <div style={{ border: '1px solid var(--rule)' }}>
          <div className="ss-mono" style={{ display: 'grid', gridTemplateColumns: '160px 120px 140px 1fr', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--rule)', fontSize: 11, opacity: 0.7, textTransform: 'uppercase' }}>
            <div>timestamp</div><div>actor</div><div>action</div><div>target · params</div>
          </div>
          <AnimatePresence mode="popLayout">
            {!audit && readErrors.audit ? (
              <UnavailableRow label="security events unavailable" />
            ) : securityEvents.length === 0 ? (
              <div className="ss-mono" style={{ padding: 20, opacity: 0.5, fontSize: 12 }}>
                {loading ? 'checking security events…' : 'no security-relevant events yet — trigger set_role, ban, register_mcp, or update_policy'}
              </div>
            ) : securityEvents.map((e, i) => (
              <motion.div
                key={e.id}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.24, delay: i * 0.02 }}
                style={{ display: 'grid', gridTemplateColumns: '160px 120px 140px 1fr', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--rule)', fontSize: 12, alignItems: 'center' }}
              >
                <div className="ss-mono" style={{ opacity: 0.6 }}>{_fmtTs(e.ts)}</div>
                <div><b>{e.actor}</b></div>
                <div>
                  <span style={{
                    padding: '2px 8px', border: '1px solid var(--rule)', fontSize: 11,
                    fontFamily: 'var(--mono)',
                    color: _actionColor(e.action),
                  }}>{e.action}</span>
                </div>
                <div className="ss-mono" style={{ fontSize: 11, opacity: 0.8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {e.target || '-'} · {String(e.params_json || '').slice(0, 80)}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
          {audit && <ReadFailure error={readErrors.audit} retained />}
        </div>
      </section>

      {/* Live agent trace strip */}
      <section style={{ marginBottom: 40 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 12 }}>
          <h2 className="ss-shelf__title">Live agent trace</h2>
          <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6 }}>last 5 supervisor turns across all roles</div>
        </div>
        <div style={{ display: 'grid', gap: 6 }}>
          <AnimatePresence mode="popLayout">
            {!trace && readErrors.trace ? (
              <UnavailableRow label="agent trace unavailable" />
            ) : (trace?.rows || []).length === 0 ? (
              <div className="ss-mono" style={{ padding: 20, opacity: 0.5, fontSize: 12, border: '1px solid var(--rule)' }}>
                {loading ? 'checking agent activity…' : 'no agent activity yet — start a chat in the agent lane'}
              </div>
            ) : (trace?.rows || []).map((row, i) => (
              <motion.div
                key={row.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.24, delay: i * 0.03 }}
                style={{ display: 'grid', gridTemplateColumns: '90px 180px 1fr 90px 90px', gap: 8, padding: '10px 12px', border: '1px solid var(--rule)', alignItems: 'center', fontSize: 12 }}
              >
                <div>
                  <RoleBadge role={row.session_role} />
                </div>
                <div className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>
                  {String(row.session_id || '').slice(0, 8)}…
                </div>
                <div>
                  <b>{row.agent_ns || row.actor || '—'}</b>
                  {row.tool_name && <span className="ss-mono" style={{ opacity: 0.65, marginLeft: 6 }}>· {row.tool_name}</span>}
                </div>
                <div className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>{row.kind}</div>
                <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55 }}>{_fmtTs(row.ts).slice(11)}</div>
              </motion.div>
            ))}
          </AnimatePresence>
          {trace && <ReadFailure error={readErrors.trace} retained />}
        </div>
      </section>

      <section className="ss-editorial">
        <h2>Five task agents, one supervisor.</h2>
        <p>
          Ask the lane: "list users", "show me recent audit events", "summarize anomalies", "restart the api service".
          Every call becomes a hop. Every hop is a candidate for the vuln you're teaching.
        </p>
      </section>
    </PageTransition>
  );
}

// -----------------------------------------------------------------------------
// Small display primitives — inlined per Wave 2C guardrail (Wave 2A owns
// shared components; we don't touch that directory).
// -----------------------------------------------------------------------------

function StaggerKpi({ label, value, sub, delay = 0, stale = false }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.32, delay, ease: [0.16, 1, 0.3, 1] }}
      style={{
        border: '1px solid var(--rule)', padding: 20,
        background: 'color-mix(in srgb, var(--paper) 92%, var(--carbon))',
      }}
    >
      <div className="ss-card__meta">{label}</div>
      <div className="ss-display" style={{ fontSize: 32, margin: '6px 0 2px 0', fontVariantNumeric: 'tabular-nums' }}>{value}</div>
      <div className="ss-mono" style={{ opacity: 0.6, fontSize: 12 }}>{sub}</div>
      {stale && <ReadFailure error="refresh failed" retained />}
    </motion.div>
  );
}

function ReadFailure({ error, retained = false }) {
  if (!error) return null;
  return (
    <div className="ss-mono" style={{ marginTop: 8, fontSize: 11, color: 'var(--rust)' }}>
      {retained ? 'stale data · ' : 'unavailable · '}{error}
    </div>
  );
}

function UnavailableRow({ label }) {
  return <div className="ss-mono" style={{ padding: 20, color: 'var(--rust)', fontSize: 12 }}>{label}</div>;
}

function StatusCard({ title, onlineOverride, children }) {
  const chip = onlineOverride ? (
    <span
      style={{
        display: 'inline-block', padding: '2px 8px',
        fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: '0.06em',
        background: ['ONLINE','OK','SERVICE_READY','RECORDED'].includes(onlineOverride) ? 'color-mix(in srgb, var(--signal) 15%, transparent)' : 'color-mix(in srgb, var(--rust) 15%, transparent)',
        color: ['ONLINE','OK','SERVICE_READY','RECORDED'].includes(onlineOverride) ? 'var(--signal)' : 'var(--rust)',
        border: `1px solid ${['ONLINE','OK','SERVICE_READY','RECORDED'].includes(onlineOverride) ? 'var(--signal)' : 'var(--rust)'}`,
      }}
    >{onlineOverride}</span>
  ) : null;
  return (
    <div style={{ border: '1px solid var(--rule)', padding: 20, background: 'var(--paper)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div className="ss-card__meta">{title}</div>
        {chip}
      </div>
      {children}
    </div>
  );
}

function StatusRow({ label, children }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0', fontSize: 13 }}>
      <div className="ss-mono" style={{ opacity: 0.6, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>{children}</div>
    </div>
  );
}

function StatusDot({ online }) {
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: online ? 'var(--signal)' : 'var(--rust)',
      boxShadow: online ? '0 0 6px color-mix(in srgb, var(--signal) 50%, transparent)' : 'none',
    }} />
  );
}

function RoleBadge({ role }) {
  const color = role === 'admin' ? 'var(--rust)' : role === 'merchant' ? 'var(--copper)' : 'var(--signal)';
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', border: `1px solid ${color}`,
      color, fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: '0.06em', textTransform: 'uppercase',
    }}>{role || '—'}</span>
  );
}

function _fmtTs(ts) {
  if (!ts) return '';
  return String(ts).replace('T', ' ').replace('Z', '').slice(0, 19);
}
function _fmtClock(d) {
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}
function _fmtMoney(n) {
  if (n == null) return '0';
  return Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function _basename(p) {
  const m = String(p || '').split('/');
  return m[m.length - 1] || p;
}
function _actionColor(action) {
  if (['set_role', 'update_policy'].includes(action)) return 'var(--rust)';
  if (['ban', 'reset_password', 'register_mcp'].includes(action)) return 'var(--copper)';
  return 'var(--ink)';
}
