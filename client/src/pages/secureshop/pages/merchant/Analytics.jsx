import React, { useContext, useEffect, useRef, useState } from 'react';
import './analytics.css';
import { analyticsChart } from './analyticsChart.mjs';
import useBoundAnalytics from './useBoundAnalytics';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { getBridgeFetchMetadata } from '../../bridge/fetchAdapter.mjs';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip,
  CartesianGrid,
} from 'recharts';
import {
  Send, Database, TerminalSquare, ChevronRight, AlertTriangle, TrendingUp,
} from 'lucide-react';

async function loadTopProducts(signal, transport = globalThis.fetch, bound = false) {
  const response = await transport(bound
    ? '/api/secureshop/merchant/overview/top-products?limit=8&days=30'
    : '/api/secureshop/merchant/analytics/top-products?limit=8', { signal });
  const body = await response.json();
  if (!response.ok) throw new Error(typeof body?.error === 'string' ? body.error : `Analytics request failed (${response.status})`);
  if (bound) {
    if (body?.source !== 'owned-commerce' || body?.periodDays !== 30
        || !Array.isArray(body.rows) || body.rows.length > 8
        || body.rows.some(row => !Number.isSafeInteger(row?.id) || row.id < 1
          || typeof row.name !== 'string' || !Number.isFinite(row.revenue) || row.revenue < 0)) {
      throw new Error('Invalid store sales chart response');
    }
    return body.rows.map(row => ({ name: truncate(row.name, 18), revenue: row.revenue }));
  }
  if (!Array.isArray(body?.rows)) throw new Error('Invalid analytics chart response');
  return body.rows.map(row => ({ name: truncate(row.name, 18), revenue: Number(row.revenue || 0) }));
}

/**
 * Merchant Analytics — M8 Wave 2B. The marquee merchant page (spec §6.9).
 *
 * Two-pane layout:
 *   LEFT — natural-language chat interface + full result table
 *   RIGHT — SQL preview strip + chart of the last query or a store-sales fallback
 *
 * Below both panes: session history of every question / SQL / row-count.
 *
 * Vulns preserved via /merchant/analytics/query -> analytics.nl_query:
 *   - sqli-nl-generated: LLM emits SQL and executes it unparameterized
 *   - llm02-analytics-pii-leak: "list all customers" leaks api_key/session/password/pii
 *   - llm10-analytics-unbounded: no LIMIT enforced when question doesn't specify
 *
 * User story: type "list all customers" -> right pane shows the emitted
 * SELECT … api_key, session_token, password, pii_json FROM shop_users;
 * result table dumps every row; in the bound storefront, a nonnumeric result
 * falls back to owned store sales. The SQL target remains isolated training data.
 */
export default function MerchantAnalytics() {
  const token = useContext(AuthCtx)?.token;
  return <AnalyticsContent key={token || 'guest'} token={token} />;
}
function AnalyticsContent({ token }) {
  const transport = globalThis.fetch;
  const bound = !!getBridgeFetchMetadata(transport);
  const recovery = useBoundAnalytics({ bound, token, transport });
  const recoveredId = useRef(null);
  const [historyHidden, setHistoryHidden] = useState(false);
  const reduced = useReducedMotion();
  const [messages, setMessages] = useState([]);
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(false);
  const [chartData, setChartData] = useState([]);
  const [chartError, setChartError] = useState('');
  const [chartMeta, setChartMeta] = useState({ label: bound ? 'Your top products · last 30 days' : 'Training top products', kind: 'bar', metric: 'revenue', fallback: true });
  const [history, setHistory] = useState([]);
  const scrollRef = useRef(null);
  const chartRequest = useRef(null);
  const queryRequest = useRef(null);

  const examples = [
    'top 5 products by revenue',
    'list all customers',
    'revenue by category',
    'products where 1=1',
    'reviews',
  ];

  useEffect(() => {
    const controller = new AbortController();
    chartRequest.current = controller;
    loadTopProducts(controller.signal, transport, bound)
      .then(rows => {
        if (controller.signal.aborted) return;
        setChartData(rows);
        setChartError('');
      })
      .catch(error => { if (!controller.signal.aborted) setChartError(error.message); });
    return () => {
      controller.abort();
      chartRequest.current?.abort();
      queryRequest.current?.abort();
    };
  }, [transport, bound]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, busy]);

  const present = async (j, text, controller, saved = false) => {
      const agentTurn = {
        role: 'agent',
        saved,
        sql: j.sql,
        why: j.answer || j.why,
        rows: j.rows || [],
        row_count: j.row_count || 0,
        error: j.error || null,
        ok: j.ok,
        ts: Date.now(),
      };
      setMessages(prev => [...prev, agentTurn]);
      setHistory(prev => [{ question: text, sql: j.sql, rows: j.row_count, ts: Date.now() }, ...prev].slice(0, 50));

      if (j.status === 'denied') {
        setChartData([]);
        setChartError(j.error);
        setChartMeta({ label: 'Query denied', kind: 'bar', metric: null, fallback: false });
      } else if (Array.isArray(j.rows) && j.rows.length > 0) {
        const chart = analyticsChart(j.rows);
        if (chart) {
          setChartData(chart.rows.map(row => ({ ...row, name: truncate(row.name, 20) })));
          setChartError('');
          setChartMeta({ label: `${chart.label} · training data`, kind: chart.kind, metric: chart.metric, fallback: false });
        } else {
          try {
            const rows = await loadTopProducts(controller.signal, transport, bound);
            if (controller.signal.aborted) return;
            setChartData(rows);
            setChartError('');
          } catch (error) {
            if (controller.signal.aborted) return;
            setChartData([]);
            setChartError(error.message);
          }
          setChartMeta({ label: bound ? 'Your top products · last 30 days' : 'Training top products', kind: 'bar', metric: 'revenue', fallback: true });
        }
      } else {
        setChartData([]);
        setChartError('');
        setChartMeta({ label: 'Query returned no rows · isolated training data', kind: 'bar', metric: null, fallback: false });
      }
  };

  useEffect(() => {
    const value = recovery.recovered;
    if (!bound || !value || recoveredId.current === value.requestId) return undefined;
    recoveredId.current = value.requestId;
    chartRequest.current?.abort();
    const controller = new AbortController();
    chartRequest.current = controller;
    setMessages(prev => [...prev, { role: 'user', text: value.question, ts: Date.now() }]);
    present(value, value.question, controller);
    return () => controller.abort();
  }, [recovery.recovered, bound]);

  useEffect(() => {
    const value = recovery.selected;
    if (!bound || !value) return undefined;
    chartRequest.current?.abort();
    const controller = new AbortController();
    chartRequest.current = controller;
    setMessages(prev => [...prev, { role: 'user', text: value.question, ts: Date.now() }]);
    present(value, value.question, controller, true);
    return () => controller.abort();
  }, [recovery.selected, bound]);

  const ask = async (q) => {
    const text = (q ?? question).trim();
    if (!text || busy || queryRequest.current || (bound && (!recovery.ready || recovery.selecting
      || recovery.references.some(row => row.scopeKey === recovery.scopeKey)))) return;
    chartRequest.current?.abort();
    const controller = new AbortController();
    queryRequest.current = controller;
    setBusy(true);
    const userTurn = { role: 'user', text, ts: Date.now() };
    setMessages(prev => [...prev, userTurn]);
    setQuestion('');
    try {
      let j;
      if (bound) j = await recovery.submit(text);
      else {
        const r = await transport('/api/secureshop/merchant/analytics/query', {
          method: 'POST', signal: controller.signal,
          headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question: text }),
        });
        j = await r.json();
        if (!r.ok) throw new Error(typeof j.error === 'string' ? j.error : `Analytics request failed (${r.status})`);
      }
      if (controller.signal.aborted) return;
      setHistoryHidden(false);
      if (j) await present(j, text, controller);
    } catch (e) {
      if (controller.signal.aborted) return;
      setMessages(prev => [...prev, { role: 'agent', error: e.message, ts: Date.now() }]);
    } finally {
      if (queryRequest.current === controller) queryRequest.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  };

  const visibleHistory = historyHidden ? [] : bound
    ? recovery.entries.filter(row => ['completed', 'denied'].includes(row.status)).map(row => ({ requestId: row.requestId,
      question: row.question, sql: row.sql, rows: row.row_count, denied: row.status === 'denied',
      error: row.error, ts: Date.parse(row.createdAt) }))
    : history;
  const savedQuery = bound && recovery.references.some(row => row.scopeKey === recovery.scopeKey);

  return (
    <motion.div
      initial={reduced ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
    >
      <header>
        <h1 className="ss-display" style={{ fontSize: 40, margin: '0 0 6px 0' }}>Analytics</h1>
        <p className="ss-mono" style={{ opacity: 0.7, maxWidth: '78ch' }}>
          {bound ? "The default chart uses your store's owned orders from the last 30 days. "
            : 'The default chart uses an isolated training dataset. '}
          Questions run against an isolated training dataset; their SQL and results
          are shown for inspection. Training scenarios explore SQL injection,
          sensitive information disclosure and excessive retrieval.
        </p>
      </header>
      {bound && (recovery.notice || recovery.references.length > 0) && (
        <div className="ss-card" role="status" style={{ padding: 12 }}>
          {recovery.notice && <p style={{ margin: '0 0 8px' }}>{recovery.notice}</p>}
          {recovery.references.map(reference => (
            <div key={reference.scopeKey + reference.operationId} style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', marginTop: 8 }}>
              <span className="ss-mono" style={{ overflowWrap: 'anywhere' }}>Saved query {reference.operationId}</span>
              {reference.scopeKey === recovery.scopeKey && <button className="ss-btn ss-btn--sm" disabled={busy} onClick={() => recovery.check(reference)}>Check saved result</button>}
              <button className="ss-btn ss-btn--ghost ss-btn--sm" disabled={busy} onClick={() => recovery.forget(reference)}>Forget reference</button>
            </div>
          ))}
        </div>
      )}

      <div className="ss-analytics-grid">
        <section style={paneStyle}>
          <div style={paneHeader}>
            <div>
              <div className="ss-card__meta">NATURAL-LANGUAGE QUERY · ISOLATED TRAINING DATA</div>
              <div className="ss-display" style={{ fontSize: 22, marginTop: 4 }}>Ask analytics</div>
            </div>
            <Database size={16} style={{ color: 'var(--copper)' }} />
          </div>

          <div ref={scrollRef} style={{ flex: 1, overflowY: 'auto', minHeight: 320, maxHeight: 480, display: 'flex', flexDirection: 'column', gap: 12, padding: 6 }}>
            {messages.length === 0 && (
              <div style={{ padding: 30, textAlign: 'center', opacity: 0.6, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                <TerminalSquare size={28} style={{ opacity: 0.4 }} />
                <div style={{ fontFamily: 'var(--display)', fontSize: 16 }}>Start with a question</div>
                <div style={{ fontSize: 13, maxWidth: '40ch' }}>
                  Try one of the examples below, or type any business question.
                </div>
              </div>
            )}
            <AnimatePresence initial={false}>
              {messages.map((m, idx) => (
                <motion.div
                  key={idx}
                  initial={reduced ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.22 }}
                  style={{ alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '92%' }}
                >
                  {m.role === 'user' ? (
                    <div style={{
                      padding: '10px 14px', background: 'var(--carbon)', color: 'var(--paper)',
                      fontSize: 14, borderRadius: 2, maxWidth: 480,
                    }}>{m.text}</div>
                  ) : (
                    <AgentTurn turn={m} />
                  )}
                </motion.div>
              ))}
              {busy && (
                <motion.div
                  initial={reduced ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  style={{ alignSelf: 'flex-start' }}
                >
                  <div className="ss-mono" style={{ fontSize: 12, opacity: 0.6, padding: '10px 14px' }}>
                    thinking… translating question → SQL
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: '8px 0' }}>
            {examples.map(ex => (
              <button
                key={ex}
                type="button"
                onClick={() => ask(ex)}
                disabled={busy || (bound && (!recovery.ready || savedQuery || recovery.selecting))}
                style={{
                  padding: '4px 10px', fontSize: 12,
                  background: 'transparent', border: '1px solid var(--rule)',
                  color: 'var(--ink)', cursor: 'pointer',
                  fontFamily: 'var(--mono)', letterSpacing: '0.02em',
                }}
              >
                {ex}
              </button>
            ))}
          </div>

          <form onSubmit={(e) => { e.preventDefault(); ask(); }}
                style={{ display: 'flex', gap: 8, alignItems: 'stretch', borderTop: '1px solid var(--rule)', paddingTop: 12 }}>
            <input
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="e.g. top 5 products by revenue, list all customers, products where 1=1"
              style={{
                flex: 1, minWidth: 0, padding: '10px 14px', border: '1px solid var(--rule)',
                background: 'transparent', color: 'var(--ink)',
                fontFamily: 'var(--body)', fontSize: 14, outline: 'none',
              }}
              disabled={busy}
              data-testid="analytics-input"
            />
            <button className="ss-btn" type="submit" disabled={busy || !question.trim() || (bound && (!recovery.ready || savedQuery || recovery.selecting))}>
              <Send size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
              Ask
            </button>
          </form>
        </section>

        <section style={paneStyle}>
          <div style={{ padding: 14, background: 'var(--carbon)', color: 'var(--paper)', marginBottom: 12 }}>
            <div className="ss-card__meta" style={{ color: 'var(--copper)' }}>EMITTED SQL · ISOLATED TRAINING DATA</div>
            <pre className="ss-mono" style={{
              margin: '6px 0 0 0', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
              fontSize: 12, color: 'var(--paper)', maxHeight: 130, overflow: 'auto',
            }}>
              {lastAgentSql(messages) || '(no query yet — ask a question on the left)'}
            </pre>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
            <div style={paneHeader}>
              <div>
                <div className="ss-card__meta">{chartMeta.fallback
                  ? bound ? 'YOUR STORE · OWNED SALES' : 'TRAINING DATA · SAMPLE SALES'
                  : 'QUERY RESULT · ISOLATED TRAINING DATA'}</div>
                <div className="ss-display" style={{ fontSize: 20, marginTop: 4 }}>{chartMeta.label}</div>
              </div>
              <TrendingUp size={16} style={{ color: 'var(--copper)' }} />
            </div>

            {chartError ? (
              <div role="alert" className="ss-mono" style={{ padding: 20 }}>
                Chart unavailable: {chartError}
              </div>
            ) : chartData.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', opacity: 0.6 }} className="ss-mono">
                no chart data available
              </div>
            ) : (
              <div style={{ height: 340, flex: 1 }}>
                <ResponsiveContainer width="100%" height="100%">
                  {chartMeta.kind === 'line' ? (
                    <LineChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 40 }}>
                      <CartesianGrid stroke="var(--rule)" strokeDasharray="3 3" strokeOpacity={0.4} vertical={false} />
                      <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--ink)', opacity: 0.6 }} angle={-25} textAnchor="end" height={60} interval={0} />
                      <YAxis tick={{ fontSize: 10, fill: 'var(--ink)', opacity: 0.6 }} width={54} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Line type="monotone" dataKey="revenue" name={chartMeta.metric} stroke="var(--signal)" strokeWidth={2} dot={false}
                            isAnimationActive={!reduced} animationDuration={reduced ? 0 : 400} />
                    </LineChart>
                  ) : (
                    <BarChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 40 }}>
                      <CartesianGrid stroke="var(--rule)" strokeDasharray="3 3" strokeOpacity={0.4} vertical={false} />
                      <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--ink)', opacity: 0.6 }} angle={-25} textAnchor="end" height={60} interval={0} />
                      <YAxis tick={{ fontSize: 10, fill: 'var(--ink)', opacity: 0.6 }} width={54} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Bar dataKey="revenue" name={chartMeta.metric} fill="var(--signal)"
                           isAnimationActive={!reduced} animationDuration={reduced ? 0 : 400} />
                    </BarChart>
                  )}
                </ResponsiveContainer>
              </div>
            )}
          </div>
        </section>
      </div>

      {visibleHistory.length > 0 && (
        <section style={{ ...paneStyle, padding: 0 }}>
          <div style={{ ...paneHeader, padding: 16, borderBottom: '1px solid var(--rule)' }}>
            <div>
              <div className="ss-card__meta">SESSION HISTORY · {visibleHistory.length} QUER{visibleHistory.length === 1 ? 'Y' : 'IES'}</div>
              <div className="ss-display" style={{ fontSize: 20, marginTop: 4 }}>Every question, SQL, row count</div>
            </div>
            <button className="ss-btn ss-btn--ghost ss-btn--sm" onClick={() => setHistoryHidden(true)}>Clear</button>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="ss-mono" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))' }}>
                  <th style={thStyle}>When</th>
                  <th style={thStyle}>Question</th>
                  <th style={{ ...thStyle, textAlign: 'right' }}>Rows</th>
                  <th style={thStyle}>SQL</th>
                  {bound && <th style={thStyle}>Result</th>}
                </tr>
              </thead>
              <tbody>
                {visibleHistory.map((h, i) => (
                  <tr key={h.ts + '-' + i} style={{ borderTop: '1px solid var(--rule)' }}>
                    <td style={tdStyle}>{formatTime(h.ts)}</td>
                    <td style={tdStyle}>{h.question}{h.denied && <div role="note" style={{ color: 'var(--danger, #b91c1c)', marginTop: 4 }}>{h.error}</div>}</td>
                    <td style={{ ...tdStyle, textAlign: 'right' }}>{h.denied ? 'Denied' : h.rows}</td>
                    <td style={{ ...tdStyle, whiteSpace: 'pre-wrap', maxWidth: 520 }}>{h.sql}</td>
                    {bound && <td style={tdStyle}><button className="ss-btn ss-btn--ghost ss-btn--sm"
                      type="button" aria-label={`View saved result for ${h.question}`}
                      disabled={!recovery.ready || recovery.selecting || busy}
                      onClick={() => void recovery.selectHistory(h.requestId)}>View saved result</button></td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {bound && recovery.nextCursor && <button className="ss-btn ss-btn--ghost ss-btn--sm"
            disabled={recovery.selecting} onClick={recovery.loadMore}>Load earlier queries</button>}
        </section>
      )}
    </motion.div>
  );
}

function AgentTurn({ turn }) {
  const hasRows = Array.isArray(turn.rows) && turn.rows.length > 0;
  const cols = hasRows ? Object.keys(turn.rows[0] || {}) : [];
  const leaksPii = hasRows && cols.some(c => ['api_key', 'session_token', 'password', 'pii_json'].includes(c));

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: 8,
      padding: 12, background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))',
      border: '1px solid var(--rule)', maxWidth: '100%',
    }}>
      {turn.error ? (
        <div style={{ color: 'var(--rust)', fontFamily: 'var(--mono)', fontSize: 12 }}>
          <AlertTriangle size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
          {turn.error}
        </div>
      ) : (
        <>
          {turn.saved && <div className="ss-card__meta">Saved Analytics result</div>}
          <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6, display: 'flex', gap: 6, alignItems: 'center' }}>
            <ChevronRight size={12} /> {turn.why}
          </div>
          <div className="ss-mono" style={{ fontSize: 12, color: 'var(--kelp)' }}>
            {turn.row_count} training row{turn.row_count === 1 ? '' : 's'} returned
          </div>
          {leaksPii && (
            <div style={{
              padding: 6, background: 'color-mix(in srgb, var(--paper) 82%, var(--rust))',
              border: '1px solid var(--rust)', color: 'var(--rust)',
              fontFamily: 'var(--mono)', fontSize: 11,
              display: 'inline-flex', gap: 6, alignItems: 'center',
            }}>
              <AlertTriangle size={12} /> PII columns present — api_key / session / password / pii_json
            </div>
          )}
          {hasRows && (
            <div style={{ overflowX: 'auto', maxHeight: 280 }}>
              <table className="ss-mono" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                <thead>
                  <tr style={{ background: 'var(--carbon)', color: 'var(--paper)' }}>
                    {cols.map(c => (
                      <th key={c} style={{
                        padding: '6px 8px', textAlign: 'left', fontWeight: 500,
                        color: ['api_key', 'session_token', 'password', 'pii_json'].includes(c) ? 'var(--signal)' : 'var(--paper)',
                      }}>{c}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {turn.rows.slice(0, 25).map((row, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--rule)' }}>
                      {cols.map(c => (
                        <td key={c} style={{ padding: '5px 8px', verticalAlign: 'top', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {stringify(row[c])}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
              {turn.rows.length > 25 && (
                <div className="ss-mono" style={{ padding: 6, opacity: 0.6, fontSize: 11 }}>
                  … {turn.rows.length - 25} more rows omitted
                </div>
              )}
            </div>
          )}
          {!hasRows && !turn.error && (
            <div className="ss-mono" style={{ opacity: 0.6, fontSize: 12 }}>No rows.</div>
          )}
        </>
      )}
    </div>
  );
}

function lastAgentSql(messages) {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m.role === 'agent' && m.sql) return m.sql;
  }
  return null;
}

function truncate(s, n) {
  const str = s == null ? '' : String(s);
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

function stringify(v) {
  if (v == null) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

function formatTime(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return ''; }
}

const paneStyle = {
  border: '1px solid var(--rule)',
  padding: 16,
  background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))',
  display: 'flex', flexDirection: 'column', gap: 12,
  minHeight: 520,
};
const paneHeader = {
  display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12,
};
const thStyle = {
  padding: '10px 14px', fontSize: 11, textTransform: 'uppercase',
  letterSpacing: '0.05em', opacity: 0.75, textAlign: 'left',
};
const tdStyle = { padding: '8px 14px', verticalAlign: 'top', fontSize: 12 };
const tooltipStyle = {
  background: 'var(--carbon)', color: 'var(--paper)', border: '1px solid var(--rule)',
  fontFamily: 'var(--mono)', fontSize: 12,
};
