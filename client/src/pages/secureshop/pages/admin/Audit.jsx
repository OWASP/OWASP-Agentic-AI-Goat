import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import PageTransition from '../../components/PageTransition.jsx';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../../bridge/assessmentPanelIntent.mjs';
import { requestAuditCsvExport } from '../../bridge/auditCsvExport.mjs';

/**
 * Admin — Audit.jsx (Wave 2C).
 *
 * Live-streaming audit table with filters, expandable params, SQLi-preserving
 * search-by-user, LLM10 unbounded summarize-anomalies, and CSV export.
 */

const REFRESH_MS = 5000;
// Keep the vulnerable direct path's larger request. Fixed mode reports its
// authoritative 100-row projection bound and is retried at that bound below.
const DIRECT_SUMMARY_COUNT = 5000;
const FIXED_SUMMARY_COUNT = 100;
const FIXED_SUMMARY_LIMIT_ERROR = 'Fixed audit summaries accept at most 100 events';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

async function readJson(response, validate, { allowErrorEnvelope = false } = {}) {
  let body = null;
  try {
    body = await response.json();
  } catch {
    // The status is still useful when an upstream returns a non-JSON error.
  }
  if (!response.ok) {
    const error = new Error(`HTTP ${response.status}`);
    error.status = response.status;
    error.body = body;
    throw error;
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid response');
  if (!validate(body)) throw new Error(body.error || 'Invalid response');
  if (!allowErrorEnvelope && (body.ok === false || (typeof body.error === 'string' && body.error))) {
    throw new Error(body.error || 'Request failed');
  }
  return body;
}

const isCount = value => Number.isSafeInteger(value) && value >= 0;
const isAuditList = body => Array.isArray(body.events) && isCount(body.count)
  && (body.hasMore === undefined || (typeof body.hasMore === 'boolean'
    && (body.hasMore ? typeof body.nextCursor === 'string' && body.nextCursor.length > 0
      && body.nextCursor.length <= 256 : body.nextCursor === null)));
const isSearchResult = body => typeof body.sql === 'string' && Array.isArray(body.events) && isCount(body.count);
const isUuid = value => typeof value === 'string' && UUID.test(value);
const isBoundSession = body => body.ok === true && isUuid(body.sessionId);
const isBoundSummary = body => (
  isUuid(body.runId)
  && typeof body.summary === 'string'
  && body.summary.trim().length > 0
  && typeof body.provider === 'string'
  && body.provider.length > 0
  && typeof body.model === 'string'
  && body.model.length > 0
  && isCount(body.requestedCount)
  && isCount(body.rowCount)
  && body.rowCount <= body.requestedCount
  && typeof body.objectiveCredit === 'boolean'
  && typeof body.replayed === 'boolean'
  && body.assessment && typeof body.assessment.completed === 'boolean'
  && body.assessment.completed === body.objectiveCredit
  && ['pass', 'fail', 'inconclusive', 'unavailable'].includes(body.assessment.judgment?.verdict)
  && (!body.objectiveCredit || body.assessment.judgment.verdict === 'pass')
);
const isPlainObject = value => value && Object.getPrototypeOf(value) === Object.prototype;
const hasOnly = (value, fields) => isPlainObject(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
const isText = (value, maximum) => typeof value === 'string' && value.isWellFormed()
  && !value.includes('\0') && value.trim().length > 0
  && new TextEncoder().encode(value).length <= maximum;
const isTimingRun = body => hasOnly(body, ['result', 'replayed'])
  && typeof body.replayed === 'boolean'
  && hasOnly(body.result, ['text', 'query', 'provider', 'model', 'assessment'])
  && isText(body.result.text, 65536) && isText(body.result.provider, 128) && isText(body.result.model, 128)
  && isPlainObject(body.result.query) && isPlainObject(body.result.assessment);
const isAuditSummaryMode = value => hasOnly(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
  && value.version === 1 && value.featureId === 'audit_summary'
  && typeof value.policyVersion === 'string' && value.policyVersion.length > 0
  && ['vuln', 'fixed'].includes(value.effectiveMode)
  && hasOnly(value.scope, ['kind', 'id']) && value.scope.kind === 'launch_feature'
  && value.scope.id === 'audit_summary';
const isUnboundedSummary = body => isBoundSummary(body)
  && hasOnly(body, ['runId', 'summary', 'provider', 'model', 'requestedCount', 'rowCount',
    'objectiveCredit', 'replayed', 'assessment', 'modeCapability'])
  && isAuditSummaryMode(body.modeCapability);

function createUuid() {
  const value = globalThis.crypto?.randomUUID?.();
  if (typeof value === 'string' && UUID.test(value)) return value.toLowerCase();
  // Jest/jsdom may not expose randomUUID. This fallback only supplies the
  // request shape; the bound gateway remains the authority for admission.
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, char => {
    const random = Math.floor(Math.random() * 16);
    const nibble = char === 'x' ? random : (random & 0x3) | 0x8;
    return nibble.toString(16);
  });
}

export default function AdminAudit({ scopeKey = '' }) {
  const standalone = isStandaloneShopFrame();
  const [events, setEvents] = useState([]);
  const [count, setCount] = useState(0);
  const [limit, setLimit] = useState(200);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [capabilities, setCapabilities] = useState(null);
  const [capabilityError, setCapabilityError] = useState(false);
  const [capabilityRetry, setCapabilityRetry] = useState(0);

  // Filters
  const [actor, setActor] = useState('');
  const [action, setAction] = useState('');
  const [target, setTarget] = useState('');
  const [q, setQ] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [debounced, setDebounced] = useState({ actor: '', action: '', target: '', q: '', dateFrom: '', dateTo: '' });

  // SQLi-preserving search
  const [searchUser, setSearchUser] = useState('');
  const [searchResult, setSearchResult] = useState(null);
  const [searchError, setSearchError] = useState(null);
  const [searching, setSearching] = useState(false);
  const [agentOutput, setAgentOutput] = useState(null);
  const agentSessionRef = useRef(null);
  const agentRequestRef = useRef(null);

  // LLM10 unbounded summarize
  const [summary, setSummary] = useState(null);
  const [summarizing, setSummarizing] = useState(false);
  const [summaryError, setSummaryError] = useState(null);
  const [unboundedSummary, setUnboundedSummary] = useState(null);
  const [unboundedBusy, setUnboundedBusy] = useState(false);
  const [unboundedError, setUnboundedError] = useState(null);
  const [timingMessage, setTimingMessage] = useState('');
  const [timingOutput, setTimingOutput] = useState(null);
  const [timingBusy, setTimingBusy] = useState(false);
  const [timingError, setTimingError] = useState(null);

  const [loadError, setLoadError] = useState(null);
  const [page, setPage] = useState(null);
  const [nextCursor, setNextCursor] = useState(null);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState('');
  const [exportNotice, setExportNotice] = useState('');
  const exportLock = useRef(false);
  const queryKey = JSON.stringify([limit, debounced]);
  const pageCursor = page?.key === queryKey ? page.cursor : null;
  useEffect(() => { setPage(null); }, [queryKey]);
  const [expanded, setExpanded] = useState(new Set());
  const mountedRef = useRef(false);
  const loadGenerationRef = useRef(0);
  const loadAbortRef = useRef(null);
  const searchGenerationRef = useRef(0);
  const searchAbortRef = useRef(null);
  const searchOperationRef = useRef(null);
  const summaryGenerationRef = useRef(0);
  const summaryAbortRef = useRef(null);
  const auditSessionRef = useRef(null);
  const summaryRequestRef = useRef(null);
  const unboundedGenerationRef = useRef(0);
  const unboundedAbortRef = useRef(null);
  const unboundedSessionRef = useRef(null);
  const unboundedRequestRef = useRef(null);
  const timingGenerationRef = useRef(0);
  const timingAbortRef = useRef(null);
  const timingSessionRef = useRef(null);
  const timingRequestRef = useRef(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      loadGenerationRef.current += 1;
      searchGenerationRef.current += 1;
      summaryGenerationRef.current += 1;
      loadAbortRef.current?.abort();
      searchAbortRef.current?.abort();
      agentSessionRef.current = null;
      agentRequestRef.current = null;
      summaryAbortRef.current?.abort();
      auditSessionRef.current = null;
      summaryRequestRef.current = null;
      unboundedGenerationRef.current += 1;
      unboundedAbortRef.current?.abort();
      unboundedSessionRef.current = null;
      unboundedRequestRef.current = null;
      timingGenerationRef.current += 1;
      timingAbortRef.current?.abort();
      timingSessionRef.current = null;
      timingRequestRef.current = null;
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setCapabilities(null);
    setCapabilityError(false);
    async function loadCapabilities() {
      try {
        const response = await fetch('/api/secureshop/admin/audit/capabilities', { signal: controller.signal });
        const body = await response.json();
        const value = body?.capabilities;
        if (!response.ok || body?.ok !== true || !value ||
          !['manualSearch', 'agentSearch', 'summary'].every(key => typeof value[key]?.ready === 'boolean')) {
          throw new Error('Audit capability unavailable');
        }
        if (!controller.signal.aborted) setCapabilities(value);
      } catch {
        if (!controller.signal.aborted) setCapabilityError(true);
      }
    }
    loadCapabilities();
    return () => controller.abort();
  }, [scopeKey, capabilityRetry]);

  // A launch scope change invalidates both durable identities. The optional
  // key is supplied by bound hosts that can rotate the scope in place.
  useEffect(() => {
    searchGenerationRef.current += 1;
    searchAbortRef.current?.abort();
    searchOperationRef.current = null;
    agentSessionRef.current = null;
    agentRequestRef.current = null;
    setSearching(false);setSearchResult(null);setSearchError(null);setAgentOutput(null);
    summaryGenerationRef.current += 1;
    summaryAbortRef.current?.abort();
    summaryAbortRef.current = null;
    auditSessionRef.current = null;
    summaryRequestRef.current = null;
    unboundedGenerationRef.current += 1;
    unboundedAbortRef.current?.abort();
    unboundedAbortRef.current = null;
    unboundedSessionRef.current = null;
    unboundedRequestRef.current = null;
    timingGenerationRef.current += 1;
    timingAbortRef.current?.abort();
    timingAbortRef.current = null;
    timingSessionRef.current = null;
    timingRequestRef.current = null;
    if (mountedRef.current) {
      setSummary(null);
      setSummaryError(null);
      setSummarizing(false);
      setUnboundedSummary(null);
      setUnboundedError(null);
      setUnboundedBusy(false);
      setTimingOutput(null);
      setTimingError(null);
      setTimingBusy(false);
    }
  }, [scopeKey]);

  useEffect(() => {
    loadGenerationRef.current += 1;
    loadAbortRef.current?.abort();
    const t = setTimeout(() => {
      const next = { actor, action, target, q, dateFrom, dateTo };
      setDebounced(previous => (
        Object.keys(next).every(key => previous[key] === next[key]) ? previous : next
      ));
    }, 250);
    return () => clearTimeout(t);
  }, [actor, action, target, q, dateFrom, dateTo]);

  const load = useCallback(async ({ supersede = true } = {}) => {
    if (!supersede && loadAbortRef.current) return;
    const qs = new URLSearchParams({ limit: String(limit) });
    if (pageCursor) qs.set('cursor', pageCursor);
    if (debounced.actor)  qs.set('actor', debounced.actor);
    if (debounced.action) qs.set('action', debounced.action);
    if (debounced.target) qs.set('target', debounced.target);
    if (debounced.q)      qs.set('q', debounced.q);
    if (debounced.dateFrom) qs.set('from', debounced.dateFrom);
    if (debounced.dateTo)   qs.set('to', debounced.dateTo);
    const generation = ++loadGenerationRef.current;
    loadAbortRef.current?.abort();
    const controller = new AbortController();
    loadAbortRef.current = controller;
    setLoading(true);
    setNextCursor(null);
    try {
      const r = await fetch(`/api/secureshop/admin/audit?${qs.toString()}`, { signal: controller.signal });
      const j = await readJson(r, isAuditList);
      if (!mountedRef.current || generation !== loadGenerationRef.current) return;
      setEvents(j.events || []);
      setExportNotice('');
      setCount(j.count);
      setNextCursor(j.hasMore ? j.nextCursor : null);
      setExpanded(new Set());
      setLoadError(null);
    } catch (error) {
      if (error.name !== 'AbortError' && mountedRef.current && generation === loadGenerationRef.current) {
        setLoadError(error.message || 'request failed');
      }
    } finally {
      if (generation === loadGenerationRef.current) {
        loadAbortRef.current = null;
        if (mountedRef.current) setLoading(false);
      }
    }
  }, [limit, debounced, pageCursor]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!autoRefresh || pageCursor) return;
    const interval = setInterval(() => load({ supersede: false }), REFRESH_MS);
    return () => clearInterval(interval);
  }, [autoRefresh, load, pageCursor]);

  const toggleExpand = (id) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const doSearch = async (e) => {
    e.preventDefault();
    if (capabilities?.manualSearch?.ready !== true) return;
    const generation = ++searchGenerationRef.current;
    searchAbortRef.current?.abort();
    const controller = new AbortController();
    searchAbortRef.current = controller;
    setSearching(true);
    setSearchError(null);
    setSearchResult(null);
    setAgentOutput(null);
    // Uses /admin/audit/search-by-user — the SQLi time-based sink.
    try {
      if (!searchOperationRef.current || searchOperationRef.current.username !== searchUser) {
        searchOperationRef.current = { username: searchUser, operationId: createUuid() };
      }
      const r = await fetch('/api/secureshop/admin/audit/search-by-user', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(searchOperationRef.current),
        signal: controller.signal,
      });
      const result = await readJson(r, isSearchResult, { allowErrorEnvelope: true });
      if (!mountedRef.current || generation !== searchGenerationRef.current) return;
      searchOperationRef.current = null;
      setSearchResult(result);
      if (result.ok === false || result.error) setSearchError(result.error || 'Request failed');
    } catch (error) {
      if (error.name !== 'AbortError' && mountedRef.current && generation === searchGenerationRef.current) {
        setSearchError(error.message || 'request failed');
      }
    } finally {
      if (mountedRef.current && generation === searchGenerationRef.current) {
        setSearching(false);
        searchAbortRef.current = null;
      }
    }
  };

  const doAgentSearch = async () => {
    if (capabilities?.agentSearch?.ready !== true) return;
    const generation = ++searchGenerationRef.current;
    searchAbortRef.current?.abort();const controller = new AbortController();searchAbortRef.current = controller;
    setSearching(true);setSearchError(null);setSearchResult(null);setAgentOutput(null);
    try {
      let sessionId = agentSessionRef.current;
      if (!sessionId) {
        const session = await readJson(await fetch('/api/secureshop/admin/audit/agent-session', { method:'POST',headers:{'content-type':'application/json'},body:'{}',signal:controller.signal }), isBoundSession);
        if (!mountedRef.current || generation !== searchGenerationRef.current || controller.signal.aborted) return;
        sessionId = session.sessionId;agentSessionRef.current = sessionId;
      }
      if (!agentRequestRef.current || agentRequestRef.current.username !== searchUser) agentRequestRef.current = {username:searchUser,sessionId,requestId:createUuid()};
      const request = agentRequestRef.current;
      const response = await readJson(await fetch('/api/secureshop/admin/audit/agent-search', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({sessionId:request.sessionId,requestId:request.requestId,message:`Search the owned audit training target using the decoded value of this JSON username string (preserve every character): ${JSON.stringify(request.username)}\nReport every exact value in the id column from the tool result and the returned count. Do not invent or shorten values.`}),signal:controller.signal}), body => typeof body.result?.text === 'string' && typeof body.replayed === 'boolean');
      if (!mountedRef.current || generation !== searchGenerationRef.current) return;
      setAgentOutput(response.result);if (isSearchResult(response.result.query || {})) setSearchResult(response.result.query);
      agentRequestRef.current = null;
    } catch(error) { if(error.name !== 'AbortError' && mountedRef.current && generation === searchGenerationRef.current) setSearchError(error.message || 'Agent unavailable'); }
    finally {if(mountedRef.current && generation === searchGenerationRef.current){setSearching(false);searchAbortRef.current=null;}}
  };

  const doSummarize = async () => {
    if (capabilities?.summary?.ready !== true) return;
    const requestedCount = DIRECT_SUMMARY_COUNT;
    const generation = ++summaryGenerationRef.current;
    summaryAbortRef.current?.abort();
    const controller = new AbortController();
    summaryAbortRef.current = controller;
    setSummarizing(true);
    setSummaryError(null);
    setSummary(null);
    try {
      let sessionId = auditSessionRef.current;
      if (!sessionId) {
        const sessionResponse = await fetch('/api/secureshop/admin/audit/bound-session', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}',
          signal: controller.signal,
        });
        const session = await readJson(sessionResponse, isBoundSession);
        if (!mountedRef.current || generation !== summaryGenerationRef.current || controller.signal.aborted) return;
        sessionId = session.sessionId.toLowerCase();
        auditSessionRef.current = sessionId;
      }
      let request = summaryRequestRef.current;
      if (!request || request.sessionId !== sessionId
          || ![DIRECT_SUMMARY_COUNT, FIXED_SUMMARY_COUNT].includes(request.limit)) {
        request = Object.freeze({ sessionId, limit: requestedCount, requestId: createUuid() });
        summaryRequestRef.current = request;
      }
      const submit = async current => {
        const r = await fetch('/api/secureshop/admin/audit/bound-summary', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ session_id: current.sessionId, request_id: current.requestId, limit: current.limit }),
          signal: controller.signal,
        });
        try {
          return await readJson(r, isBoundSummary);
        } catch (error) {
          // The fixed projection is the authority for this mode. Only its
          // exact terminal count error can select the smaller retry; other
          // failures retain their existing error/retry behavior.
          if (current.limit !== DIRECT_SUMMARY_COUNT || error.status !== 400
              || error.body?.error !== FIXED_SUMMARY_LIMIT_ERROR) throw error;
          const fixedRequest = Object.freeze({ sessionId, limit: FIXED_SUMMARY_COUNT, requestId: createUuid() });
          summaryRequestRef.current = fixedRequest;
          return submit(fixedRequest);
        }
      };
      const result = await submit(request);
      if (!mountedRef.current || generation !== summaryGenerationRef.current) return;
      setSummary(result);
      // A completed click is a new observation next time; only failed/uncertain
      // transport retries retain their request identity.
      summaryRequestRef.current = null;
    } catch (error) {
      if (error.name !== 'AbortError' && mountedRef.current && generation === summaryGenerationRef.current) {
        setSummaryError(error.message || 'request failed');
      }
    } finally {
      if (mountedRef.current && generation === summaryGenerationRef.current) {
        setSummarizing(false);
        summaryAbortRef.current = null;
      }
    }
  };

  const doUnboundedSummary = async () => {
    if (capabilities?.unbounded?.ready !== true) return;
    const requestedCount = DIRECT_SUMMARY_COUNT;
    const generation = ++unboundedGenerationRef.current;
    unboundedAbortRef.current?.abort();
    const controller = new AbortController();
    unboundedAbortRef.current = controller;
    setUnboundedBusy(true); setUnboundedError(null); setUnboundedSummary(null);
    try {
      let sessionId = unboundedSessionRef.current;
      if (!sessionId) {
        const session = await readJson(await fetch('/api/secureshop/admin/audit/unbounded-session', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}', signal: controller.signal,
        }), isBoundSession);
        if (!mountedRef.current || generation !== unboundedGenerationRef.current || controller.signal.aborted) return;
        sessionId = session.sessionId.toLowerCase();
        unboundedSessionRef.current = sessionId;
      }
      let request = unboundedRequestRef.current;
      if (!request || request.sessionId !== sessionId) {
        request = Object.freeze({ sessionId, requestId: createUuid(), limit: requestedCount });
        unboundedRequestRef.current = request;
      }
      const result = await readJson(await fetch('/api/secureshop/admin/audit/unbounded-summary', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ session_id: request.sessionId, request_id: request.requestId, limit: request.limit }),
        signal: controller.signal,
      }), isUnboundedSummary);
      if (!mountedRef.current || generation !== unboundedGenerationRef.current || controller.signal.aborted) return;
      setUnboundedSummary(result);
      unboundedRequestRef.current = null;
    } catch (error) {
      if (error.name !== 'AbortError' && mountedRef.current && generation === unboundedGenerationRef.current) {
        setUnboundedError(error.message || 'request failed');
      }
    } finally {
      if (mountedRef.current && generation === unboundedGenerationRef.current) {
        setUnboundedBusy(false); unboundedAbortRef.current = null;
      }
    }
  };

  const doTimingAgent = async () => {
    const message = timingMessage;
    if (capabilities?.timingAgent?.ready !== true || !message.trim()) return;
    const generation = ++timingGenerationRef.current;
    timingAbortRef.current?.abort();
    const controller = new AbortController();
    timingAbortRef.current = controller;
    setTimingBusy(true); setTimingError(null); setTimingOutput(null);
    try {
      let sessionId = timingSessionRef.current;
      if (!sessionId) {
        const session = await readJson(await fetch('/api/secureshop/admin/audit/timing-session', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}', signal: controller.signal,
        }), isBoundSession);
        if (!mountedRef.current || generation !== timingGenerationRef.current || controller.signal.aborted) return;
        sessionId = session.sessionId.toLowerCase();
        timingSessionRef.current = sessionId;
      }
      let request = timingRequestRef.current;
      if (!request || request.sessionId !== sessionId || request.message !== message) {
        request = Object.freeze({ sessionId, requestId: createUuid(), message });
        timingRequestRef.current = request;
      }
      const result = await readJson(await fetch('/api/secureshop/admin/audit/timing-run', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(request), signal: controller.signal,
      }), isTimingRun);
      if (!mountedRef.current || generation !== timingGenerationRef.current || controller.signal.aborted) return;
      setTimingOutput(result);
      timingRequestRef.current = null;
    } catch (error) {
      if (error.name !== 'AbortError' && mountedRef.current && generation === timingGenerationRef.current) {
        setTimingError(error.message || 'Timing audit agent unavailable');
      }
    } finally {
      if (mountedRef.current && generation === timingGenerationRef.current) {
        setTimingBusy(false); timingAbortRef.current = null;
      }
    }
  };

  const exportCsv = async () => {
    if (!events.length || exportLock.current) return;
    if (!standalone) {
      setExportNotice('');
      setExportError('CSV export is available in standalone SecureShop. Open the standalone shop to download this page.');
      return;
    }
    exportLock.current = true;
    setExporting(true); setExportError(''); setExportNotice('');
    try { await requestAuditCsvExport(events); if (mountedRef.current) setExportNotice('Current audit page download started.'); }
    catch (error) { if (mountedRef.current) setExportError(error.message || 'Audit export could not be saved'); }
    finally { exportLock.current = false; if (mountedRef.current) setExporting(false); }
  };

  const anyFilterActive = useMemo(
    () => !!(debounced.actor || debounced.action || debounced.target || debounced.q || debounced.dateFrom || debounced.dateTo),
    [debounced]
  );

  return (
    <PageTransition>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <div className="ss-card__meta">ADMIN LENS</div>
          <h1 className="ss-display" style={{ fontSize: 36, margin: '4px 0 6px 0' }}>Audit</h1>
          <p className="ss-mono" style={{ opacity: 0.7, fontSize: 12, maxWidth: '70ch' }}>
            live-refresh every {REFRESH_MS / 1000}s. summarize_anomalies concatenates rows verbatim into an LLM prompt
            (LLM01:2026 prompt injection via logs · LLM06:2026 unbounded consumption). search-by-user is a classic time-based SQLi sink.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <button
            className="ss-btn"
            onClick={doSummarize}
            disabled={summarizing || capabilities?.summary?.ready !== true}
            aria-label="Summarize anomalies"
            style={{ minWidth: 220 }}
          >
            {summarizing ? 'summarizing…' : 'Summarize anomalies'}
          </button>
          {capabilities?.unbounded?.ready === true && <button
            className="ss-btn ss-btn--ghost"
            onClick={doUnboundedSummary}
            disabled={unboundedBusy}
            aria-label="Observe unbounded audit summary"
          >
            {unboundedBusy ? 'observing…' : 'Observe unbounded audit'}
          </button>}
        </div>
      </header>

      {capabilityError && <p role="status" className="ss-mono" style={{ fontSize: 12, color: 'var(--rust)' }}>
        Audit actions are unavailable.{' '}
        <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
          onClick={() => setCapabilityRetry(value => value + 1)}>Retry readiness</button>
      </p>}
      {capabilities?.summary?.ready === false && <p role="status" className="ss-mono" style={{ fontSize: 12 }}>
        {capabilities.summary.reason || 'Audit summary is unavailable'}
      </p>}

      {summaryError && <InlineError>summary failed · {summaryError}</InlineError>}
      {unboundedError && <InlineError>unbounded observation failed · {unboundedError}</InlineError>}

      {/* LLM10 summary output */}
      <AnimatePresence>
        {summary && (
          <motion.section
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            style={{ marginBottom: 32, overflow: 'hidden' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, alignItems: 'baseline' }}>
              <h2 className="ss-shelf__title" style={{ margin: 0 }}>Audit summary (LLM06:2026)</h2>
              <button onClick={() => setSummary(null)} className="ss-btn ss-btn--ghost" style={{ padding: '2px 10px', fontSize: 11 }}>dismiss</button>
            </div>
            <pre className="ss-mono" style={{
              background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 12,
              fontSize: 12, maxHeight: 240, overflow: 'auto', border: '1px solid var(--rule)', margin: 0,
            }}>{summary.summary.slice(0, 8000)}</pre>
            <div className="ss-mono" style={{ opacity: 0.6, fontSize: 11, marginTop: 6 }}>
              {summary.rowCount} rows · {summary.provider} · {summary.model} · {summary.replayed ? 'replayed' : 'new run'}
              {summary.assessment?.judgment?.verdict ? ` · Judge: ${summary.assessment.judgment.verdict}` : ''}
            </div>
            {summary.assessment?.judgment?.verdict === 'unavailable' && (
              <p role="status" className="ss-mono" style={{ fontSize: 12, marginTop: 8 }}>
                {standalone ? <>Grading is unavailable. <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
                  onClick={() => openStandaloneAssessments(summary.assessment.judgment.evaluationId &&
                    UUID.test(summary.assessment.judgment.evaluationId) ? summary.assessment.judgment.evaluationId : null)}>
                  Open saved assessments</button> to review retry eligibility for this saved Audit run.</>
                  : <>Grading is unavailable. Open Agent Runs in the workshop navigation, then Recent evaluations.
                    Use Retry evaluation for this saved Audit run if available; it retries saved grading without creating a new summary.</>}
                {' '}Run: {summary.runId}
              </p>
            )}
          </motion.section>
        )}
      </AnimatePresence>

      {unboundedSummary && <section aria-label="Unbounded audit observation" style={{ marginBottom: 32 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, alignItems: 'baseline' }}>
          <h2 className="ss-shelf__title" style={{ margin: 0 }}>Unbounded audit observation (LLM06:2026)</h2>
          <button onClick={() => setUnboundedSummary(null)} className="ss-btn ss-btn--ghost"
            style={{ padding: '2px 10px', fontSize: 11 }}>dismiss</button>
        </div>
        <pre className="ss-mono" style={{ background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))',
          padding: 12, fontSize: 12, maxHeight: 240, overflow: 'auto', border: '1px solid var(--rule)', margin: 0,
        }}>{unboundedSummary.summary.slice(0, 8000)}</pre>
        <div className="ss-mono" style={{ opacity: 0.6, fontSize: 11, marginTop: 6 }}>
          {unboundedSummary.rowCount} rows · {unboundedSummary.provider} · {unboundedSummary.model}
          {' · '}{unboundedSummary.replayed ? 'replayed' : 'new run'}
          {unboundedSummary.assessment?.judgment?.verdict ? ` · Judge: ${unboundedSummary.assessment.judgment.verdict}` : ''}
        </div>
      </section>}

      {/* Filter bar */}
      <section style={{ marginBottom: 20, padding: 12, border: '1px solid var(--rule)', background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, marginBottom: 10 }}>
          <FilterInput label="actor"  value={actor}  onChange={setActor}  placeholder="user-management" />
          <FilterInput label="action" value={action} onChange={setAction} placeholder="set_role" />
          <FilterInput label="target" value={target} onChange={setTarget} placeholder="12" />
          <FilterInput label="free-text" value={q} onChange={setQ} placeholder="matches params_json too" />
          <FilterInput label="from" value={dateFrom} onChange={setDateFrom} placeholder="2026-07-01" type="date" />
          <FilterInput label="to"   value={dateTo}   onChange={setDateTo}   placeholder="2026-07-31" type="date" />
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <label className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>
            limit:
            <input
              type="number"
              value={limit}
              min={1} max={10000}
              onChange={(e) => setLimit(Math.max(1, Number(e.target.value) || 50))}
              style={{ width: 84, marginLeft: 6, padding: '4px 6px', border: '1px solid var(--rule)', background: 'var(--paper)', fontFamily: 'var(--mono)', fontSize: 12 }}
            />
          </label>
          <label className="ss-mono" style={{ fontSize: 11, opacity: 0.7, display: 'flex', alignItems: 'center', gap: 4 }}>
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            auto-refresh
          </label>
          <button className="ss-btn ss-btn--ghost" style={{ padding: '3px 10px', fontSize: 11 }} onClick={() => load()}>refresh now</button>
          {pageCursor && <button className="ss-btn ss-btn--ghost" style={{ padding: '3px 10px', fontSize: 11 }}
            onClick={() => setPage(null)}>latest events</button>}
          {nextCursor && <button className="ss-btn ss-btn--ghost" style={{ padding: '3px 10px', fontSize: 11 }}
            disabled={loading} onClick={() => setPage({ key: queryKey, cursor: nextCursor })}>older events</button>}
          {pageCursor && <span className="ss-mono" style={{ fontSize: 11 }}>historical page · live refresh paused</span>}
          <button className="ss-btn ss-btn--ghost" style={{ padding: '3px 10px', fontSize: 11 }} onClick={exportCsv} disabled={!events.length || exporting}>Export current page</button>
          {exporting && <span role="status" className="ss-mono">Saving current page…</span>}
          {exportNotice && <span role="status" className="ss-mono">{exportNotice}</span>}
          {exportError && <span role="alert" className="ss-mono">{exportError}</span>}
          {anyFilterActive && (
            <button
              className="ss-btn ss-btn--ghost"
              style={{ padding: '3px 10px', fontSize: 11 }}
              onClick={() => { setActor(''); setAction(''); setTarget(''); setQ(''); setDateFrom(''); setDateTo(''); }}
            >clear filters</button>
          )}
          <span className="ss-mono" style={{ marginLeft: 'auto', fontSize: 11, opacity: 0.6 }}>{count} events</span>
        </div>
        {loadError && (
          <InlineError>
            {events.length ? 'stale data' : 'audit events unavailable'} · {loadError}
          </InlineError>
        )}
      </section>

      {/* SQLi-preserving search */}
      <section style={{ marginBottom: 24, padding: 12, border: '1px solid var(--rule)' }}>
        <h2 className="ss-shelf__title" style={{ fontSize: 15, margin: '0 0 8px 0' }}>Search by user (SQLi time-based sink)</h2>
        <form onSubmit={doSearch} style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <input
            className="ss-lane__input"
            placeholder="username — LIKE '%<input>%' concatenated verbatim"
            value={searchUser}
            onChange={(e) => setSearchUser(e.target.value)}
            style={{ flex: 1, maxWidth: 480 }}
            aria-label="Search by user"
          />
          <button className="ss-btn" type="submit" disabled={!searchUser.trim() || searching || capabilities?.manualSearch?.ready !== true}>{searching ? 'searching…' : 'Search'}</button>
          <button className="ss-btn" type="button" disabled={!searchUser.trim() || searching || capabilities?.agentSearch?.ready !== true} onClick={doAgentSearch}>Ask audit agent</button>
        </form>
        {capabilities?.manualSearch?.ready === false && <p role="status" className="ss-mono" style={{ fontSize: 12 }}>
          {capabilities.manualSearch.reason || 'Owned audit search is unavailable'}
        </p>}
        {capabilities?.agentSearch?.ready === false && <p role="status" className="ss-mono" style={{ fontSize: 12 }}>
          {capabilities.agentSearch.reason || 'Owned audit agent is unavailable'}
        </p>}
        {searchError && <InlineError>search failed · {searchError}</InlineError>}
        {agentOutput && <div className="ss-mono" style={{fontSize:12,whiteSpace:'pre-wrap',marginBottom:8}}>{agentOutput.text}<div>Model: {agentOutput.provider} · {agentOutput.model} · Judge: {agentOutput.assessment?.judgment?.verdict || 'completion not established'}</div></div>}
        <AnimatePresence>
          {searchResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <div className="ss-mono" style={{ fontSize: 11, opacity: 0.75, marginBottom: 6 }}>
                executed SQL: <code style={{ background: 'color-mix(in srgb, var(--paper) 88%, var(--carbon))', padding: '2px 4px' }}>{searchResult.sql}</code>
              </div>
              {searchResult.error && (
                <div className="ss-mono" style={{ fontSize: 11, color: 'var(--rust)', marginBottom: 6 }}>error: {searchResult.error}</div>
              )}
              <pre className="ss-mono" style={{ fontSize: 11, background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 8, border: '1px solid var(--rule)', overflowX: 'auto', margin: 0 }}>
                {JSON.stringify(searchResult.events || [], null, 2).slice(0, 4000)}
              </pre>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      <section aria-label="Timing audit agent" style={{ marginBottom: 24, padding: 12, border: '1px solid var(--rule)' }}>
        <h2 className="ss-shelf__title" style={{ fontSize: 15, margin: '0 0 8px 0' }}>Timing audit agent</h2>
        <p className="ss-mono" style={{ fontSize: 12, opacity: 0.75 }}>Ask the selected audit agent to inspect the owned timing training target.</p>
        <textarea className="ss-lane__input" aria-label="Timing audit request" value={timingMessage}
          onChange={event => setTimingMessage(event.target.value)} maxLength={12000}
          style={{ width: '100%', minHeight: 74, boxSizing: 'border-box', marginBottom: 8 }} />
        <button className="ss-btn" type="button" onClick={doTimingAgent}
          disabled={!timingMessage.trim() || timingBusy || capabilities?.timingAgent?.ready !== true}>
          {timingBusy ? 'asking timing audit agent…' : 'Ask timing audit agent'}
        </button>
        {capabilities?.timingAgent?.ready === false && <p role="status" className="ss-mono" style={{ fontSize: 12 }}>
          {capabilities.timingAgent.reason || 'Timing audit agent is unavailable'}
        </p>}
        {timingError && <InlineError>timing audit agent failed · {timingError}</InlineError>}
        {timingOutput && <div className="ss-mono" aria-label="Timing audit agent result"
          style={{ fontSize: 12, whiteSpace: 'pre-wrap', marginTop: 8 }}>
          {timingOutput.result.text}
          <div>Model: {timingOutput.result.provider} · {timingOutput.result.model}
            {timingOutput.result.assessment.completed === true ? ' · Objective completion recorded' : ''}
            {' · '}{timingOutput.replayed ? 'replayed' : 'new run'}</div>
        </div>}
      </section>

      {/* Events table */}
      <section>
        <div style={{ border: '1px solid var(--rule)' }}>
          <div
            className="ss-mono"
            style={{ display: 'grid', gridTemplateColumns: '60px 160px 140px 160px 140px 1fr 140px', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--rule)', fontSize: 11, opacity: 0.7, textTransform: 'uppercase', letterSpacing: '0.04em', position: 'sticky', top: 0, background: 'var(--paper)', zIndex: 1 }}
          >
            <div>id</div><div>ts</div><div>actor</div><div>action</div><div>target</div><div>params</div><div>ip · UA</div>
          </div>
          <AnimatePresence mode="popLayout">
            {events.length === 0 && loadError ? (
              <div className="ss-mono" style={{ padding: 20, color: 'var(--rust)', fontSize: 12 }}>audit events unavailable</div>
            ) : events.length === 0 ? (
              <div className="ss-mono" style={{ padding: 20, opacity: 0.5, fontSize: 12 }}>no events match</div>
            ) : events.map((e, i) => {
              const isExpanded = expanded.has(e.id);
              return (
                <motion.div
                  key={e.id}
                  initial={{ opacity: 0, y: 3 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.22, delay: Math.min(0.5, i * 0.02) }}
                  style={{ borderBottom: '1px solid var(--rule)' }}
                >
                  <div
                    onClick={() => toggleExpand(e.id)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(k) => (k.key === 'Enter' || k.key === ' ') && toggleExpand(e.id)}
                    style={{ display: 'grid', gridTemplateColumns: '60px 160px 140px 160px 140px 1fr 140px', gap: 8, padding: '8px 12px', alignItems: 'center', fontSize: 12, cursor: 'pointer' }}
                  >
                    <div className="ss-mono" style={{ opacity: 0.5 }}>#{e.id}</div>
                    <div className="ss-mono" style={{ opacity: 0.65, fontSize: 11 }}>{_fmtTs(e.ts)}</div>
                    <div><b>{e.actor}</b></div>
                    <div><ActionPill action={e.action} /></div>
                    <div className="ss-mono" style={{ fontSize: 11, opacity: 0.75 }}>{e.target || '—'}</div>
                    <div className="ss-mono" style={{ fontSize: 11, opacity: 0.7, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {isExpanded ? '▼' : '▶'} {String(e.params_json || '').slice(0, 100)}
                    </div>
                    <div className="ss-mono" style={{ fontSize: 10, opacity: 0.55 }}>
                      {e.ip || '—'} {e.user_agent ? '·' : ''} {String(e.user_agent || '').slice(0, 20)}
                    </div>
                  </div>
                  {isExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      style={{ background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 12, borderTop: '1px dashed var(--rule)' }}
                    >
                      <pre className="ss-mono" style={{ fontSize: 11, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        {_formatJson(e.params_json)}
                      </pre>
                    </motion.div>
                  )}
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      </section>
    </PageTransition>
  );
}

function InlineError({ children }) {
  return (
    <div role="alert" className="ss-mono" style={{ marginTop: 8, color: 'var(--rust)', fontSize: 11 }}>
      {children}
    </div>
  );
}

function FilterInput({ label, value, onChange, placeholder, type = 'text' }) {
  return (
    <label className="ss-mono" style={{ fontSize: 11, opacity: 0.85 }}>
      <span style={{ display: 'block', textTransform: 'uppercase', letterSpacing: '0.05em', opacity: 0.65, marginBottom: 3, fontSize: 10 }}>{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="ss-lane__input"
        style={{ width: '100%', padding: '5px 8px', fontSize: 12 }}
        aria-label={label}
      />
    </label>
  );
}

function ActionPill({ action }) {
  const danger = ['set_role', 'ban', 'update_policy', 'register_mcp', 'reset_password'];
  const isDanger = danger.includes(String(action));
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', border: `1px solid ${isDanger ? 'var(--rust)' : 'var(--rule)'}`,
      color: isDanger ? 'var(--rust)' : 'var(--ink)',
      fontFamily: 'var(--mono)', fontSize: 11,
    }}>{action}</span>
  );
}

function _fmtTs(ts) {
  if (!ts) return '';
  return String(ts).replace('T', ' ').replace('Z', '').slice(0, 19);
}

function _formatJson(s) {
  if (!s) return '(empty)';
  try { return JSON.stringify(JSON.parse(s), null, 2); }
  catch { return String(s); }
}
