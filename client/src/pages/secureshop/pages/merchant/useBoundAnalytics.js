import { useEffect, useRef, useState } from 'react';
import { readAnalyticsReferences, saveAnalyticsReference, forgetAnalyticsReference } from './analyticsRecovery.mjs';

const BASE = '/api/secureshop/merchant/analytics';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function result(value, requestId) {
  if (!value || value.requestId !== requestId || !UUID.test(value.sessionId) || typeof value.question !== 'string') throw Error('Invalid Analytics response');
  if (['pending', 'uncertain'].includes(value.status)) return value;
  const denied = value.status === 'denied';
  const validOutcome = denied
    ? value.ok === false && value.responseSource === 'server' && value.answer === null
      && value.provider === null && value.model === null && value.error === 'Database permission denied (42501).'
      && value.receipt?.version === 4 && value.receipt?.mode?.mode === 'fixed'
      && value.receipt?.denial?.code === '42501' && value.receipt?.denial?.source === 'postgresql'
      && value.receipt?.denial?.backendAbsent === true && value.row_count === 0
      && value.rows?.length === 0 && value.columns?.length === 0
      && value.receipt?.protectedEvidence?.version === 1
      && Array.isArray(value.receipt?.protectedEvidence?.observations)
      && value.receipt.protectedEvidence.observations.length === 0
      && value.receipt.protectedEvidence.truncated === false
    : value.status === 'completed' && value.ok === true && value.error === null && typeof value.answer === 'string';
  if (!validOutcome || !UUID.test(value.runId)
      || typeof value.sql !== 'string' || !Array.isArray(value.rows)
      || value.row_count !== value.rows.length || !Array.isArray(value.columns)
      || value.receipt?.requestId !== requestId || value.receipt?.runId !== value.runId
      || value.receipt?.sessionId !== value.sessionId || value.receipt?.result?.sql !== value.sql
      || JSON.stringify(value.receipt?.result?.rows) !== JSON.stringify(value.rows)
      || JSON.stringify(value.receipt?.result?.columns) !== JSON.stringify(value.columns)
      || value.receipt?.result?.row_count !== value.row_count || value.receipt?.result?.error !== value.error
      || value.effectReceipt?.status !== 'completed' || value.effectReceipt?.runId !== value.runId) throw Error('Invalid Analytics response');
  return value;
}
function sameListedResult(listed, read) {
  const { createdAt, ...expected } = listed;
  const { createdAt: readAt, ...actual } = read;
  const pending = [[expected, actual]];
  while (pending.length) {
    const [left, right] = pending.pop();
    if (Object.is(left, right)) continue;
    if (!left || !right || typeof left !== 'object' || typeof right !== 'object'
      || Array.isArray(left) !== Array.isArray(right)) return false;
    const leftKeys = Object.keys(left).sort(), rightKeys = Object.keys(right).sort();
    if (leftKeys.length !== rightKeys.length
      || leftKeys.some((key, index) => key !== rightKeys[index])) return false;
    for (const key of leftKeys) pending.push([left[key], right[key]]);
  }
  return true;
}
export default function useBoundAnalytics({ bound, token, transport }) {
  const [state, setState] = useState({ ready: false, scopeKey: null, references: [], entries: [], nextCursor: null,
    notice: '', recovered: null, selected: null, selecting: false });
  const lease = useRef(null), identity = useRef(null);
  const stateRef = useRef(state);
  stateRef.current = state;
  identity.current = { token, transport, bound };
  const current = captured => !!captured && lease.current === captured && !captured.signal.aborted
    && identity.current.token === captured.token && identity.current.transport === captured.transport && identity.current.bound;
  async function json(captured, path, options) {
    if (!current(captured)) throw new DOMException('Analytics session changed', 'AbortError');
    const response = await captured.transport(BASE + path, { ...options, signal: captured.signal });
    const body = await response.json();
    if (!current(captured)) throw new DOMException('Analytics session changed', 'AbortError');
    if (!response.ok) throw Error(typeof body?.error === 'string' ? body.error : 'Analytics operation unavailable');
    return body;
  }
  async function history(captured, cursor = null) {
    const page = await json(captured, '/history?limit=20' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''));
    if (!Array.isArray(page.entries) || page.entries.length > 20 || (page.nextCursor !== null && typeof page.nextCursor !== 'string')) throw Error('Invalid Analytics history');
    const entries = page.entries.map(entry => {
      if (!UUID.test(entry.requestId) || !Number.isFinite(Date.parse(entry.createdAt))) throw Error('Invalid Analytics history');
      return result(entry, entry.requestId);
    });
    if (current(captured)) setState(old => ({ ...old, entries: cursor ? [...old.entries, ...entries] : entries, nextCursor: page.nextCursor }));
  }
  async function recover(captured, reference) {
    if (!current(captured) || reference.scopeKey !== captured.scopeKey) throw Error('Original Analytics session required');
    const value = result(await json(captured, '/requests/' + reference.operationId), reference.operationId);
    if (['completed', 'denied'].includes(value.status)) {
      const references = await forgetAnalyticsReference(reference);
      if (current(captured)) setState(old => ({ ...old, references, recovered: value, notice: 'Saved query recovered. No query was repeated.' }));
      await history(captured);
    } else if (current(captured)) setState(old => ({ ...old, notice: value.status === 'pending' ? 'Query is still running. Check its saved result before starting another.' : 'Query outcome is unverified. Check its saved result; it will not be repeated.' }));
    return value;
  }
  useEffect(() => {
    const controller = new AbortController(), captured = { token, transport, signal: controller.signal, scopeKey: null, working: true };
    lease.current = captured;
    setState({ ready: false, scopeKey: null, references: [], entries: [], nextCursor: null,
      notice: '', recovered: null, selected: null, selecting: false });
    if (bound) (async () => {
      try {
        const value = await json(captured, '');
        if (value?.ok !== true || value.analytics?.capability !== 'secureshop-owned-analytics.v1' || !/^[a-f0-9]{64}$/.test(value.analytics?.scopeKey || '')) throw Error('Analytics capability unavailable');
        captured.scopeKey = value.analytics.scopeKey;
        const references = readAnalyticsReferences();
        setState(old => ({ ...old, ready: false, scopeKey: captured.scopeKey, references }));
        try { await history(captured); } catch (error) { if (current(captured)) setState(old => ({ ...old, notice: error.message })); }
        for (const reference of references.filter(row => row.scopeKey === captured.scopeKey)) await recover(captured, reference);
      } catch (error) { if (current(captured)) setState(old => ({ ...old, notice: error.message })); }
      finally { captured.working = false; if (current(captured)) setState(old => ({ ...old, ready: !!captured.scopeKey })); }
    })();
    return () => { controller.abort(); if (lease.current === captured) lease.current = null; };
  }, [bound, token, transport]); // All work below uses the captured immutable transport/session lease.

  async function submit(question) {
    const captured = lease.current;
    if (!captured || !current(captured) || !captured.scopeKey || captured.working) throw Error('Analytics is not ready');
    if (readAnalyticsReferences().some(row => row.scopeKey === captured.scopeKey)) throw Error('Check or explicitly forget the saved query before starting another.');
    captured.working = true;
    const reference = { scopeKey: captured.scopeKey, operationId: crypto.randomUUID(), state: 'pending' };
    let saved = false;
    try {
      const references = await saveAnalyticsReference(reference); saved = true;
      if (!current(captured)) throw new DOMException('Analytics session changed', 'AbortError');
      setState(old => ({ ...old, references, notice: '' }));
      const value = result(await json(captured, '/query', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question, requestId: reference.operationId }) }), reference.operationId);
      if (value.question !== question) throw Error('Analytics response does not match the admitted question');
      if (['completed', 'denied'].includes(value.status)) {
        const remaining = await forgetAnalyticsReference(reference);
        if (current(captured)) setState(old => ({ ...old, references: remaining }));
        // A history read failure must not turn a confirmed query into an unknown outcome.
        try { await history(captured); } catch (error) { if (current(captured)) setState(old => ({ ...old, notice: error.message })); }
        return value;
      }
      if (current(captured)) setState(old => ({ ...old, notice: 'Query outcome is not yet confirmed. Check the saved result; no automatic retry will run.' }));
      return null;
    } catch (error) {
      if (saved && current(captured)) {
        try { const references = await saveAnalyticsReference({ ...reference, state: 'unknown' }); if (current(captured)) setState(old => ({ ...old, references })); } catch { /* Retain the original durable reference if updating fails. */ }
        if (current(captured)) setState(old => ({ ...old, notice: 'Query outcome is unverified. Check the saved result; no automatic retry will run.' }));
      }
      throw error;
    } finally { captured.working = false; }
  }
  async function check(reference) {
    const captured = lease.current;
    if (!captured || !current(captured) || captured.working) return;
    captured.working = true;
    try { await recover(captured, reference); } catch (error) { if (current(captured)) setState(old => ({ ...old, notice: error.message })); }
    finally { captured.working = false; }
  }
  async function selectHistory(requestId) {
    const captured = lease.current;
    if (!captured || !current(captured) || !captured.scopeKey || captured.working
      || !stateRef.current.ready || stateRef.current.scopeKey !== captured.scopeKey) return false;
    const listed = stateRef.current.entries.find(entry => entry.requestId === requestId);
    if (!listed || !['completed', 'denied'].includes(listed.status)) return false;
    captured.working = true;
    setState(old => ({ ...old, selecting: true, notice: '' }));
    try {
      const read = result(await json(captured, '/requests/' + requestId), requestId);
      const stillListed = stateRef.current.entries.find(entry => entry.requestId === requestId);
      if (!current(captured) || stateRef.current.scopeKey !== captured.scopeKey
        || !stillListed || !sameListedResult(listed, stillListed)
        || !sameListedResult(stillListed, read)) throw Error('Saved Analytics history changed');
      setState(old => ({ ...old, selected: read, notice: '' }));
      return true;
    } catch (error) {
      if (current(captured)) setState(old => ({ ...old, notice: error.message }));
      return false;
    } finally {
      captured.working = false;
      if (current(captured)) setState(old => ({ ...old, selecting: false }));
    }
  }
  async function forget(reference) {
    const captured = lease.current;
    if (!captured || !current(captured) || captured.working) return;
    try { const references = await forgetAnalyticsReference(reference); if (current(captured)) setState(old => ({ ...old, references, notice: 'Saved reference forgotten. This does not cancel or repeat the query.' })); }
    catch (error) { if (current(captured)) setState(old => ({ ...old, notice: error.message })); }
  }
  async function loadMore() {
    const captured = lease.current;
    if (!captured || !current(captured) || captured.working || !state.nextCursor) return;
    captured.working = true;
    try { await history(captured, state.nextCursor); } catch (error) { if (current(captured)) setState(old => ({ ...old, notice: error.message })); }
    finally { captured.working = false; }
  }
  return { ...state, submit, check, forget, loadMore, selectHistory };
}
