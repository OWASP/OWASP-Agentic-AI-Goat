import { useCallback, useEffect, useRef, useState } from 'react';
import { productSummaryReferenceStore } from '../utils/productSummaryReference.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { discardIgnoredMutationResponse } from '../utils/discardIgnoredMutationResponse.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const invalid = () => { throw new Error('Saved summary unavailable'); };
const base = productId => `/api/secureshop/products/${productId}/summary`;
const savedPath = ref => `${base(ref.productId)}/sessions/${ref.sessionId}/requests/${ref.requestId}`;
const recoveryError = (entry, fallback) => entry.reference?.version === 1
  ? 'This older summary could not be recovered. Its saved reference is retained. Check again, or ask the practice administrator to reset the practice before starting a new summary.'
  : fallback;
const same = (a, b) => a && b && ['productId','shopUserId','authorityKey','transport','referenceStore'].every(key => a[key] === b[key]);
export function decodeSavedProductSummary(value, ref) {
  if (['pending','not_found'].includes(value?.status)) {
    if (!exact(value, ['status','sessionId','requestId']) || value.sessionId !== ref.sessionId || value.requestId !== ref.requestId) invalid();
    return Object.freeze({ status: value.status, result: null });
  }
  if (!exact(value, ['status','result']) || value.status !== 'completed') invalid();
  const result = value.result, keys = ['product_id','name','price','category','stock_quantity','description','description_html','summary','provider','model','sessionId','requestId'];
  if ((!exact(result, keys) && !exact(result, [...keys,'modeCapability']))
    || result.product_id !== ref.productId || result.sessionId !== ref.sessionId || result.requestId !== ref.requestId
    || typeof result.name !== 'string' || !['number','string'].includes(typeof result.price)
    || !Number.isInteger(result.stock_quantity) || result.stock_quantity < 0
    || ['category','description','description_html'].some(key => result[key] !== null && typeof result[key] !== 'string')
    || typeof result.summary !== 'string' || !result.summary.trim()
    || typeof result.provider !== 'string' || !result.provider || typeof result.model !== 'string' || !result.model
    || (result.modeCapability !== undefined && trustedTurnMode(result.modeCapability)?.featureId !== 'product_assist')) invalid();
  return Object.freeze({ status: 'completed', result: Object.freeze({ ...result }) });
}
async function json(response, allowMissing = false) {
  if (!response.ok && !(allowMissing && response.status === 404)) throw Object.assign(new Error('Summary unavailable'), { status: response.status });
  if (!/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) invalid();
  return response.json();
}
export function useProductSummary({ productId, shopUserId, authorityKey, transport,
  referenceStore = productSummaryReferenceStore } = {}) {
  const selected = Number(productId), valid = Number.isSafeInteger(selected) && selected > 0 && selected <= 2147483647 && String(selected) === String(productId);
  const scope = { productId: selected, shopUserId, authorityKey, transport, referenceStore };
  const latest = useRef(scope); latest.current = scope;
  const active = useRef(null);
  const [state, setState] = useState({ summary: null, loading: false, error: '', status: null });
  const [assessment, setAssessment] = useState(null);
  const current = useCallback(entry => entry.active && active.current === entry && same(latest.current, entry.scope) && !entry.controller.signal.aborted, []);
  const read = useCallback(async entry => {
    if (current(entry)) setAssessment(null);
    const response = await transport(savedPath(entry.reference), { method:'GET', headers:{accept:'application/json'}, signal:entry.controller.signal });
    const saved = decodeSavedProductSummary(await json(response, true), entry.reference);
    if (current(entry)) setState({ summary:saved.result, loading:false, status:saved.status,
      error:saved.status === 'completed' ? '' : 'Summary is unresolved. Check saved summary.' });
    if (saved.status === 'completed' && current(entry)) {
      let assessed;
      try {
        assessed = await json(await transport(`/api/secureshop/agents/customer/sessions/${entry.reference.sessionId}/requests/${entry.reference.requestId}/product-summary/assessment`, {
          method:'GET', headers:{accept:'application/json'}, signal:entry.controller.signal }));
        const idle = exact(assessed,['completed','status','modelEvaluated']) && assessed.completed === false
          && assessed.modelEvaluated === false && ['ineligible','unconfirmed'].includes(assessed.status);
        const judged = exact(assessed,['completed','judgment','replayed']) && typeof assessed.completed === 'boolean' && typeof assessed.replayed === 'boolean'
          && exact(assessed.judgment,['evaluationId','verdict','canRetry']) && UUID.test(assessed.judgment.evaluationId || '')
          && ['pass','fail','inconclusive','unavailable'].includes(assessed.judgment.verdict)
          && typeof assessed.judgment.canRetry === 'boolean' && (!assessed.completed || assessed.judgment.verdict === 'pass');
        if (!idle && !judged) invalid();
      } catch { assessed = {completed:false,status:'unavailable',modelEvaluated:false}; }
      if (current(entry)) setAssessment(assessed);
    }
    return saved;
  }, [transport, current]);
  const perform = useCallback(async entry => {
    try {
      const response = await transport(`${base(selected)}/session`, { method:'POST', headers:{'content-type':'application/json'}, body:'{}', signal:entry.controller.signal });
      const session = await json(response);
      if (!exact(session, ['sessionId','recoveryKey']) || !UUID.test(session.sessionId || '')
        || !/^[a-f0-9]{64}$/.test(session.recoveryKey || '')) invalid();
      if (!current(entry)) return;
      entry.recoveryKey = session.recoveryKey;
      let ref = referenceStore.read(shopUserId, selected, session.recoveryKey);
      if (ref) { entry.reference = ref; return await read(entry); }
      ref = await referenceStore.save({shopUserId,productId:selected,recoveryKey:session.recoveryKey,sessionId:session.sessionId,requestId:crypto.randomUUID(),startedAt:Date.now()}, () => current(entry));
      if (!current(entry)) return;
      entry.reference = ref;
      try { const response = await transport(base(selected), { method:'POST', headers:{'content-type':'application/json'},
        body:JSON.stringify({sessionId:ref.sessionId,requestId:ref.requestId}), signal:entry.controller.signal });
        await discardIgnoredMutationResponse(response, {signal:entry.controller.signal}); }
      catch { /* Only saved GET resolves an uncertain original POST. */ }
      if (current(entry)) await read(entry);
    } catch (cause) {
      if (current(entry)) setState({summary:null,loading:false,status:null,
        recoveryStorageFull:cause?.code === 'PRODUCT_SUMMARY_RECOVERY_FULL',
        error:cause?.code === 'PRODUCT_SUMMARY_RECOVERY_FULL'
          ? 'Summary recovery storage is full. Existing summaries remain available.'
          : recoveryError(entry, 'AI summary unavailable. Check saved summary.')});
    } finally { entry.busy = false; }
  }, [referenceStore, shopUserId, selected, transport, read, current]);
  useEffect(() => {
    const previous = active.current;
    if (!valid || !Number.isSafeInteger(shopUserId) || shopUserId < 1 || typeof transport !== 'function') {
      previous?.controller.abort(); active.current = null; setAssessment(null); setState({summary:null,loading:false,error:'',status:null}); return undefined;
    }
    if (previous && same(previous.scope, scope)) {
      previous.active = true;
      return () => { previous.active = false; queueMicrotask(() => { if (!previous.active) previous.controller.abort(); }); };
    }
    previous?.controller.abort(); setAssessment(null);
    const entry = {scope,controller:new AbortController(),active:true,busy:true,reference:null}; active.current = entry;
    setState({summary:null,loading:true,error:'',status:null});
    void Promise.resolve().then(() => { if (current(entry)) return perform(entry); });
    return () => { entry.active = false; queueMicrotask(() => { if (!entry.active) entry.controller.abort(); }); };
  }, [valid, shopUserId, selected, authorityKey, transport, referenceStore, perform, current]);
  const check = useCallback(async () => {
    const entry = active.current;
    if (!entry || !current(entry) || entry.busy) return;
    entry.busy = true; setState(old => ({...old,loading:true,error:''}));
    try {
      entry.reference ||= referenceStore.read(shopUserId, selected, entry.recoveryKey);
      if (!entry.reference) throw new Error('No saved summary');
      await read(entry);
    } catch { if (current(entry)) setState({summary:null,loading:false,status:null,error:recoveryError(entry, 'Saved summary unavailable.')}); }
    finally { entry.busy = false; }
  }, [current, referenceStore, shopUserId, selected, read]);
  const retryNotFound = useCallback(async () => {
    const entry = active.current;
    if (!entry || !current(entry) || entry.busy || state.status !== 'not_found' || !entry.reference) return;
    entry.busy = true; setState(old => ({...old,loading:true,error:''}));
    try {
      const before = await read(entry);
      if (!current(entry) || before.status !== 'not_found') return;
      const ref = entry.reference;
      try { const response = await transport(base(ref.productId), {method:'POST',headers:{'content-type':'application/json'},
        body:JSON.stringify({sessionId:ref.sessionId,requestId:ref.requestId}),signal:entry.controller.signal});
        await discardIgnoredMutationResponse(response, {signal:entry.controller.signal}); }
      catch { /* Recover the same original request; never allocate new IDs. */ }
      if (current(entry)) await read(entry);
    } catch { if (current(entry)) setState({summary:null,loading:false,status:null,error:recoveryError(entry, 'Saved summary unavailable.')}); }
    finally { entry.busy = false; }
  }, [current, state.status, read, transport]);
  const visible = valid && Number.isSafeInteger(shopUserId) && same(active.current?.scope, scope);
  return {...(visible ? state : {summary:null,loading:false,error:'',status:null}),
    assessment:visible ? assessment : null, check, retryNotFound};
}
