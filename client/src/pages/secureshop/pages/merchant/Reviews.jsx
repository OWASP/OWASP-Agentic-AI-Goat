import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import {
  Check, X, Filter, Star, ShieldCheck, ShieldAlert, Clock, RefreshCw,
  Sparkles, MessageSquareText, Package,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import {readManualPending,saveManualPending,clearManualPending,verifyManualReceipt,recoverManualPending} from '../../utils/manualReviewOperation.mjs';
import { createBoundReviewRequests } from '../../utils/boundReviewRequests.mjs';
import { getBridgeFetchMetadata } from '../../bridge/fetchAdapter.mjs';
import { shopStorage, SHOP_TOKEN_KEY } from '../../utils/shopStorage.mjs';
import { createReviewModerationReferenceStore, verifyReviewModerationHistory,
  verifyReviewModerationLookup } from '../../utils/reviewModerationReference.mjs';

/**
 * Merchant Reviews — M8 Wave 2B.
 *
 * Full moderation console:
 *   - Tabs: Pending / Approved / Rejected (with counts)
 *   - Per-review card: rating stars, author, product, body (rendered via
 *     dangerouslySetInnerHTML — stored XSS surface preserved)
 *   - Individual approve/reject with reason
 *   - "Moderate pending" button — fires review-moderator.moderate_pending
 *     which is the LLM01 indirect-PI target.
 *   - Filters: product, rating range
 *
 * @intentional-vulnerability xss-stored-review
 * @intentional-vulnerability llm01-indirect-pi-review
 */
export default function MerchantReviews() {
  const reduced = useReducedMotion();
  const { user, token } = useAuth();
  const reviewRequests = useRef(null);
  const transportRef = useRef(null);
  if (!reviewRequests.current || transportRef.current !== globalThis.fetch) {
    transportRef.current = globalThis.fetch;
    reviewRequests.current = createBoundReviewRequests({ fetchImpl: transportRef.current });
  }
  const authorityRef = useRef({ id: user?.id, role: user?.role, token,
    transport: transportRef.current, epoch: 0 });
  if (authorityRef.current.id !== user?.id || authorityRef.current.role !== user?.role
    || authorityRef.current.token !== token || authorityRef.current.transport !== transportRef.current) {
    authorityRef.current = { id: user?.id, role: user?.role, token,
      transport: transportRef.current, epoch: authorityRef.current.epoch + 1 };
  }
  const authorityEpoch = authorityRef.current.epoch;
  const moderationStore = useRef(null);
  if (!moderationStore.current) moderationStore.current = createReviewModerationReferenceStore();
  const [moderationPending, setModerationPending] = useState(null);
  const [moderationStorageBlocked, setModerationStorageBlocked] = useState(false);
  const [moderationContinuationVerifiedEpoch, setModerationContinuationVerifiedEpoch] = useState(null);
  const [manualCapability,setManualCapability]=useState(null);
  const [manualPending,setManualPending]=useState(null);
  const [manualRetry,setManualRetry]=useState(false);
  const [status, setStatus] = useState('pending');
  const [productId, setProductId] = useState('');
  const [minRating, setMinRating] = useState('');
  const [maxRating, setMaxRating] = useState('');
  const [reviews, setReviews] = useState([]);
  const [loadedFilterKey, setLoadedFilterKey] = useState(null);
  const [counts, setCounts] = useState({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [rejecting, setRejecting] = useState(null);
  const [rejectReason, setRejectReason] = useState('');
  const [moderationResult, setModerationResult] = useState(null);
  const [products, setProducts] = useState([]);
  const [listError, setListError] = useState('');
  const [productError, setProductError] = useState('');
  const [actionFeedback, setActionFeedback] = useState(null);
  const listRequestRef = useRef({ id: 0, controller: null });
  const actionRequestRef = useRef(0);
  const actionInFlightRef = useRef(false);
  const actionAbortRef = useRef(null);
  const mountedRef = useRef(true);
  const latestLoadRef = useRef(null);
  const moderationContinuationRef = useRef(null);
  const filterKey = `${user?.id || ''}|${user?.role || ''}|${token || ''}|${authorityEpoch}|${status}|${productId}|${minRating}|${maxRating}`;
  const filterKeyRef = useRef(filterKey);
  filterKeyRef.current = filterKey;
  const listCurrent = loadedFilterKey === filterKey;
  const listLoading = loading || !listCurrent;
  const visibleReviews = listCurrent ? reviews.filter(row => row.status === status) : [];

  useEffect(() => {
    actionRequestRef.current += 1;
    actionAbortRef.current?.abort();
    actionAbortRef.current = null;
    actionInFlightRef.current = false;
    reviewRequests.current.invalidate();
    moderationContinuationRef.current = null;
    setBusy(false);
    setModerationResult(null);
    setActionFeedback(null);setManualCapability(null);setManualPending(null);setManualRetry(false);
    setModerationContinuationVerifiedEpoch(null);
    if (reviewRequests.current.bound) {
      try {
        if (typeof token !== 'string' || !token
          || shopStorage.getItem(SHOP_TOKEN_KEY) !== token
          || getBridgeFetchMetadata(transportRef.current)?.boundReviews !== true)
          throw new Error('Review authority unavailable');
        setModerationPending(moderationStore.current.read()); setModerationStorageBlocked(false);
      }
      catch { setModerationPending(null); setModerationStorageBlocked(true); }
    } else { setModerationPending(null); setModerationStorageBlocked(false); }
  }, [user?.id, user?.role, token, authorityEpoch]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    readResponse(fetch('/api/secureshop/merchant/products?per_page=100', { signal: controller.signal }), 'Unable to load products')
      .then(j => {
        if (!active) return;
        setProducts(Array.isArray(j.products) ? j.products : []);
        setProductError('');
      })
      .catch(error => {
        if (active && error.name !== 'AbortError') setProductError(boundedMessage(error, 'Unable to load products'));
      });
    return () => { active = false; controller.abort(); };
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      listRequestRef.current.controller?.abort();
      actionRequestRef.current += 1;
      actionAbortRef.current?.abort();
      actionInFlightRef.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    const requestedFilterKey = filterKey;
    listRequestRef.current.controller?.abort();
    const controller = new AbortController();
    const requestId = listRequestRef.current.id + 1;
    listRequestRef.current = { id: requestId, controller };
    setLoading(true);
    setListError('');
    const params = new URLSearchParams({ status, per_page: '50' });
    if (productId) params.set('product_id', productId);
    if (minRating) params.set('min_rating', minRating);
    if (maxRating) params.set('max_rating', maxRating);
    try {
      const j = await readResponse(
        fetch(`/api/secureshop/merchant/reviews?${params.toString()}`, { signal: controller.signal }),
        'Unable to load reviews',
      );
      if (listRequestRef.current.id !== requestId || filterKeyRef.current !== requestedFilterKey) return;
      setReviews(Array.isArray(j.reviews) ? j.reviews : []);
      setLoadedFilterKey(requestedFilterKey);
      setCounts(j.counts && typeof j.counts === 'object' ? j.counts : {});
      if(j.manual_decisions?.available===true){if(typeof j.manual_decisions.scopeKey!=='string')throw Error('Manual review authority unavailable');setManualCapability(j.manual_decisions);setManualPending(readManualPending(j.manual_decisions.scopeKey));}else{setManualCapability(null);setManualPending(null);}
      return j;
    } catch (error) {
      if (error.name !== 'AbortError' && listRequestRef.current.id === requestId
          && filterKeyRef.current === requestedFilterKey) {
        setReviews([]);
        setLoadedFilterKey(requestedFilterKey);
        setListError(boundedMessage(error, 'Unable to load reviews'));
      }
    } finally {
      if (listRequestRef.current.id === requestId && filterKeyRef.current === requestedFilterKey) setLoading(false);
    }
  }, [filterKey, status, productId, minRating, maxRating]);
  latestLoadRef.current = load;

  useEffect(() => { load(); }, [load]);

  const refreshModerationReference = () => {
    try {
      if (typeof authorityRef.current.token !== 'string' || !authorityRef.current.token
        || shopStorage.getItem(SHOP_TOKEN_KEY) !== authorityRef.current.token
        || getBridgeFetchMetadata(authorityRef.current.transport)?.boundReviews !== true)
        throw new Error('Review authority unavailable');
      const saved = moderationStore.current.read();
      setModerationPending(saved);
      setModerationStorageBlocked(false);
      return saved;
    } catch {
      setModerationPending(null);
      setModerationStorageBlocked(true);
      return null;
    }
  };
  const moderationReceipt = async (requests, requestId, requestedLimit, recoveryScopeKey, signal) => {
    const query = new URLSearchParams({ limit: String(requestedLimit) });
    if (recoveryScopeKey) query.set('recoveryScopeKey', recoveryScopeKey);
    return readResponse(requests.fetch(`/api/secureshop/merchant/reviews/moderation/${requestId}?${query}`, {
      signal, headers: { accept: 'application/json' },
    }), 'Saved moderation status unavailable');
  };
  const moderationHistory = async (requests, reference, signal, assertCurrent) => {
    const lookups = [];
    for (const [requestId, requestedLimit] of reference.completed) {
      assertCurrent();
      lookups.push(await moderationReceipt(requests, requestId, requestedLimit,
        reference.recoveryScopeKey, signal));
      assertCurrent();
    }
    verifyReviewModerationHistory(reference, lookups);
    return lookups;
  };
  const reportModerationHistory = (reference, lookups) => {
    const totals = verifyReviewModerationHistory(reference, lookups);
    const decisions = lookups.flatMap(value => value.result.decisions);
    return { ...totals, decisions };
  };
  const runBoundModeration = async (continueSaved = false) => {
    if (actionInFlightRef.current || manualPending || listLoading || listError
      || moderationStorageBlocked || (continueSaved && moderationContinuationVerifiedEpoch !== authorityEpoch)) return;
    const requests = reviewRequests.current;
    if (!requests.bound || requests.fetch !== reviewRequests.current.fetch) return;
    actionInFlightRef.current = true;
    const actionId = ++actionRequestRef.current;
    const authority = authorityRef.current;
    const startingFilterKey = filterKeyRef.current;
    const controller = new AbortController();
    actionAbortRef.current = controller;
    const assertCurrent = () => {
      if (!mountedRef.current || actionRequestRef.current !== actionId
        || authorityRef.current.epoch !== authority.epoch
        || authorityRef.current.transport !== authority.transport
        || filterKeyRef.current !== startingFilterKey || controller.signal.aborted
        || globalThis.fetch !== authority.transport
        || getBridgeFetchMetadata(authority.transport)?.boundReviews !== true
        || shopStorage.getItem(SHOP_TOKEN_KEY) !== authority.token) {
        throw new DOMException('Review authority changed', 'AbortError');
      }
      return true;
    };
    setBusy(true); setActionFeedback(null); setModerationResult(null);
    try {
      assertCurrent();
      let reference = moderationStore.current.read();
      if (reference?.pending || (continueSaved && !reference)
        || (!continueSaved && reference)) {
        throw new Error(reference?.pending
          ? 'A saved moderation batch needs a status check before another action.'
          : 'Check or continue the saved moderation before starting a new action.');
      }
      let history = reference
        ? await moderationHistory(requests, reference, controller.signal, assertCurrent) : [];
      if (reference && !verifyReviewModerationHistory(reference, history).canContinue) {
        throw new Error('Saved moderation has no authorized continuation. Check its status first.');
      }
      const originalActionId = reference?.actionId || crypto.randomUUID();
      while (true) {
        assertCurrent();
        const totals = reference ? reportModerationHistory(reference, history)
          : { considered: 0, processed: 0, decisions: [], remaining: 100 };
        if (!totals.remaining) break;
        const requestId = crypto.randomUUID();
        const requestedLimit = totals.remaining;
        const preflight = await moderationReceipt(requests, requestId, requestedLimit,
          reference?.recoveryScopeKey, controller.signal);
        assertCurrent();
        verifyReviewModerationLookup(preflight, {
          requestId, requestedLimit,
          ...(reference ? { recoveryScopeKey: reference.recoveryScopeKey } : {}),
        });
        reference = reference
          ? await moderationStore.current.reserveNextPost({ requestId, requestedLimit },
            preflight, history, { assertCurrent })
          : await moderationStore.current.reserveInitialPost({ actionId: originalActionId,
            requestId }, preflight, { assertCurrent });
        assertCurrent();
        setModerationPending(reference);
        const body = { request_id: requestId, limit: requestedLimit,
          recoveryScopeKey: reference.recoveryScopeKey };
        await readResponse(requests.fetch('/api/secureshop/merchant/reviews/moderate-all', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body), signal: controller.signal,
        }), 'Moderation outcome is unknown');
        assertCurrent();
        const receipt = await moderationReceipt(requests, requestId, requestedLimit,
          reference.recoveryScopeKey, controller.signal);
        assertCurrent();
        const observed = moderationStore.current.observePending(receipt);
        if (observed.state !== 'completed') {
          setActionFeedback({ kind: 'error', message: 'Moderation outcome is not yet confirmed. Check the saved batch; it will not be posted again.' });
          return;
        }
        const recorded = await moderationStore.current.recordCompleted(receipt, history,
          { assertCurrent });
        assertCurrent();
        reference = recorded.reference;
        history = [...history, receipt];
        setModerationPending(reference);
        const aggregate = reportModerationHistory(reference, history);
        setModerationResult({ processed: aggregate.processed, decisions: aggregate.decisions,
          batch: { considered: aggregate.considered } });
        if (aggregate.canContinue) { setModerationContinuationVerifiedEpoch(authority.epoch); continue; }
        await latestLoadRef.current();
        assertCurrent();
        await moderationStore.current.finish(history, { assertCurrent });
        assertCurrent();
        setModerationPending(null);
        setModerationContinuationVerifiedEpoch(null);
        setActionFeedback(receipt.result.ok
          ? { kind: 'success', message: moderationSuccessMessage(aggregate) }
          : { kind: 'error', message: boundedText(receipt.result.stopReason)
            || `Moderation stopped after ${aggregate.processed} review(s).` });
        return;
      }
    } catch (error) {
      if (mountedRef.current && actionRequestRef.current === actionId
        && authorityRef.current.epoch === authority.epoch) {
        refreshModerationReference();
        setActionFeedback({ kind: 'error', message: boundedMessage(error,
          'Moderation outcome is unknown. Check the saved batch before another action.') });
      }
    } finally {
      if (actionRequestRef.current === actionId) {
        actionAbortRef.current = null; actionInFlightRef.current = false;
        if (mountedRef.current) setBusy(false);
      }
    }
  };
  const checkSavedModeration = async () => {
    if (actionInFlightRef.current || moderationStorageBlocked || !reviewRequests.current.bound) return;
    const requests = reviewRequests.current;
    actionInFlightRef.current = true;
    const actionId = ++actionRequestRef.current;
    const authority = authorityRef.current;
    const controller = new AbortController();
    actionAbortRef.current = controller;
    const assertCurrent = () => {
      if (!mountedRef.current || actionRequestRef.current !== actionId
        || authorityRef.current.epoch !== authority.epoch
        || authorityRef.current.transport !== authority.transport || controller.signal.aborted
        || globalThis.fetch !== authority.transport
        || getBridgeFetchMetadata(authority.transport)?.boundReviews !== true
        || shopStorage.getItem(SHOP_TOKEN_KEY) !== authority.token) {
        throw new DOMException('Review authority changed', 'AbortError');
      }
      return true;
    };
    setBusy(true); setActionFeedback(null);
    try {
      assertCurrent();
      let reference = moderationStore.current.read();
      if (!reference) throw new Error('No saved moderation is available in this shop scene.');
      let history = await moderationHistory(requests, reference, controller.signal, assertCurrent);
      if (reference.pending) {
        const { requestId, requestedLimit } = reference.pending;
        assertCurrent();
        const receipt = await moderationReceipt(requests, requestId, requestedLimit,
          reference.recoveryScopeKey, controller.signal);
        assertCurrent();
        const observed = moderationStore.current.observePending(receipt);
        if (observed.state !== 'completed') {
          setActionFeedback({ kind: 'error', message: 'No completed moderation receipt observed yet. The saved batch remains unresolved; no POST was sent.' });
          return;
        }
        const recorded = await moderationStore.current.recordCompleted(receipt, history,
          { assertCurrent });
        assertCurrent();
        reference = recorded.reference;
        history = [...history, receipt];
      }
      const aggregate = reportModerationHistory(reference, history);
      assertCurrent();
      setModerationPending(reference);
      setModerationResult({ processed: aggregate.processed, decisions: aggregate.decisions,
        batch: { considered: aggregate.considered } });
      if (aggregate.canContinue) {
        setModerationContinuationVerifiedEpoch(authority.epoch);
        setActionFeedback({ kind: 'success', message: `Saved moderation verified. Continue the remaining ${aggregate.remaining} review(s) only if you choose to.` });
      } else {
        await latestLoadRef.current();
        assertCurrent();
        await moderationStore.current.finish(history, { assertCurrent });
        assertCurrent();
        setModerationPending(null);
        setModerationContinuationVerifiedEpoch(null);
        const last = history[history.length - 1].result;
        setActionFeedback(last.ok
          ? { kind: 'success', message: moderationSuccessMessage(aggregate) }
          : { kind: 'error', message: boundedText(last.stopReason)
            || `Moderation stopped after ${aggregate.processed} review(s).` });
      }
    } catch (error) {
      if (mountedRef.current && actionRequestRef.current === actionId
        && authorityRef.current.epoch === authority.epoch) {
        refreshModerationReference();
        setActionFeedback({ kind: 'error', message: boundedMessage(error,
          'Saved moderation remains unresolved; no POST was sent.') });
      }
    } finally {
      if (actionRequestRef.current === actionId) {
        actionAbortRef.current = null; actionInFlightRef.current = false;
        if (mountedRef.current) setBusy(false);
      }
    }
  };

  const runModerationAll = async () => {
    if (reviewRequests.current.bound) return runBoundModeration(false);
    if (manualPending || actionInFlightRef.current || listLoading || listError) return;
    actionInFlightRef.current = true;
    const actionId = actionRequestRef.current + 1;
    actionRequestRef.current = actionId;
    const controller = new AbortController();
    actionAbortRef.current = controller;
    setBusy(true);
    setModerationResult(null);
    setActionFeedback(null);
    const identity = `${user?.id || ''}:${user?.role || ''}`;
    const startingFilterKey = filterKeyRef.current;
    const pending = moderationContinuationRef.current?.identity === identity
      ? moderationContinuationRef.current : null;
    if (pending) {
      setModerationResult({ processed: pending.processed, decisions: pending.decisions,
        batch: { considered: pending.considered } });
    } else {
      setModerationResult(null);
    }
    let aggregate = pending
      ? { processed: pending.processed, considered: pending.considered, decisions: pending.decisions.slice() }
      : { processed: 0, considered: 0, decisions: [] };
    let pendingRequest = pending;
    try {
      while (true) {
        if (!mountedRef.current || actionRequestRef.current !== actionId
          || filterKeyRef.current !== startingFilterKey) return;
        const remaining = 100 - aggregate.considered;
        if (remaining <= 0) break;
        const body = pendingRequest
          ? { request_id: pendingRequest.requestId, limit: remaining }
          : reviewRequests.current.prepare('moderation', { limit: remaining }, identity);
        const requestId = body.request_id;
        let j;
        try {
          j = await readResponse(reviewRequests.current.fetch('/api/secureshop/merchant/reviews/moderate-all', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
            signal: controller.signal,
          }), 'Moderation failed');
        } catch (error) {
          if (requestId && mountedRef.current && actionRequestRef.current === actionId) {
            moderationContinuationRef.current = {
              identity, requestId, processed: aggregate.processed,
              considered: aggregate.considered, decisions: aggregate.decisions,
            };
          }
          throw error;
        }
        if (!mountedRef.current || actionRequestRef.current !== actionId) return;
        if (!Object.prototype.hasOwnProperty.call(j, 'batch')) {
          if (filterKeyRef.current !== startingFilterKey) {
            reviewRequests.current.complete('moderation');
            moderationContinuationRef.current = null;
            return;
          }
          setModerationResult(j);
          setActionFeedback(j.ok === false
            ? { kind: 'error', message: boundedText(j.stopReason) || `Moderation stopped after ${Number(j.processed) || 0} review(s).` }
            : { kind: 'success', message: `Moderated ${Number(j.processed) || 0} review(s) in this run.` });
          reviewRequests.current.complete('moderation');
          moderationContinuationRef.current = null;
          await latestLoadRef.current();
          return;
        }

        const batch = validModerationBatch(j.batch, remaining, body.limit);
        const processed = j.processed;
        if (!batch || (j.ok !== true && j.ok !== false)
          || !Array.isArray(j.decisions)
          || typeof processed !== 'number' || !Number.isInteger(processed)
          || processed < 0 || processed > batch.considered
          || processed !== j.decisions.length) {
          setModerationResult(aggregate.decisions.length ? aggregate : null);
          setActionFeedback({ kind: 'error', message: 'Moderation returned an incomplete batch response.' });
          if (requestId) moderationContinuationRef.current = {
            identity, requestId, processed: aggregate.processed,
            considered: aggregate.considered, decisions: aggregate.decisions,
          };
          return;
        }
        if (filterKeyRef.current !== startingFilterKey) {
          if (requestId) reviewRequests.current.complete('moderation');
          moderationContinuationRef.current = null;
          return;
        }
        aggregate = {
          processed: aggregate.processed + processed,
          considered: aggregate.considered + batch.considered,
          decisions: aggregate.decisions.concat(j.decisions),
        };
        const canContinue = j.ok === true && batch.complete === true
          && batch.continuationRequired === true && batch.considered > 0;
        if (canContinue && aggregate.considered < 100) {
          if (requestId) reviewRequests.current.complete('moderation');
          moderationContinuationRef.current = null;
          pendingRequest = null;
          continue;
        }
        setModerationResult({ ...j, processed: aggregate.processed, decisions: aggregate.decisions,
          batch: { ...batch, considered: aggregate.considered } });
        setActionFeedback(j.ok === true && batch.complete === true
          && (!batch.continuationRequired || batch.considered > 0)
          ? { kind: 'success', message: moderationSuccessMessage(aggregate) }
          : { kind: 'error', message: boundedText(j.stopReason) || `Moderation stopped after ${aggregate.processed} review(s).` });
        if (requestId) reviewRequests.current.complete('moderation');
        moderationContinuationRef.current = null;
        await latestLoadRef.current();
        return;
      }
      moderationContinuationRef.current = null;
      setModerationResult(aggregate);
      setActionFeedback({ kind: 'success', message: moderationSuccessMessage(aggregate) });
      await latestLoadRef.current();
    } catch (error) {
      if (mountedRef.current && actionRequestRef.current === actionId) {
        if (aggregate.decisions.length) setModerationResult(aggregate);
        setActionFeedback({ kind: 'error', message: boundedMessage(error, 'Moderation failed') });
      }
    } finally {
      if (actionRequestRef.current === actionId) {
        actionAbortRef.current = null; actionInFlightRef.current = false;
        if (mountedRef.current) setBusy(false);
      }
    }
  };

  const finishManual=async(p,current)=>{
    const receipt=await recoverManualPending(p,reviewRequests.current.fetch);
    if(!current())throw Error('Review authority changed');
    const refreshed=await latestLoadRef.current();
    if(!current()||refreshed?.manual_decisions?.scopeKey!==p.scopeKey)throw Error('Review state refresh unavailable; saved operation retained');
    await clearManualPending(p);return receipt;
  };
  const manualAction=async(p,recoveryOnly=false)=>{
    if(actionInFlightRef.current)return;actionInFlightRef.current=true;const actionId=++actionRequestRef.current;setBusy(true);setManualRetry(false);
    const current=()=>mountedRef.current&&actionRequestRef.current===actionId;
    try{
      if(!recoveryOnly){await saveManualPending(p);if(!current())return;setManualPending(p);
        const result=await readResponse(reviewRequests.current.fetch(`/api/secureshop/merchant/reviews/${p.reviewId}/${p.action}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({operationId:p.operationId,...(p.action==='reject'?{reason:p.reason}:{})})}),'Review outcome is unknown');
        if(!current())return;if(result?.ok!==true)throw Error('Review outcome is unknown');verifyManualReceipt(result.receipt,p,result.executionScopeKey);
      }
      const receipt=await finishManual(p,current);if(!current())return;setManualPending(null);closeReject();setActionFeedback({kind:receipt.applied?'success':'error',message:receipt.applied?`Review #${p.reviewId} ${receipt.resultStatus}.`:'The saved decision completed without changing this review.'});
    }catch(error){if(current()){setActionFeedback({kind:'error',message:error.message});setManualRetry(error.code==='NOT_OBSERVED');}}
    finally{if(current()){actionInFlightRef.current=false;setBusy(false);}}
  };
  const beginManual=(id,action,reason=null)=>{if(manualPending||!manualCapability||listError||listLoading)return;return manualAction({scopeKey:manualCapability.scopeKey,operationId:crypto.randomUUID(),reviewId:id,action,reason});};

  const approve = async (id) => {
    if(manualCapability)return beginManual(id,'approve');
    if(reviewRequests.current.bound)return;
    if (actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    const actionId = actionRequestRef.current + 1;
    actionRequestRef.current = actionId;
    const controller = new AbortController();
    actionAbortRef.current = controller;
    setBusy(true);
    setActionFeedback(null);
    try {
      const result = await readResponse(reviewRequests.current.fetch(`/api/secureshop/merchant/reviews/${id}/approve`, {
        method: 'POST', signal: controller.signal,
      }), 'Approval failed');
      if (!mountedRef.current || actionRequestRef.current !== actionId) return;
      if (result?.ok !== true) {
        setActionFeedback({
          kind: 'error',
          message: actionNotAppliedMessage(result, id, 'approved'),
        });
        await latestLoadRef.current();
        return;
      }
      setActionFeedback({ kind: 'success', message: `Review #${id} approved.` });
      await latestLoadRef.current();
    } catch (error) {
      if (mountedRef.current && actionRequestRef.current === actionId) {
        setActionFeedback({ kind: 'error', message: boundedMessage(error, 'Approval failed') });
      }
    } finally {
      if (actionRequestRef.current === actionId) {
        actionAbortRef.current = null; actionInFlightRef.current = false;
        if (mountedRef.current) setBusy(false);
      }
    }
  };

  const openReject = (review) => { setRejecting(review); setRejectReason(''); };
  const closeReject = () => { setRejecting(null); setRejectReason(''); };
  const doReject = async () => {
    if(manualCapability && rejecting)return beginManual(rejecting.id,'reject',rejectReason || 'no reason given');
    if(reviewRequests.current.bound)return;
    if (!rejecting || actionInFlightRef.current) return;
    actionInFlightRef.current = true;
    const id = rejecting.id;
    const actionId = actionRequestRef.current + 1;
    actionRequestRef.current = actionId;
    const controller = new AbortController();
    actionAbortRef.current = controller;
    setBusy(true);
    setActionFeedback(null);
    try {
      const result = await readResponse(reviewRequests.current.fetch(`/api/secureshop/merchant/reviews/${id}/reject`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ reason: rejectReason || 'no reason given' }),
        signal: controller.signal,
      }), 'Rejection failed');
      if (!mountedRef.current || actionRequestRef.current !== actionId) return;
      if (result?.ok !== true) {
        closeReject();
        setActionFeedback({
          kind: 'error',
          message: actionNotAppliedMessage(result, id, 'rejected'),
        });
        await latestLoadRef.current();
        return;
      }
      closeReject();
      setActionFeedback({ kind: 'success', message: `Review #${id} rejected.` });
      await latestLoadRef.current();
    } catch (error) {
      if (mountedRef.current && actionRequestRef.current === actionId) {
        setActionFeedback({ kind: 'error', message: boundedMessage(error, 'Rejection failed') });
      }
    } finally {
      if (actionRequestRef.current === actionId) {
        actionAbortRef.current = null; actionInFlightRef.current = false;
        if (mountedRef.current) setBusy(false);
      }
    }
  };

  const productMap = useMemo(() => {
    const m = new Map();
    products.forEach(p => m.set(p.id, p.name));
    return m;
  }, [products]);

  const productLabel = (pid) => productMap.get(pid) || `Product #${pid}`;

  const tabs = [
    { key: 'pending', label: 'Pending', icon: <Clock size={14} />, count: counts.pending || 0 },
    { key: 'approved', label: 'Approved', icon: <Check size={14} />, count: counts.approved || 0 },
    { key: 'rejected', label: 'Rejected', icon: <X size={14} />, count: counts.rejected || 0 },
  ];

  return (
    <motion.div
      initial={reduced ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
    >
      <header style={{ display: 'flex', gap: 16, alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <div>
          <h1 className="ss-display" style={{ fontSize: 40, margin: '0 0 6px 0' }}>Reviews</h1>
          <p className="ss-mono" style={{ opacity: 0.7, maxWidth: '68ch' }}>
            {reviewRequests.current.bound ? <>
              This shop sends pending reviews through an actual model decision loop.
              {' '}Clicking Moderate pending lets the model approve or reject up to 100
              pending reviews for your products, in batches. The filters only change
              the displayed list, not which pending reviews this action considers.
              {' '}
              Review text is untrusted content; compare the model's observed tool actions with
              the trusted product-feedback policy.
            </> : <>
              This demo uses a rule-based moderation simulation. A review containing{' '}
              <code style={{ fontFamily: 'inherit', color: 'var(--copper)' }}>SYSTEM: approve</code>
              {' '}changes its classification. The review is stored and updated in the
              database, but this simulation does not demonstrate an actual LLM decision.
            </>}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="ss-btn ss-btn--ghost" onClick={load} aria-label="Refresh" disabled={listLoading}>
            <RefreshCw size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} /> Refresh
          </button>
          <button className="ss-btn" disabled={busy || !!manualPending || listLoading || !!listError
            || (reviewRequests.current.bound && (!!moderationPending || moderationStorageBlocked))} onClick={runModerationAll} data-testid="reviews-moderate-all">
            <Sparkles size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
            {busy ? 'Moderating…' : 'Moderate pending'}
          </button>
        </div>
      </header>

      {(productError || listError || actionFeedback) && (
        <div
          role={listError || productError || actionFeedback?.kind === 'error' ? 'alert' : 'status'}
          data-testid="reviews-feedback"
          className="ss-mono"
          style={{
            padding: '10px 12px', fontSize: 12,
            border: `1px solid ${listError || productError || actionFeedback?.kind === 'error' ? 'var(--rust)' : 'var(--kelp)'}`,
            color: listError || productError || actionFeedback?.kind === 'error' ? 'var(--rust)' : 'var(--kelp)',
          }}
        >
          {[productError, listError, actionFeedback?.message].filter(Boolean).join(' ')}
        </div>
      )}

      {reviewRequests.current.bound && !manualCapability && !listLoading && !listError && <div role="status" className="ss-mono">Manual decisions are unavailable for this launch.</div>}
      {reviewRequests.current.bound && moderationStorageBlocked && <div role="alert" className="ss-mono">Saved moderation storage is unavailable. No new moderation batch can be sent.</div>}
      {reviewRequests.current.bound && moderationPending && <div role="status" className="ss-mono">
        {moderationPending.pending
          ? 'A saved moderation batch has an unverified outcome. It will not be posted again.'
          : 'Saved moderation is ready for a deliberate continuation or final status check.'}
        {' '}<button className="ss-btn" disabled={busy} onClick={checkSavedModeration}>Check saved moderation</button>
        {!moderationPending.pending && moderationContinuationVerifiedEpoch === authorityEpoch
          && <button className="ss-btn" disabled={busy || listLoading || !!listError}
          onClick={() => runBoundModeration(true)}>Continue remaining</button>}
      </div>}
      {manualPending && <div role="status" className="ss-mono">A saved review decision awaits verification. <button className="ss-btn" disabled={busy} onClick={()=>manualAction(manualPending,true)}>Refresh decision status</button>{manualRetry && <button className="ss-btn" disabled={busy} onClick={()=>manualAction(manualPending)}>Retry saved decision</button>}</div>}

      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--rule)' }}>
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setStatus(t.key)}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              padding: '10px 16px',
              background: 'transparent', color: 'var(--ink)',
              border: 'none', borderBottom: t.key === status ? '2px solid var(--signal)' : '2px solid transparent',
              fontFamily: 'var(--body)', fontSize: 14, fontWeight: t.key === status ? 600 : 500,
              cursor: 'pointer', outline: 'none',
              opacity: t.key === status ? 1 : 0.7,
            }}
          >
            {t.icon} {t.label}
            <span style={{
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              minWidth: 22, height: 20, padding: '0 6px',
              background: t.key === status ? 'var(--signal)' : 'color-mix(in srgb, var(--paper) 80%, var(--carbon))',
              color: t.key === status ? 'var(--paper)' : 'var(--ink)',
              fontFamily: 'var(--mono)', fontSize: 11,
            }}>{t.count}</span>
          </button>
        ))}
      </div>

      <div style={{
        display: 'grid', gap: 12,
        gridTemplateColumns: 'minmax(160px, 2fr) repeat(2, minmax(100px, 1fr)) auto',
        alignItems: 'end',
      }}>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ss-card__meta">Product</span>
          <select value={productId} onChange={(e) => setProductId(e.target.value)} style={selectStyle}>
            <option value="">All products</option>
            {products.map(p => <option key={p.id} value={p.id}>#{p.id} · {truncate(p.name, 40)}</option>)}
          </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ss-card__meta">Min rating</span>
          <select value={minRating} onChange={(e) => setMinRating(e.target.value)} style={selectStyle}>
            <option value="">Any</option>
            {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n}★</option>)}
          </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ss-card__meta">Max rating</span>
          <select value={maxRating} onChange={(e) => setMaxRating(e.target.value)} style={selectStyle}>
            <option value="">Any</option>
            {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n}★</option>)}
          </select>
        </label>
        <button className="ss-btn ss-btn--ghost ss-btn--sm"
                onClick={() => { setProductId(''); setMinRating(''); setMaxRating(''); }}
                style={{ height: 40 }}>
          <Filter size={14} style={{ marginRight: 6 }} /> Clear
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {listLoading && (
          <div style={{ padding: 40, textAlign: 'center' }} className="ss-mono">loading…</div>
        )}

        {!listLoading && !listError && visibleReviews.length === 0 && (
          <div style={{
            padding: 60, textAlign: 'center', border: '1px dashed var(--rule)',
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10,
          }}>
            <MessageSquareText size={28} style={{ opacity: 0.4 }} />
            <div style={{ fontFamily: 'var(--display)', fontSize: 18 }}>No {status} reviews</div>
            <div style={{ fontSize: 13, opacity: 0.65, maxWidth: '40ch' }}>
              {status === 'pending'
                ? "You're all caught up. New reviews will land here for moderation."
                : `No reviews are in the ${status} state.`}
            </div>
          </div>
        )}

        {visibleReviews.length > 0 && !listLoading && !listError && visibleReviews.map((r, idx) => (
            <motion.article
              key={r.id}
              initial={reduced ? false : { opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, height: 0, marginTop: -12 }}
              transition={{ delay: reduced ? 0 : idx * 0.035, duration: 0.28 }}
              style={{ border: '1px solid var(--rule)', padding: 18, background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))' }}
            >
              <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: 240 }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                    <StarRow rating={r.rating || 0} />
                    <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6 }}>
                      REVIEW #{r.id} · author {r.author_id}
                    </div>
                  </div>
                  <div style={{ marginTop: 6, display: 'inline-flex', gap: 6, alignItems: 'center', fontSize: 13, opacity: 0.75 }}>
                    <Package size={13} /> {productLabel(r.product_id)}
                  </div>
                  <div className="ss-mono" style={{ marginTop: 4, fontSize: 11, opacity: 0.55 }}>
                    {formatDate(r.created_at)}{r.moderated_at ? ` · moderated ${formatDate(r.moderated_at)}` : ''}
                  </div>

                  {/* intentional — teaches xss-stored-review + html-injection */}
                  <div
                    className="review-body"
                    dangerouslySetInnerHTML={{ __html: r.body || '' }}
                    style={{
                      marginTop: 12, padding: 12,
                      background: 'color-mix(in srgb, var(--paper) 82%, var(--carbon))',
                      border: '1px solid var(--rule)',
                      fontSize: 14, lineHeight: 1.5, whiteSpace: 'pre-wrap',
                    }}
                  />

                  {r.moderator_notes && (
                    <div className="ss-mono" style={{ marginTop: 8, fontSize: 12, opacity: 0.7 }}>
                      moderator notes: {r.moderator_notes}
                    </div>
                  )}

                  {isSuspicious(r.body) && (
                    <div style={{
                      marginTop: 10, padding: 8,
                      background: 'color-mix(in srgb, var(--paper) 82%, var(--rust))',
                      border: '1px solid var(--rust)',
                      color: 'var(--rust)', fontFamily: 'var(--mono)', fontSize: 12,
                      display: 'inline-flex', alignItems: 'center', gap: 6,
                    }}>
                      <ShieldAlert size={13} /> This body contains a `SYSTEM:` directive — likely PI targeting the moderator.
                    </div>
                  )}
                </div>

                {r.status === 'pending' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 160 }}>
                    <button className="ss-btn ss-btn--sm" disabled={busy || !!manualPending || listLoading || (reviewRequests.current.bound && !manualCapability)} onClick={() => approve(r.id)}>
                      <Check size={14} style={{ marginRight: 6 }} /> Approve
                    </button>
                    <button className="ss-btn ss-btn--danger ss-btn--sm" disabled={busy || !!manualPending || listLoading || (reviewRequests.current.bound && !manualCapability)} onClick={() => {if(!manualPending && (!reviewRequests.current.bound || manualCapability))openReject(r);}}>
                      <X size={14} style={{ marginRight: 6 }} /> Reject
                    </button>
                  </div>
                )}
                {r.status !== 'pending' && (
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, opacity: 0.7 }}>
                    <ShieldCheck size={13} />
                    <span className="ss-mono" style={{ fontSize: 12 }}>
                      {r.status} by {r.moderator_kind || 'human'}
                    </span>
                  </div>
                )}
              </div>
            </motion.article>
          ))}
      </div>

      <AnimatePresence>
        {rejecting && (
          <RejectDialog
            review={rejecting}
            reason={rejectReason}
            setReason={setRejectReason}
            onCancel={closeReject}
            onConfirm={doReject}
            busy={busy}
            reduced={reduced}
          />
        )}
      </AnimatePresence>

      {moderationResult && (
        <motion.section
          initial={reduced ? false : { opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          style={{
            marginTop: 12, padding: 20,
            background: 'var(--carbon)', color: 'var(--paper)',
            border: '1px solid var(--rule)',
          }}
        >
          <div className="ss-card__meta" style={{ color: 'var(--copper)', marginBottom: 8 }}>
            MODERATE_PENDING · {moderationResult.processed} PROCESSED
          </div>
          <table className="ss-mono" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ opacity: 0.7, textAlign: 'left' }}>
                <th style={{ padding: 6 }}>Review</th>
                <th style={{ padding: 6 }}>Product</th>
                <th style={{ padding: 6 }}>Decision</th>
                <th style={{ padding: 6 }}>Notes</th>
              </tr>
            </thead>
            <tbody>
              {(moderationResult.decisions || []).map(d => (
                <tr key={d.review_id} style={{ borderTop: '1px solid var(--rule)' }}>
                  <td style={{ padding: 6 }}>#{d.review_id}</td>
                  <td style={{ padding: 6 }}>{d.product_id}</td>
                  <td style={{ padding: 6, color: d.applied_decision === 'approve' ? 'var(--kelp)' : 'var(--rust)' }}>
                    {d.applied_decision}
                  </td>
                  <td style={{ padding: 6, opacity: 0.7 }}>{d.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.section>
      )}
    </motion.div>
  );
}

function validModerationBatch(batch, remaining, requested) {
  if (!batch || typeof batch !== 'object' || Array.isArray(batch)) return null;
  if (typeof batch.requested !== 'number' || !Number.isInteger(batch.requested)
    || batch.requested <= 0 || batch.requested !== requested
    || typeof batch.considered !== 'number' || !Number.isInteger(batch.considered)
    || batch.considered < 0 || batch.considered > remaining || batch.considered > batch.requested
    || typeof batch.complete !== 'boolean' || typeof batch.continuationRequired !== 'boolean'
    || (batch.continuationRequired && (!batch.complete || batch.considered <= 0
      || batch.considered >= batch.requested))) return null;
  return batch;
}

function moderationSuccessMessage({ processed, considered }) {
  const count = `Moderated ${processed} review(s) in this run.`;
  return considered >= 100
    ? `${count} This run reached its 100-review limit; pending reviews may remain.`
    : count;
}

function RejectDialog({ review, reason, setReason, onCancel, onConfirm, reduced, busy }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onCancel(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onCancel]);
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      style={{
        position: 'fixed', inset: 0, zIndex: 300,
        background: 'rgba(11, 13, 16, 0.55)',
        display: 'grid', placeItems: 'center', padding: 24,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onCancel(); }}
      role="dialog" aria-modal="true"
    >
      <motion.div
        initial={reduced ? { opacity: 0 } : { scale: 0.96, opacity: 0 }}
        animate={reduced ? { opacity: 1 } : { scale: 1, opacity: 1 }}
        exit={reduced ? { opacity: 0 } : { scale: 0.96, opacity: 0 }}
        transition={{ duration: reduced ? 0 : 0.22, ease: [0.34, 1.56, 0.64, 1] }}
        style={{
          background: 'var(--paper)', color: 'var(--ink)',
          border: '1px solid var(--rule)', padding: 24, width: '100%', maxWidth: 480,
          boxShadow: '0 16px 48px rgba(0,0,0,0.28)',
        }}
      >
        <div className="ss-card__meta">REJECT REVIEW #{review.id}</div>
        <h2 className="ss-display" style={{ fontSize: 22, margin: '4px 0 12px 0' }}>Reason?</h2>
        <textarea
          rows={4} autoFocus
          placeholder="Spam · off-topic · abusive · PI attempt · other"
          value={reason} onChange={(e) => setReason(e.target.value)}
          style={{ ...inputStyle, fontFamily: 'var(--body)', fontSize: 14, minHeight: 100 }}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 16 }}>
          <button className="ss-btn ss-btn--ghost" disabled={busy} onClick={onCancel}>Cancel</button>
          <button className="ss-btn ss-btn--danger" disabled={busy} onClick={onConfirm}>{busy ? 'Rejecting…' : 'Reject'}</button>
        </div>
      </motion.div>
    </motion.div>
  );
}

function StarRow({ rating }) {
  const stars = Array.from({ length: 5 }, (_, i) => i < rating);
  return (
    <span style={{ display: 'inline-flex', gap: 2 }} aria-label={`${rating} of 5`}>
      {stars.map((filled, i) => (
        <Star key={i} size={14}
              fill={filled ? 'var(--amber)' : 'transparent'}
              stroke={filled ? 'var(--amber)' : 'var(--rule)'} />
      ))}
    </span>
  );
}

function isSuspicious(body) {
  const s = String(body || '');
  return /SYSTEM\s*:\s*(approve|reject|ignore|forward)/i.test(s) || /<script[^>]*>/i.test(s);
}

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function formatDate(s) {
  if (!s) return '';
  try {
    const d = new Date(s);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return String(s); }
}

const inputStyle = {
  width: '100%', padding: '10px 12px',
  background: 'transparent', color: 'var(--ink)',
  border: '1px solid var(--rule)', fontFamily: 'var(--body)', fontSize: 14,
  outline: 'none',
};
const selectStyle = { ...inputStyle, appearance: 'auto', minHeight: 40 };

async function readResponse(responsePromise, fallback) {
  const response = await responsePromise;
  let body;
  try { body = await response.json(); } catch { body = null; }
  if (!response.ok) {
    const detail = body && (body.error || body.message);
    const error = new Error(boundedText(detail) || `${fallback} (HTTP ${response.status})`);
    error.name = 'RequestError';
    throw error;
  }
  return body && typeof body === 'object' ? body : {};
}

function boundedMessage(error, fallback) {
  return boundedText(error?.message) || fallback;
}

function actionNotAppliedMessage(result, id, action) {
  const detail = boundedText(result?.error || result?.message);
  if (detail) return detail;
  if (result?.ok === false) {
    return `Review #${id} was not ${action} because it is no longer pending.`;
  }
  return `The change to review #${id} could not be confirmed.`;
}

function boundedText(value) {
  const text = typeof value === 'string' ? value.trim().replace(/\s+/g, ' ') : '';
  return text.length > 240 ? `${text.slice(0, 239)}…` : text;
}
