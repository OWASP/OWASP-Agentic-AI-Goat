import { useCallback, useEffect, useRef, useState } from 'react';
import { couponDigest } from '../utils/couponReference.mjs';
import { decodeCustomerCouponProposal, decodeSavedCouponResult } from '../components/CustomerCouponProposalCard.jsx';

const BASE = '/api/secureshop/agents/customer';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const unavailable = () => { throw Error('Saved coupon confirmation unavailable'); };

async function json(response) {
  if (!response.ok || !/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) unavailable();
  return response.json();
}

export function decodeSavedCustomerCoupon(value) {
  if (exact(value, ['status']) && value.status === 'unconfirmed')
    return { status: 'unconfirmed', result: null };
  if (!exact(value, ['status', 'result']) || value.status !== 'completed') unavailable();
  return { status: 'completed', result: decodeSavedCouponResult(value.result) };
}

export function decodeSavedCouponAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated'])
    && value.completed === false && value.modelEvaluated === false
    && ['unconfirmed', 'ineligible'].includes(value.status)) return value;
  if (!exact(value, ['completed', 'judgment', 'replayed'])
    || typeof value.completed !== 'boolean' || typeof value.replayed !== 'boolean'
    || !exact(value.judgment, ['verdict', 'evaluationId', 'canRetry'])
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    || typeof value.judgment.evaluationId !== 'string' || !UUID.test(value.judgment.evaluationId)
    || typeof value.judgment.canRetry !== 'boolean') unavailable();
  return value;
}

function originalMatches(saved, source) {
  if (saved?.status !== 'completed' || saved?.replayed !== true
    || saved?.stopReason !== 'end_turn' || saved?.sessionId !== source.sessionId
    || saved?.requestId !== source.requestId) return false;
  let proposal;
  try { proposal = decodeCustomerCouponProposal(saved.couponProposal); } catch { return false; }
  return !!proposal && ['version', 'kind', 'status', 'proposalId', 'code', 'codeSha256']
    .every(key => proposal[key] === source.proposal[key]);
}

export function useCustomerCouponConfirmation({ shopUserId, authorityKey, transport,
  referenceStore, sourceSessionId, sourceRequestId, proposal } = {}) {
  const [reference, setReference] = useState(null);
  const [status, setStatus] = useState('idle');
  const [result, setResult] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const epochRef = useRef(0), activeRef = useRef(null), mountedRef = useRef(false);
  const referenceRef = useRef(null), completedRef = useRef(false);
  const sourceRef = useRef(null);
  sourceRef.current = { sessionId: sourceSessionId, requestId: sourceRequestId, proposal };
  const current = useCallback((epoch, controller) => mountedRef.current
    && epochRef.current === epoch && activeRef.current === controller
    && !controller.signal.aborted, []);

  const readSaved = useCallback(async (saved, controller, epoch) => {
    const response = await transport(`${BASE}/coupons/confirm/${saved.sessionId}/${saved.requestId}/${saved.proposalId}`, {
      method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
    });
    const value = decodeSavedCustomerCoupon(await json(response));
    if (!current(epoch, controller)) return null;
    setStatus(value.status); setResult(value.result);
    if (value.status !== 'completed') setAssessment(null);
    completedRef.current = value.status === 'completed';
    return value;
  }, [transport, current]);

  useEffect(() => {
    mountedRef.current = true; const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    referenceRef.current = null; completedRef.current = false;
    setReference(null); setStatus('idle'); setResult(null); setAssessment(null); setBusy(false); setError(null);
    try {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1
        || typeof referenceStore?.read !== 'function' || typeof referenceStore?.save !== 'function'
        || typeof referenceStore?.clear !== 'function' || typeof transport !== 'function') unavailable();
      const saved = referenceStore.read(shopUserId);
      if (saved) {
        referenceRef.current = saved; setReference(saved); setStatus('unconfirmed');
        const controller = new AbortController(); activeRef.current = controller;
        setBusy(true);
        void readSaved(saved, controller, epoch).catch(() => {
          if (current(epoch, controller)) setError('Check the saved coupon again.');
        }).finally(() => { if (current(epoch, controller)) setBusy(false);
          if (activeRef.current === controller) activeRef.current = null; });
      }
    } catch { setStatus('error'); setError('Saved coupon storage unavailable.'); }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [shopUserId, authorityKey, transport, referenceStore, readSaved, current]);

  const check = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try { return !!await readSaved(referenceRef.current, controller, epoch); }
    catch { if (current(epoch, controller)) setError('Saved coupon result unavailable.'); return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [readSaved, current]);

  const confirm = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || referenceRef.current) return false;
    const source = sourceRef.current;
    let trusted;
    try { trusted = decodeCustomerCouponProposal(source.proposal); }
    catch { setError('Coupon proposal unavailable.'); return false; }
    if (!trusted || ![source.sessionId, source.requestId].every(id => typeof id === 'string' && UUID.test(id)))
      return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    const unchanged = () => current(epoch, controller)
      && sourceRef.current.sessionId === source.sessionId
      && sourceRef.current.requestId === source.requestId
      && sourceRef.current.proposal?.proposalId === trusted.proposalId
      && sourceRef.current.proposal?.code === trusted.code
      && sourceRef.current.proposal?.codeSha256 === trusted.codeSha256;
    try {
      if (await couponDigest(trusted.code) !== trusted.codeSha256 || !unchanged()) unavailable();
      const response = await transport(`${BASE}/operations/${source.sessionId}/${source.requestId}`, {
        method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
      });
      if (!originalMatches(await json(response), { ...source, proposal: trusted }) || !unchanged()) unavailable();
      const saved = await referenceStore.save({ shopUserId, sessionId: source.sessionId,
        requestId: source.requestId, proposalId: trusted.proposalId, startedAt: Date.now() }, unchanged);
      if (!current(epoch, controller)) return false;
      referenceRef.current = saved; setReference(saved); setStatus('unconfirmed');
      // One physical confirmation only. Any lost response resolves through the
      // exact protected saved GET; never repeat the mutation.
      try {
        await transport(`${BASE}/coupons/confirm`, { method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId,
            proposalId: saved.proposalId }), signal: controller.signal });
      } catch { /* The saved GET decides the result. */ }
      if (!current(epoch, controller)) return false;
      return (await readSaved(saved, controller, epoch))?.status === 'completed';
    } catch {
      if (current(epoch, controller)) {
        try {
          const retained = referenceStore.read(shopUserId);
          if (retained) { referenceRef.current = retained; setReference(retained); setStatus('unconfirmed'); }
        } catch { /* Missing storage proof never authorizes a second POST. */ }
        setError(referenceRef.current ? 'Coupon outcome unresolved. Check the saved operation.'
          : 'Coupon confirmation unavailable.');
      }
      return false;
    } finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [shopUserId, transport, referenceStore, readSaved, current]);

  const clearCompleted = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !completedRef.current || !referenceRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller;
    try {
      await referenceStore.clear(referenceRef.current, () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = null; completedRef.current = false;
      setReference(null); setStatus('idle'); setResult(null); setAssessment(null); setError(null); return true;
    } catch { if (current(epoch, controller)) setError('Saved coupon could not be cleared.'); return false; }
    finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [referenceStore, current]);

  const checkAssessment = useCallback(async (retry = false) => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current || !completedRef.current
      || retry && assessment?.status !== 'unconfirmed') return false;
    const saved = referenceRef.current;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const path = retry ? `${BASE}/coupons/assessment-retry`
        : `${BASE}/coupons/assessment/${saved.sessionId}/${saved.requestId}/${saved.proposalId}`;
      const response = await transport(path, retry ? { method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId,
          proposalId: saved.proposalId }), signal: controller.signal }
        : { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      const value = decodeSavedCouponAssessment(await json(response));
      if (!current(epoch, controller)) return false;
      setAssessment(value);
      return true;
    } catch {
      if (current(epoch, controller)) setError('Saved coupon assessment unavailable.');
      return false;
    } finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [assessment, transport, current]);

  return { reference, status, result, assessment, busy, error, confirm, check,
    readAssessment: () => checkAssessment(false), retryAssessment: () => checkAssessment(true),
    clearCompleted };
}
