import { useCallback, useEffect, useRef, useState } from 'react';
import { decodeCustomerTicketProposal, decodeSavedTicketResult } from '../components/CustomerTicketConfirmationCard.jsx';
import { ticketTextDigest } from '../utils/adminTicketPresentation.mjs';

const BASE = '/api/secureshop/agents/customer';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const unavailable = () => { throw Error('Saved ticket confirmation unavailable'); };

async function json(response) {
  if (!response.ok || !/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) unavailable();
  return response.json();
}

export function decodeSavedCustomerTicket(value, reference) {
  if (exact(value, ['status']) && value.status === 'unconfirmed')
    return { status: 'unconfirmed', result: null };
  if (!exact(value, ['status', 'result']) || value.status !== 'completed') unavailable();
  const result = decodeSavedTicketResult(value.result);
  if (result.proposalId !== reference.proposalId || result.operationId !== reference.proposalId
    || result.requestId !== reference.requestId) unavailable();
  return { status: 'completed', result };
}

function originalMatches(saved, source) {
  if (saved?.status !== 'completed' || saved?.replayed !== true
    || saved?.stopReason !== 'end_turn' || saved?.sessionId !== source.sessionId
    || saved?.requestId !== source.requestId) return false;
  let proposal;
  try { proposal = decodeCustomerTicketProposal(saved.ticketProposal); } catch { return false; }
  return !!proposal && ['version', 'kind', 'status', 'proposalId', 'subject', 'body',
    'subjectSha256', 'bodySha256'].every(key => proposal[key] === source.proposal[key]);
}

export function useCustomerTicketConfirmation({ shopUserId, authorityKey, transport,
  referenceStore, sourceSessionId, sourceRequestId, proposal } = {}) {
  const [reference, setReference] = useState(null);
  const [status, setStatus] = useState('idle');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const epochRef = useRef(0), activeRef = useRef(null), mountedRef = useRef(false);
  const referenceRef = useRef(null), completedRef = useRef(false), sourceRef = useRef(null);
  sourceRef.current = { sessionId: sourceSessionId, requestId: sourceRequestId, proposal };
  const current = useCallback((epoch, controller) => mountedRef.current
    && epochRef.current === epoch && activeRef.current === controller
    && !controller.signal.aborted, []);

  const readSaved = useCallback(async (saved, controller, epoch) => {
    const response = await transport(`${BASE}/tickets/confirm/${saved.sessionId}/${saved.requestId}/${saved.proposalId}`, {
      method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
    });
    const value = decodeSavedCustomerTicket(await json(response), saved);
    if (!current(epoch, controller)) return null;
    setStatus(value.status); setResult(value.result);
    completedRef.current = value.status === 'completed';
    return value;
  }, [transport, current]);

  useEffect(() => {
    mountedRef.current = true; const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    referenceRef.current = null; completedRef.current = false;
    setReference(null); setStatus('idle'); setResult(null); setBusy(false); setError(null);
    try {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1
        || typeof referenceStore?.read !== 'function' || typeof referenceStore?.save !== 'function'
        || typeof referenceStore?.clear !== 'function' || typeof transport !== 'function') unavailable();
      const saved = referenceStore.read(shopUserId);
      if (saved) {
        referenceRef.current = saved; setReference(saved); setStatus('unconfirmed');
        const controller = new AbortController(); activeRef.current = controller; setBusy(true);
        void readSaved(saved, controller, epoch).catch(() => {
          if (current(epoch, controller)) setError('Check the saved ticket again.');
        }).finally(() => { if (current(epoch, controller)) setBusy(false);
          if (activeRef.current === controller) activeRef.current = null; });
      }
    } catch { setStatus('error'); setError('Saved ticket storage unavailable.'); }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [shopUserId, authorityKey, transport, referenceStore, readSaved, current]);

  const check = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || !referenceRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try { return !!await readSaved(referenceRef.current, controller, epoch); }
    catch { if (current(epoch, controller)) setError('Saved ticket result unavailable.'); return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [readSaved, current]);

  const confirm = useCallback(async () => {
    if (!mountedRef.current || activeRef.current || referenceRef.current) return false;
    const source = sourceRef.current;
    let trusted;
    try { trusted = decodeCustomerTicketProposal(source.proposal); }
    catch { setError('Ticket proposal unavailable.'); return false; }
    if (!trusted || ![source.sessionId, source.requestId].every(id => typeof id === 'string' && UUID.test(id)))
      return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    const unchanged = () => current(epoch, controller)
      && sourceRef.current.sessionId === source.sessionId
      && sourceRef.current.requestId === source.requestId
      && sourceRef.current.proposal?.proposalId === trusted.proposalId
      && sourceRef.current.proposal?.subject === trusted.subject
      && sourceRef.current.proposal?.body === trusted.body
      && sourceRef.current.proposal?.subjectSha256 === trusted.subjectSha256
      && sourceRef.current.proposal?.bodySha256 === trusted.bodySha256;
    try {
      if (await ticketTextDigest(trusted.subject) !== trusted.subjectSha256
        || await ticketTextDigest(trusted.body) !== trusted.bodySha256 || !unchanged()) unavailable();
      const response = await transport(`${BASE}/operations/${source.sessionId}/${source.requestId}`, {
        method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal,
      });
      if (!originalMatches(await json(response), { ...source, proposal: trusted }) || !unchanged()) unavailable();
      const saved = await referenceStore.save({ shopUserId, sessionId: source.sessionId,
        requestId: source.requestId, proposalId: trusted.proposalId, startedAt: Date.now() }, unchanged);
      if (!current(epoch, controller)) return false;
      referenceRef.current = saved; setReference(saved); setStatus('unconfirmed');
      // The acknowledged reference precedes exactly one physical confirmation.
      // A lost POST response is resolved only by the protected saved GET.
      try {
        await transport(`${BASE}/tickets/confirm`, { method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId,
            proposalId: saved.proposalId }), signal: controller.signal });
      } catch { /* Read the saved operation instead of repeating the effect. */ }
      if (!current(epoch, controller)) return false;
      return (await readSaved(saved, controller, epoch))?.status === 'completed';
    } catch {
      if (current(epoch, controller)) {
        try {
          const retained = referenceStore.read(shopUserId);
          if (retained) { referenceRef.current = retained; setReference(retained); setStatus('unconfirmed'); }
        } catch { /* Missing storage proof never authorizes a second POST. */ }
        setError(referenceRef.current ? 'Ticket outcome unresolved. Check the saved operation.'
          : 'Ticket confirmation unavailable.');
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
      setReference(null); setStatus('idle'); setResult(null); setError(null); return true;
    } catch { if (current(epoch, controller)) setError('Saved ticket could not be cleared.'); return false; }
    finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [referenceStore, current]);

  return { reference, status, result, busy, error, confirm, check, clearCompleted };
}
