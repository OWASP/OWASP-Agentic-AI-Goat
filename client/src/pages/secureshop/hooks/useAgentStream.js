import { useCallback, useEffect, useRef, useState } from 'react';
import {
  parseAgentFrame,
  requireAgentContentType,
  takeAgentFrame,
} from '../utils/agentStreamProtocol.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { decodeCustomerCards } from '../utils/customerCards.mjs';
import { decodeCustomerOrderPage } from '../utils/customerOrderPage.mjs';
import { decodeCatalogPage } from '../utils/catalogPage.mjs';
import { decodeCustomerTurnOperations } from '../utils/customerTurnOperations.mjs';
import { decodePracticePaymentSetup } from '../utils/practicePaymentOperation.mjs';
import { decodeAddressSetup } from '../utils/addressSetupOperation.mjs';
import { decodeRefundSetup } from '../utils/refundSetup.mjs';
import { decodeProfileProposal, profileRequestDigest } from '../utils/profileOperation.mjs';
import { decodeCustomerCouponProposal } from '../components/CustomerCouponProposalCard.jsx';
import { decodeCustomerTicketProposal } from '../components/CustomerTicketConfirmationCard.jsx';
import { readCustomerChatReference, saveCustomerChatReference,
  clearCustomerChatReference } from '../utils/customerChatReferences.mjs';
import { readCustomerChatCompletedReference, saveCustomerChatCompletedReference,
  clearCustomerChatCompletedReference, sameCustomerChatReference } from '../utils/customerChatCompletedReferences.mjs';

const MAX_CUSTOMER_MESSAGE = 8192;
const SAVED_CHAT_LABEL = 'Saved customer chat request';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CUSTOMER_CHOICE_LABEL = {
  product: 'product', cart_item: 'cart item', order: 'order',
  address: 'address', payment_method: 'practice payment method',
};
function normalizeCustomerSelection(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || typeof value.choiceId !== 'string' || !UUID.test(value.choiceId)) return null;
  const keys = Object.keys(value).sort().join(',');
  const choiceId = value.choiceId.toLowerCase();
  if (keys === 'choiceId') return { choiceId };
  if (keys === 'choiceId,intent' && value.intent === 'details') return { choiceId, intent: 'details' };
  if (keys === 'choiceId,intent' && value.intent === 'order_details') return { choiceId, intent: 'order_details' };
  if (keys === 'choiceId,intent' && ['address_checkout', 'address_edit'].includes(value.intent)) {
    return { choiceId, intent: value.intent };
  }
  if (keys === 'choiceId,intent' && value.intent === 'cart_remove') return { choiceId, intent: 'cart_remove' };
  if (keys === 'choiceId,intent,quantity' && ['cart_add', 'cart_update'].includes(value.intent)
    && Number.isInteger(value.quantity) && value.quantity >= 1 && value.quantity <= 99) {
    return { choiceId, intent: value.intent, quantity: value.quantity };
  }
  return null;
}

const exactRoleFields = (value, fields) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
function decodeAgencyRole(value) {
  if (value == null) return null;
  if (!exactRoleFields(value, ['version', 'teachingRole', 'changed']) || value.version !== 1
    || value.teachingRole !== 'admin' || typeof value.changed !== 'boolean') {
    throw Error('Saved teaching role result is invalid');
  }
  return { version: 1, teachingRole: 'admin', changed: value.changed };
}
function decodeAgencyAssessment(value) {
  if (exactRoleFields(value, ['completed', 'status', 'modelEvaluated'])
    && value.completed === false && value.modelEvaluated === false
    && ['ineligible', 'unconfirmed', 'pending'].includes(value.status)) return { ...value };
  if (exactRoleFields(value, ['completed', 'judgment', 'replayed'])
    && typeof value.completed === 'boolean' && typeof value.replayed === 'boolean'
    && exactRoleFields(value.judgment, ['evaluationId', 'verdict', 'canRetry'])
    && UUID.test(value.judgment.evaluationId || '')
    && ['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    && typeof value.judgment.canRetry === 'boolean'
    && (!value.completed || value.judgment.verdict === 'pass')) {
    return { completed: value.completed, judgment: { ...value.judgment }, replayed: value.replayed };
  }
  throw Error('Saved role assessment is invalid');
}
const roleAssessmentStatus = status => ({ completed: false, status, modelEvaluated: false });
// Original receipts remain on the server. Tool observations never establish credit.
const publicRoleObservation = value => ({ isError: value?.isError === true,
  content: [{ type: 'text', text: 'Teaching role action observed. Check the saved assessment for the outcome.' }] });

function newRequestId() {
  if (typeof globalThis.crypto?.randomUUID === 'function') return globalThis.crypto.randomUUID();
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto?.getRandomValues !== 'function') throw new Error('Secure request identity unavailable');
  globalThis.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * POST-based SSE client for the SecureShop supervisors.
 *
 * Aborting fetch/cancelling its reader stops this client's transport and state
 * updates only. It does not prove that a backend model call or tool effect was
 * cancelled; server-side generation/effect fencing remains a separate concern.
 */
export function useAgentStream({ base = '/api/secureshop', role = 'customer', defaultUserId = null,
  boundCustomerChat = false, authorityKey = null, transport = globalThis.fetch } = {}) {
  const [sessionId, setSessionId] = useState(null);
  const [turns, setTurns] = useState([]);
  const [status, setStatus] = useState('idle');
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(null);
  const [completedPage, setCompletedPage] = useState(null);
  const [canStopWatching, setCanStopWatching] = useState(false);
  const sessionRef = useRef(null);
  const activeRef = useRef(null);
  const generationRef = useRef(0);
  const mountedRef = useRef(false);
  const nextTurnRef = useRef(0);
  const attemptedRecoveryRef = useRef(null);
  const attemptedCompletedRecoveryRef = useRef(null);
  const storageFaultRef = useRef(false);
  const defaultUid = defaultUserId != null ? defaultUserId : (role === 'merchant' ? 2 : 1);
  const durableCustomer = boundCustomerChat && role === 'customer';
  const endpoint = useCallback((leaf) => `${base}/agents/${role}/${leaf}`, [base, role]);

  const isCurrent = useCallback((operation) => (
    mountedRef.current
    && generationRef.current === operation.generation
    && activeRef.current === operation
  ), []);

  const cancelActive = useCallback(() => {
    const active = activeRef.current;
    if (!active) return;
    active.controller.abort();
    try {
      const cancelled = active.reader?.cancel();
      cancelled?.catch?.(() => {});
    } catch {}
    activeRef.current = null;
  }, []);

  const stopWatching = useCallback(() => {
    const operation = activeRef.current;
    if (!durableCustomer || !operation?.watching || !operation.reference
      || !isCurrent(operation)) return false;
    operation.watching = false;
    attemptedRecoveryRef.current = operation.reference.requestId;
    cancelActive();
    setCanStopWatching(false);
    setStatus('unresolved');
    setError('Stopped watching response. The agent may still finish. Check the saved chat before continuing.');
    setTurns(previous => previous.map((turn, index) => index === operation.turnIndex
      ? { ...turn, status: 'unresolved' } : turn));
    return true;
  }, [cancelActive, durableCustomer, isCurrent]);

  useEffect(() => {
    mountedRef.current = true;
    generationRef.current += 1;
    cancelActive();
    sessionRef.current = null;
    nextTurnRef.current = 0;
    attemptedRecoveryRef.current = null;
    attemptedCompletedRecoveryRef.current = null;
    storageFaultRef.current = false;
    setSessionId(null);
    setTurns([]);
    setStatus('idle');
    setError(null);
    setCanStopWatching(false);
    let retained = null, completed = null;
    try {
      if (durableCustomer) {
        retained = readCustomerChatReference(defaultUid);
        if (!retained) completed = readCustomerChatCompletedReference(defaultUid);
      }
    }
    catch (caught) {
      storageFaultRef.current = true;
      setError(errorMessage(caught));
      setStatus('error');
    }
    setPending(retained);
    setCompletedPage(completed);
    if (retained) {
      sessionRef.current = retained.sessionId;
      setSessionId(retained.sessionId);
      nextTurnRef.current = 1;
      setTurns([{ user: SAVED_CHAT_LABEL, requestId: retained.requestId, hops: [], reply: '',
        status: 'error', startedAt: retained.startedAt }]);
      setStatus('unresolved');
    } else if (completed) {
      setStatus('recovering');
    }
    return () => {
      mountedRef.current = false;
      generationRef.current += 1;
      cancelActive();
    };
  }, [base, role, defaultUid, durableCustomer, authorityKey, transport, cancelActive]);

  const requestSession = useCallback(async (userId, operation) => {
    const response = await transport(endpoint('session'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(durableCustomer ? {} : { userId }),
      signal: operation.controller.signal,
    });
    if (!response.ok) throw new Error(`Agent session request failed (${response.status})`);
    requireAgentContentType(response, 'application/json', 'Agent session');
    const body = await response.json();
    if (typeof body?.sessionId !== 'string' || !body.sessionId.trim()) {
      throw new Error('Agent session response is missing sessionId');
    }
    if (!isCurrent(operation)) return null;
    sessionRef.current = body.sessionId;
    setSessionId(body.sessionId);
    return body.sessionId;
  }, [durableCustomer, endpoint, isCurrent, transport]);

  const readAgencyAssessment = useCallback(async (reference, operation) => {
    try {
      const response = await transport(endpoint(`sessions/${encodeURIComponent(reference.sessionId)}/requests/${encodeURIComponent(reference.requestId)}/agency-role/assessment`), {
        method: 'GET', headers: { accept: 'application/json' }, signal: operation.controller.signal,
      });
      if (!response.ok) throw Error('Saved role assessment unavailable');
      requireAgentContentType(response, 'application/json', 'Saved role assessment');
      const result = decodeAgencyAssessment(await response.json());
      return isCurrent(operation) ? result : null;
    } catch {
      return isCurrent(operation) ? roleAssessmentStatus('unavailable') : null;
    }
  }, [endpoint, isCurrent, transport]);

  const readSavedTurn = useCallback(async (reference, operation) => {
    const response = await transport(endpoint(`operations/${encodeURIComponent(reference.sessionId)}/${encodeURIComponent(reference.requestId)}`), {
      method: 'GET', headers: { accept: 'application/json' }, signal: operation.controller.signal,
    });
    if (!response.ok) {
      const error = new Error(`Saved chat lookup failed (${response.status})`);
      error.status = response.status;
      throw error;
    }
    requireAgentContentType(response, 'application/json', 'Saved chat');
    const result = await response.json();
    if (!isCurrent(operation)) return null;
    if (result?.sessionId !== reference.sessionId || result?.requestId !== reference.requestId) {
      throw new Error('Saved chat identity mismatch');
    }
    const operations = decodeCustomerTurnOperations(result.operations);
    if (result.status === 'unconfirmed') return { status: 'unconfirmed', operations };
    const modeCapability = trustedTurnMode(result.modeCapability);
    if (result.status !== 'completed' || result.replayed !== true || !modeCapability
      || typeof result.text !== 'string' || !Array.isArray(result.hops)
      || result.hops.length > 16 || typeof result.stopReason !== 'string') {
      throw new Error('Saved chat response is invalid');
    }
    const hops = result.hops.map((hop, index) => {
      if (!hop || typeof hop !== 'object' || typeof hop.tool !== 'string')
        throw new Error('Saved chat trace is invalid');
      return { ...hop, ...(hop.tool === 'user-management.set_role' ? { result: publicRoleObservation(hop.result) } : {}),
        id: `${reference.requestId}:${index}`, status: hop.error ? 'error' : 'ok', modeCapability };
    });
    const paymentSetup = decodePracticePaymentSetup(
      Object.hasOwn(result, 'paymentSetup') ? result.paymentSetup : null);
    const addressSetup = decodeAddressSetup(
      Object.hasOwn(result, 'addressSetup') ? result.addressSetup : null);
    const refundSetup = decodeRefundSetup(
      Object.hasOwn(result, 'refundSetup') ? result.refundSetup : null);
    if (refundSetup && result.stopReason !== 'end_turn') throw Error('Saved refund review is invalid.');
    const profileProposal = decodeProfileProposal(
      Object.hasOwn(result, 'profileProposal') ? result.profileProposal : null);
    if (profileProposal && (result.stopReason !== 'end_turn'
      || await profileRequestDigest(profileProposal.proposalId,
        profileProposal.expectedSnapshotSha256, profileProposal.after) !== profileProposal.requestSha256)) {
      throw Error('Saved profile review is invalid.');
    }
    const couponProposal = decodeCustomerCouponProposal(
      Object.hasOwn(result, 'couponProposal') ? result.couponProposal : null);
    if (couponProposal && result.stopReason !== 'end_turn') throw Error('Saved coupon proposal is invalid.');
    const ticketProposal = decodeCustomerTicketProposal(
      Object.hasOwn(result, 'ticketProposal') ? result.ticketProposal : null);
    if (ticketProposal && result.stopReason !== 'end_turn') throw Error('Saved ticket proposal is invalid.');
    const cards = decodeCustomerCards(result.cards) || [];
    const orderPage = decodeCustomerOrderPage(result.orderPage, cards);
    if (orderPage && result.stopReason !== 'end_turn') throw Error('Saved order page is invalid');
    const catalogPage = decodeCatalogPage(result.catalogPage ?? null, 12);
    if (catalogPage && result.stopReason !== 'end_turn') throw Error('Saved catalog page is invalid');
    const agencyRole = decodeAgencyRole(result.agencyRole);
    const agencyAssessment = agencyRole ? await readAgencyAssessment(reference, operation) : null;
    if (!isCurrent(operation)) return null;
    return { status: 'completed', text: result.text, stopReason: result.stopReason,
      agencyRole, agencyAssessment,
      hops, cards, orderPage, catalogPage, operations,
      paymentSetup, addressSetup, refundSetup, profileProposal, couponProposal, ticketProposal, modeCapability };
  }, [endpoint, isCurrent, readAgencyAssessment, transport]);

  const projectSavedTurn = useCallback((reference, result) => {
    const failed = ['error', 'cancelled'].includes(result.stopReason);
    setTurns(previous => {
      const turn = { user: previous.find(row => row.requestId === reference.requestId)?.user || SAVED_CHAT_LABEL,
        sessionId: reference.sessionId, requestId: reference.requestId, hops: result.hops, cards: result.cards,
        operations: result.operations, orderPage: result.orderPage, catalogPage: result.catalogPage,
        paymentSetup: result.paymentSetup,
        addressSetup: result.addressSetup, refundSetup: result.refundSetup,
        profileProposal: result.profileProposal, couponProposal: result.couponProposal,
        ticketProposal: result.ticketProposal, agencyRole: result.agencyRole,
        agencyAssessment: result.agencyAssessment,
        reply: result.text, stopReason: result.stopReason,
        modeCapability: result.modeCapability, status: failed ? 'error' : 'done',
        startedAt: reference.startedAt, finishedAt: Date.now() };
      const index = previous.findIndex(row => row.requestId === reference.requestId);
      if (index < 0) return [...previous, turn];
      const copy = [...previous]; copy[index] = turn; return copy;
    });
    return failed;
  }, []);

  const createSession = useCallback(async (userId = defaultUid) => {
    if (!mountedRef.current) throw new Error('Agent stream is not active');
    if (activeRef.current) throw new Error('Agent request already in progress');
    if (durableCustomer && (storageFaultRef.current || pending || completedPage
      || readCustomerChatReference(defaultUid))) {
      throw new Error('Check the saved chat before starting another');
    }
    const operation = {
      generation: generationRef.current,
      controller: new AbortController(),
      reader: null,
      turnIndex: null,
    };
    activeRef.current = operation;
    if (isCurrent(operation)) {
      setError(null);
      setStatus('thinking');
    }
    try {
      const created = await requestSession(userId, operation);
      if (isCurrent(operation)) setStatus('idle');
      return created;
    } catch (caught) {
      if (isCurrent(operation)) {
        setError(errorMessage(caught));
        setStatus('error');
      }
      throw caught;
    } finally {
      if (activeRef.current === operation) activeRef.current = null;
    }
  }, [completedPage, defaultUid, durableCustomer, isCurrent, pending, requestSession]);

  const send = useCallback(async (message, selection = null, catalogContinuation = null) => {
    if (activeRef.current) return false;
    if (durableCustomer) {
      try {
        if (storageFaultRef.current || pending || completedPage || readCustomerChatReference(defaultUid)) return false;
      } catch (caught) {
        storageFaultRef.current = true;
        setError(errorMessage(caught)); setStatus('error'); return false;
      }
    }
    if (durableCustomer && (typeof message !== 'string' || !message.trim()
      || new TextEncoder().encode(message).byteLength > MAX_CUSTOMER_MESSAGE)) {
      setError('Enter a message of at most 8192 bytes');
      setStatus('error');
      return false;
    }
    const selectedIntent = selection === null ? null : normalizeCustomerSelection(selection);
    if (selection !== null && (!durableCustomer || !selectedIntent)) {
      setError('Invalid customer choice');
      setStatus('error');
      return false;
    }
    if (catalogContinuation !== null) {
      const latest = turns.at(-1);
      if (!durableCustomer || selection !== null || message !== 'Show more products'
        || !catalogContinuation || Object.getPrototypeOf(catalogContinuation) !== Object.prototype
        || Object.keys(catalogContinuation).sort().join(',') !== 'intent,sourceRequestId'
        || catalogContinuation.intent !== 'catalog_next'
        || typeof catalogContinuation.sourceRequestId !== 'string'
        || !UUID.test(catalogContinuation.sourceRequestId)
        || catalogContinuation.sourceRequestId !== catalogContinuation.sourceRequestId.toLowerCase()
        || latest?.status !== 'done' || latest.stopReason !== 'end_turn'
        || !trustedTurnMode(latest.modeCapability) || latest.sessionId !== sessionRef.current
        || latest.requestId !== catalogContinuation.sourceRequestId
        || latest.catalogPage?.hasMore !== true) return false;
    }
    let selectedCard = null;
    if (selection !== null) {
      const latest = turns.at(-1);
      selectedCard = latest?.status === 'done' && latest.stopReason === 'end_turn'
        && trustedTurnMode(latest.modeCapability)
        ? latest.cards?.find(card => card.choiceId === selectedIntent.choiceId) : null;
      const expectedKind = selectedIntent.intent === 'cart_update' || selectedIntent.intent === 'cart_remove'
        ? 'cart_item' : selectedIntent.intent === 'order_details' ? 'order'
          : selectedIntent.intent === 'address_checkout' || selectedIntent.intent === 'address_edit' ? 'address'
          : selectedIntent.intent ? 'product' : null;
      if (!selectedCard || (expectedKind && selectedCard.kind !== expectedKind)) {
        setError('Invalid customer choice');
        setStatus('error');
        return false;
      }
    }
    const operation = {
      generation: generationRef.current,
      controller: new AbortController(),
      reader: null,
      turnIndex: nextTurnRef.current,
    };
    nextTurnRef.current += 1;
    activeRef.current = operation;
    if (!isCurrent(operation)) {
      activeRef.current = null;
      return false;
    }

    setError(null);
    setStatus('thinking');
    setTurns((previous) => [
      ...previous,
      { user: selectedCard
        ? selectedIntent.intent === 'details'
          ? `View details: ${selectedCard.title}`
          : selectedIntent.intent === 'order_details'
            ? `View details: ${selectedCard.title}`
          : selectedIntent.intent === 'address_checkout'
            ? `Use for checkout: ${selectedCard.title}`
          : selectedIntent.intent === 'address_edit'
            ? `Edit address: ${selectedCard.title}`
          : selectedIntent.intent === 'cart_add'
            ? `Add ${selectedIntent.quantity} to cart: ${selectedCard.title}`
            : selectedIntent.intent === 'cart_update'
              ? `Update quantity to ${selectedIntent.quantity}: ${selectedCard.title}`
              : selectedIntent.intent === 'cart_remove'
                ? `Remove from cart: ${selectedCard.title}`
            : `Selected ${CUSTOMER_CHOICE_LABEL[selectedCard.kind]}: ${selectedCard.title}` : message,
      hops: [], reply: '', status: 'in-flight', startedAt: Date.now() },
    ]);

    try {
      const sid = sessionRef.current || await requestSession(defaultUid, operation);
      if (!sid || !isCurrent(operation)) return false;
      const requestId = durableCustomer ? newRequestId() : null;
      let reference = null;
      if (requestId) {
        reference = { shopUserId: defaultUid, sessionId: sid, requestId, startedAt: Date.now() };
        setPending(reference);
        setTurns(previous => previous.map((turn, index) => index === operation.turnIndex
          ? { ...turn, sessionId: sid, requestId } : turn));
        await saveCustomerChatReference(reference);
        if (!isCurrent(operation)) return false;
        operation.reference = reference;
        operation.watching = true;
        setCanStopWatching(true);
      }
      const response = await transport(endpoint('chat'), {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
        body: JSON.stringify({ sessionId: sid, message, ...(requestId ? { requestId } : {}),
          ...(selectedIntent ? { selection: selectedIntent } : {}),
          ...(catalogContinuation ? { catalogContinuation } : {}) }),
        signal: operation.controller.signal,
      });
      if (!response.ok) throw new Error(`Agent chat request failed (${response.status})`);
      requireAgentContentType(response, 'text/event-stream', 'Agent chat');
      if (!response.body || typeof response.body.getReader !== 'function') {
        throw new Error('No response body from server');
      }

      const reader = response.body.getReader();
      operation.reader = reader;
      if (!isCurrent(operation)) {
        await cancelReader(reader);
        return false;
      }
      const decoder = new TextDecoder();
      let buffer = '';
      let terminal = null;

      readLoop: while (true) {
        const part = await reader.read();
        if (!isCurrent(operation)) return false;
        if (part.done) {
          buffer += decoder.decode();
          break;
        }
        buffer += decoder.decode(part.value, { stream: true });
        while (true) {
          const extracted = takeAgentFrame(buffer);
          if (!extracted) break;
          buffer = extracted.rest;
          const event = parseAgentFrame(extracted.frame);
          if (!event) continue;
          if (requestId && (event.payload.requestId !== requestId
            || event.payload.sessionId !== sid)) {
            throw new Error('Agent stream identity mismatch');
          }
          if (requestId && event.name === 'done' && !trustedTurnMode(event.payload.modeCapability)) {
            throw new Error('Agent stream is missing trusted mode');
          }
          const cards = requestId && ['tool_result', 'assistant_message', 'done'].includes(event.name)
            ? decodeCustomerCards(event.payload.cards) : undefined;
          _consume(event.name, event.payload, setTurns, operation.turnIndex, cards);
          if (event.name === 'done') {
            operation.watching = false;
            setCanStopWatching(false);
            const failed = event.payload.stopReason === 'error' || event.payload.stopReason === 'cancelled';
            terminal = failed ? 'error' : 'done';
            if (reference) {
              const saved = await readSavedTurn(reference, operation);
              if (!saved || !isCurrent(operation)) return false;
              if (saved.status === 'unconfirmed') {
                setTurns(previous => previous.map((turn, index) => index === operation.turnIndex
                  ? { ...turn, operations: saved.operations, status: 'unresolved' } : turn));
                setError('The saved chat is not confirmed yet. Check this request again before sending another.');
                setStatus('unresolved');
                terminal = 'unresolved';
                break readLoop;
              }
              await saveCustomerChatCompletedReference(reference, () => isCurrent(operation));
              if (!isCurrent(operation)) return false;
              terminal = projectSavedTurn(reference, saved) ? 'error' : 'done';
              await clearCustomerChatReference(reference);
              if (!isCurrent(operation)) return false;
              setPending(null);
            }
            if (failed) {
              setError(event.payload.stopReason === 'cancelled'
                ? 'Agent request was cancelled'
                : 'Agent stopped with an error');
              setStatus('error');
            } else {
              setStatus('idle');
            }
            break readLoop;
          }
          if (event.name === 'error') {
            terminal = 'error';
            setError(event.payload.message || 'error');
            setStatus('error');
            // A later done frame or exact GET can still establish the saved outcome.
          }
        }
      }

      if (terminal) {
        await cancelReader(reader);
        return terminal === 'done';
      }
      throw new Error('Agent stream ended before a terminal event');
    } catch (caught) {
      if (isCurrent(operation)) {
        setError(errorMessage(caught));
        let unresolved = false;
        if (durableCustomer) {
          try { unresolved = !!(pending || readCustomerChatReference(defaultUid)); }
          catch { unresolved = true; storageFaultRef.current = true; }
        }
        setStatus(unresolved ? 'unresolved' : 'error');
        markTurnError(setTurns, operation.turnIndex);
        await cancelReader(operation.reader);
      }
      return false;
    } finally {
      if (activeRef.current === operation) {
        activeRef.current = null;
        setCanStopWatching(false);
      }
    }
  }, [completedPage, defaultUid, durableCustomer, endpoint, isCurrent, pending, projectSavedTurn,
    readSavedTurn, requestSession, transport, turns]);

  const recover = useCallback(async () => {
    if (!durableCustomer || activeRef.current || !mountedRef.current) return false;
    let reference, completedOnly = false;
    try {
      reference = readCustomerChatReference(defaultUid);
      if (!reference && completedPage) {
        reference = readCustomerChatCompletedReference(defaultUid);
        if (!sameCustomerChatReference(reference, completedPage)) {
          setCompletedPage(null); setStatus('idle'); return false;
        }
        completedOnly = true;
      }
    }
    catch (caught) { storageFaultRef.current = true; setStatus('unresolved'); setError(errorMessage(caught)); return false; }
    if (!reference) return false;
    const operation = { generation: generationRef.current, controller: new AbortController(), reader: null };
    activeRef.current = operation;
    setStatus('recovering');
    setError(null);
    try {
      const result = await readSavedTurn(reference, operation);
      if (!result || !isCurrent(operation)) return false;
      if (completedOnly) {
        const newerPending = readCustomerChatReference(defaultUid);
        const currentPage = readCustomerChatCompletedReference(defaultUid);
        if (newerPending) {
          setCompletedPage(null);
          setPending(newerPending);
          sessionRef.current = newerPending.sessionId;
          setSessionId(newerPending.sessionId);
          nextTurnRef.current = 1;
          setTurns([{ user: SAVED_CHAT_LABEL, requestId: newerPending.requestId, hops: [], reply: '',
            status: 'error', startedAt: newerPending.startedAt }]);
          setStatus('unresolved');
          setError('A newer saved chat request needs checking.');
          return false;
        }
        if (!sameCustomerChatReference(currentPage, reference)) {
          setCompletedPage(currentPage);
          setStatus(currentPage ? 'unresolved' : 'idle');
          setError(currentPage ? 'Saved chat page changed. Check the current page.' : null);
          return false;
        }
      }
      if (result.status === 'unconfirmed') {
        if (completedOnly) {
          await clearCustomerChatCompletedReference(reference, () => isCurrent(operation));
          if (!isCurrent(operation)) return false;
          setCompletedPage(null); setStatus('idle');
          setError('Saved chat page is no longer available. Start a new chat.');
          return false;
        }
        setTurns(previous => previous.map(turn => turn.requestId === reference.requestId
          ? { ...turn, operations: result.operations } : turn));
        setStatus('unresolved');
        setError(result.operations.length
          ? 'A saved action exists, but the chat result is not confirmed. Check this request again; no action was retried.'
          : 'No confirmed saved result yet. Check this chat again later.');
        return false;
      }
      if (!completedOnly) {
        await saveCustomerChatCompletedReference(reference, () => isCurrent(operation));
        if (!isCurrent(operation)) return false;
      }
      const failed = projectSavedTurn(reference, result);
      sessionRef.current = reference.sessionId;
      setSessionId(reference.sessionId);
      if (completedOnly) nextTurnRef.current = Math.max(nextTurnRef.current, 1);
      if (!completedOnly) await clearCustomerChatReference(reference);
      if (!isCurrent(operation)) return false;
      if (completedOnly) setCompletedPage(null);
      else setPending(null);
      setStatus(failed ? 'error' : 'idle');
      if (failed) setError('Agent stopped with an error');
      return true;
    } catch (caught) {
      if (isCurrent(operation)) {
        if (completedOnly && [401, 403, 404].includes(caught?.status)) {
          let newerPending = null, currentPage = null;
          try {
            newerPending = readCustomerChatReference(defaultUid);
            currentPage = readCustomerChatCompletedReference(defaultUid);
            if (!newerPending && sameCustomerChatReference(currentPage, reference)) {
              await clearCustomerChatCompletedReference(reference, () => isCurrent(operation));
            }
            newerPending = readCustomerChatReference(defaultUid);
            currentPage = readCustomerChatCompletedReference(defaultUid);
          } catch (storageError) {
            if (isCurrent(operation)) { setStatus('unresolved'); setError(errorMessage(storageError)); }
            return false;
          }
          if (isCurrent(operation)) {
            setCompletedPage(newerPending ? null : currentPage);
            setPending(newerPending);
            if (newerPending) {
              sessionRef.current = newerPending.sessionId;
              setSessionId(newerPending.sessionId);
              nextTurnRef.current = 1;
              setTurns([{ user: SAVED_CHAT_LABEL, requestId: newerPending.requestId, hops: [], reply: '',
                status: 'error', startedAt: newerPending.startedAt }]);
            }
            setStatus(newerPending || currentPage ? 'unresolved' : 'idle');
            setError(newerPending ? 'A newer saved chat request needs checking.'
              : currentPage ? 'Saved chat page changed. Check the current page.'
                : 'Saved chat page is no longer available. Start a new chat.');
          }
        } else {
          setStatus('unresolved'); setError(errorMessage(caught));
        }
      }
      return false;
    } finally {
      if (activeRef.current === operation) activeRef.current = null;
    }
  }, [completedPage, defaultUid, durableCustomer, isCurrent, projectSavedTurn, readSavedTurn]);

  const refreshAgencyAssessment = useCallback(async (sessionId, requestId) => {
    if (!durableCustomer || activeRef.current || !mountedRef.current || pending || completedPage
      || !turns.some(turn => turn.sessionId === sessionId && turn.requestId === requestId && turn.agencyRole)) return false;
    const operation = { generation: generationRef.current, controller: new AbortController(), reader: null };
    activeRef.current = operation;
    const update = assessment => setTurns(previous => previous.map(turn => turn.sessionId === sessionId
      && turn.requestId === requestId ? { ...turn, agencyAssessment: assessment } : turn));
    setStatus('recovering');
    update(roleAssessmentStatus('checking'));
    try {
      const outcome = await readAgencyAssessment({ sessionId, requestId }, operation);
      if (!outcome || !isCurrent(operation)) return false;
      update(outcome);
      return outcome.status !== 'unavailable';
    } finally {
      if (isCurrent(operation)) setStatus('idle');
      if (activeRef.current === operation) activeRef.current = null;
    }
  }, [completedPage, durableCustomer, isCurrent, pending, readAgencyAssessment, turns]);

  useEffect(() => {
    if (!pending || activeRef.current || attemptedRecoveryRef.current === pending.requestId) return;
    attemptedRecoveryRef.current = pending.requestId;
    void recover();
  }, [pending, recover, status]);

  useEffect(() => {
    if (pending || !completedPage || activeRef.current
      || attemptedCompletedRecoveryRef.current === completedPage.requestId) return;
    attemptedCompletedRecoveryRef.current = completedPage.requestId;
    void recover();
  }, [completedPage, pending, recover, status]);

  return { sessionId, turns, status, error, pending,
    completedPagePending: !!completedPage, canStopWatching,
    send, createSession, recover, stopWatching, refreshAgencyAssessment };
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

async function cancelReader(reader) {
  if (!reader || typeof reader.cancel !== 'function') return;
  try { await reader.cancel(); } catch {}
}

function markTurnError(setTurns, turnIndex) {
  setTurns((previous) => {
    if (!previous[turnIndex]) return previous;
    const copy = [...previous];
    copy[turnIndex] = { ...copy[turnIndex], status: 'error', finishedAt: Date.now() };
    return copy;
  });
}

function _consume(name, payload, setTurns, turnIndex, cards) {
  setTurns((previous) => {
    if (!previous[turnIndex]) return previous;
    const copy = [...previous];
    const current = { ...copy[turnIndex] };
    const modeCapability = trustedTurnMode(payload.modeCapability);
    if (cards !== undefined) current.cards = cards;
    if (name === 'tool_call') {
      current.hops = [...current.hops, {
        id: payload.id,
        tool: payload.tool,
        params: payload.params,
        step: payload.step,
        status: 'in-flight',
        policyViolation: payload.policyViolation || null,
        modeCapability,
      }];
    } else if (name === 'tool_result') {
      current.hops = current.hops.map((hop) => hop.id === payload.id ? ({
        ...hop,
        result: hop.tool === 'user-management.set_role' ? publicRoleObservation(payload.result) : payload.result,
        latencyMs: payload.latencyMs,
        status: 'ok',
        policyViolation: payload.policyViolation != null ? payload.policyViolation : hop.policyViolation,
        modeCapability: modeCapability || hop.modeCapability,
      }) : hop);
    } else if (name === 'assistant_message') {
      current.reply = payload.text || '';
      current.stopReason = payload.stopReason;
      if (modeCapability) current.modeCapability = modeCapability;
    } else if (name === 'done') {
      current.status = payload.stopReason === 'error' || payload.stopReason === 'cancelled' ? 'error' : 'done';
      current.stopReason = payload.stopReason != null ? payload.stopReason : current.stopReason;
      current.finishedAt = Date.now();
      if (modeCapability) current.modeCapability = modeCapability;
    } else if (name === 'error') {
      current.status = 'error';
      current.finishedAt = Date.now();
    }
    if (modeCapability && !current.modeCapability) current.modeCapability = modeCapability;
    copy[turnIndex] = current;
    return copy;
  });
}
