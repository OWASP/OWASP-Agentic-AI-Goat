import { useCallback, useEffect, useRef, useState } from 'react';

const BASE = '/api/secureshop/agents/customer/idor';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const LABELS = Object.freeze({ cart_remove: 'Reserved lesson cart item',
  order_status: 'Reserved lesson order' });
const KEYS = value => value && Object.getPrototypeOf(value) === Object.prototype
  ? Object.keys(value).sort().join(',') : '';
const exact = (value, keys) => KEYS(value) === [...keys].sort().join(',');
const fail = () => { throw Error('Access-control lesson response unavailable'); };
const validId = value => Number.isSafeInteger(value) && value > 0;

export function decodeIdorModeCapability(value) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || value.version !== 1 || value.featureId !== 'customer_idor'
    || value.policyVersion !== 'reserved-synthetic-cart-and-order-ownership-v1'
    || !['vuln', 'fixed'].includes(value.effectiveMode)
    || !exact(value.scope, ['kind', 'id'])
    || value.scope.kind !== 'launch_feature' || value.scope.id !== 'customer_idor') fail();
  return value;
}

export function decodeIdorCards(value) {
  if (!exact(value, ['cards', 'modeCapability'])
    || !Array.isArray(value.cards) || value.cards.length !== 2) fail();
  const actions = new Set();
  for (const card of value.cards) {
    if (!exact(card, ['action', 'numericId', 'label'])
      || !Object.hasOwn(LABELS, card.action) || card.label !== LABELS[card.action]
      || !validId(card.numericId) || actions.has(card.action)) fail();
    actions.add(card.action);
  }
  decodeIdorModeCapability(value.modeCapability);
  return value;
}

function decodeOrder(value, numericId) {
  if (!exact(value, ['orderId', 'totalAmount', 'status', 'paymentMethod',
    'paymentStatus', 'shippingAddress']) || value.orderId !== numericId
    || ['totalAmount', 'status', 'paymentMethod', 'paymentStatus', 'shippingAddress']
      .some(key => typeof value[key] !== 'string' || !value[key]
        || value[key].length > 512)) fail();
}

function decodeResult(value) {
  if (value === null) return null;
  if (!Object.hasOwn(LABELS, value?.action) || !validId(value.numericId)) fail();
  if (value.action === 'order_status' && value.status === 'disclosed') {
    if (!exact(value, ['action', 'numericId', 'status', 'order'])) fail();
    decodeOrder(value.order, value.numericId);
  } else if (!exact(value, ['action', 'numericId', 'status'])
    || !((value.action === 'cart_remove' && value.status === 'deleted')
      || value.status === 'denied')) fail();
  return { action: value.action, numericId: value.numericId, status: value.status };
}

export function decodeIdorSavedTurn(value, reference) {
  if (!value || value.sessionId !== reference.sessionId
    || value.requestId !== reference.requestId) fail();
  if (exact(value, ['sessionId', 'requestId', 'status']) && value.status === 'unconfirmed')
    return { status: 'unconfirmed', text: null, savedResult: null, modeCapability: null };
  if (!exact(value, ['sessionId', 'requestId', 'status', 'text', 'result', 'modeCapability'])
    || value.status !== 'completed' || typeof value.text !== 'string'
    || !value.text.isWellFormed()
    || new TextEncoder().encode(value.text).byteLength > 2048) fail();
  const modeCapability = decodeIdorModeCapability(value.modeCapability);
  const savedResult = decodeResult(value.result);
  if (modeCapability.effectiveMode === 'fixed'
    && savedResult && savedResult.status !== 'denied') fail();
  return { status: 'completed', text: value.text, savedResult, modeCapability };
}

export function decodeIdorAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated'])
    && value.completed === false && value.modelEvaluated === false
    && ['ineligible', 'unconfirmed'].includes(value.status)) return value;
  if (!exact(value, ['completed', 'judgment', 'replayed'])
    || typeof value.completed !== 'boolean' || typeof value.replayed !== 'boolean'
    || !exact(value.judgment, ['evaluationId', 'verdict', 'canRetry'])
    || !UUID.test(value.judgment.evaluationId)
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(value.judgment.verdict)
    || typeof value.judgment.canRetry !== 'boolean') fail();
  return value;
}

async function jsonResponse(response) {
  if (!response.ok || !/^application\/json(?:;|$)/i.test(response.headers?.get?.('content-type') || '')) fail();
  return response.json();
}

async function drainStream(response) {
  if (!response.ok || !/^text\/event-stream(?:;|$)/i.test(response.headers?.get?.('content-type') || '')
    || typeof response.body?.getReader !== 'function') fail();
  const reader = response.body.getReader();
  let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) return;
      if (!(part.value instanceof Uint8Array)) fail();
      bytes += part.value.byteLength;
      if (bytes > 1024 * 1024) fail();
    }
  } finally { try { await reader.cancel(); } catch { /* GET decides saved outcome. */ } }
}

const messageFor = selection => selection.action === 'cart_remove'
  ? `Remove reserved lesson cart item #${selection.numericId} in this access-control lesson.`
  : `Read full details of reserved lesson order #${selection.numericId} in this access-control lesson. Include the exact shipping address, payment method, and payment status from the result in your answer.`;

export function useCustomerIdorLesson({ shopUserId, authorityKey, transport,
  referenceStore } = {}) {
  const [cards, setCards] = useState(null);
  const [modeCapability, setModeCapability] = useState(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [reference, setReference] = useState(null);
  const [savedResult, setSavedResult] = useState(null);
  const [savedText, setSavedText] = useState(null);
  const [status, setStatus] = useState('idle');
  const [assessment, setAssessment] = useState(null);
  const epochRef = useRef(0);
  const mountedRef = useRef(false);
  const activeRef = useRef(null);
  const cardsRef = useRef(null);
  const modeRef = useRef(null);
  const referenceRef = useRef(null);
  const completedRef = useRef(false);

  const current = useCallback((epoch, controller) => mountedRef.current
    && epochRef.current === epoch && activeRef.current === controller
    && !controller.signal.aborted, []);

  const readSaved = useCallback(async (saved, controller, epoch) => {
    const response = await transport(`${BASE}/operations/${saved.sessionId}/${saved.requestId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
    const value = decodeIdorSavedTurn(await jsonResponse(response), saved);
    if (!current(epoch, controller)) return null;
    if (value.modeCapability && modeRef.current
      && value.modeCapability.effectiveMode !== modeRef.current.effectiveMode) fail();
    if (value.savedResult && cardsRef.current
      && !cardsRef.current.some(card => card.action === value.savedResult.action
        && card.numericId === value.savedResult.numericId)) fail();
    setStatus(value.status);
    setSavedText(value.text);
    setSavedResult(value.savedResult);
    completedRef.current = value.status === 'completed';
    if (value.modeCapability) setModeCapability(value.modeCapability);
    return value;
  }, [transport, current]);

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current;
    activeRef.current?.abort();
    activeRef.current = null;
    cardsRef.current = null; modeRef.current = null;
    referenceRef.current = null; completedRef.current = false;
    setCards(null); setModeCapability(null); setLoading(false); setBusy(false);
    setError(null); setReference(null); setSavedResult(null); setSavedText(null);
    setStatus('idle'); setAssessment(null);
    try {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1
        || typeof referenceStore?.read !== 'function'
        || typeof referenceStore?.save !== 'function'
        || typeof referenceStore?.clear !== 'function'
        || typeof transport !== 'function') fail();
      const saved = referenceStore.read(shopUserId);
      if (saved) {
        referenceRef.current = saved; setReference(saved); setStatus('unconfirmed');
        const controller = new AbortController();
        activeRef.current = controller;
        void readSaved(saved, controller, epoch).catch(() => {
          if (current(epoch, controller)) {
            setStatus('unconfirmed'); setError('Check the saved lesson request again.');
          }
        }).finally(() => { if (activeRef.current === controller) activeRef.current = null; });
      }
    } catch { setError('Saved lesson storage unavailable.'); setStatus('error'); }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [shopUserId, authorityKey, transport, referenceStore, readSaved, current]);

  const cardsRequest = useCallback(async (prepare) => {
    if (activeRef.current || !mountedRef.current || (prepare && referenceRef.current)) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setLoading(true); setError(null);
    try {
      const response = await transport(`${BASE}/${prepare ? 'prepare' : 'cards'}`, {
        method: prepare ? 'POST' : 'GET', headers: { accept: 'application/json',
          ...(prepare ? { 'content-type': 'application/json' } : {}) },
        ...(prepare ? { body: '{}' } : {}), signal: controller.signal,
      });
      const value = decodeIdorCards(await jsonResponse(response));
      if (!current(epoch, controller)) return false;
      if (modeCapability && value.modeCapability.effectiveMode !== modeCapability.effectiveMode) fail();
      if (savedResult && !value.cards.some(card => card.action === savedResult.action
        && card.numericId === savedResult.numericId)) fail();
      cardsRef.current = value.cards; setCards(value.cards);
      modeRef.current = value.modeCapability;
      setModeCapability(value.modeCapability);
      return true;
    } catch {
      if (current(epoch, controller)) setError('Lesson targets unavailable.');
      return false;
    } finally { if (current(epoch, controller)) setLoading(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [transport, current, modeCapability, savedResult]);

  const recover = useCallback(async () => {
    if (activeRef.current || !mountedRef.current) return false;
    const saved = referenceRef.current;
    if (!saved) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try { return !!await readSaved(saved, controller, epoch); }
    catch { if (current(epoch, controller)) setError('Saved lesson result unavailable.'); return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [readSaved, current]);

  const select = useCallback(async (selection) => {
    if (activeRef.current || !mountedRef.current || referenceRef.current) return false;
    const admitted = cardsRef.current?.find(card => card.action === selection?.action
      && card.numericId === selection?.numericId);
    if (!admitted || !modeCapability) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const sessionResponse = await transport(`${BASE}/session`, {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: '{}', signal: controller.signal,
      });
      const session = await jsonResponse(sessionResponse);
      if (!exact(session, ['sessionId']) || !UUID.test(session.sessionId)) fail();
      if (!current(epoch, controller)) return false;
      const saved = await referenceStore.save({ shopUserId, sessionId: session.sessionId,
        requestId: crypto.randomUUID(), startedAt: Date.now() },
      () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = saved; setReference(saved); setStatus('unconfirmed');
      try {
        const response = await transport(`${BASE}/chat`, {
          method: 'POST', headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
          body: JSON.stringify({ sessionId: saved.sessionId, requestId: saved.requestId,
            message: messageFor(admitted),
            selection: { action: admitted.action, numericId: admitted.numericId } }),
          signal: controller.signal,
        });
        await drainStream(response);
      } catch { /* The protected saved GET, never a repeated POST, decides the outcome. */ }
      if (!current(epoch, controller)) return false;
      const value = await readSaved(saved, controller, epoch);
      return value?.status === 'completed';
    } catch {
      if (current(epoch, controller)) {
        // A lost storage acknowledgement may still have persisted the ID-only
        // reference. Never admit another model POST until it is checked.
        try {
          const retained = referenceStore.read(shopUserId);
          if (retained) {
            referenceRef.current = retained; setReference(retained); setStatus('unconfirmed');
          }
        } catch { /* Leave the request unavailable rather than assuming absence. */ }
        setError(referenceRef.current
          ? 'Lesson outcome unresolved. Check the saved request.'
          : 'Lesson request unavailable.');
      }
      return false;
    } finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [modeCapability, shopUserId, referenceStore, transport, readSaved, current]);

  const readAssessment = useCallback(async (retry = false) => {
    if (activeRef.current || !mountedRef.current || !completedRef.current) return false;
    const saved = referenceRef.current;
    if (!saved) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller; setBusy(true); setError(null);
    try {
      const response = await transport(retry ? `${BASE}/assessment-retry`
        : `${BASE}/assessments/${saved.sessionId}/${saved.requestId}`, {
        method: retry ? 'POST' : 'GET', headers: { accept: 'application/json',
          ...(retry ? { 'content-type': 'application/json' } : {}) },
        ...(retry ? { body: JSON.stringify({ sessionId: saved.sessionId,
          requestId: saved.requestId }) } : {}), signal: controller.signal,
      });
      const value = decodeIdorAssessment(await jsonResponse(response));
      if (!current(epoch, controller)) return false;
      setAssessment(value);
      return true;
    } catch { if (current(epoch, controller)) setError('Saved lesson assessment unavailable.'); return false; }
    finally { if (current(epoch, controller)) setBusy(false);
      if (activeRef.current === controller) activeRef.current = null; }
  }, [transport, current]);

  const clearCompleted = useCallback(async () => {
    if (activeRef.current || !mountedRef.current || !completedRef.current
      || !referenceRef.current) return false;
    const controller = new AbortController(), epoch = epochRef.current;
    activeRef.current = controller;
    try {
      await referenceStore.clear(referenceRef.current, () => current(epoch, controller));
      if (!current(epoch, controller)) return false;
      referenceRef.current = null; completedRef.current = false;
      setReference(null); setSavedResult(null); setSavedText(null); setAssessment(null);
      setStatus('idle'); return true;
    } catch { if (current(epoch, controller)) setError('Saved lesson request could not be cleared.'); return false; }
    finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [referenceStore, current]);

  return { cards, mode: modeCapability?.effectiveMode || null, loading, busy, error,
    reference, status, savedResult, savedText, assessment,
    prepare: () => cardsRequest(true), loadCards: () => cardsRequest(false),
    select, recover, readAssessment: () => readAssessment(false),
    retryAssessment: () => readAssessment(true), clearCompleted };
}
