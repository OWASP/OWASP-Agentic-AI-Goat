import { useCallback, useEffect, useRef, useState } from 'react';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

export function useProductQuestion({ productId, ownerKey }) {
  const selected = Number(productId);
  const validProduct = /^[1-9][0-9]*$/.test(String(productId))
    && Number.isSafeInteger(selected) && selected <= 2147483647;
  const [turns, setTurns] = useState([]);
  const [status, setStatus] = useState('idle');
  const [error, setError] = useState(null);
  const session = useRef(null);
  const active = useRef(null);
  const generation = useRef(0);
  const mounted = useRef(false);

  useEffect(() => {
    mounted.current = true;
    generation.current += 1;
    active.current?.abort();
    active.current = null;
    session.current = null;
    setTurns([]);
    setStatus('idle');
    setError(null);
    return () => {
      mounted.current = false;
      generation.current += 1;
      active.current?.abort();
      active.current = null;
    };
  }, [selected, ownerKey]);

  const send = useCallback(async message => {
    if (!validProduct || typeof message !== 'string' || !message.trim()
      || new TextEncoder().encode(message).length > 8192 || active.current) return false;
    const controller = new AbortController();
    const admitted = generation.current;
    const requestId = crypto.randomUUID();
    const current = () => mounted.current && generation.current === admitted
      && active.current === controller && !controller.signal.aborted;
    active.current = controller;
    setError(null);
    setStatus('thinking');
    setTurns(previous => [...previous, { productId: selected, user: message, reply: '', status: 'in-flight', startedAt: Date.now() }]);
    try {
      const response = await fetch(`/api/secureshop/products/${selected}/question`, {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ message, requestId, ...(session.current ? { sessionId: session.current } : {}) }),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Product question failed (${response.status})`);
      if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json'))
        throw new Error('Product question returned an invalid response');
      const body = await response.json();
      if (!current()) return false;
      if (Number(body?.product_id) !== selected || body?.requestId !== requestId
        || typeof body?.answer !== 'string' || !body.answer.trim()
        || !UUID.test(body?.sessionId || '')) throw new Error('Product question response did not match the request');
      session.current = body.sessionId;
      setTurns(previous => previous.map((turn, index) => index === previous.length - 1
        ? { ...turn, reply: body.answer, modeCapability: trustedTurnMode(body.modeCapability),
            status: 'done', finishedAt: Date.now() } : turn));
      setStatus('idle');
      return true;
    } catch (cause) {
      if (current()) {
        setError(cause instanceof Error ? cause.message : 'Product question failed');
        setStatus('error');
        setTurns(previous => previous.map((turn, index) => index === previous.length - 1
          ? { ...turn, status: 'error', finishedAt: Date.now() } : turn));
      }
      return false;
    } finally { if (active.current === controller) active.current = null; }
  }, [selected, validProduct]);

  return { turns, status, error, send, validProduct };
}
