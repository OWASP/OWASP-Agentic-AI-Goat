import { useCallback, useEffect, useRef, useState } from 'react';
import { parseAgentFrame, requireAgentContentType, takeAgentFrame } from '../utils/agentStreamProtocol.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { decodeRegisteredMcpSetup } from '../utils/roleMcpRegistry.mjs';
import { sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { assertRegisteredAdminChatReference, clearRegisteredAdminChatReference,
  readRegisteredAdminChatReference, saveRegisteredAdminChatReference } from '../utils/registeredAdminChatReference.mjs';
import { clearRegisteredAdminCompletedReference, readRegisteredAdminCompletedReference,
  saveRegisteredAdminCompletedReference } from '../utils/registeredAdminCompletedReference.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const path = leaf => `/api/secureshop/agents/admin/${leaf}`;
const newId = () => globalThis.crypto.randomUUID().toLowerCase();
const messageValid = message => typeof message === 'string' && !!message.trim()
  && message.isWellFormed() && !message.includes('\0')
  && new TextEncoder().encode(message).byteLength <= 8192;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const sameReference = (left, right) => !!left && !!right
  && ['shopUserId', 'sessionId', 'requestId', 'startedAt'].every(key => left[key] === right[key]);
function decodeSavedAssessment(value) {
  if (exact(value, ['completed', 'status', 'modelEvaluated']) && value.completed === false
    && ['ineligible', 'unconfirmed'].includes(value.status) && value.modelEvaluated === false) {
    return Object.freeze({ kind: value.status });
  }
  const judgment = value?.judgment;
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
    || typeof value.replayed !== 'boolean' || !judgment
    || Object.getPrototypeOf(judgment) !== Object.prototype
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(judgment.verdict)
    || !UUID.test(judgment.evaluationId || '') || typeof judgment.canRetry !== 'boolean') {
    throw Error('Saved registered-tools assessment invalid');
  }
  return Object.freeze({ kind: 'judgment', completed: value.completed, replayed: value.replayed,
    judgment: Object.freeze({ verdict: judgment.verdict,
      evaluationId: judgment.evaluationId.toLowerCase(), canRetry: judgment.canRetry }) });
}

export function useRegisteredAdminStream({ shopUserId, authorityKey, transport = globalThis.fetch }) {
  const [turns, setTurns] = useState([]), [pending, setPending] = useState(null);
  const [completedPage, setCompletedPage] = useState(null);
  const [status, setStatus] = useState('idle'), [error, setError] = useState(null);
  const sessionRef = useRef(null), epochRef = useRef(0), activeRef = useRef(null);
  const storageFaultRef = useRef(false);
  useEffect(() => {
    const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null; sessionRef.current = null;
    storageFaultRef.current = false; setTurns([]); setPending(null); setCompletedPage(null);
    setStatus('idle'); setError(null);
    try {
      const saved = readRegisteredAdminChatReference();
      if (saved) {
        setPending(saved); setStatus('unresolved');
        if (saved.shopUserId === shopUserId) {
          sessionRef.current = saved.sessionId;
          setTurns([{ ...saved, user: 'Saved registered-tools request', reply: '', status: 'error' }]);
        }
      } else {
        const completed = readRegisteredAdminCompletedReference();
        if (completed?.shopUserId === shopUserId) setCompletedPage(completed);
      }
    } catch {
      storageFaultRef.current = true; setStatus('error');
      setError('Saved registered-tools request is unavailable');
    }
    return () => { if (epochRef.current === epoch) ++epochRef.current;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [shopUserId, authorityKey, transport]);

  const readExact = useCallback(async (reference, signal) => {
    const response = await transport(path(`chat/requests/${reference.sessionId}/${reference.requestId}`), { signal });
    if (!response.ok) throw Object.assign(
      Error(`Saved registered-tools request unavailable (${response.status})`), { status: response.status });
    requireAgentContentType(response, 'application/json', 'Registered-tools request');
    const value = await response.json();
    if (value.sessionId !== reference.sessionId || value.requestId !== reference.requestId
      || !['unconfirmed', 'completed'].includes(value.status)) throw Error('Saved registered-tools identity mismatch');
    if (value.status === 'unconfirmed') {
      if (!exact(value, ['sessionId', 'requestId', 'status'])) {
        throw Error('Saved registered-tools result invalid');
      }
      return value;
    }
    const expectedMode = { version: 1, featureId: 'registered_mcp',
      policyVersion: 'registered-schema-approval-v1',
      effectiveMode: value.result?.modeCapability?.effectiveMode,
      scope: { kind: 'launch_feature', id: 'registered_mcp' } };
    if (!exact(value, ['sessionId', 'requestId', 'status', 'result', 'replayed'])
      || value.replayed !== true || !exact(value.result,
        ['sessionId', 'text', 'stopReason', 'hops', 'steps', 'modeCapability'])
      || value.result.sessionId !== reference.sessionId || typeof value.result.text !== 'string'
      || new TextEncoder().encode(value.result.text).byteLength > 262144
      || typeof value.result.stopReason !== 'string'
      || !Array.isArray(value.result.hops) || value.result.hops.length > 4
      || value.result.hops.some(hop => !hop || Object.getPrototypeOf(hop) !== Object.prototype
        || typeof hop.tool !== 'string' || !hop.tool.trim()
        || new TextEncoder().encode(hop.tool).byteLength > 256
        || !(hop.error === null || hop.error === undefined
          || (typeof hop.error === 'object' && !Array.isArray(hop.error))))
      || !Number.isInteger(value.result.steps) || value.result.steps < 0 || value.result.steps > 5
      || !['fixed', 'vuln'].includes(expectedMode.effectiveMode)
      || !sameRolePolicyMode(value.result.modeCapability, expectedMode)
      || trustedTurnMode(value.result.modeCapability)?.featureId !== 'registered_mcp') {
      throw Error('Saved registered-tools result invalid');
    }
    return value;
  }, [transport]);

  const recoverCompleted = useCallback(async (reference = completedPage) => {
    if (!reference || !sameReference(reference, completedPage) || activeRef.current
      || storageFaultRef.current || reference.shopUserId !== shopUserId || pending) return false;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setStatus('recovering'); setError(null);
    const current = () => epochRef.current === epoch && !controller.signal.aborted;
    const reconcile = () => {
      const newerPending = readRegisteredAdminChatReference();
      if (newerPending) {
        setPending(newerPending); setStatus('unresolved');
        if (newerPending.shopUserId === shopUserId) sessionRef.current = newerPending.sessionId;
        return false;
      }
      const latest = readRegisteredAdminCompletedReference();
      if (!sameReference(latest, reference)) {
        setCompletedPage(latest?.shopUserId === shopUserId ? latest : null);
        setStatus('idle');
        return false;
      }
      return true;
    };
    try {
      if (!reconcile()) return false;
      const saved = await readExact(reference, controller.signal);
      if (!current() || !reconcile()) return false;
      if (saved.status !== 'completed') {
        setStatus('idle'); setError('The saved registered-tools result is not yet complete.');
        return false;
      }
      sessionRef.current = reference.sessionId;
      const failed = ['error', 'cancelled'].includes(saved.result.stopReason);
      setTurns([{ ...reference, user: 'Saved registered-tools request', reply: saved.result.text,
        hops: saved.result.hops, modeCapability: saved.result.modeCapability,
        stopReason: saved.result.stopReason,
        status: failed ? 'error' : 'done' }]);
      setStatus('idle');
      if (failed) setError('Registered tools did not complete');
      return !failed;
    } catch (caught) {
      if (current()) {
        if ([401, 403, 404].includes(caught.status)) {
          try { await clearRegisteredAdminCompletedReference(reference, current); }
          catch {
            if (current()) { setStatus('idle'); setError('The saved registered-tools page could not be cleared. Check it again.'); }
            return false;
          }
          if (!current()) return false;
          const newerPending = readRegisteredAdminChatReference();
          if (newerPending) { setPending(newerPending); setStatus('unresolved'); return false; }
          const newerCompleted = readRegisteredAdminCompletedReference();
          if (newerCompleted && !sameReference(newerCompleted, reference)) {
            setCompletedPage(newerCompleted.shopUserId === shopUserId ? newerCompleted : null);
            setStatus('idle'); return false;
          }
          setCompletedPage(null); setStatus('idle'); setError('The saved registered-tools page is no longer available.');
        } else { setStatus('idle'); setError(caught.message || 'Saved registered-tools page unavailable'); }
      }
      return false;
    } finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [completedPage, pending, readExact, shopUserId]);

  useEffect(() => {
    if (completedPage && !pending && !turns.some(turn => sameReference(turn, completedPage)
      && ['done', 'error'].includes(turn.status))) void recoverCompleted(completedPage);
  }, [completedPage, pending, recoverCompleted, turns]);

  const recover = useCallback(async () => {
    if (!pending || activeRef.current || storageFaultRef.current || pending.shopUserId !== shopUserId) return false;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setStatus('recovering'); setError(null);
    const current = () => epochRef.current === epoch && !controller.signal.aborted;
    try {
      const value = await readExact(pending, controller.signal);
      if (!current()) return false;
      if (value.status === 'unconfirmed') {
        setStatus('unresolved'); setError('The registered-tools outcome is unconfirmed. Check it again.');
        return false;
      }
      const failed = ['error', 'cancelled'].includes(value.result.stopReason);
      await saveRegisteredAdminCompletedReference(pending, current);
      if (!current()) return false;
      setCompletedPage(pending);
      setTurns(previous => previous.map(turn => turn.requestId === pending.requestId
        ? { ...turn, reply: value.result.text, hops: value.result.hops,
          modeCapability: value.result.modeCapability, stopReason: value.result.stopReason,
          status: failed ? 'error' : 'done' } : turn));
      await clearRegisteredAdminChatReference(pending, current);
      if (!current()) return false;
      setPending(null); setStatus(failed ? 'error' : 'idle');
      if (failed) setError('Registered tools did not complete');
      return !failed;
    } catch (caught) {
      if (current()) { setStatus('unresolved'); setError(caught.message || 'Saved registered-tools request unavailable'); }
      return false;
    } finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [pending, readExact, shopUserId]);

  const assessment = useCallback(async (reference, retry = false, description = false) => {
    if (!reference || !exact(reference, ['sessionId', 'requestId'])
      || ![reference.sessionId, reference.requestId].every(value => typeof value === 'string'
        && UUID.test(value) && value === value.toLowerCase()) || activeRef.current
      || pending || storageFaultRef.current) {
      return Object.freeze({ kind: 'error', message: 'Saved registered-tools assessment unavailable.' });
    }
    const source = turns.find(turn => turn.sessionId === reference.sessionId
      && turn.requestId === reference.requestId && turn.status === 'done'
      && turn.stopReason === 'end_turn');
    if (!source || source.shopUserId !== shopUserId) {
      return Object.freeze({ kind: 'error', message: 'Return to the verified saved registered-tools result.' });
    }
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller;
    const current = () => epochRef.current === epoch && !controller.signal.aborted;
    try {
      const original = await readExact(source, controller.signal);
      if (!current()) return Object.freeze({ kind: 'stale' });
      if (original.status !== 'completed' || original.result.stopReason !== 'end_turn'
        || readRegisteredAdminChatReference()) {
        return Object.freeze({ kind: 'error', message: 'Saved registered-tools result changed.' });
      }
      const url = description
        ? (retry ? path('chat/description-assessment')
          : path(`chat/description-assessment/${reference.sessionId}/${reference.requestId}`))
        : (retry ? path('chat/assessment-retry')
          : path(`chat/assessment/${reference.sessionId}/${reference.requestId}`));
      const response = await transport(url, retry ? {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(reference), signal: controller.signal,
      } : { signal: controller.signal });
      if (!current()) return Object.freeze({ kind: 'stale' });
      if (!response.ok) throw Error(`Saved registered-tools assessment unavailable (${response.status})`);
      requireAgentContentType(response, 'application/json', 'Registered-tools assessment');
      const result = decodeSavedAssessment(await response.json());
      if (!current()) return Object.freeze({ kind: 'stale' });
      return result;
    } catch (caught) {
      return Object.freeze({ kind: 'error', message: caught.message || 'Saved registered-tools assessment unavailable.' });
    } finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [pending, readExact, shopUserId, transport, turns]);
  const readAssessment = useCallback(reference => assessment(reference, false), [assessment]);
  const retryAssessment = useCallback(reference => assessment(reference, true), [assessment]);
  const readDescriptionAssessment = useCallback(reference => assessment(reference, false, true), [assessment]);
  const submitDescriptionAssessment = useCallback(reference => assessment(reference, true, true), [assessment]);

  const send = useCallback(async (message, setup = null) => {
    if (activeRef.current || pending || storageFaultRef.current || !messageValid(message)
      || !Number.isSafeInteger(shopUserId) || shopUserId < 1) return false;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setStatus('thinking'); setError(null);
    const current = () => epochRef.current === epoch && !controller.signal.aborted;
    let reference = null;
    try {
      if (readRegisteredAdminChatReference()) throw Error('Check the saved registered-tools request before sending another');
      if (setup) {
        const expected = decodeRegisteredMcpSetup(setup, setup.sessionId, setup.requestId);
        if (message !== expected.message) throw Error('Registered-tools handoff message changed');
        const response = await transport(path(`assistant/operations/${expected.sessionId}/${expected.requestId}`),
          { signal: controller.signal });
        if (!response.ok) throw Error('Registered-tools handoff unavailable');
        const saved = await response.json();
        if (!current()) return false;
        const actual = decodeRegisteredMcpSetup(saved.registeredMcpSetup,
          expected.sessionId, expected.requestId);
        if (saved.status !== 'completed' || saved.replayed !== true || saved.stopReason !== 'end_turn'
          || !actual || JSON.stringify(actual) !== JSON.stringify(expected)) {
          throw Error('Registered-tools handoff changed');
        }
      }
      let sessionId = sessionRef.current;
      if (!sessionId) {
        const response = await transport(path('session'), {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}', signal: controller.signal,
        });
        if (!response.ok) throw Error(`Registered-tools session unavailable (${response.status})`);
        requireAgentContentType(response, 'application/json', 'Registered-tools session');
        const opened = await response.json();
        if (!UUID.test(opened?.sessionId || '')) throw Error('Registered-tools session identity invalid');
        if (!current()) return false;
        sessionId = opened.sessionId; sessionRef.current = sessionId;
      }
      reference = { shopUserId, sessionId, requestId: newId(), startedAt: Date.now() };
      await saveRegisteredAdminChatReference(reference, current);
      if (!current()) return false;
      assertRegisteredAdminChatReference(reference); setPending(reference);
      setTurns(previous => [...previous, { ...reference, user: message, reply: '', status: 'in-flight' }]);
      const response = await transport(path('chat'), {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
        body: JSON.stringify({ sessionId, requestId: reference.requestId, message }), signal: controller.signal,
      });
      if (!response.ok) throw Error(`Registered-tools request unavailable (${response.status})`);
      requireAgentContentType(response, 'text/event-stream', 'Registered-tools stream');
      if (!response.body?.getReader) throw Error('Registered-tools stream unavailable');
      const reader = response.body.getReader(), decoder = new TextDecoder();
      let buffer = '', bytes = 0, events = 0;
      while (true) {
        const part = await reader.read();
        if (!current()) { await reader.cancel(); return false; }
        if (part.done) break;
        bytes += part.value.byteLength;
        if (bytes > 131072) throw Error('Registered-tools stream limit exceeded');
        buffer += decoder.decode(part.value, { stream: true });
        while (true) {
          const next = takeAgentFrame(buffer);
          if (!next) break;
          buffer = next.rest;
          if (++events > 80) throw Error('Registered-tools stream limit exceeded');
          const event = parseAgentFrame(next.frame);
          if (!event) continue;
          if (event.name === 'done') {
            const saved = await readExact(reference, controller.signal);
            if (!current()) return false;
            if (saved.status === 'unconfirmed') {
              setStatus('unresolved'); setError('Check the saved registered-tools request.');
              return false;
            }
            const failed = ['error', 'cancelled'].includes(saved.result.stopReason);
            await saveRegisteredAdminCompletedReference(reference, current);
            if (!current()) return false;
            setCompletedPage(reference);
            setTurns(previous => previous.map(turn => turn.requestId === reference.requestId
              ? { ...turn, reply: saved.result.text, hops: saved.result.hops,
                modeCapability: saved.result.modeCapability, stopReason: saved.result.stopReason,
                status: failed ? 'error' : 'done' } : turn));
            await clearRegisteredAdminChatReference(reference, current);
            if (!current()) return false;
            setPending(null); setStatus(failed ? 'error' : 'idle');
            if (failed) setError('Registered tools did not complete');
            try { await reader.cancel(); } catch { /* terminal readback is authoritative */ }
            return !failed;
          }
          if (event.name === 'error') throw Error('Registered-tools outcome is uncertain. Check the saved request.');
        }
      }
      throw Error('Registered-tools stream ended before completion');
    } catch (caught) {
      if (current()) {
        try {
          const saved = readRegisteredAdminChatReference();
          if (saved) {
            setPending(saved); setStatus('unresolved');
            if (saved.shopUserId === shopUserId) sessionRef.current = saved.sessionId;
          } else setStatus('error');
        } catch {
          storageFaultRef.current = true; setStatus('error');
        }
        setError(caught.message || 'Registered tools unavailable');
      }
      return false;
    } finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [pending, readExact, shopUserId, transport]);

  return Object.freeze({ turns, pending, completedPage, status, error, send, recover,
    recoverCompleted, readAssessment, retryAssessment, readDescriptionAssessment, submitDescriptionAssessment });
}
