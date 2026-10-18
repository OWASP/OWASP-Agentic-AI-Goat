import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createScenarioFence } from './experience.mjs';

const CLOSED = Object.freeze({ open: false, status: 'idle', error: '' });

export default function useWorkshopResetController({
  owner,
  title,
  description,
  mutation,
  onBegin,
  onCommit,
  onError,
  operationStorageKey,
}) {
  const fenceRef = useRef(null);
  if (!fenceRef.current) fenceRef.current = createScenarioFence();
  const [confirmation, setConfirmation] = useState(CLOSED);
  const runningRef = useRef(false);
  const operationRef = useRef(null);
  const attemptRef = useRef(null);
  const ownerKey = `${owner.attendeeId}:${owner.workshopKey}:${owner.scenarioId}`;
  const stableOwner = useMemo(() => ({ ...owner }), [ownerKey]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    setConfirmation(CLOSED);
    return () => {
      fenceRef.current.invalidate(stableOwner);
      attemptRef.current = null;
      runningRef.current = false;
    };
  }, [stableOwner]);

  const requestReset = useCallback(() => {
    if (runningRef.current) return;
    setConfirmation({ open: true, status: 'confirming', error: '' });
  }, []);

  const cancelReset = useCallback(() => {
    if (runningRef.current) return;
    setConfirmation(CLOSED);
  }, []);

  const confirmReset = useCallback(async () => {
    if (runningRef.current) return false;
    runningRef.current = true;
    const attempt = Symbol('reset-attempt');
    attemptRef.current = attempt;
    const token = fenceRef.current.capture(stableOwner);
    setConfirmation({ open: true, status: 'resetting', error: '' });
    try {
      onBegin?.();
      let operationId;
      if (operationStorageKey) {
        if (operationRef.current?.key !== operationStorageKey) operationRef.current = null;
        let saved;
        try { saved = sessionStorage.getItem(operationStorageKey); } catch {}
        operationId = operationRef.current?.id || (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(saved || '') ? saved : null);
        if (!operationId) {
          const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
          bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
          const hex = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
          operationId = `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
        }
        operationRef.current = { key: operationStorageKey, id: operationId };
        try { sessionStorage.setItem(operationStorageKey, operationId); } catch {}
      }
      const result = await mutation({ operationId });
      if (!token.isCurrent()) return false;
      await onCommit?.(result);
      if (!token.isCurrent()) return false;
      if (operationStorageKey) {
        operationRef.current = null;
        try { sessionStorage.removeItem(operationStorageKey); } catch {}
      }
      setConfirmation(CLOSED);
      return true;
    } catch (error) {
      if (!token.isCurrent()) return false;
      const message = onError?.(error) || error?.message || 'Reset failed. Try again.';
      setConfirmation({ open: true, status: 'failed', error: message });
      return false;
    } finally {
      if (attemptRef.current === attempt) {
        attemptRef.current = null;
        runningRef.current = false;
      }
    }
  }, [mutation, onBegin, onCommit, onError, stableOwner, operationStorageKey]);

  const invalidate = useCallback(() => {
    fenceRef.current.invalidate(stableOwner);
    attemptRef.current = null;
    runningRef.current = false;
    setConfirmation(CLOSED);
  }, [stableOwner]);

  return {
    requestReset,
    cancelReset,
    confirmReset,
    invalidate,
    resetting: confirmation.status === 'resetting',
    confirmation: {
      ...confirmation,
      title,
      description,
      onCancel: cancelReset,
      onConfirm: confirmReset,
    },
  };
}
