import React, { createContext, useCallback, useContext, useMemo, useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle2, AlertTriangle, Info, XCircle, X } from 'lucide-react';

/**
 * SecureShop v2 Toast system — small, ephemeral, screen-reader-announced.
 */
const ToastCtx = createContext(null);
const NOOP_TOAST = Object.freeze({
  push: () => {}, dismiss: () => {}, success: () => {}, error: () => {}, info: () => {}, warn: () => {},
});

let counter = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const dismiss = useCallback((id) => {
    setToasts((t) => t.filter((x) => x.id !== id));
  }, []);

  const push = useCallback((toast) => {
    const id = ++counter;
    const t = { id, kind: 'info', duration: 3500, ...toast };
    setToasts((prev) => [...prev, t]);
    if (t.duration > 0) {
      setTimeout(() => dismiss(id), t.duration);
    }
    return id;
  }, [dismiss]);

  const api = useMemo(() => ({
    push,
    dismiss,
    success: (message, opts = {}) => push({ ...opts, message, kind: 'success' }),
    error:   (message, opts = {}) => push({ ...opts, message, kind: 'error' }),
    info:    (message, opts = {}) => push({ ...opts, message, kind: 'info' }),
    warn:    (message, opts = {}) => push({ ...opts, message, kind: 'warn' }),
  }), [push, dismiss]);

  return (
    <ToastCtx.Provider value={api}>
      {children}
      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </ToastCtx.Provider>
  );
}

function ToastStack({ toasts, onDismiss }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted || typeof document === 'undefined') return null;

  return createPortal(
    <div className="ss-toast-stack" aria-live="polite" aria-atomic="false">
      <AnimatePresence>
        {toasts.map((t) => (
          <motion.div
            key={t.id}
            className={`ss-toast ss-toast--${t.kind}`}
            role="status"
            initial={{ opacity: 0, y: 12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, x: 20 }}
            transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
          >
            <ToastIcon kind={t.kind} />
            <div className="ss-toast__body">{t.message}</div>
            <button className="ss-toast__close" aria-label="Dismiss" onClick={() => onDismiss(t.id)}>
              <X size={14} />
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>,
    document.body,
  );
}

function ToastIcon({ kind }) {
  if (kind === 'success') return <CheckCircle2 size={18} color="var(--kelp)" />;
  if (kind === 'error')   return <XCircle size={18} color="var(--rust)" />;
  if (kind === 'warn')    return <AlertTriangle size={18} color="var(--amber)" />;
  return <Info size={18} color="var(--copper)" />;
}

export function useToast() {
  const ctx = useContext(ToastCtx);
  // Public/login and isolated component mounts may intentionally omit the
  // provider. Keep their no-op API referentially stable across renders so it
  // is safe in effect dependency arrays.
  return ctx || NOOP_TOAST;
}

export { ToastCtx };
