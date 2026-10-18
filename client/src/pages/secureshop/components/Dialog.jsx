import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { X } from 'lucide-react';

/**
 * SecureShop v2 Dialog — accessible modal with framer-motion.
 *
 * Features: ESC to close, focus trap (first focusable), backdrop click to close.
 */
export default function Dialog({
  open,
  onClose,
  title,
  children,
  footer,
  size = 'md',
  closeOnBackdrop = true,
}) {
  const bodyRef = useRef(null);
  const previouslyFocused = useRef(null);
  const closeRef = useRef(onClose);
  const reduce = useReducedMotion();

  useEffect(() => { closeRef.current = onClose; }, [onClose]);

  useEffect(() => {
    if (!open) return;
    previouslyFocused.current = document.activeElement;
    // Focus first focusable inside the dialog on next tick.
    const t = setTimeout(() => {
      if (bodyRef.current?.contains(document.activeElement)) return;
      const el = bodyRef.current?.querySelector(
        'button, input, textarea, select, a[href], [tabindex]:not([tabindex="-1"])',
      );
      el?.focus();
    }, 40);
    const onKey = (e) => {
      if (e.key === 'Escape') { e.stopPropagation(); closeRef.current?.(); }
      if (e.key === 'Tab') {
        // Simple focus trap
        const nodes = bodyRef.current?.querySelectorAll(
          'button, input, textarea, select, a[href], [tabindex]:not([tabindex="-1"])',
        );
        if (!nodes || !nodes.length) return;
        const first = nodes[0];
        const last = nodes[nodes.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault(); last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault(); first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      clearTimeout(t);
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
      previouslyFocused.current?.focus?.();
    };
  }, [open]);

  if (typeof document === 'undefined') return null;

  const sizeStyle = {
    sm: { minWidth: 'min(320px, 100%)', maxWidth: 'min(480px, 100%)' },
    md: { minWidth: 'min(480px, 100%)', maxWidth: 'min(640px, 100%)' },
    lg: { minWidth: 'min(720px, 100%)', maxWidth: 'min(960px, 100%)' },
  }[size] || {};

  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div
          className="ss-modal-backdrop"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: reduce ? 0 : 0.2 }}
          onClick={(e) => {
            if (closeOnBackdrop && e.target === e.currentTarget) onClose?.();
          }}
          role="dialog"
          aria-modal="true"
          aria-labelledby={title ? 'ss-dialog-title' : undefined}
        >
          <motion.div
            ref={bodyRef}
            className="ss-modal"
            style={sizeStyle}
            initial={{ scale: reduce ? 1 : 0.96, opacity: 0, y: reduce ? 0 : 4 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: reduce ? 1 : 0.96, opacity: 0, y: reduce ? 0 : 4 }}
            transition={{ duration: reduce ? 0 : 0.24, ease: [0.34, 1.56, 0.64, 1] }}
          >
            {(title || onClose) && (
              <div className="ss-modal__head">
                {title && <h2 id="ss-dialog-title" className="ss-modal__title">{title}</h2>}
                {onClose && (
                  <button
                    className="ss-modal__close"
                    onClick={onClose}
                    aria-label="Close dialog"
                    type="button"
                  >
                    <X size={20} />
                  </button>
                )}
              </div>
            )}
            <div>{children}</div>
            {footer && <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--rule)' }}>{footer}</div>}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}
