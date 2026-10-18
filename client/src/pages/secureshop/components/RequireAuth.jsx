import React, { useEffect, useRef } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { toast } from 'react-toastify';
import { useAuth } from '../context/AuthContext';
import { safeLoginDestination } from '../utils/loginDestination.mjs';

/**
 * SecureShop v2 RequireAuth — M8 Task C, hardened Wave 5B U6.
 *
 * Wraps protected routes. If the visitor is not authed, redirects to
 * /secureshop/login and preserves the intended path via ?next=.
 *
 * Optional requireRole prop blocks access unless user.role matches. A role
 * mismatch returns to that persona's own overview.
 */
export default function RequireAuth({ children, requireRole }) {
  const { isAuthed, loading, user, token, error, retrySession } = useAuth();
  const location = useLocation();
  const toastFired = useRef(false);
  const mismatch = requireRole && isAuthed && user?.role !== requireRole;

  useEffect(() => {
    if (mismatch && !toastFired.current) {
      toastFired.current = true;
      try { toast.error('Insufficient permissions'); } catch {}
    }
  }, [mismatch]);

  if (loading) {
    return (
      <div style={{ padding: '80px 32px', fontFamily: 'Inter, sans-serif', opacity: 0.65 }}>
        Loading session…
      </div>
    );
  }

  if (!isAuthed) {
    if (token && error) return <div style={{ padding: '80px 32px', fontFamily: 'Inter, sans-serif' }}>
      <p role="alert">{error}</p>
      <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={retrySession}>Retry</button>
    </div>;
    const nextParam = encodeURIComponent(location.pathname + location.search + location.hash);
    return <Navigate to={`/secureshop/login?next=${nextParam}`} replace />;
  }

  if (mismatch) {
    const knownRole = ['customer', 'merchant', 'admin'].includes(user?.role);
    return <Navigate to={knownRole ? safeLoginDestination('', user) : '/secureshop'} replace />;
  }

  return children;
}
