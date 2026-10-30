import { shopStorage, flushShopStorage, disconnectShopStorage } from '../utils/shopStorage.mjs';
import React, { createContext, useContext, useEffect, useMemo, useState, useCallback, useRef } from 'react';
import { createSecureShopFetch } from '../../../utils/secureShopFetch.mjs';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { requestStandaloneSessionIntent } from '../bridge/standaloneIntents.mjs';

/**
 * SecureShop v2 AuthContext — M8 Task C.
 *
 * Owns the v2 auth state:
 *   - token in localStorage under `secureshop_v2_token`
 *   - user object hydrated from GET /api/secureshop/v2/auth/whoami on mount
 *   - login/register/logout/switchRole methods
 *
 * Kept intentionally small — the real render surfaces live in Login/Register.
 */

const STORAGE_KEY = 'secureshop_v2_token';
const API_BASE = '/api/secureshop/v2/auth';

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => {
    try { return shopStorage.getItem(STORAGE_KEY); } catch { return null; }
  });
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(Boolean(token));
  const [error, setError] = useState(null);
  const [sessionRetry, setSessionRetry] = useState(0);
  const [personaExpiresAt, setPersonaExpiresAt] = useState(null);

  const identityUser = useRef(null);
  const publishUser = useCallback((value) => { identityUser.current = value; setUser(value); }, []);
  const transitions = useRef(Promise.resolve());
  const pendingTransitions = useRef(0);
  const identityGeneration = useRef(0);
  const hydrationAbort = useRef(null);
  const renewalAbort = useRef(null);
  const profileAbort = useRef(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => {
    mounted.current = false; hydrationAbort.current?.abort(); renewalAbort.current?.abort(); profileAbort.current?.abort();
  }; }, []);
  const enqueueIdentityChange = useCallback((change) => {
    identityGeneration.current++;
    hydrationAbort.current?.abort();
    renewalAbort.current?.abort();
    profileAbort.current?.abort();
    pendingTransitions.current++;
    const operation = transitions.current.then(() => {
      if (!mounted.current) throw new DOMException('Shop authentication cancelled', 'AbortError');
      return change();
    });
    transitions.current = operation.catch(() => {});
    return operation.finally(() => {
      pendingTransitions.current--;
      if (mounted.current) setLoading(false);
    });
  }, []);

  // Hydrate user from token via /whoami on mount and whenever the token changes.
  useEffect(() => {
    let cancelled = false;
    const generation = identityGeneration.current;
    const controller = new AbortController();
    hydrationAbort.current = controller;
    const current = () => !cancelled && mounted.current && generation === identityGeneration.current;
    async function hydrate() {
      if (pendingTransitions.current) { setLoading(false); return; }
      if (!token) { publishUser(null); setLoading(false); return; }
      setLoading(true);
      try {
        const r = await fetch(`${API_BASE}/whoami`, {
          headers: { Authorization: `Bearer ${token}` }, signal: controller.signal,
        });
        if (!current()) return;
        if (!r.ok) {
          if (r.status === 401 || r.status === 403) {
            await enqueueIdentityChange(() => persistToken(null));
            return;
          }
          throw new Error('whoami failed');
        }
        const data = await r.json();
        if (current()) { publishUser(data.user); setPersonaExpiresAt(data.expiresAt || null); setError(null); }
      } catch (e) {
        if (current()) {
          // A transient readiness/network failure must not erase the identity
          // just accepted by login. The next owned request will still enforce
          // the server-side session boundary.
          setError('Unable to verify the shop session right now. Retry when OWASP AI SecureShop is ready.');
        }
      } finally {
        if (current()) setLoading(false);
      }
    }
    hydrate();
    return () => { cancelled = true; controller.abort(); };
  }, [token, sessionRetry]);
  const retrySession = useCallback(() => setSessionRetry(value => value + 1), []);

  // M9 fix — install a fetch interceptor so any /api/secureshop/* request
  // automatically carries the Bearer token. Wave 5A F2 walled off merchant
  // and admin REST endpoints behind requireRole(), but the merchant/admin
  // React pages (57+ inline fetch calls) never learned to send the token,
  // which meant every merchant KPI, listing table, review queue, price
  // suggestion, analytics query, admin overview KPI, users table, audit
  // stream, policies list, MCP registry, and system dashboard 401'd on load.
  // Rather than touch 57 call sites, patch window.fetch centrally. Callers
  // that already set Authorization win (preserves alg=none testing).
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const original = window.fetch;
    // The acknowledged frame transport already snapshots the shop token. A
    // second wrapper would discard its private bound-review identity, causing
    // later-mounted pages to omit required idempotency IDs.
    if (getBridgeFetchMetadata(original)) return;
    const patched = createSecureShopFetch({
      fetchImpl: original.bind(window),
      getPageUrl: () => window.location.href,
      getRequestBaseUrl: () => document.baseURI,
      getToken: () => shopStorage.getItem(STORAGE_KEY),
    });
    window.fetch = patched;
    return () => {
      // Only restore if we're still the installed patch (avoid clobbering
      // a later provider's install).
      if (window.fetch === patched) {
        window.fetch = original;
      }
    };
  }, []);

  const persistToken = useCallback(async (next) => {
    if (!mounted.current) throw new DOMException('Shop authentication cancelled', 'AbortError');
    try {
      if (next) shopStorage.setItem(STORAGE_KEY, next);
      else shopStorage.removeItem(STORAGE_KEY);
      await flushShopStorage();
    } catch {
      if (!mounted.current) throw new DOMException('Shop authentication cancelled', 'AbortError');
      disconnectShopStorage();
      const message = 'Shop session could not be saved. Reload and try again.';
      setToken(null);
      publishUser(null);
      setError(message);
      throw new Error(message);
    }
    if (!mounted.current) throw new DOMException('Shop authentication cancelled', 'AbortError');
    setToken(next);
    if (!next) { publishUser(null); setPersonaExpiresAt(null); }
  }, []);

  // The parent rotates launch authority independently. Refresh this persona
  // through the acknowledged bridge so each request carries the latest parent
  // launch handle while the shop JWT remains private to the frame.
  useEffect(() => {
    if (!token || !personaExpiresAt) return;
    const expiry = Date.parse(personaExpiresAt);
    if (!Number.isFinite(expiry)) return;
    let stopped = false; let timer = null;
    const capturedToken = token;
    const expire = () => {
      if (stopped || !mounted.current || shopStorage.getItem(STORAGE_KEY) !== capturedToken) return;
      void enqueueIdentityChange(async () => {
        if (shopStorage.getItem(STORAGE_KEY) !== capturedToken) return;
        await persistToken(null); setPersonaExpiresAt(null);
      }).catch(() => {});
    };
    const refresh = () => {
      if (stopped || !mounted.current || shopStorage.getItem(STORAGE_KEY) !== capturedToken) return;
      void enqueueIdentityChange(async () => {
        if (shopStorage.getItem(STORAGE_KEY) !== capturedToken) return;
        const controller = new AbortController(); renewalAbort.current = controller;
        try {
          const response = await fetch(`${API_BASE}/renew`, { method: 'PATCH',
            headers: { Authorization: `Bearer ${capturedToken}` }, signal: controller.signal });
          const data = await response.json().catch(() => ({}));
          if (controller.signal.aborted || shopStorage.getItem(STORAGE_KEY) !== capturedToken) return;
          if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
              await persistToken(null); setPersonaExpiresAt(null); publishUser(null); return;
            }
            throw new Error('persona renewal failed');
          }
          const nextExpiry = Date.parse(data.expiresAt);
          if (typeof data.token !== 'string' || !data.token || !Number.isFinite(nextExpiry)
            || nextExpiry <= Date.now() || !data.user || typeof data.user !== 'object') {
            throw new Error('invalid persona renewal');
          }
          if (nextExpiry <= expiry) {
            timer = setTimeout(expire, Math.max(0, expiry - Date.now()));
            return;
          }
          await persistToken(data.token);
          if (!mounted.current || controller.signal.aborted) return;
          publishUser(data.user); setPersonaExpiresAt(data.expiresAt);
        } finally {
          if (renewalAbort.current === controller) renewalAbort.current = null;
        }
      }).catch(() => {
        if (!stopped && mounted.current && Date.now() < expiry) {
          timer = setTimeout(refresh, Math.min(60000, Math.max(1000, (expiry - Date.now()) / 4)));
        }
      });
    };
    const remaining = expiry - Date.now();
    if (remaining <= 0) expire();
    else timer = setTimeout(refresh, Math.max(0, remaining - Math.min(5 * 60 * 1000, remaining / 5)));
    timer?.unref?.();
    return () => { stopped = true; if (timer !== null) clearTimeout(timer); renewalAbort.current?.abort(); };
  }, [token, personaExpiresAt, enqueueIdentityChange, persistToken, publishUser]);

  const saveProfile = useCallback(async ({ full_name, email, phone }) => {
    if (!mounted.current || pendingTransitions.current || !token || !identityUser.current) {
      throw new DOMException('Shop identity changed', 'AbortError');
    }
    const owner = identityUser.current.id;
    const generation = ++identityGeneration.current;
    hydrationAbort.current?.abort();
    setLoading(false);
    profileAbort.current?.abort();
    const controller = new AbortController();
    profileAbort.current = controller;
    const current = () => mounted.current && !controller.signal.aborted
      && generation === identityGeneration.current && identityUser.current?.id === owner;
    try {
      const response = await fetch(`${API_BASE}/users/me`, {
        method: 'PUT', headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ full_name, email, phone }), signal: controller.signal,
      });
      const data = await response.json();
      if (!current()) throw new DOMException('Shop identity changed', 'AbortError');
      if (!response.ok || !data.ok) throw new Error(data.error || 'save failed');
      if (!data.user || String(data.user.id) !== String(owner)
        || typeof data.user.email !== 'string'
        || (data.user.full_name !== null && typeof data.user.full_name !== 'string')
        || (data.user.phone !== null && typeof data.user.phone !== 'string')) {
        throw new Error('Invalid profile response');
      }
      // Profile publication cannot replace role/session authority.
      const updated = { ...identityUser.current, full_name: data.user.full_name,
        email: data.user.email, phone: data.user.phone };
      publishUser(updated);
      return updated;
    } catch (error) {
      if (!current()) throw new DOMException('Shop identity changed', 'AbortError');
      throw error;
    } finally {
      if (profileAbort.current === controller) profileAbort.current = null;
    }
  }, [token, publishUser]);

  // Refresh display fields only after a trusted profile operation has been
  // confirmed by its exact receipt. This read cannot replace shop authority.
  const refreshProfile = useCallback(async () => {
    if (!mounted.current || pendingTransitions.current || !token || !identityUser.current)
      throw new DOMException('Shop identity changed', 'AbortError');
    const owner = identityUser.current.id;
    const role = identityUser.current.role;
    const generation = identityGeneration.current;
    const controller = new AbortController();
    profileAbort.current?.abort();
    profileAbort.current = controller;
    const current = () => mounted.current && !controller.signal.aborted
      && generation === identityGeneration.current && identityUser.current?.id === owner
      && identityUser.current?.role === role
      && shopStorage.getItem(STORAGE_KEY) === token;
    try {
      const response = await fetch(`${API_BASE}/users/me`, {
        method: 'GET', headers: { Authorization: `Bearer ${token}` }, signal: controller.signal,
      });
      const data = await response.json();
      if (!current()) throw new DOMException('Shop identity changed', 'AbortError');
      if (!response.ok || data.ok !== true || !data.user || String(data.user.id) !== String(owner)
        || data.user.role !== role || typeof data.user.email !== 'string'
        || (data.user.full_name !== null && typeof data.user.full_name !== 'string')
        || (data.user.phone !== null && typeof data.user.phone !== 'string'))
        throw new Error('Current profile is unavailable.');
      const updated = { ...identityUser.current, full_name: data.user.full_name,
        email: data.user.email, phone: data.user.phone };
      publishUser(updated);
      return updated;
    } finally {
      if (profileAbort.current === controller) profileAbort.current = null;
    }
  }, [token, publishUser]);

  const login = useCallback((username, password) => enqueueIdentityChange(async () => {
    setError(null);
    const r = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !data.token) {
      const msg = data.error || 'Sign in failed';
      setError(msg);
      throw new Error(msg);
    }
    await persistToken(data.token);
    publishUser(data.user);
    setPersonaExpiresAt(data.expiresAt || null);
    return data.user;
  }), [persistToken, enqueueIdentityChange]);

  const register = useCallback(({ username, email, password, role = 'customer', full_name }) => enqueueIdentityChange(async () => {
    setError(null);
    const r = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, email, password, role, full_name }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !data.token) {
      const msg = data.error || 'Registration failed';
      setError(msg);
      throw new Error(msg);
    }
    await persistToken(data.token);
    publishUser(data.user);
    setPersonaExpiresAt(data.expiresAt || null);
    return data.user;
  }), [persistToken, enqueueIdentityChange]);

  const logout = useCallback(() => enqueueIdentityChange(async () => {
    if (getBridgeFetchMetadata(window.fetch)?.standalone) {
      await requestStandaloneSessionIntent('logout');
      return;
    }
    try {
      const currentToken = shopStorage.getItem(STORAGE_KEY);
      await fetch(`${API_BASE}/logout`, {
        method: 'POST',
        headers: currentToken ? { Authorization: `Bearer ${currentToken}` } : {},
      });
    } catch {}
    await persistToken(null);
    publishUser(null);
  }), [token, persistToken, enqueueIdentityChange]);

  /**
   * M14 — switching role is now a logout + login flow against a DISTINCT
   * companion identity (student_customer / student_merchant / student_admin).
   * The old JWT-mutating /switch-role endpoint is kept server-side for
   * backwards compat but the UI no longer calls it. `switchRole()` returns
   * the target username so the caller (TopNav) can navigate to
   * /secureshop/login?prefill=<target_username>.
   *
   * If the caller is already on the target role, we treat this as a no-op
   * and return the current user unchanged.
   */
  const switchRole = useCallback((nextRole) => enqueueIdentityChange(async () => {
    if (!nextRole) throw new Error('nextRole required');
    if (identityUser.current && identityUser.current.role === nextRole) return identityUser.current;
    if (getBridgeFetchMetadata(window.fetch)?.standalone) {
      await requestStandaloneSessionIntent('switch-role', { role: nextRole });
      return { target_username: `student_${String(nextRole).toLowerCase()}`, target_role: nextRole };
    }
    // Log out on the server (best-effort — stateless JWT, so the client
    // just discards the token). Then the caller navigates to /login?prefill=.
    try {
      const currentToken = shopStorage.getItem(STORAGE_KEY);
      await fetch(`${API_BASE}/logout`, {
        method: 'POST',
        headers: currentToken ? { Authorization: `Bearer ${currentToken}` } : {},
      });
    } catch { /* best-effort */ }
    await persistToken(null);
    publishUser(null);
    return { target_username: `student_${String(nextRole).toLowerCase()}`, target_role: nextRole };
  }), [token, user, persistToken, enqueueIdentityChange]);

  const value = useMemo(() => ({
    user, token, loading, error,
    isAuthed: Boolean(user && token),
    login, register, logout, switchRole, saveProfile, refreshProfile, retrySession,
  }), [user, token, loading, error, login, register, logout, switchRole, saveProfile, refreshProfile, retrySession]);

  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

export { AuthCtx };
