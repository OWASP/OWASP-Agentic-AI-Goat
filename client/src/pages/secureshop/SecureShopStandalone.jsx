import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import SecureShopAccess from './SecureShopAccess.jsx';
import { SecureShopRegisterForm } from './pages/Register.jsx';
import SecureShopGuestLanding from './SecureShopGuestLanding.jsx';
import SecureShopStandaloneBound from './SecureShopStandaloneBound.jsx';
import SecureShopPassword from './SecureShopPassword.jsx';
import { createStandaloneShopClient } from './standaloneClient.mjs';
import { safeShopRoute } from './bridge/guestRouting.mjs';
import { STANDALONE_SESSION_CHANNEL } from './bridge/standaloneIntents.mjs';
import Spinner from './components/Spinner.jsx';
import './theme.css';

function ShopOpening({ message = 'Opening OWASP AI SecureShop…', error, onRetry }) {
  return <main className="ss-root" style={{ minHeight: '100dvh', display: 'grid', placeItems: 'center',
    background: 'var(--paper, #f8f6f1)' }}>
    <div style={{ textAlign: 'center', padding: 24 }}>
      <div className="ss-mono" style={{ fontSize: 12, letterSpacing: '0.12em' }}>OWASP AI SecureShop</div>
      {!error && <Spinner aria-hidden="true" style={{ display: 'block', margin: '20px auto 0' }} />}
      <p role={error ? 'alert' : 'status'}>{error || message}</p>
      {error && <button type="button" className="ss-btn ss-btn--ghost" onClick={onRetry}>Retry</button>}
    </div>
  </main>;
}

export default function SecureShopStandalone({ client: suppliedClient }) {
  const location = useLocation();
  const navigate = useNavigate();
  const clientRef = useRef(null);
  if (!clientRef.current) clientRef.current = suppliedClient || createStandaloneShopClient({
    fetchImpl: (...args) => window.fetch(...args),
  });
  const client = clientRef.current;
  const [session, setSession] = useState({ status: 'loading', user: null, expiresAt: null, error: null });
  const [check, setCheck] = useState(0);
  const [boundEpoch, setBoundEpoch] = useState(0);
  const routeRef = useRef(`${location.pathname}${location.search}${location.hash}`);
  routeRef.current = `${location.pathname}${location.search}${location.hash}`;
  const sessionGeneration = useRef(0);
  const mounted = useRef(false);
  const logoutPending = useRef(false);
  const isCurrentSession = useCallback(generation => mounted.current
    && sessionGeneration.current === generation, []);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; sessionGeneration.current += 1; };
  }, []);

  useEffect(() => {
    if (session.logoutDestination && routeRef.current === session.logoutDestination) {
      logoutPending.current = false;
      setSession(current => current.logoutDestination === session.logoutDestination
        ? { ...current, logoutDestination: null } : current);
    }
  }, [location.pathname, location.search, location.hash, session.logoutDestination]);

  useEffect(() => {
    const controller = new AbortController();
    const generation = ++sessionGeneration.current;
    client.session(controller.signal).then(result => {
      if (!controller.signal.aborted && isCurrentSession(generation)) setSession({ status: 'ready', user: result?.user || null,
        expiresAt: result?.expiresAt || null, error: null });
    }).catch(error => {
      if (!controller.signal.aborted && isCurrentSession(generation)) setSession(error.status === 401
        ? { status: 'ready', user: null, expiresAt: null, error: null }
        : { status: 'error', user: null, expiresAt: null,
          error: 'Unable to verify the shop session right now. Retry when OWASP AI SecureShop is ready.', retry: 'session' });
    });
    return () => controller.abort();
  }, [client, check, isCurrentSession]);

  const renewalPending = useRef(false);
  const renewBound = useCallback(async () => {
    if (renewalPending.current || logoutPending.current) return;
    renewalPending.current = true;
    const generation = ++sessionGeneration.current;
    try {
      const result = await client.renew();
      if (!isCurrentSession(generation)) return;
      setSession({ status: 'ready', user: result.user, expiresAt: result.expiresAt, error: null });
      setBoundEpoch(value => value + 1);
    } catch (error) {
      if (!isCurrentSession(generation)) return;
      if (error.status === 401) {
        setSession({ status: 'ready', user: null, expiresAt: null, error: null });
        navigate(`/secureshop/login?next=${encodeURIComponent(safeShopRoute(routeRef.current, { publicOnly: false }) || '/secureshop')}`);
      } else setSession({ status: 'error', user: null, expiresAt: null,
        error: 'Unable to renew the shop session right now. Retry when OWASP AI SecureShop is ready.', retry: 'renew' });
    } finally { renewalPending.current = false; }
  }, [client, navigate, isCurrentSession]);

  const login = useCallback(async (username, password) => {
    const generation = ++sessionGeneration.current;
    const result = await client.login(username, password);
    if (!isCurrentSession(generation)) throw new Error('Shop session changed during sign-in; try again');
    setSession({ status: 'ready', user: result.user, expiresAt: result.expiresAt, error: null });
    return result.user;
  }, [client, isCurrentSession]);
  const register = useCallback(async ({ username, email, password, role }) => {
    const generation = ++sessionGeneration.current;
    const result = await client.register({ username, email, password, role });
    if (!isCurrentSession(generation)) throw new Error('Shop session changed during registration; try again');
    setSession({ status: 'ready', user: result.user, expiresAt: result.expiresAt, error: null });
    return result.user;
  }, [client, isCurrentSession]);

  const onSessionIntent = useCallback(async ({ type, role, frame, nonce, requestId }) => {
    if (type === 'password-route') { navigate('/secureshop/password'); return; }
    if (type === 'auth-required') {
      if (logoutPending.current) return;
      const generation = ++sessionGeneration.current;
      try {
        const result = await client.session();
        if (!isCurrentSession(generation)) return;
        if (result?.user) {
          setSession({ status: 'ready', user: result.user, expiresAt: result.expiresAt || null, error: null });
          setBoundEpoch(value => value + 1);
          return;
        }
      } catch (error) {
        if (!isCurrentSession(generation)) return;
        if (error.status !== 401) {
          setSession({ status: 'error', user: null, expiresAt: null,
            error: 'Unable to verify the shop session right now. Retry when OWASP AI SecureShop is ready.', retry: 'session' });
          return;
        }
      }
      if (!isCurrentSession(generation)) return;
      setSession({ status: 'ready', user: null, expiresAt: null, error: null });
      navigate(`/secureshop/login?next=${encodeURIComponent(safeShopRoute(routeRef.current, { publicOnly: false }) || '/secureshop')}`);
      return;
    }
    if (!['logout', 'switch-role'].includes(type) || !requestId || !frame || !nonce) return;
    if (logoutPending.current) return;
    logoutPending.current = true;
    const generation = ++sessionGeneration.current;
    try {
      await client.logout();
      if (!isCurrentSession(generation)) { logoutPending.current = false; return; }
      frame.contentWindow?.postMessage({ channel: STANDALONE_SESSION_CHANNEL, type: 'result',
        nonce, requestId, ok: true }, '*');
      // Give the verified frame result a turn to arrive before closing it.
      window.setTimeout(() => {
        if (!isCurrentSession(generation)) return;
        const logoutDestination = type === 'switch-role'
          ? `/secureshop/login?prefill=student_${role}` : '/secureshop';
        // The protected-route guard must honor the completed session action
        // even if React renders once before the router reaches its destination.
        setSession({ status: 'ready', user: null, expiresAt: null, error: null, logoutDestination });
        navigate(logoutDestination, { replace: true });
      }, 50);
    } catch (error) {
      logoutPending.current = false;
      if (!isCurrentSession(generation)) return;
      frame.contentWindow?.postMessage({ channel: STANDALONE_SESSION_CHANNEL, type: 'result',
        nonce, requestId, ok: false, error: error.message || 'Shop sign-out failed' }, '*');
    }
  }, [client, navigate, isCurrentSession]);

  if (session.status === 'loading') return <ShopOpening />;
  if (session.status === 'error' && location.pathname !== '/secureshop/login') return <ShopOpening error={session.error}
    onRetry={() => {
      if (session.retry === 'renew') { setSession(value => ({ ...value, status: 'loading' })); renewBound(); }
      else { setSession(value => ({ ...value, status: 'loading' })); setCheck(value => value + 1); }
    }} />;
  if (!session.user && session.logoutDestination && routeRef.current !== session.logoutDestination) {
    return <Navigate to={session.logoutDestination} replace />;
  }
  if (location.pathname === '/secureshop/login') return <SecureShopAccess login={login}
    user={session.user} sessionError={session.error}
    retrySession={() => setCheck(value => value + 1)} />;
  if (location.pathname === '/secureshop/register') return <SecureShopRegisterForm register={register}
    isAuthed={Boolean(session.user)} user={session.user} />;
  if (location.pathname === '/secureshop/password') {
    if (!session.user) return <ShopOpening error="Sign in to change your shop password."
      onRetry={() => navigate('/secureshop/login?next=%2Fsecureshop%2Fpassword')} />;
    return <SecureShopPassword client={client} onChanged={() => {
      sessionGeneration.current += 1;
      setSession({ status: 'ready', user: null, expiresAt: null, error: null });
      navigate('/secureshop/login');
    }} />;
  }
  const requestedRoute = safeShopRoute(routeRef.current, { publicOnly: false });
  if (!session.user && requestedRoute && !safeShopRoute(routeRef.current)) {
    return <Navigate to={`/secureshop/login?next=${encodeURIComponent(requestedRoute)}`} replace />;
  }
  return session.user
    ? <SecureShopStandaloneBound key={`${session.user.principalId}:${boundEpoch}`} client={client}
      user={session.user} onSessionIntent={onSessionIntent} onRenewNeeded={renewBound} />
    : <SecureShopGuestLanding />;
}
