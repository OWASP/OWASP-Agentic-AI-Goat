import React, { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { mountShopFrame } from './bridge/handshake.mjs';
import { compileGuestRead } from './bridge/guestRead.mjs';
import { safeShopRoute } from './bridge/guestRouting.mjs';
import { createGuestCartHost, exactCartMessage, GUEST_CART_CHANNEL, validGuestCartItems } from './bridge/guestCartProtocol.mjs';
import NotFound from './pages/NotFound.jsx';
import './theme.css';

const CHANNEL = 'owasp-ai-goat-secureshop-guest-route-v1';

function ShopOpening({ message = 'Opening OWASP AI SecureShop…', error = false, onRetry }) {
  return <main className="ss-root" style={{ minHeight: '100dvh', display: 'grid', placeItems: 'center',
    background: 'var(--paper, #f8f6f1)', color: 'var(--ink, #242422)' }}>
    <div style={{ textAlign: 'center', padding: 24 }}>
      <div className="ss-mono" style={{ fontSize: 12, letterSpacing: '0.12em', marginBottom: 20 }}>OWASP AI SecureShop</div>
      {!error && <div className="ss-skel" aria-hidden="true" style={{ width: 96, height: 3, margin: '0 auto 20px' }} />}
      <p role={error ? 'alert' : 'status'}>{message}</p>
      {error && <><button type="button" className="ss-btn ss-btn--ghost" onClick={onRetry}>Retry</button>{' '}
        <a href="/secureshop" className="ss-btn ss-btn--ghost">Back to home</a></>}
    </div>
  </main>;
}

// Public storefront stays in the same opaque sandbox as the authenticated
// shop. The parent owns a read-only API bridge and never hands over a launch,
// platform credential, shop persona, or mutable shop state.
export default function SecureShopGuestLanding() {
  const location = useLocation();
  const navigate = useNavigate();
  const navigateRef = useRef(navigate);
  navigateRef.current = navigate;
  const host = useRef(null);
  const frame = useRef(null);
  const session = useRef(null);
  const cartHost = useRef(null);
  if (!cartHost.current) {
    let storage = null;
    try { storage = window.sessionStorage; } catch { /* page-local cart remains usable */ }
    cartHost.current = createGuestCartHost(storage);
  }
  const route = `${location.pathname}${location.search}${location.hash}`;
  const routeRef = useRef(route);
  routeRef.current = route;
  const publicRoute = safeShopRoute(route);
  const protectedRoute = publicRoute ? null : safeShopRoute(route, { publicOnly: false });
  const [status, setStatus] = useState('visible');
  const [retry, setRetry] = useState(0);
  const frameAllowed = Boolean(publicRoute) && ['visible', 'ready'].includes(status);

  useEffect(() => {
    if (protectedRoute) navigateRef.current(`/secureshop/login?next=${encodeURIComponent(protectedRoute)}`, { replace: true });
  }, [protectedRoute]);

  useEffect(() => {
    if (!frameAllowed || !host.current) return undefined;
    const initial = safeShopRoute(routeRef.current);
    if (!initial) return undefined;
    const element = document.createElement('iframe');
    element.title = 'OWASP AI SecureShop storefront';
    element.setAttribute('aria-label', 'OWASP AI SecureShop storefront');
    Object.assign(element.style, { width: '100%', height: '100%', border: '0', display: 'block' });
    const url = `/secureshop-frame.html?guest=1&entry=${encodeURIComponent(initial)}`;
    const active = mountShopFrame({ frame: element, url, origin: window.location.origin,
      waitForInitialLoad: true,
      compileOperation: compileGuestRead, transportOptions: { publicOnly: true },
      onDisconnect: () => {
        if (session.current === active) setStatus('connection-error');
      } });
    frame.current = element;
    session.current = active;
    host.current.replaceChildren(element);
    active.ready.then(() => {
      if (session.current === active) {
        const nonce = new URL(element.src).hash.slice(1);
        if (nonce) element.contentWindow?.postMessage({ channel: GUEST_CART_CHANNEL,
          type: 'hydrate', nonce, ...cartHost.current.current() }, '*');
        setStatus('ready');
      }
    }).catch(() => {
      if (session.current === active) setStatus('connection-error');
    });
    return () => {
      active.close();
      element.remove();
      if (frame.current === element) frame.current = null;
      if (session.current === active) session.current = null;
    };
  }, [frameAllowed, retry]);

  useEffect(() => {
    const element = frame.current;
    if (!element || !session.current || status !== 'ready') return;
    const current = safeShopRoute(route);
    const nonce = new URL(element.src).hash.slice(1);
    if (current && nonce) element.contentWindow?.postMessage({ channel: CHANNEL,
      type: 'set-route', nonce, route: current }, '*');
  }, [route, status]);

  useEffect(() => {
    const onMessage = event => {
      const element = frame.current;
      if (!element || event.source !== element.contentWindow || event.origin !== 'null') return;
      const data = event.data;
      const nonce = new URL(element.src).hash.slice(1);
      if (exactCartMessage(data, 'snapshot') && data.nonce === nonce) {
        if (!validGuestCartItems(data.items)) return;
        const result = cartHost.current.commit(data.baseRevision, data.items);
        if (result === 'saved') element.contentWindow?.postMessage({ channel: GUEST_CART_CHANNEL,
          type: 'ack', nonce, revision: cartHost.current.current().revision }, '*');
        else if (result === 'stale') element.contentWindow?.postMessage({ channel: GUEST_CART_CHANNEL,
          type: 'hydrate', nonce, ...cartHost.current.current() }, '*');
        else if (result === 'unavailable') element.contentWindow?.postMessage({ channel: GUEST_CART_CHANNEL,
          type: 'storage-error', nonce }, '*');
        return;
      }
      if (!data || Object.keys(data).length !== 4 || data.channel !== CHANNEL
        || !['route', 'auth', 'register'].includes(data.type)
        || data.nonce !== nonce) return;
      const target = safeShopRoute(data.route, { publicOnly: data.type === 'route' });
      if (!target) return;
      if (data.type === 'auth' || data.type === 'register') {
        navigate(`/secureshop/${data.type === 'register' ? 'register' : 'login'}?next=${encodeURIComponent(target)}`);
      } else if (target !== routeRef.current) {
        navigate(target);
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [navigate]);

  if (!publicRoute) {
    if (protectedRoute) return <ShopOpening message="Opening shop sign in…" />;
    return <main className="ss-root" aria-label="OWASP AI SecureShop"><NotFound /></main>;
  }
  if (status === 'connection-error') {
    return <ShopOpening error message="OWASP AI SecureShop is currently unavailable." onRetry={() => { setStatus('visible'); setRetry(n => n + 1); }} />;
  }
  return <main aria-label="OWASP AI SecureShop" style={{ position: 'fixed', inset: 0, zIndex: 1000,
    background: 'var(--paper, #f8f6f1)' }}>
    <div ref={host} style={{ width: '100%', height: '100dvh' }} />
    {status !== 'ready' && <div style={{ position: 'absolute', inset: 0 }}><ShopOpening /></div>}
  </main>;
}
