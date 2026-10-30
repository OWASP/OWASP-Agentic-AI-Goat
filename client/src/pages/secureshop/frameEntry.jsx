import React from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import '../../index.css';
import SecureShopApp from './SecureShopApp';
import { startShopFrame } from './bridge/runtime.mjs';
import { guestNavigationIntent, safeShopRoute } from './bridge/guestRouting.mjs';
import { createGuestCartFrameChannel } from './bridge/guestCartFrame.mjs';
import { validGuestCartItems } from './bridge/guestCartProtocol.mjs';
import { GuestCartChannelContext } from './bridge/GuestCartChannelContext.jsx';
import { STANDALONE_SESSION_CHANNEL } from './bridge/standaloneIntents.mjs';
import { BOUND_CART_REFRESH_CHANNEL, BOUND_CART_REFRESH_EVENT } from './bridge/cartRefresh.mjs';

const GUEST_CHANNEL = 'owasp-ai-goat-secureshop-guest-route-v1';
const BOUND_CHANNEL = 'owasp-ai-goat-secureshop-bound-route-v1';

function GuestRouteSync({ origin, nonce }) {
  const location = useLocation();
  const navigate = useNavigate();
  const current = `${location.pathname}${location.search}${location.hash}`;
  const previousPublic = React.useRef(safeShopRoute(current) || '/secureshop');
  React.useEffect(() => {
    const intent = guestNavigationIntent(current, previousPublic.current);
    if (!intent) return;
    if (intent.kind === 'route') previousPublic.current = intent.route;
    window.parent.postMessage({ channel: GUEST_CHANNEL, type: intent.kind,
      nonce, route: intent.route }, origin);
  }, [current, nonce, origin]);
  React.useEffect(() => {
    const onMessage = event => {
      const data = event.data;
      if (event.source !== window.parent || event.origin !== origin || !data
        || Object.keys(data).length !== 4 || data.channel !== GUEST_CHANNEL
        || data.type !== 'set-route' || data.nonce !== nonce) return;
      const route = safeShopRoute(data.route);
      if (route && route !== current) navigate(route, { replace: true });
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [current, navigate, nonce, origin]);
  return safeShopRoute(current) ? <SecureShopApp /> : null;
}

function BoundRouteSync({ origin, nonce, standalone }) {
  const location = useLocation();
  const navigate = useNavigate();
  const current = `${location.pathname}${location.search}${location.hash}`;
  React.useEffect(() => {
    const route = safeShopRoute(current, { publicOnly: false });
    if (route) window.parent.postMessage({ channel: BOUND_CHANNEL, type: 'route', nonce, route }, origin);
    else if (standalone && /^\/secureshop\/(?:v2\/)?login\/?$/.test(location.pathname)) {
      window.parent.postMessage({ channel: STANDALONE_SESSION_CHANNEL, type: 'auth-required', nonce }, origin);
    }
  }, [current, location.pathname, nonce, origin, standalone]);
  React.useEffect(() => {
    const onMessage = event => {
      const data = event.data;
      if (event.source !== window.parent || event.origin !== origin || event.ports.length !== 0
        || !data || data.nonce !== nonce) return;
      if (standalone && Object.keys(data).length === 5
        && data.channel === BOUND_CART_REFRESH_CHANNEL && data.type === 'refresh'
        && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(data.requestId)
        && validGuestCartItems(data.items) && data.items.length > 0) {
        window.dispatchEvent(new CustomEvent(BOUND_CART_REFRESH_EVENT, { detail: {
          requestId: data.requestId, items: data.items, nonce, origin,
        } }));
        return;
      }
      if (Object.keys(data).length !== 4 || data.channel !== BOUND_CHANNEL || data.type !== 'set-route') return;
      const route = safeShopRoute(data.route, { publicOnly: false });
      if (route && route !== current) navigate(route, { replace: true });
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [current, navigate, nonce, origin]);
  return <SecureShopApp />;
}

// This entry runs only inside the opaque sandbox. It never loads platform auth
// or reads platform storage. In-frame routing must not replace the document
// whose message channel owns the current launch generation.
const mount = document.getElementById('root');
const origin = new URL(import.meta.url).origin;
const frameParams = new URL(window.location.href).searchParams;
const guest = frameParams.get('guest') === '1';
const standalone = !guest && frameParams.get('standalone') === '1';
const entry = safeShopRoute(frameParams.get('entry'), { publicOnly: guest }) || '/secureshop';
const nonce = window.location.hash.slice(1);
if (window.parent === window) {
  mount.textContent = 'Open OWASP AI SecureShop from your account.';
} else {
  startShopFrame({ origin, guest, standalone, enableBoundReviews: !guest, render() {
    mount.removeAttribute('role');
    const cartChannel = guest ? createGuestCartFrameChannel({ frameWindow: window, origin, nonce }) : null;
    const root = createRoot(mount);
    root.render(<React.StrictMode>
      <MemoryRouter initialEntries={[entry]}>
        <GuestCartChannelContext.Provider value={cartChannel}>
          {guest ? <GuestRouteSync origin={origin} nonce={nonce} /> : <BoundRouteSync origin={origin} nonce={nonce} standalone={standalone} />}
        </GuestCartChannelContext.Provider>
        <ToastContainer position="top-right" autoClose={5000} />
      </MemoryRouter>
    </React.StrictMode>);
    return () => { root.unmount(); cartChannel?.close(); };
  } }).catch(() => {
    mount.setAttribute('role', 'alert');
    mount.textContent = 'Your OWASP AI SecureShop connection is unavailable. Return to OWASP AI SecureShop and reconnect.';
  });
}
