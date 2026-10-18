import React, { useEffect, useRef, useSyncExternalStore } from 'react';
import { useOutlet, useLocation } from 'react-router-dom';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { Sparkles, X } from 'lucide-react';

import TopNav from './TopNav.jsx';
import AgentLane from './AgentLane.jsx';
import Footer from './Footer.jsx';
import { useAuth } from '../context/AuthContext';
import { CartProvider } from '../context/CartContext.jsx';
import { ToastProvider } from '../context/ToastContext.jsx';
import '../theme.css';

const MOBILE_LANE_QUERY = '(max-width: 900px)';
const isMobileLane = () => globalThis.matchMedia?.(MOBILE_LANE_QUERY).matches ?? false;
function subscribeMobileLane(onChange) {
  const query = globalThis.matchMedia?.(MOBILE_LANE_QUERY);
  if (!query) return () => {};
  if (query.addEventListener) {
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }
  query.addListener(onChange);
  return () => query.removeListener(onChange);
}

export default function Shell() {
  const location = useLocation();
  // Capture the matched element for this pathname. A live Outlet inside an
  // exiting presence can mount the next page under the previous exit state.
  const outlet = useOutlet();
  const { isAuthed, user, error: sessionError, retrySession } = useAuth();
  const reduce = useReducedMotion();

  // Wave 5B U8 — role is derived from the JWT via AuthContext. No local state,
  // no drift between UI role and token role. TopNav's role selector delegates
  // to AuthContext.switchRole() which rotates the JWT server-side.
  const role = user?.role || 'customer';
  const [laneOpen, setLaneOpen] = React.useState(false);
  const mobileLane = useSyncExternalStore(subscribeMobileLane, isMobileLane, () => false);
  const announceRef = useRef(null);
  const laneToggleRef = useRef(null);

  useEffect(() => {
    if (announceRef.current) {
      const p = location.pathname;
      const label = p.split('/').filter(Boolean).slice(-1)[0] || 'home';
      announceRef.current.textContent = `Navigated to ${label}`;
    }
  }, [location.pathname]);

  const showLane = isAuthed;
  const laneClass = showLane ? '' : 'ss-shell--no-lane';
  const productMatch = location.pathname.match(/^\/secureshop\/(?:v2\/)?product\/(\d+)\/?$/);
  const selectedProductId = productMatch ? Number(productMatch[1]) : null;

  return (
    <ToastProvider>
      <CartProvider>
        <div className="ss-root">
          <div className={`ss-shell ${laneClass}`}>
            <TopNav role={role} />
            {sessionError && <div role="alert" style={{ padding: '10px 20px',
              borderBottom: '1px solid var(--rust)', color: 'var(--rust)', fontSize: 13 }}>
              {sessionError}{' '}<button type="button" className="ss-btn ss-btn--sm ss-btn--ghost"
                onClick={retrySession}>Retry session</button>
            </div>}
            <main className="ss-main" data-testid="main" id="ss-main">
              <AnimatePresence mode="wait">
                <motion.div
                  key={location.pathname}
                  initial={reduce ? { opacity: 0 } : { opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={reduce ? { opacity: 0 } : { opacity: 0, y: -6 }}
                  transition={{ duration: reduce ? 0 : 0.24, ease: [0.16, 1, 0.3, 1] }}
                >
                  {outlet}
                </motion.div>
              </AnimatePresence>
            </main>
            {showLane && <div className={`ss-lane-mobile-content ss-lane-host${laneOpen ? ' ss-lane-host--open' : ''}${reduce ? ' ss-lane-host--reduced' : ''}`}
              aria-hidden={mobileLane && !laneOpen} inert={mobileLane && !laneOpen}>
              <div className="ss-lane-host__bar">
                <div className="ss-lane-host__title">Agent lane</div>
                <button type="button" onClick={() => { setLaneOpen(false); laneToggleRef.current?.focus(); }}
                  aria-label="Close" className="ss-lane-host__close"><X size={20} /></button>
              </div>
              <AgentLane role={role} productId={selectedProductId} instance={mobileLane ? 'mobile' : 'desktop'} />
            </div>}
            <Footer />
          </div>

          {/* Screen reader route announcer */}
          <div
            ref={announceRef}
            aria-live="polite"
            aria-atomic="true"
            style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}
          />

          {showLane && <button ref={laneToggleRef} className="ss-fab ss-fab--mobile"
            onClick={() => setLaneOpen(value => !value)}
            aria-label={laneOpen ? 'Close agent lane' : 'Open agent lane'} type="button">
            {laneOpen ? <X size={22} /> : <Sparkles size={22} />}
          </button>}
        </div>
      </CartProvider>
    </ToastProvider>
  );
}
