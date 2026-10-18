import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, ShoppingBag, Bell, User, ChevronDown, LogOut, Repeat, Menu, X, Check,
} from 'lucide-react';

import RoleSwitcher from './RoleSwitcher.jsx';
import { useAuth } from '../context/AuthContext';
import { useCart } from '../context/CartContext.jsx';
import { useToast } from '../context/ToastContext.jsx';

const NAV_BY_ROLE = {
  customer: [
    { to: '/secureshop/catalog',   label: 'Shop' },
    { to: '/secureshop/catalog?category=Electronics', label: 'Categories' },
    { to: '/secureshop/catalog?sort=deals', label: 'Deals' },
    { to: '/secureshop/orders',    label: 'Orders' },
  ],
  merchant: [
    { to: '/secureshop/merchant',           label: 'Overview' },
    { to: '/secureshop/merchant/listings',  label: 'Listings' },
    { to: '/secureshop/merchant/reviews',   label: 'Reviews' },
    { to: '/secureshop/merchant/pricing',   label: 'Pricing' },
    { to: '/secureshop/merchant/analytics', label: 'Analytics' },
    { to: '/secureshop/merchant/inbox',     label: 'Inbox' },
  ],
  admin: [
    { to: '/secureshop/admin',                    label: 'Overview' },
    { to: '/secureshop/admin/users',              label: 'Users' },
    { to: '/secureshop/admin/audit',              label: 'Audit' },
    { to: '/secureshop/admin/tickets',            label: 'Tickets' },
    { to: '/secureshop/admin/policies',           label: 'Policies' },
    { to: '/secureshop/admin/mcp',                label: 'MCP' },
    { to: '/secureshop/admin/access-control',     label: 'Access' },
    { to: '/secureshop/admin/system',             label: 'System' },
  ],
};

export default function TopNav({ role }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, token, isAuthed, logout, switchRole } = useAuth();
  const transport = globalThis.fetch;
  const { count: cartCount } = useCart();
  const toast = useToast();

  const items = NAV_BY_ROLE[role] || NAV_BY_ROLE.customer;
  const brandTo = role === 'merchant' ? '/secureshop/merchant'
                : role === 'admin'    ? '/secureshop/admin'
                : (isAuthed ? '/secureshop/home' : '/secureshop');

  const [q, setQ] = useState('');
  const [searchResult, setSearchResult] = useState({ query: null, role: null, token: null,
    transport: null, rows: [] });
  const hits = searchResult.query === q && searchResult.role === role
    && searchResult.token === token && searchResult.transport === transport
    ? searchResult.rows : [];
  const [searchOpen, setSearchOpen] = useState(false);
  const debounceTimer = useRef(null);

  const [notifOpen, setNotifOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const [switchSubOpen, setSwitchSubOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [traceResult, setTraceResult] = useState({ role: null, token: null, transport: null,
    status: 'idle', rows: [], error: null });
  const currentTrace = traceResult.role === role && traceResult.token === token
    && traceResult.transport === transport;
  const notifs = currentTrace ? traceResult.rows : [];
  const notifStatus = currentTrace ? traceResult.status : 'idle';
  const notifError = currentTrace ? traceResult.error : null;

  const searchRef = useRef(null);
  const notifRef = useRef(null);
  const userRef = useRef(null);

  // M14 — role switching is now a logout + login-as-target flow. Distinct
  // identities (student_customer / student_merchant / student_admin) mean
  // there's no "same user in a different lens"; each role is a separate
  // account with its own JWT. AuthContext.switchRole() logs out and returns
  // the target username; we navigate to /login?prefill=<username>.
  const beginRoleSwitch = useCallback(async (nextRole) => {
    setSwitchSubOpen(false);
    setUserOpen(false);
    if (nextRole === role) return; // no-op
    try {
      const target = await switchRole(nextRole);
      const targetUsername = target?.target_username || `student_${nextRole}`;
      toast.info(`Sign in as ${targetUsername}`);
      navigate(`/secureshop/login?prefill=${encodeURIComponent(targetUsername)}`);
    } catch (e) {
      toast.error(`Switch failed: ${e.message}`);
    }
  }, [role, switchRole, navigate, toast]);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;
    setSearchResult({ query: q, role, token, transport, rows: [] });
    if (!q.trim()) return () => { cancelled = true; controller.abort(); };
    debounceTimer.current = setTimeout(async () => {
      try {
        const r = await transport(`/api/secureshop/products?search=${encodeURIComponent(q)}&limit=8`, { signal: controller.signal });
        const j = await r.json();
        if (!r.ok || !Array.isArray(j?.products)) throw new Error('Search unavailable');
        if (!cancelled) setSearchResult({ query: q, role, token, transport, rows: j.products });
      } catch { if (!cancelled) setSearchResult({ query: q, role, token, transport, rows: [] }); }
    }, 250);
    return () => { cancelled = true; clearTimeout(debounceTimer.current); controller.abort(); };
  }, [q, role, token, transport]);

  useEffect(() => {
    if (!notifOpen || !isAuthed) return;
    if (!['customer', 'merchant', 'admin'].includes(role)) {
      setTraceResult({ role, token, transport, status: 'error', rows: [], error: 'Unsupported role' });
      return;
    }
    const controller = new AbortController();
    setTraceResult({ role, token, transport, status: 'loading', rows: [], error: null });
    transport(`/api/secureshop/agents/${role}/trace/latest?limit=5`, { signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!Array.isArray(data?.rows) || data.rows.length > 5) throw new Error('Invalid response');
        if (!controller.signal.aborted) setTraceResult({ role, token, transport,
          status: 'ready', rows: data.rows, error: null });
      })
      .catch(error => {
        const message = typeof error?.message === 'string' ? error.message : '';
        if (!controller.signal.aborted) setTraceResult({ role, token, transport,
          status: 'error', rows: [], error: message.startsWith('HTTP ') ? message : 'Read failed' });
      });
    return () => controller.abort();
  }, [notifOpen, isAuthed, role, token, transport]);

  useEffect(() => {
    const onClick = (e) => {
      if (searchRef.current && !searchRef.current.contains(e.target)) setSearchOpen(false);
      if (notifRef.current && !notifRef.current.contains(e.target)) setNotifOpen(false);
      if (userRef.current && !userRef.current.contains(e.target)) setUserOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);

  const submitSearch = (e) => {
    e.preventDefault();
    if (!q.trim()) return;
    setSearchOpen(false);
    setMobileOpen(false);
    navigate(`/secureshop/catalog?q=${encodeURIComponent(q)}`);
  };

  const handleLogout = async () => {
    setUserOpen(false);
    try {
      await logout();
      navigate('/secureshop');
    } catch (error) {
      toast.error(`Sign out failed: ${error.message}`);
    }
  };

  const isActive = (to) => {
    const [path] = to.split('?');
    return location.pathname === path;
  };

  const userInitials = useMemo(() => {
    const name = user?.full_name || user?.username || '';
    return name ? name.trim().split(/\s+/).map((s) => s[0]).slice(0, 2).join('').toUpperCase() : 'SC';
  }, [user]);

  return (
    <nav className="ss-nav" role="navigation" aria-label="Primary">
      <button
        className="ss-nav__icon-btn ss-nav__mobile-toggle"
        aria-label="Menu"
        onClick={() => setMobileOpen(true)}
        style={{ display: 'none' }}
      >
        <Menu size={20} />
      </button>
      <style>{`@media (max-width: 900px){.ss-nav__mobile-toggle{display:inline-flex !important;} .ss-nav__desktop-links{display:none !important;} .ss-nav__desktop-search{display:none !important;}}`}</style>

      <Link to={brandTo} className="ss-nav__brand" aria-label="SecureShop home">SECURESHOP</Link>

      <div className="ss-nav__desktop-links" style={{ display: 'flex', gap: 22, flex: '0 0 auto' }}>
        {items.map((it) => (
          <Link
            key={it.to}
            to={it.to}
            className={`ss-nav__link ${isActive(it.to) ? 'ss-nav__link--active' : ''}`}
          >
            {it.label}
          </Link>
        ))}
      </div>

      <div className="ss-nav__desktop-search" style={{ flex: 1, minWidth: 0, display: 'flex', justifyContent: 'center' }} ref={searchRef}>
        <form onSubmit={submitSearch} className="ss-nav__search" role="search">
          <Search size={14} className="ss-nav__search-icon" />
          <input
            className="ss-nav__search-input"
            placeholder="Search products, categories, brands…"
            value={q}
            onChange={(e) => { setQ(e.target.value); setSearchOpen(true); }}
            onFocus={() => setSearchOpen(true)}
            aria-label="Search products"
          />
          <AnimatePresence>
            {searchOpen && hits.length > 0 && (
              <motion.div
                className="ss-nav__dropdown"
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
                role="listbox"
              >
                {hits.map((p) => (
                  <Link
                    key={p.id}
                    to={`/secureshop/product/${p.id}`}
                    className="ss-nav__dropdown-item"
                    onClick={() => setSearchOpen(false)}
                    role="option"
                  >
                    <div style={{ fontWeight: 500 }}>{p.name}</div>
                    <div style={{ fontSize: 11, opacity: 0.6, fontFamily: 'var(--mono)' }}>
                      {p.category || '—'} · ${Number(p.price).toFixed(2)}
                    </div>
                  </Link>
                ))}
                <button
                  type="submit"
                  onClick={submitSearch}
                  style={{
                    width: '100%', textAlign: 'left', padding: '10px 14px',
                    background: 'var(--carbon)', color: 'var(--paper)',
                    border: 0, cursor: 'pointer', fontFamily: 'var(--mono)', fontSize: 12,
                  }}
                >
                  See all results for "{q}" →
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </form>
      </div>

      <div className="ss-nav__account-actions" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {/* Customer cart is available to guests and customer personas. */}
        {(!isAuthed || role === 'customer') && (
          <Link to="/secureshop/cart" className="ss-nav__icon-btn" aria-label={`Cart (${cartCount})`}>
            <ShoppingBag size={20} />
            {cartCount > 0 && <span className="ss-nav__badge" aria-hidden="true">{cartCount}</span>}
          </Link>
        )}

        {isAuthed && (
          <div className="ss-nav__notifications" ref={notifRef} style={{ position: 'relative' }}>
            <button
              className="ss-nav__icon-btn"
              onClick={() => setNotifOpen((v) => !v)}
              aria-label="Notifications"
              aria-expanded={notifOpen}
            >
              <Bell size={20} />
              {notifs.length > 0 && <span className="ss-nav__badge">{notifs.length}</span>}
            </button>
            <AnimatePresence>
              {notifOpen && (
                <motion.div
                  className="ss-nav__dropdown"
                  style={{ right: 0, left: 'auto', minWidth: 320 }}
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                >
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--rule)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--copper)' }}>
                    Recent agent activity
                  </div>
                  {notifStatus === 'loading' ? (
                    <div style={{ padding: 20, fontSize: 13, opacity: 0.6, textAlign: 'center' }}>Loading activity…</div>
                  ) : notifStatus === 'error' ? (
                    <div role="alert" style={{ padding: 20, fontSize: 13, opacity: 0.6, textAlign: 'center' }}>
                      Recent activity unavailable ({notifError}). Close and reopen to retry.
                    </div>
                  ) : notifs.length === 0 ? (
                    <div style={{ padding: 20, fontSize: 13, opacity: 0.6, textAlign: 'center' }}>
                      No activity yet. Ask the agents something.
                    </div>
                  ) : notifs.slice(0, 5).map((n) => (
                    <div key={n.id} className="ss-nav__dropdown-item">
                      <div style={{ fontFamily: 'var(--mono)', fontSize: 11, opacity: 0.5 }}>
                        {n.ts ? new Date(n.ts).toLocaleTimeString() : ''} · {n.kind}
                      </div>
                      <div style={{ fontSize: 13, marginTop: 2 }}>
                        {n.agent_ns || 'supervisor'}{n.tool_name ? '.' + n.tool_name : ''}
                      </div>
                    </div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

        {isAuthed && <RoleSwitcher role={role} onChange={beginRoleSwitch} />}

        {isAuthed ? (
          <div ref={userRef} style={{ position: 'relative' }}>
            <button
              className="ss-nav__avatar"
              onClick={() => setUserOpen((v) => !v)}
              aria-label="Account menu"
              aria-expanded={userOpen}
              title={user?.username || 'account'}
            >
              {userInitials}
            </button>
            <AnimatePresence>
              {userOpen && (
                <motion.div
                  className="ss-nav__dropdown"
                  style={{ right: 0, left: 'auto', minWidth: 240 }}
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                >
                  <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--rule)' }}>
                    <div style={{ fontWeight: 600 }}>{user?.full_name || user?.username}</div>
                    <div style={{ fontSize: 12, opacity: 0.65, fontFamily: 'var(--mono)' }}>{user?.email}</div>
                  </div>
                  <Link className="ss-nav__dropdown-item" to="/secureshop/account" onClick={() => setUserOpen(false)}>
                    <User size={14} style={{ verticalAlign: '-2px', marginRight: 8 }} /> Profile
                  </Link>
                  <div style={{ position: 'relative' }}>
                    <button
                      className="ss-nav__dropdown-item"
                      onClick={() => setSwitchSubOpen((v) => !v)}
                      aria-expanded={switchSubOpen}
                      aria-haspopup="menu"
                      style={{ background: 'transparent', border: 0, width: '100%', textAlign: 'left', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
                    >
                      <span>
                        <Repeat size={14} style={{ verticalAlign: '-2px', marginRight: 8 }} /> Switch role
                      </span>
                      <ChevronDown
                        size={12}
                        style={{ opacity: 0.7, transform: switchSubOpen ? 'rotate(180deg)' : 'none', transition: 'transform 160ms' }}
                      />
                    </button>
                    <AnimatePresence>
                      {switchSubOpen && (
                        <motion.div
                          role="menu"
                          initial={{ opacity: 0, y: -4 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -4 }}
                          style={{
                            padding: '4px 0', borderTop: '1px solid var(--rule)',
                            borderBottom: '1px solid var(--rule)',
                            background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))',
                          }}
                        >
                          {['customer', 'merchant', 'admin'].map((r) => (
                            <button
                              key={r}
                              role="menuitem"
                              className="ss-nav__dropdown-item"
                              onClick={() => beginRoleSwitch(r)}
                              disabled={r === role}
                              style={{
                                background: 'transparent', border: 0, width: '100%',
                                textAlign: 'left', cursor: r === role ? 'default' : 'pointer',
                                opacity: r === role ? 0.55 : 1,
                                display: 'flex', alignItems: 'center', gap: 6,
                                paddingLeft: 26,
                              }}
                            >
                              {r === role
                                ? <Check size={12} style={{ color: 'var(--kelp)' }} />
                                : <span style={{ width: 12 }} />}
                              <span style={{ textTransform: 'capitalize' }}>{r}</span>
                            </button>
                          ))}
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                  <button
                    className="ss-nav__dropdown-item"
                    onClick={handleLogout}
                    style={{ background: 'transparent', border: 0, width: '100%', textAlign: 'left', cursor: 'pointer', color: 'var(--rust)' }}
                  >
                    <LogOut size={14} style={{ verticalAlign: '-2px', marginRight: 8 }} /> Sign out
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        ) : (
          <div style={{ display: 'flex', gap: 8 }}>
            <Link to="/secureshop/login" className="ss-btn ss-btn--ghost ss-btn--sm">Sign in</Link>
            <Link to="/secureshop/register" className="ss-btn ss-btn--sm">Register</Link>
          </div>
        )}
      </div>

      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed', inset: 0, background: 'var(--paper)', zIndex: 60,
              padding: '20px', display: 'flex', flexDirection: 'column', gap: 20,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className="ss-nav__brand">SECURESHOP</div>
              <button onClick={() => setMobileOpen(false)} aria-label="Close menu" style={{ background: 'transparent', border: 0 }}>
                <X size={22} />
              </button>
            </div>
            <form onSubmit={submitSearch}>
              <input
                className="ss-nav__search-input"
                placeholder="Search..."
                value={q}
                onChange={(e) => setQ(e.target.value)}
                autoFocus
                style={{ paddingLeft: 12 }}
              />
            </form>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 18 }}>
              {items.map((it) => (
                <Link key={it.to} to={it.to} onClick={() => setMobileOpen(false)}
                      style={{ padding: '10px 0', borderBottom: '1px solid var(--rule)', color: 'var(--ink)', textDecoration: 'none' }}>
                  {it.label}
                </Link>
              ))}
              {isAuthed && (
                <>
                  {role === 'customer' && <Link to="/secureshop/cart" onClick={() => setMobileOpen(false)}
                        style={{ padding: '10px 0', borderBottom: '1px solid var(--rule)', color: 'var(--ink)', textDecoration: 'none' }}>
                    Cart ({cartCount})
                  </Link>}
                  <Link to="/secureshop/account" onClick={() => setMobileOpen(false)}
                        style={{ padding: '10px 0', borderBottom: '1px solid var(--rule)', color: 'var(--ink)', textDecoration: 'none' }}>
                    Account
                  </Link>
                  <button onClick={handleLogout}
                          style={{ padding: '10px 0', color: 'var(--rust)', background: 'transparent', border: 0, textAlign: 'left', fontSize: 18 }}>
                    Sign out
                  </button>
                </>
              )}
              {!isAuthed && (
                <>
                  <Link to="/secureshop/login" onClick={() => setMobileOpen(false)}
                        style={{ padding: '10px 0', borderBottom: '1px solid var(--rule)', color: 'var(--signal)', textDecoration: 'none' }}>
                    Sign in
                  </Link>
                  <Link to="/secureshop/register" onClick={() => setMobileOpen(false)}
                        style={{ padding: '10px 0', color: 'var(--ink)', textDecoration: 'none' }}>
                    Register
                  </Link>
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
}

// M14 — the SwitchRolePasswordModal was removed. Role changes now go through
// AuthContext.switchRole() which performs a logout and returns the target
// companion username. The TopNav navigates to
// /secureshop/login?prefill=<username> so the user only types the password.
