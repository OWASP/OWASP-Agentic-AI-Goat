import React, { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import { safeLoginDestination } from '../utils/loginDestination.mjs';
import GoatBrand from '../../../components/GoatBrand';

// M14 — the three DISTINCT identities. Post-M14 role changes go through
// logout + login-as-target instead of mutating a JWT in place. The legacy
// student_c/m/a rows still exist as aliases.
const QUICK_PICKS = [
  { username: 'student_customer', role: 'Customer', hint: 'browse, buy, chat with the customer agent' },
  { username: 'student_merchant', role: 'Merchant', hint: 'manage listings, moderate reviews, analytics' },
  { username: 'student_admin',    role: 'Admin',    hint: 'policies, MCP registry, system diagnostics' },
];

export default function Login() {
  const { login, isAuthed, user, error, retrySession } = useAuth();
  return <SecureShopLoginForm login={login} isAuthed={isAuthed} user={user}
    sessionError={error} retrySession={retrySession} />;
}

export function SecureShopLoginForm({ login, isAuthed = false, user = null,
  sessionError = null, retrySession }) {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = params.get('next') || '/secureshop/home';
  const destination = loggedInUser => safeLoginDestination(next, loggedInUser);

  // M14 — the RoleSwitcher redirects here with ?prefill=<target_username>
  // so the user only has to type the password. If the prefill target is one
  // of the demo accounts we auto-fill student123 too so demos flow smoothly.
  const prefill = params.get('prefill') || '';
  const isDemoAccount = prefill && (
    prefill.startsWith('student_') || prefill === 'alice' || prefill === 'bob'
  );
  const [username, setUsername] = useState(prefill);
  const [password, setPassword] = useState(isDemoAccount ? 'student123' : '');
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const userRef = useRef(null);
  const pwRef = useRef(null);
  const previousPrefill = useRef(prefill);

  useEffect(() => {
    if (isAuthed && user) navigate(destination(user), { replace: true });
  }, [isAuthed, navigate, next, user]);

  useEffect(() => {
    // The standalone controller may render sign-in after sign-out, then add
    // ?prefill in the next navigation without remounting this form.
    if (previousPrefill.current !== prefill) {
      previousPrefill.current = prefill;
      setUsername(prefill);
      setPassword(isDemoAccount ? 'student123' : '');
      setErr(null);
    }
    // If prefill was supplied, focus the password field so the user just
    // hits Enter after landing here from the RoleSwitcher.
    if (prefill) pwRef.current?.focus();
    else userRef.current?.focus();
  }, [prefill]);

  async function handleSubmit(e) {
    e.preventDefault();
    setErr(null);
    if (!username) { userRef.current?.focus(); setErr('username required'); return; }
    if (!password) { pwRef.current?.focus(); setErr('password required'); return; }
    setBusy(true);
    try {
      const loggedInUser = await login(username, password);
      navigate(destination(loggedInUser), { replace: true });
    } catch (e) {
      setErr(e.message || 'Sign in failed');
      pwRef.current?.select();
    } finally {
      setBusy(false);
    }
  }

  function quickPick(u) {
    setUsername(u);
    setPassword('student123');
    setErr(null);
    setTimeout(() => pwRef.current?.focus(), 0);
  }

  return (
    <div className="ss-root" style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: '32px' }}>
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
        style={{
          display: 'grid', gridTemplateColumns: 'minmax(0, 480px) minmax(0, 380px)', gap: 48,
          alignItems: 'start', maxWidth: 940, width: '100%',
        }}
      >
        <div>
          <Link to="/secureshop" style={{
            fontFamily: 'Fraunces, serif', fontWeight: 700, fontSize: 22,
            letterSpacing: '0.02em', textTransform: 'uppercase',
            color: 'var(--ink)', textDecoration: 'none',
          }}>
            <GoatBrand shop />
          </Link>

          <h1 className="ss-display" style={{ fontSize: 56, margin: '32px 0 12px 0', lineHeight: 1.02 }}>
            Sign in.
          </h1>
          <p style={{ fontSize: 16, opacity: 0.75, maxWidth: '38ch', marginBottom: 28 }}>
            SecureShop v2 is an agentic e-commerce demo. Use a demo account or your own if you already registered.
          </p>

          <form onSubmit={handleSubmit} className="ss-form" style={{ maxWidth: 380 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label htmlFor="ss-login-user">Username</label>
              <input
                id="ss-login-user"
                ref={userRef}
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                aria-invalid={Boolean(err && !username)}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label htmlFor="ss-login-pw">Password</label>
              <div style={{ position: 'relative' }}>
                <input
                  id="ss-login-pw"
                  ref={pwRef}
                  type={showPw ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  aria-invalid={Boolean(err && !password)}
                  style={{ width: '100%', paddingRight: 60 }}
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  className="ss-btn ss-btn--ghost"
                  style={{
                    position: 'absolute', right: 4, top: 4, bottom: 4,
                    padding: '0 10px', fontSize: 12,
                    minWidth: 52,
                  }}
                >
                  {showPw ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>

            <AnimatePresence>
              {(err || sessionError) && (
                <motion.div
                  role="alert"
                  aria-live="polite"
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  transition={{ duration: 0.22 }}
                  style={{
                    padding: '10px 12px',
                    background: 'color-mix(in srgb, var(--rust) 12%, transparent)',
                    border: '1px solid var(--rust)', color: 'var(--rust)',
                    fontSize: 13, borderRadius: 6,
                  }}
                >
                  {err || sessionError}
                  {!err && sessionError && retrySession && <button type="button" className="ss-btn ss-btn--sm ss-btn--ghost"
                    onClick={retrySession} style={{ marginLeft: 12 }}>Retry session</button>}
                </motion.div>
              )}
            </AnimatePresence>

            <button
              type="submit"
              className="ss-btn"
              disabled={busy}
              style={{ marginTop: 4 }}
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>

            <div style={{ fontSize: 13, opacity: 0.75, marginTop: 6 }}>
              No account? <Link to={`/secureshop/register${next && next !== '/secureshop/home' ? `?next=${encodeURIComponent(next)}` : ''}`} style={{ color: 'var(--signal)' }}>Register</Link>
            </div>
          </form>
        </div>

        <div>
          <div style={{
            fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase',
            color: 'var(--copper)', marginBottom: 12,
          }}>
            Demo accounts
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {QUICK_PICKS.map((qp) => (
              <motion.button
                key={qp.username}
                type="button"
                whileHover={{ x: 2 }}
                whileTap={{ scale: 0.985 }}
                transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
                onClick={() => quickPick(qp.username)}
                style={{
                  textAlign: 'left', padding: 16,
                  border: '1px solid var(--rule)', background: 'transparent',
                  color: 'var(--ink)', cursor: 'pointer',
                }}
              >
                <div style={{ fontSize: 10, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--copper)' }}>
                  {qp.role}
                </div>
                <div style={{ fontFamily: 'Fraunces, serif', fontSize: 18, fontWeight: 600, margin: '4px 0 4px 0' }}>
                  {qp.username}
                </div>
                <div style={{ fontSize: 12, opacity: 0.7 }}>{qp.hint}</div>
              </motion.button>
            ))}
          </div>

          <div style={{
            marginTop: 20, fontSize: 12, opacity: 0.6,
            fontFamily: 'JetBrains Mono, monospace',
          }}>
            All demo passwords: <span style={{ color: 'var(--ink)' }}>student123</span>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
