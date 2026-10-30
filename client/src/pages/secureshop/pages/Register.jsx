import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import { safeShopRoute } from '../bridge/guestRouting.mjs';
import { safeLoginDestination } from '../utils/loginDestination.mjs';

const ROLES = [
  { value: 'customer', label: 'Customer', hint: 'shop products, chat with the customer agent' },
  { value: 'merchant', label: 'Merchant', hint: 'manage listings and reviews' },
];

function passwordStrength(pw) {
  if (!pw) return { score: 0, label: 'enter a password' };
  let s = 0;
  if (pw.length >= 8) s += 1;
  if (pw.length >= 12) s += 1;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s += 1;
  if (/\d/.test(pw)) s += 1;
  if (/[^A-Za-z0-9]/.test(pw)) s += 1;
  const labels = ['too short', 'weak', 'ok', 'good', 'strong', 'excellent'];
  return { score: Math.min(s, 5), label: labels[Math.min(s, 5)] };
}

const passwordBytes = value => new TextEncoder().encode(value).length;

export default function Register() {
  const auth = useAuth();
  return <SecureShopRegisterForm {...auth} />;
}

export function SecureShopRegisterForm({ register, isAuthed, user }) {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = safeShopRoute(params.get('next'), { publicOnly: false }) || '/secureshop/home';

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [role, setRole] = useState('customer');
  const [fullName, setFullName] = useState('');
  const [touched, setTouched] = useState({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const userRef = useRef(null);

  useEffect(() => { if (isAuthed && user) navigate(safeLoginDestination(next, user), { replace: true }); }, [isAuthed, navigate, next, user]);
  useEffect(() => { userRef.current?.focus(); }, []);

  const strength = useMemo(() => passwordStrength(password), [password]);
  const errors = useMemo(() => {
    const e = {};
    if (!username) e.username = 'required';
    else if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) e.username = '3–32 chars, letters/numbers/._-';
    if (!email) e.email = 'required';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) e.email = 'invalid email';
    if (!password) e.password = 'required';
    else if (passwordBytes(password) < 8 || passwordBytes(password) > 72) e.password = '8–72 UTF-8 bytes';
    if (confirm !== password) e.confirm = 'passwords do not match';
    return e;
  }, [username, email, password, confirm]);

  const canSubmit = Object.keys(errors).length === 0 && !busy;

  async function handleSubmit(e) {
    e.preventDefault();
    setTouched({ username: true, email: true, password: true, confirm: true });
    if (Object.keys(errors).length) return;
    setBusy(true);
    setErr(null);
    try {
      const registeredUser = await register({ username, email, password, role, full_name: fullName || null });
      navigate(safeLoginDestination(next, registeredUser), { replace: true });
    } catch (e) {
      setErr(e.message || 'Registration failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="ss-root" style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: '32px' }}>
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
        style={{ maxWidth: 640, width: '100%' }}
      >
        <Link to="/secureshop" style={{
          fontFamily: 'Fraunces, serif', fontWeight: 700, fontSize: 22,
          letterSpacing: '0.02em', textTransform: 'uppercase',
          color: 'var(--ink)', textDecoration: 'none',
        }}>
          OWASP AI SecureShop
        </Link>

        <h1 className="ss-display" style={{ fontSize: 48, margin: '28px 0 8px 0', lineHeight: 1.05 }}>
          Create your account.
        </h1>
        <p style={{ fontSize: 15, opacity: 0.75, marginBottom: 24 }}>
          Choose a customer or merchant account for your shop practice.
        </p>

        <form onSubmit={handleSubmit} className="ss-form" style={{ maxWidth: 640 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label htmlFor="reg-user">Username</label>
              <input
                id="reg-user" ref={userRef}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, username: true }))}
                autoComplete="username"
                aria-invalid={Boolean(touched.username && errors.username)}
              />
              {touched.username && errors.username && (
                <div style={{ fontSize: 12, color: 'var(--rust)' }}>{errors.username}</div>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label htmlFor="reg-full">Full name (optional)</label>
              <input id="reg-full" value={fullName} onChange={(e) => setFullName(e.target.value)} autoComplete="name" />
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label htmlFor="reg-email">Email</label>
            <input
              id="reg-email" type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, email: true }))}
              autoComplete="email"
              aria-invalid={Boolean(touched.email && errors.email)}
            />
            {touched.email && errors.email && (
              <div style={{ fontSize: 12, color: 'var(--rust)' }}>{errors.email}</div>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label htmlFor="reg-pw">Password</label>
              <input
                id="reg-pw" type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, password: true }))}
                autoComplete="new-password"
                aria-invalid={Boolean(touched.password && errors.password)}
              />
              <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
                {[0, 1, 2, 3, 4].map((i) => (
                  <div key={i} style={{
                    flex: 1, height: 3, borderRadius: 2,
                    background: i < strength.score
                      ? (strength.score >= 4 ? 'var(--kelp)' : strength.score >= 3 ? 'var(--amber)' : 'var(--signal)')
                      : 'var(--rule)',
                    transition: 'background 220ms cubic-bezier(0.16, 1, 0.3, 1)',
                  }} />
                ))}
              </div>
              <div style={{ fontSize: 11, opacity: 0.7, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                {strength.label}
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label htmlFor="reg-pw2">Confirm password</label>
              <input
                id="reg-pw2" type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, confirm: true }))}
                autoComplete="new-password"
                aria-invalid={Boolean(touched.confirm && errors.confirm)}
              />
              {touched.confirm && errors.confirm && (
                <div style={{ fontSize: 12, color: 'var(--rust)' }}>{errors.confirm}</div>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <label>Role</label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              {ROLES.map((r) => (
                <motion.button
                  key={r.value}
                  type="button"
                  whileTap={{ scale: 0.985 }}
                  onClick={() => setRole(r.value)}
                  style={{
                    textAlign: 'left', padding: 14, cursor: 'pointer',
                    border: `1px solid ${role === r.value ? 'var(--signal)' : 'var(--rule)'}`,
                    background: role === r.value ? 'color-mix(in srgb, var(--signal) 6%, transparent)' : 'transparent',
                    color: 'var(--ink)',
                  }}
                  aria-pressed={role === r.value}
                >
                  <div style={{
                    fontFamily: 'Fraunces, serif', fontSize: 17, fontWeight: 600, marginBottom: 4,
                  }}>{r.label}</div>
                  <div style={{ fontSize: 12, opacity: 0.72 }}>{r.hint}</div>
                </motion.button>
              ))}
            </div>
          </div>

          <AnimatePresence>
            {err && (
              <motion.div
                role="alert"
                aria-live="polite"
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                style={{
                  padding: '10px 12px', fontSize: 13,
                  background: 'color-mix(in srgb, var(--rust) 12%, transparent)',
                  border: '1px solid var(--rust)', color: 'var(--rust)', borderRadius: 6,
                }}
              >
                {err}
              </motion.div>
            )}
          </AnimatePresence>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 4 }}>
            <button type="submit" className="ss-btn" disabled={!canSubmit}>
              {busy ? 'Creating account…' : 'Create account'}
            </button>
            <Link to={`/secureshop/login${next && next !== '/secureshop' ? `?next=${encodeURIComponent(next)}` : ''}`}
              className="ss-btn ss-btn--ghost" style={{ textDecoration: 'none' }}>
              Sign in instead
            </Link>
          </div>
        </form>
      </motion.div>
    </div>
  );
}
