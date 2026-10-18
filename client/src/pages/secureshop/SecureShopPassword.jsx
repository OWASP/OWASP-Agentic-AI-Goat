import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import './theme.css';

export default function SecureShopPassword({ client, onChanged }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const submit = async event => {
    event.preventDefault();
    const bytes = new TextEncoder().encode(next).byteLength;
    if (bytes < 8 || bytes > 72) { setError('Use a new password of 8 to 72 UTF-8 bytes.'); return; }
    if (next !== confirm) { setError('New passwords do not match.'); return; }
    setBusy(true); setError('');
    try { await client.password(current, next); onChanged(); }
    catch (cause) { setError(cause.message || 'Could not change password.'); }
    finally { setBusy(false); }
  };
  return <main className="ss-root" style={{ minHeight: '100dvh', display: 'grid', placeItems: 'center', padding: 32 }}>
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }} style={{ width: '100%', maxWidth: 480 }}>
      <Link to="/secureshop/account" style={{ fontFamily: 'Fraunces, serif', fontWeight: 700, fontSize: 22,
        letterSpacing: '0.02em', textTransform: 'uppercase', color: 'var(--ink)', textDecoration: 'none' }}>SecureShop</Link>
      <h1 className="ss-display" style={{ fontSize: 48, margin: '28px 0 8px' }}>Change password.</h1>
      <p style={{ opacity: 0.75, marginBottom: 24 }}>You’ll sign in again after changing your password.</p>
      <form className="ss-form" onSubmit={submit}>
        <label htmlFor="shop-current-password">Current password</label>
        <input id="shop-current-password" type="password" autoComplete="current-password" value={current}
          onChange={event => setCurrent(event.target.value)} required />
        <label htmlFor="shop-new-password">New password</label>
        <input id="shop-new-password" type="password" autoComplete="new-password" value={next}
          onChange={event => setNext(event.target.value)} required />
        <label htmlFor="shop-confirm-password">Confirm new password</label>
        <input id="shop-confirm-password" type="password" autoComplete="new-password" value={confirm}
          onChange={event => setConfirm(event.target.value)} required />
        {error && <p role="alert" style={{ color: 'var(--rust)' }}>{error}</p>}
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <button type="submit" className="ss-btn" disabled={busy}>{busy ? 'Updating…' : 'Update password'}</button>
          <Link to="/secureshop/account" className="ss-btn ss-btn--ghost" style={{ textDecoration: 'none' }}>Cancel</Link>
        </div>
      </form>
    </motion.div>
  </main>;
}
