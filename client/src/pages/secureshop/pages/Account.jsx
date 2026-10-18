import { shopStorage } from '../utils/shopStorage.mjs';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { User, Shield, MapPin, KeyRound, Monitor, Copy, Eye, EyeOff, RefreshCw, Trash2, Plus } from 'lucide-react';

import Tabs from '../components/Tabs.jsx';
import Card from '../components/Card.jsx';
import Button from '../components/Button.jsx';
import Input from '../components/Input.jsx';
import Badge from '../components/Badge.jsx';
import UploadZone from '../components/UploadZone.jsx';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext.jsx';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { STANDALONE_SESSION_CHANNEL } from '../bridge/standaloneIntents.mjs';
import PracticeAddressSetup from '../components/PracticeAddressSetup.jsx';
import PracticeProfileUpdate from '../components/PracticeProfileUpdate.jsx';
import { decodeAddressCards } from '../utils/addressSetupOperation.mjs';

const TABS = [
  { id: 'profile',   label: 'Profile',    icon: <User size={14} /> },
  { id: 'security',  label: 'Security',   icon: <Shield size={14} /> },
  { id: 'addresses', label: 'Addresses',  icon: <MapPin size={14} /> },
  { id: 'apikeys',   label: 'API Keys',   icon: <KeyRound size={14} /> },
  { id: 'sessions',  label: 'Sessions',   icon: <Monitor size={14} /> },
];

function _authHeaders() {
  try {
    const t = shopStorage.getItem('secureshop_v2_token');
    return t ? { Authorization: `Bearer ${t}` } : {};
  } catch { return {}; }
}

export default function Account() {
  const { user } = useAuth();
  const [tab, setTab] = useState('profile');

  return (
    <div>
      <h1 className="ss-display" style={{ fontSize: 40, marginBottom: 8 }}>Account</h1>
      <div style={{ opacity: 0.65, marginBottom: 24, fontSize: 14 }}>
        Signed in as <strong>{user?.username}</strong> · role: <Badge>{user?.role || 'customer'}</Badge>
      </div>

      <Tabs
        tabs={TABS.map((t) => ({ id: t.id, label: <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>{t.icon}{t.label}</span> }))}
        value={tab}
        onChange={setTab}
      >
        {tab === 'profile'   && <ProfileTab />}
        {tab === 'security'  && <SecurityTab />}
        {tab === 'addresses' && (user?.role === 'customer' && getBridgeFetchMetadata(window.fetch)
          ? <BoundAddressesTab /> : <AddressesTab />)}
        {tab === 'apikeys'   && <APIKeysTab />}
        {tab === 'sessions'  && <SessionsTab />}
      </Tabs>
    </div>
  );
}

function ProfileTab() {
  const { user, token, saveProfile, refreshProfile } = useAuth();
  const toast = useToast();
  const [name, setName] = useState(user?.full_name || '');
  const [email, setEmail] = useState(user?.email || '');
  const [phone, setPhone] = useState(user?.phone || '');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setName(user?.full_name || '');
    setEmail(user?.email || '');
    setPhone(user?.phone || '');
  }, [user?.id, user?.full_name, user?.email, user?.phone]);

  const save = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await saveProfile({ full_name: name, email, phone });
      toast.success('Profile saved');
    } catch (e) {
      if (e.name !== 'AbortError') toast.error(`Save failed: ${e.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.24 }}
      style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 32, marginTop: 20 }}
    >
      {user?.role === 'customer' ? <div style={{ maxWidth: 520 }}>
        <PracticeProfileUpdate entryPoint="account" authorityKey={JSON.stringify([user?.id, token])}
          transport={window.fetch} onConfirmed={refreshProfile} />
        <Input label="Username" value={user?.username || ''} disabled helper="Contact support to change your username" />
      </div> : <form className="ss-form" onSubmit={save} style={{ maxWidth: 520 }}>
        <Input label="Full name" value={name} onChange={(e) => setName(e.target.value)} />
        <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <Input label="Phone" type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} helper="Optional — used only for shipping notifications" />
        <Input label="Username" value={user?.username || ''} disabled helper="Contact support to change your username" />
        <div style={{ marginTop: 8 }}>
          <Button type="submit" loading={saving}>Save changes</Button>
        </div>
      </form>}

      <Card padded style={{ padding: 24 }}>
        <div className="ss-card__meta" style={{ marginBottom: 12 }}>Avatar</div>
        <p style={{ fontSize: 13, opacity: 0.75, marginTop: 0, marginBottom: 14 }}>
          Upload any file. MIME and filename are honored as provided — this is the M5 uploads surface.
        </p>
        <UploadZone kind="avatar" scopeId={user?.id || 1} label="Upload avatar" />
      </Card>
    </motion.section>
  );
}

function SecurityTab() {
  const toast = useToast();
  const standalone = getBridgeFetchMetadata(window.fetch)?.standalone === true;
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [saving, setSaving] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (next !== confirm) return toast.error('New passwords do not match');
    if (!next || next.length < 8) return toast.error('Password must be at least 8 characters');
    setSaving(true);
    try {
      const r = await fetch('/api/secureshop/v2/auth/users/me/password', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ..._authHeaders() },
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      const j = await r.json();
      if (!r.ok || !j.ok) throw new Error(j.error || 'password change failed');
      toast.success('Password updated');
      setCurrent(''); setNext(''); setConfirm('');
    } catch (e) {
      toast.error(`Update failed: ${e.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.24 }}
      style={{ marginTop: 20, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}
    >
      <Card padded style={{ padding: 24 }}>
        <h3 style={{ fontFamily: 'var(--display)', fontSize: 20, marginTop: 0 }}>Change password</h3>
        {standalone ? <>
          <p style={{ fontSize: 13, opacity: 0.75 }}>Change your password on the SecureShop account page.</p>
          <Button onClick={() => window.parent.postMessage({ channel: STANDALONE_SESSION_CHANNEL,
            type: 'password-route', nonce: window.location.hash.slice(1) }, new URL(document.baseURI).origin)}>
            Change password
          </Button>
        </> : <form onSubmit={submit} className="ss-form">
          <Input label="Current password" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          <Input label="New password" type="password" value={next} onChange={(e) => setNext(e.target.value)} required helper="At least 8 characters" />
          <Input label="Confirm new password" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
          <div><Button type="submit" loading={saving}>Update password</Button></div>
        </form>}
      </Card>

      <Card padded style={{ padding: 24 }}>
        <h3 style={{ fontFamily: 'var(--display)', fontSize: 20, marginTop: 0 }}>Two-factor</h3>
        <p style={{ fontSize: 13, opacity: 0.75 }}>
          2FA is <Badge variant="rust">not enabled</Badge> on this account.
        </p>
        <Button variant="ghost" onClick={() => toast.info('2FA setup not yet available in v2')}>Enable 2FA</Button>
      </Card>
    </motion.section>
  );
}

function BoundAddressesTab() {
  const { user, token } = useAuth();
  const toast = useToast();
  const transport = window.fetch;
  const [addresses, setAddresses] = useState([]);
  const [status, setStatus] = useState('loading');
  const [editing, setEditing] = useState(null);
  const epochRef = useRef(0);
  const authorityKey = JSON.stringify([user?.id, token]);
  const refresh = useCallback(async () => {
    const epoch = ++epochRef.current;
    setStatus('loading');
    try {
      const response = await transport('/api/secureshop/customer/commerce/addresses',
        { method: 'GET', headers: { accept: 'application/json' } });
      if (!response.ok) throw Error('Saved addresses unavailable');
      const value = decodeAddressCards(await response.json());
      if (epoch === epochRef.current) { setAddresses(value.addresses.map((row, index) => ({
        ...row.fields, id: row.addressId, choiceId: row.choiceId,
        title: value.cards[index].title, detail: value.cards[index].detail,
      }))); setStatus('ready'); }
    } catch { if (epoch === epochRef.current) setStatus('error'); }
  }, [transport, authorityKey]);
  useEffect(() => { void refresh(); return () => { epochRef.current += 1; }; }, [refresh]);
  const del = async addressId => {
    const epoch = ++epochRef.current;
    const headers = _authHeaders();
    try {
      const response = await transport(`/api/secureshop/v2/auth/users/me/addresses/${addressId}`,
        { method: 'DELETE', headers });
      const value = await response.json().catch(() => ({}));
      if (epoch !== epochRef.current || _authHeaders().Authorization !== headers.Authorization) return;
      if (!response.ok || value.ok !== true) throw Error(value.error || 'delete failed');
      toast.success('Address deleted');
      await refresh();
    } catch (error) {
      if (epoch === epochRef.current) toast.error(`Delete failed: ${error.message}`);
    }
  };
  return <motion.section initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.24 }} style={{ marginTop: 20 }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 16 }}>
      <h3 style={{ fontFamily: 'var(--display)', fontSize: 22, margin: 0 }}>Saved addresses</h3>
      <Button size="sm" onClick={() => setEditing({ action: 'create', choiceId: null })}
        icon={<Plus size={14} />}>Add address</Button>
    </div>
    {status === 'loading' && <p role="status">Loading your addresses…</p>}
    {status === 'error' && <p role="alert">Saved addresses are unavailable.</p>}
    {status === 'ready' && (addresses.length === 0
      ? <div style={{ padding: 20, opacity: 0.65, fontSize: 14 }}>No addresses yet. Click "Add address" to create one.</div>
      : <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
        {addresses.map(address => <Card key={address.choiceId} padded style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <div style={{ fontFamily: 'var(--display)', fontSize: 18, fontWeight: 600 }}>{address.label || '—'}</div>
            {address.isDefault && <Badge variant="signal">Default</Badge>}
          </div>
          <div style={{ fontSize: 14, lineHeight: 1.5 }}>
            <div>{address.line1}</div>
            {address.line2 && <div>{address.line2}</div>}
            <div>{[address.city, address.state, address.zip].filter(Boolean).join(', ')}</div>
            {address.phone && <div style={{ opacity: 0.7, fontSize: 12, marginTop: 4 }}>{address.phone}</div>}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            <Button size="sm" variant="ghost" onClick={() => setEditing({ action: 'update', choiceId: address.choiceId })}>Edit</Button>
            <Button size="sm" variant="ghost" onClick={() => void del(address.id)}>Delete</Button>
          </div>
        </Card>)}
      </div>)}
    {editing ? <div role="dialog" aria-modal="true" aria-label={editing.action === 'create' ? 'Add address' : 'Edit address'}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', display: 'flex',
        alignItems: 'center', justifyContent: 'center', zIndex: 100, overflow: 'auto' }}>
      <div style={{ background: 'var(--paper)', padding: 24, maxWidth: 480, width: '100%',
        maxHeight: '90vh', overflow: 'auto', border: '1px solid var(--rule)' }}>
        <h3 style={{ fontFamily: 'var(--display)', fontSize: 22, marginTop: 0 }}>
          {editing.action === 'create' ? 'Add address' : 'Edit address'}
        </h3>
        <PracticeAddressSetup key={`${editing.action}:${editing.choiceId || 'new'}`}
          entryPoint="account" action={editing.action} choiceId={editing.choiceId}
          authorityKey={authorityKey} transport={transport}
          onCancel={() => setEditing(null)} onConfirmed={() => { setEditing(null); return refresh(); }}
          onStale={() => { setEditing(null); return refresh(); }} />
      </div>
    </div>
      : <PracticeAddressSetup entryPoint="chat" setup={null} authorityKey={authorityKey}
        transport={transport} onConfirmed={refresh} />}
  </motion.section>;
}

function AddressesTab() {
  const toast = useToast();
  const [addresses, setAddresses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [editing, setEditing] = useState(null); // null = closed, {} = new, {id, ...} = edit
  const requestEpoch = useRef(0);

  const load = useCallback(async () => {
    const epoch = ++requestEpoch.current;
    const headers = _authHeaders();
    const isCurrent = () => epoch === requestEpoch.current
      && _authHeaders().Authorization === headers.Authorization;
    setLoading(true);
    setError(null);
    try {
      const r = await fetch('/api/secureshop/v2/auth/users/me/addresses', { headers });
      const j = await r.json().catch(() => ({}));
      if (!isCurrent()) return;
      if (!r.ok) throw new Error(j.error || `request failed (${r.status})`);
      setAddresses(j.addresses || []);
    } catch (e) {
      if (isCurrent()) setError(e?.message || 'request failed');
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    return () => { requestEpoch.current += 1; };
  }, [load]);

  const del = async (id) => {
    const epoch = ++requestEpoch.current;
    const headers = _authHeaders();
    const isCurrent = () => epoch === requestEpoch.current
      && _authHeaders().Authorization === headers.Authorization;
    try {
      const r = await fetch(`/api/secureshop/v2/auth/users/me/addresses/${id}`, {
        method: 'DELETE', headers,
      });
      const j = await r.json().catch(() => ({}));
      if (!isCurrent()) return;
      if (!r.ok || !j.ok) throw new Error(j.error || 'delete failed');
      toast.success('Address deleted');
      await load();
    } catch (e) {
      if (isCurrent()) toast.error(`Delete failed: ${e.message}`);
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.24 }}
      style={{ marginTop: 20 }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 16 }}>
        <h3 style={{ fontFamily: 'var(--display)', fontSize: 22, margin: 0 }}>Saved addresses</h3>
        <Button size="sm" onClick={() => setEditing({})} icon={<Plus size={14} />}>Add address</Button>
      </div>
      {loading ? (
        <div className="ss-mono" style={{ opacity: 0.6 }}>Loading…</div>
      ) : error ? (
        <div role="alert" style={{ padding: 20, color: 'var(--red)', fontSize: 14 }}>
          Unable to load addresses: {error}
        </div>
      ) : addresses.length === 0 ? (
        <div style={{ padding: 20, opacity: 0.65, fontSize: 14 }}>
          No addresses yet. Click "Add address" to create one.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          {addresses.map((a) => (
            <Card key={a.id} padded style={{ padding: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div style={{ fontFamily: 'var(--display)', fontSize: 18, fontWeight: 600 }}>{a.label || '—'}</div>
                {a.is_default ? <Badge variant="signal">Default</Badge> : null}
              </div>
              <div style={{ fontSize: 14, lineHeight: 1.5 }}>
                <div>{a.line1}</div>
                {a.line2 && <div>{a.line2}</div>}
                <div>
                  {[a.city, a.state, a.zip].filter(Boolean).join(', ')}
                </div>
                {a.phone && <div style={{ opacity: 0.7, fontSize: 12, marginTop: 4 }}>{a.phone}</div>}
              </div>
              <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
                <Button size="sm" variant="ghost" onClick={() => setEditing(a)}>Edit</Button>
                <Button size="sm" variant="ghost" onClick={() => del(a.id)}>Delete</Button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {editing && (
        <AddressEditor
          initial={editing}
          onCancel={() => setEditing(null)}
          onSaved={async () => { setEditing(null); await load(); }}
        />
      )}
    </motion.section>
  );
}

function AddressEditor({ initial, onCancel, onSaved }) {
  const toast = useToast();
  const [form, setForm] = useState({
    label: initial.label || '',
    line1: initial.line1 || '',
    line2: initial.line2 || '',
    city:  initial.city  || '',
    state: initial.state || '',
    zip:   initial.zip   || '',
    phone: initial.phone || '',
    is_default: !!initial.is_default,
  });
  const [saving, setSaving] = useState(false);
  const isNew = !initial.id;
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    if (!form.line1.trim()) return toast.error('Street address required');
    setSaving(true);
    try {
      const url = isNew
        ? '/api/secureshop/v2/auth/users/me/addresses'
        : `/api/secureshop/v2/auth/users/me/addresses/${initial.id}`;
      const r = await fetch(url, {
        method: isNew ? 'POST' : 'PUT',
        headers: { 'content-type': 'application/json', ..._authHeaders() },
        body: JSON.stringify(form),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) throw new Error(j.error || 'save failed');
      toast.success(isNew ? 'Address added' : 'Address updated');
      await onSaved();
    } catch (e) {
      toast.error(`Save failed: ${e.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}
      onClick={onCancel}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{ background: 'var(--paper)', padding: 24, maxWidth: 480, width: '100%', border: '1px solid var(--rule)' }}
      >
        <h3 style={{ fontFamily: 'var(--display)', fontSize: 22, marginTop: 0 }}>
          {isNew ? 'Add address' : 'Edit address'}
        </h3>
        <form onSubmit={submit} className="ss-form">
          <Input label="Label" value={form.label} onChange={set('label')} placeholder="Home, Work, …" />
          <Input label="Street address" value={form.line1} onChange={set('line1')} required />
          <Input label="Apt / suite" value={form.line2} onChange={set('line2')} />
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: 10 }}>
            <Input label="City" value={form.city} onChange={set('city')} />
            <Input label="State" value={form.state} onChange={set('state')} />
            <Input label="ZIP" value={form.zip} onChange={set('zip')} />
          </div>
          <Input label="Phone" type="tel" value={form.phone} onChange={set('phone')} />
          <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}>
            <input type="checkbox" checked={form.is_default} onChange={(e) => setForm((f) => ({ ...f, is_default: e.target.checked }))} />
            Set as default
          </label>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 8 }}>
            <Button variant="ghost" type="button" onClick={onCancel}>Cancel</Button>
            <Button type="submit" loading={saving}>{isNew ? 'Add' : 'Save'}</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

// The opaque storefront cannot use the parent origin's async clipboard grant.
// Keep this command in the original Copy click stack, before any await.
function copySelectedApiKey(key) {
  const focused = document.activeElement;
  const selection = window.getSelection();
  const ranges = selection ? Array.from({ length: selection.rangeCount },
    (_, index) => selection.getRangeAt(index).cloneRange()) : [];
  const inputSelection = typeof focused?.selectionStart === 'number'
    ? [focused.selectionStart, focused.selectionEnd, focused.selectionDirection] : null;
  const field = document.createElement('textarea');
  field.value = key;
  field.readOnly = true;
  field.tabIndex = -1;
  field.setAttribute('aria-hidden', 'true');
  Object.assign(field.style, { position: 'fixed', top: '0', left: '0', opacity: '0', pointerEvents: 'none' });
  try {
    document.body.appendChild(field);
    field.focus({ preventScroll: true });
    field.select();
    return document.execCommand('copy') === true;
  } finally {
    field.remove();
    try { if (focused?.isConnected) focused.focus({ preventScroll: true }); } catch { /* Detached or unfocusable control. */ }
    try {
      if (selection) {
        selection.removeAllRanges();
        for (const range of ranges) {
          if (range.startContainer.isConnected && range.endContainer.isConnected) selection.addRange(range);
        }
      }
      if (inputSelection && focused?.isConnected) focused.setSelectionRange(...inputSelection);
    } catch { /* Copy result does not depend on a later selection change. */ }
  }
}

function APIKeysTab() {
  const toast = useToast();
  const [reveal, setReveal] = useState(false);
  const [key, setKey] = useState(null);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch('/api/secureshop/v2/auth/users/me/api-keys', { headers: _authHeaders() });
      const j = await r.json();
      setKey(j.api_key || '');
    } catch {
      setKey('');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const copy = async () => {
    if (!key) return;
    if (getBridgeFetchMetadata(window.fetch)) {
      if (typeof document.execCommand !== 'function') {
        toast.error('Clipboard unavailable; API key was not copied');
        return;
      }
      try {
        if (copySelectedApiKey(key)) toast.success('API key copied to clipboard');
        else toast.error('Clipboard access was denied; API key was not copied');
      } catch {
        toast.error('Clipboard access was denied; API key was not copied');
      }
      return;
    }
    const clipboard = typeof navigator === 'undefined' ? null : navigator.clipboard;
    if (!clipboard || typeof clipboard.writeText !== 'function') {
      toast.error('Clipboard unavailable; API key was not copied');
      return;
    }
    try {
      await clipboard.writeText(key);
      toast.success('API key copied to clipboard');
    } catch {
      toast.error('Clipboard access was denied; API key was not copied');
    }
  };

  const rotate = async () => {
    setRotating(true);
    try {
      const r = await fetch('/api/secureshop/v2/auth/users/me/api-keys/rotate', {
        method: 'POST', headers: _authHeaders(),
      });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'rotate failed');
      setKey(j.api_key);
      setReveal(true);
      toast.success('New API key generated');
    } catch (e) {
      toast.error(`Rotate failed: ${e.message}`);
    } finally {
      setRotating(false);
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.24 }}
      style={{ marginTop: 20 }}
    >
      <Card padded style={{ padding: 24, maxWidth: 640 }}>
        <h3 style={{ fontFamily: 'var(--display)', fontSize: 20, marginTop: 0 }}>Live API key</h3>
        <p style={{ fontSize: 13, opacity: 0.75 }}>
          Use this key to authenticate against the SecureShop v2 API. Never commit it to source control.
        </p>
        {loading ? (
          <div className="ss-mono" style={{ opacity: 0.6 }}>Loading…</div>
        ) : !key ? (
          <div style={{ padding: 12, background: 'color-mix(in srgb, var(--amber) 12%, transparent)', border: '1px solid var(--amber)', fontSize: 13, marginBottom: 12 }}>
            You do not have an API key yet. Generate one to start using the API.
          </div>
        ) : (
          <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
            <input
              className="ss-input"
              value={reveal ? key : (key.slice(0, 12) + '·'.repeat(20))}
              readOnly
              style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 12 }}
            />
            <Button variant="ghost" size="md" onClick={() => setReveal((v) => !v)} icon={reveal ? <EyeOff size={14} /> : <Eye size={14} />}>
              {reveal ? 'Hide' : 'Reveal'}
            </Button>
            <Button variant="ghost" size="md" onClick={copy} icon={<Copy size={14} />}>Copy</Button>
          </div>
        )}
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <Button size="sm" variant="ghost" onClick={rotate} loading={rotating} icon={<RefreshCw size={14} />}>
            {key ? 'Rotate key' : 'Generate key'}
          </Button>
        </div>
        <div style={{ marginTop: 16, padding: 12, background: 'color-mix(in srgb, var(--amber) 12%, transparent)', border: '1px solid var(--amber)', fontSize: 12 }}>
          <strong>Heads up:</strong> keys are stored in plaintext in the DB (intentional — teaches LLM02 sensitive info disclosure).
        </div>
      </Card>
    </motion.section>
  );
}

function SessionsTab() {
  const toast = useToast();
  const { logout } = useAuth();
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const requestEpoch = useRef(0);

  const load = useCallback(async () => {
    const epoch = ++requestEpoch.current;
    const headers = _authHeaders();
    const isCurrent = () => epoch === requestEpoch.current
      && _authHeaders().Authorization === headers.Authorization;
    setLoading(true);
    setError(null);
    try {
      const r = await fetch('/api/secureshop/v2/auth/users/me/sessions', { headers });
      const j = await r.json().catch(() => ({}));
      if (!isCurrent()) return;
      if (r.status === 401 || r.status === 403) {
        await logout();
        return;
      }
      if (!r.ok) throw new Error(j.error || `request failed (${r.status})`);
      setSessions(j.sessions || []);
    } catch (e) {
      if (isCurrent()) setError(e?.message || 'request failed');
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [logout]);

  useEffect(() => {
    load();
    return () => { requestEpoch.current += 1; };
  }, [load]);

  const revoke = async (id) => {
    const epoch = ++requestEpoch.current;
    const headers = _authHeaders();
    const isCurrent = () => epoch === requestEpoch.current
      && _authHeaders().Authorization === headers.Authorization;
    try {
      const r = await fetch(`/api/secureshop/v2/auth/users/me/sessions/${id}/revoke`, {
        method: 'POST', headers,
      });
      const j = await r.json().catch(() => ({}));
      if (!isCurrent()) return;
      if (!r.ok || !j.ok) throw new Error(j.error || 'revoke failed');
      toast.success('Session revoked');
      if (sessions.find((session) => session.id === id)?.is_current) await logout();
      else await load();
    } catch (e) {
      if (isCurrent()) toast.error(`Revoke failed: ${e.message}`);
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.24 }}
      style={{ marginTop: 20 }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 16 }}>
        <h3 style={{ fontFamily: 'var(--display)', fontSize: 22, margin: 0 }}>Active sessions</h3>
        <Button size="sm" variant="ghost" onClick={load} icon={<RefreshCw size={14} />}>Refresh</Button>
      </div>
      {loading ? (
        <div className="ss-mono" style={{ opacity: 0.6 }}>Loading…</div>
      ) : error ? (
        <div role="alert" style={{ padding: 20, color: 'var(--red)', fontSize: 14 }}>
          Unable to load sessions: {error}
        </div>
      ) : sessions.length === 0 ? (
        <div style={{ padding: 20, opacity: 0.65, fontSize: 14 }}>
          No active sessions found for this account.
        </div>
      ) : (
        <table className="ss-table">
          <thead>
            <tr>
              <th>User agent</th>
              <th>IP</th>
              <th>Signed in</th>
              <th>Last seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id}>
                <td style={{ maxWidth: 320, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {s.user_agent || '—'}
                </td>
                <td className="ss-mono">{s.ip || '—'}</td>
                <td>{s.created_at ? new Date(s.created_at).toLocaleString() : '—'}</td>
                <td>{s.last_seen_at ? new Date(s.last_seen_at).toLocaleString() : '—'}</td>
                <td>
                  <Button size="sm" variant="ghost" onClick={() => revoke(s.id)} icon={<Trash2 size={14} />}>
                    Revoke
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </motion.section>
  );
}
