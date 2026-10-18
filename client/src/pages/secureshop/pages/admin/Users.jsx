import React, { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { getBridgeFetchMetadata } from '../../bridge/fetchAdapter.mjs';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { readPending, savePending, clearPending, assertSaved, assertReceipt, readOperation,
  acknowledgeRegisteredSelfChange, requestReauthenticationForUnresolvedSelfChange } from './userAdminOperation';
import PasswordResetPanel from './PasswordResetPanel.jsx';
import { isStandaloneShopFrame } from '../../bridge/assessmentPanelIntent.mjs';
import { openStandalonePasswordReset, openStandaloneTeachingPasswordReset } from '../../bridge/passwordResetIntent.mjs';
import PageTransition from '../../components/PageTransition.jsx';
import { useToast } from '../../context/ToastContext.jsx';

/**
 * Admin — Users.jsx (Wave 2C).
 *
 * Full user management surface. Preserves LLM06 (set_role) and LLM02 (lookup)
 * excessive-agency surfaces by routing through the admin agent's tools.
 *
 * Features:
 *   - Search (debounced 300ms), filter (role, banned), pagination (25/page)
 *   - Table with id, username, email, role, banned_at, api key + session token snippets
 *   - Per-row actions: view details (side sheet), change role, reset password, ban
 *   - Bulk lookup by name (LLM02 leak surface)
 */

const ROLES = ['customer', 'merchant', 'admin', 'banned'];
const IDENTITY_KINDS = new Set(['teaching_persona', 'registered_account']);
const RESET_CHANNELS = new Set(['bound_persona', 'protected_account', 'none']);
const PAGE_SIZE = 25;
const DEBOUNCE_MS = 300;

export default function AdminUsers() {
  const transport = globalThis.fetch;
  const attachedBoundFrame = useRef(false);
  if (getBridgeFetchMetadata(transport)?.boundReviews) attachedBoundFrame.current = true;
  const boundFrame = attachedBoundFrame.current;
  const standaloneFrame = boundFrame && isStandaloneShopFrame();
  const shopAuth = useContext(AuthCtx);
  const authToken = shopAuth?.token ?? null;
  const authRef = useRef(authToken); authRef.current = authToken;
  const [administration, setAdministration] = useState(null);
  const lookupScope = useRef(administration?.scopeKey); lookupScope.current = administration?.scopeKey;
  const [pendingChange, setPendingChange] = useState(null);
  const [mutationError, setMutationError] = useState(null);
  const [authLossFor, setAuthLossFor] = useState(null);
  const mutationLock = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [users, setUsers] = useState([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [bannedFilter, setBannedFilter] = useState('');
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState(null);
  const [errorFor, setErrorFor] = useState(null);
  const [loadedFor, setLoadedFor] = useState(null);
  const readController = useRef(null);
  const [resetTarget, setResetTarget] = useState(null);
  const [selected, setSelected] = useState(null);
  const [lookupInput, setLookupInput] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  useEffect(() => { setLookupResult(null); setResetTarget(null); setAuthLossFor(null); }, [authToken, transport, administration?.scopeKey]);
  const [banReason, setBanReason] = useState('');
  const validBanReason = typeof banReason === 'string' && !!banReason.trim()
    && banReason.isWellFormed() && new TextEncoder().encode(banReason).byteLength <= 1024;
  const queryKey = JSON.stringify([page, debounced, roleFilter, bannedFilter]);
  const inScope = marker => marker?.authToken === authToken && marker?.transport === transport && marker?.queryKey === queryKey;
  const currentData = inScope(loadedFor);
  const currentError = inScope(errorFor) ? loadError : null;
  const visibleUsers = currentData ? users : [];
  const visibleTotal = currentData ? total : 0;
  const visiblePages = currentData ? pages : 1;
  const visibleAdministration = currentData ? administration : null;
  const visibleSelected = currentData ? visibleUsers.find(user => user.id === selected?.id) : null;
  useEffect(() => { setSelected(null); }, [queryKey, authToken, transport]);

  // Debounce search input.
  useEffect(() => {
    const t = setTimeout(() => { setPage(1); setDebounced(search.trim()); }, DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [search]);

  const toastApi = useToast();
  const showToast = useCallback((msg, kind = 'info') => {
    if (kind === 'success') toastApi.success(msg);
    else if (kind === 'error') toastApi.error(msg);
    else if (kind === 'warn') toastApi.warn(msg);
    else toastApi.info(msg);
  }, [toastApi]);

  const load = useCallback(async () => {
    readController.current?.abort();
    const controller = new AbortController();
    readController.current = controller;
    setBusy(true);
    setLoadError(null);
    setErrorFor(null);
    try {
      const q = new URLSearchParams({
        page: String(page),
        pageSize: String(PAGE_SIZE),
      });
      if (debounced) q.set('search', debounced);
      if (roleFilter) q.set('role', roleFilter);
      if (bannedFilter) q.set('banned', bannedFilter);
      const r = await transport(`/api/secureshop/admin/users?${q.toString()}`, { signal: controller.signal });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      const count = j?.total ?? j?.count;
      if (!Array.isArray(j?.users) || !Number.isSafeInteger(count) || count < 0
        || j.page !== page || j.pageSize !== PAGE_SIZE
        || !Number.isSafeInteger(j.pages) || j.pages < 1
        || j.pages !== Math.max(1, Math.ceil(count / PAGE_SIZE)) || j.users.length > PAGE_SIZE
        || j.users.some(user => !user || !Number.isSafeInteger(user.id) || user.id < 1
          || typeof user.username !== 'string' || !ROLES.includes(user.role)
          || (boundFrame && (!IDENTITY_KINDS.has(user.identity_kind)
            || !RESET_CHANNELS.has(user.reset_channel)
            || (user.reset_channel === 'bound_persona' && user.identity_kind !== 'teaching_persona')
            || (user.reset_channel === 'protected_account' && user.identity_kind !== 'registered_account'))))) {
        throw new Error('Invalid users response');
      }
      if (controller.signal.aborted || (authRef.current !== authToken || globalThis.fetch !== transport)) return;
      if (j.administration?.roleBan === true) {
        if (typeof j.administration.scopeKey !== 'string' || j.users.some(u => typeof u.authority_version !== 'string' || !/^[1-9]\d*$/.test(u.authority_version))) throw new Error('Invalid user authority response');
        setAdministration(j.administration);
        setPendingChange(readPending(j.administration.scopeKey));
      } else { setAdministration(null); setPendingChange(null); }
      if (page > j.pages) { setPage(j.pages); return j; }
      setUsers(j.users);
      setTotal(count);
      setPages(j.pages);
      setLoadedFor({ authToken, transport, queryKey });
      return j;
    } catch (e) {
      if (!controller.signal.aborted && authRef.current === authToken && globalThis.fetch === transport) {
        setLoadError(e.message);
        setErrorFor({ authToken, transport, queryKey });
        showToast(`load failed: ${e.message}`, 'error');
      }
    } finally {
      if (!controller.signal.aborted && authRef.current === authToken && globalThis.fetch === transport) setBusy(false);
    }
  }, [page, debounced, roleFilter, bannedFilter, queryKey, showToast, authToken, transport, boundFrame]);

  useEffect(() => { load(); return () => readController.current?.abort(); }, [load]);

  const reconcile = async (operation) => {
    await readOperation(operation, transport);
    const current = await load();
    if (!mounted.current || (authRef.current !== authToken || globalThis.fetch !== transport)) return;
    if (current?.administration?.scopeKey !== operation.scopeKey) throw new Error('Authority changed; inspect current user state after signing in again');
    await clearPending(operation, undefined, undefined,
      () => mounted.current && authRef.current === authToken && globalThis.fetch === transport);
    if (!mounted.current || authRef.current !== authToken || globalThis.fetch !== transport) return;
    setPendingChange(null);
    setMutationError(null);
    setAuthLossFor(null);
  };
  const acknowledgeSelfChange = async (operation, receipt) => {
    if (!mounted.current || authRef.current !== authToken || globalThis.fetch !== transport) return;
    const actorId = shopAuth?.user?.id ?? administration?.resetActorId;
    if (!standaloneFrame) {
      throw new Error('Shop sign-in is required to continue after changing your own role');
    }
    await acknowledgeRegisteredSelfChange(operation, receipt, actorId,
      () => mounted.current && authRef.current === authToken && globalThis.fetch === transport);
    if (!mounted.current || authRef.current !== authToken || globalThis.fetch !== transport) return;
    setPendingChange(null);
    setMutationError(null);
    setAuthLossFor(null);
  };
  const isSelfRegisteredChange = (operation, target) => standaloneFrame
    && target?.identity_kind === 'registered_account'
    && operation.targetId === (shopAuth?.user?.id ?? administration?.resetActorId)
    && (operation.action === 'ban' || operation.role !== 'admin');
  const mutateUser = async (id, action, role) => {
    if (mutationLock.current || busy || currentError || !currentData || (boundFrame && !administration?.roleBan) || pendingChange) return;
    if (action === 'ban' && !validBanReason) {
      setMutationError('Enter a reason before banning this account.');
      return;
    }
    const target = users.find(u => u.id === id);
    if (!target?.authority_version) return;
    mutationLock.current = true;
    setBusy(true); setMutationError(null); setAuthLossFor(null);
    const operation = { scopeKey: administration.scopeKey, targetId: id, action, role,
      reason: action === 'ban' ? banReason : undefined,
      operationId: null, expectedVersion: target.authority_version };
    try {
      operation.operationId = crypto.randomUUID();
      await savePending(operation, undefined, undefined,
        () => mounted.current && authRef.current === authToken && globalThis.fetch === transport);
      if (!mounted.current || (authRef.current !== authToken || globalThis.fetch !== transport)) return;
      assertSaved(operation);
      setPendingChange(operation);
      const response = await transport(`/api/secureshop/admin/users/${id}/${action === 'ban' ? 'ban' : 'role'}`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ operationId: operation.operationId, expectedVersion: operation.expectedVersion,
          ...(action === 'ban' ? { reason: operation.reason } : { role }) }),
      });
      if (!mounted.current || (authRef.current !== authToken || globalThis.fetch !== transport)) return;
      const result = await response.json();
      if (!mounted.current || (authRef.current !== authToken || globalThis.fetch !== transport)) return;
      if (!response.ok || result?.ok !== true) throw new Error('User change was not acknowledged');
      const receipt = assertReceipt(result.receipt, operation);
      const selfChange = isSelfRegisteredChange(operation, target);
      if (selfChange) await acknowledgeSelfChange(operation, receipt);
      else await reconcile(operation);
      if (mounted.current && authRef.current === authToken && globalThis.fetch === transport && !selfChange) showToast('User change confirmed', 'success');
    } catch (error) {
      if (mounted.current && authRef.current === authToken && globalThis.fetch === transport) {
        try { setPendingChange(readPending(administration.scopeKey)); }
        catch { /* The error still blocks a new saved operation. */ }
        setMutationError(error.message + '. Refresh to inspect the saved operation; do not submit another change.');
      }
    } finally { mutationLock.current = false; if (mounted.current && authRef.current === authToken && globalThis.fetch === transport) setBusy(false); }
  };
  const legacyMutation = async (id, action, body) => {
    if (boundFrame || administration || mutationLock.current || busy || currentError || !currentData) return;
    mutationLock.current=true;setBusy(true);
    try {
      const response=await fetch(`/api/secureshop/admin/users/${id}/${action}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
      if (!response.ok || (await response.json())?.ok!==true) throw new Error('User change was not acknowledged');
      if (mounted.current && authRef.current===authToken && globalThis.fetch===transport) await load();
    } catch(error) { if (mounted.current && authRef.current===authToken && globalThis.fetch===transport) setMutationError(error.message); }
    finally { mutationLock.current=false;if(mounted.current && authRef.current===authToken && globalThis.fetch===transport)setBusy(false); }
  };
  const changeRole = (id, role) => administration ? mutateUser(id, role === 'banned' ? 'ban' : 'set_role', role === 'banned' ? undefined : role) : legacyMutation(id,'role',{role});
  const ban = id => administration ? mutateUser(id, 'ban') : legacyMutation(id,'ban',{reason:banReason || 'no reason given'});
  const recoverChange = async () => {
    if (!pendingChange || mutationLock.current) return;
    mutationLock.current = true; setBusy(true); setAuthLossFor(null);
    try { await reconcile(pendingChange); }
    catch (error) { if (mounted.current && authRef.current === authToken && globalThis.fetch === transport) {
      setAuthLossFor(error.code === 'ADMIN_AUTH_CHANGED' ? pendingChange.operationId : null);
      setMutationError(error.message);
    } }
    finally { mutationLock.current = false; if (mounted.current && authRef.current === authToken && globalThis.fetch === transport) setBusy(false); }
  };

  const resetPassword = async (id) => {
    if (boundFrame) {
      const target = users.find(user => user.id === id);
      if (!target || target.id === administration?.resetActorId) return;
      if (target.identity_kind === 'registered_account' && target.reset_channel === 'protected_account'
        && standaloneFrame) {
        openStandalonePasswordReset(target.id);
      } else if (target.identity_kind === 'teaching_persona' && target.reset_channel === 'bound_persona'
        && administration?.passwordReset === true
        && target.password_reset_available === true) {
        if (standaloneFrame) openStandaloneTeachingPasswordReset(target.id);
        else setResetTarget(target);
      }
      return;
    }
    if (boundFrame || administration || mutationLock.current || busy || currentError || !currentData) return;
    mutationLock.current=true;
    setBusy(true);
    try {
      const r = await fetch(`/api/secureshop/admin/users/${id}/reset-password`, { method: 'POST' });
      const j = await r.json();
      if (j.ok) {
        showToast(`temp password: ${j.temporary_password}`, 'success');
        window.alert(`Temporary password for user ${id}: ${j.temporary_password}\n\n(email_sent=${j.email_sent} — intentional: no delivery)`);
      } else showToast('reset failed', 'error');
      await load();
    } catch(error) { if(mounted.current && authRef.current===authToken && globalThis.fetch===transport) setMutationError(error.message);
    } finally {
      mutationLock.current=false;setBusy(false);
    }
  };
  const resetEnabled = target => !busy && !currentError && currentData && target.id !== administration?.resetActorId
    && (!boundFrame ? !administration
      : target.identity_kind === 'registered_account' && target.reset_channel === 'protected_account'
        ? standaloneFrame : target.identity_kind === 'teaching_persona'
          && target.reset_channel === 'bound_persona' && administration?.passwordReset === true
          && target.password_reset_available === true);

  const doLookup = async (e) => {
    e.preventDefault();
    if (!currentData || currentError || (boundFrame && administration?.credentialLookup !== true) || busy || mutationLock.current) return;
    mutationLock.current = true; setBusy(true); setLookupResult(null);
    const username = lookupInput;
    const capturedScope = lookupScope.current;
    try {
      const r = await transport('/api/secureshop/admin/users/lookup', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username }),
      });
      if (!r.ok) throw new Error(`Lookup unavailable (HTTP ${r.status})`);
      const result = await r.json();
      if (boundFrame && (result?.ok !== true || result.synthetic !== true || !Object.hasOwn(result, 'user'))) throw new Error('Invalid lookup response');
      if (mounted.current && authRef.current === authToken && globalThis.fetch === transport && lookupScope.current === capturedScope) setLookupResult(result);
    } catch (error) {
      if (mounted.current && authRef.current === authToken && globalThis.fetch === transport && lookupScope.current === capturedScope) setMutationError(error.message);
    } finally {
      mutationLock.current = false;
      if (mounted.current && authRef.current === authToken && globalThis.fetch === transport && lookupScope.current === capturedScope) setBusy(false);
    }
  };

  const totalUsersLabel = useMemo(() => currentError ? 'users unavailable' : !currentData ? 'users loading…' : `${visibleTotal} user${visibleTotal === 1 ? '' : 's'}`, [visibleTotal, currentData, currentError]);

  return (
    <PageTransition>
      <header style={{ marginBottom: 24 }}>
        <div className="ss-card__meta">ADMIN LENS</div>
        {(pendingChange || mutationError) && <div role="alert">{mutationError || 'A user change awaits verification.'} <button className="ss-btn" onClick={recoverChange} disabled={busy || !pendingChange}>Refresh change status</button>
          {pendingChange && authLossFor === pendingChange.operationId && standaloneFrame
            && pendingChange.targetId === (shopAuth?.user?.id ?? administration?.resetActorId)
            && (pendingChange.action === 'ban' || pendingChange.role !== 'admin') &&
            <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
              onClick={() => {
                try { requestReauthenticationForUnresolvedSelfChange(pendingChange,
                  shopAuth?.user?.id ?? administration?.resetActorId,
                  () => mounted.current && authRef.current === authToken
                    && globalThis.fetch === transport && administration?.scopeKey === pendingChange.scopeKey); }
                catch (error) { setMutationError(error.message); }
              }}>Sign in again</button>}</div>}
        <h1 className="ss-display" style={{ fontSize: 36, margin: '4px 0 6px 0' }}>Users</h1>
        <p className="ss-mono" style={{ opacity: 0.7, fontSize: 12, maxWidth: '70ch' }}>
          {boundFrame ? 'Teaching personas and registered shop accounts are listed together. Role and ban changes require current administrator authority. Each account uses its own password recovery channel. Credential lookup, when enabled, displays isolated synthetic teaching records.' : <>set_role writes shop_users.role with no re-auth. The agent lane can call it too — that's the excessive-agency sink (LLM03:2026). lookup returns bcrypt + session_token + api_key — that's the LLM02 sensitive-disclosure sink.</>}
        </p>
      </header>

      {boundFrame && !standaloneFrame && visibleAdministration?.passwordReset === true && <PasswordResetPanel
        key={administration.scopeKey + ':' + authToken} scopeKey={administration.scopeKey}
        target={resetTarget} onClose={() => { setResetTarget(null); load(); }} />}
      {/* Bulk lookup — LLM02 leak surface */}
      <section style={{ marginBottom: 32, padding: 16, border: '1px solid var(--rule)', background: 'color-mix(in srgb, var(--paper) 94%, var(--carbon))' }}>
        <h2 className="ss-shelf__title" style={{ fontSize: 16, marginBottom: 10 }}>Bulk lookup by name</h2>
        <form onSubmit={doLookup} style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <input
            className="ss-lane__input"
            placeholder="username (returns full row incl. bcrypt + api_key + session_token)"
            value={lookupInput}
            onChange={(e) => setLookupInput(e.target.value)}
            style={{ flex: 1, maxWidth: 480 }}
            aria-label="Bulk lookup username"
          />
          <button className="ss-btn" type="submit" disabled={busy || !currentData || !!currentError || (boundFrame && visibleAdministration?.credentialLookup !== true) || !lookupInput.trim()}>Look up</button>
        </form>
        <AnimatePresence>
          {lookupResult && currentData && (
            <motion.pre
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="ss-mono"
              style={{ background: 'color-mix(in srgb, var(--paper) 88%, var(--carbon))', padding: 12, fontSize: 12, overflowX: 'auto', border: '1px solid var(--rule)', margin: 0 }}
            >
              {JSON.stringify(lookupResult, null, 2)}
            </motion.pre>
          )}
        </AnimatePresence>
        <div className="ss-mono" style={{ opacity: 0.55, fontSize: 11, marginTop: 6 }}>
          notice: response includes bcrypt_hash, session_token, api_key, pii_json — LLM02.
        </div>
      </section>

      {/* Filter bar */}
      <section style={{ marginBottom: 16, display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          className="ss-lane__input"
          placeholder="search username / email / name (debounced 300ms)"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, minWidth: 260, maxWidth: 480 }}
          aria-label="Search users"
        />
        <select
          value={roleFilter}
          onChange={(e) => { setPage(1); setRoleFilter(e.target.value); }}
          style={{ padding: '8px 10px', border: '1px solid var(--rule)', background: 'var(--paper)', fontFamily: 'var(--mono)', fontSize: 13 }}
          aria-label="Role filter"
        >
          <option value="">all roles</option>
          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
        </select>
        <select
          value={bannedFilter}
          onChange={(e) => { setPage(1); setBannedFilter(e.target.value); }}
          style={{ padding: '8px 10px', border: '1px solid var(--rule)', background: 'var(--paper)', fontFamily: 'var(--mono)', fontSize: 13 }}
          aria-label="Banned filter"
        >
          <option value="">all statuses</option>
          <option value="false">active only</option>
          <option value="true">banned only</option>
        </select>
        <span
          className="ss-mono"
          style={{
            padding: '4px 12px', border: '1px solid var(--rule)', borderRadius: 20,
            fontSize: 12, background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))',
          }}
        >{totalUsersLabel}</span>
        {busy && <span className="ss-mono" style={{ fontSize: 11, opacity: 0.55 }}>loading…</span>}
      </section>

      {currentError && <div role="alert" className="ss-mono" style={{ marginBottom: 16, color: 'var(--rust)', fontSize: 12 }}>
        Users unavailable: {currentError}.{visibleUsers.length > 0 ? ' Retained rows may be stale.' : ''}{' '}
        <button className="ss-btn" onClick={load} disabled={busy}>Retry</button>
      </div>}

      {/* User table */}
      <section style={{ marginBottom: 24 }}>
        <div style={{ border: '1px solid var(--rule)', overflowX: 'auto' }}>
          <div className="ss-mono" style={{ display: 'grid', gridTemplateColumns: '60px 180px 220px 100px 120px 140px 140px 140px 160px', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--rule)', fontSize: 11, opacity: 0.7, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            <div>id</div><div>username</div><div>email</div><div>role</div><div>status</div><div>api key</div><div>session</div><div>created</div><div>actions</div>
          </div>
          <AnimatePresence mode="popLayout">
            {visibleUsers.length === 0 ? (
              <div className="ss-mono" style={{ padding: 30, opacity: 0.5, fontSize: 12 }}>
                {busy || (!currentData && !currentError) ? 'loading…' : currentError ? 'User directory unavailable' : 'no users match — try clearing filters'}
              </div>
            ) : visibleUsers.map((u, i) => (
              <motion.div
                key={u.id}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.24, delay: i * 0.035 }}
                style={{ display: 'grid', gridTemplateColumns: '60px 180px 220px 100px 120px 140px 140px 140px 160px', gap: 8, padding: '10px 12px', borderBottom: '1px solid var(--rule)', alignItems: 'center', fontSize: 13 }}
              >
                <div className="ss-mono" style={{ opacity: 0.6 }}>#{u.id}</div>
                <div><b>{u.username}</b>{boundFrame && <div className="ss-mono" style={{ marginTop: 3,
                  fontSize: 10, opacity: 0.65 }}>{u.identity_kind === 'teaching_persona' ? 'Teaching persona' : 'Shop account'}</div>}</div>
                <div className="ss-mono" style={{ opacity: 0.75, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u.email || '—'}</div>
                <div>
                  <select
                    value={u.role || 'customer'}
                    onChange={(e) => changeRole(u.id, e.target.value)}
                    disabled={busy || !!currentError || !!pendingChange || (boundFrame && !administration?.roleBan)}
                    aria-label={`Change role for ${u.username}`}
                    style={{ padding: '4px 6px', border: '1px solid var(--rule)', background: 'var(--paper)', fontFamily: 'var(--mono)', fontSize: 12 }}
                  >
                    {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                <div>
                  {u.banned_at
                    ? <span className="ss-mono" style={{ color: 'var(--rust)', fontSize: 11 }}>banned {String(u.banned_at).slice(0, 10)}</span>
                    : <span className="ss-mono" style={{ opacity: 0.65, fontSize: 11 }}>active</span>}
                </div>
                <div className="ss-mono" style={{ fontSize: 11, opacity: 0.65 }}>{_truncKey(u.api_key)}</div>
                <div className="ss-mono" style={{ fontSize: 11, opacity: 0.65 }}>{_truncKey(u.session_token)}</div>
                <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6 }}>{u.created_at ? String(u.created_at).slice(0, 10) : '—'}</div>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button onClick={() => setSelected(u)} className="ss-btn" style={{ padding: '3px 8px', fontSize: 11 }} aria-label={`View ${u.username}`}>view</button>
                  <button onClick={() => resetPassword(u.id)} title={u.reset_channel === 'protected_account' && standaloneFrame
                    ? 'Open protected account recovery' : u.reset_channel === 'bound_persona' && administration?.passwordReset
                      ? 'Reset teaching persona with private recovery' : 'Password reset recovery is not available'}
                    className="ss-btn" style={{ padding: '3px 8px', fontSize: 11 }} disabled={!resetEnabled(u)}>reset</button>
                  <button onClick={() => ban(u.id)} className="ss-btn" style={{ padding: '3px 8px', fontSize: 11, background: u.banned_at ? 'var(--rule)' : undefined }} disabled={busy || !!currentError || !!pendingChange || (boundFrame && !administration?.roleBan) || (administration && !validBanReason) || u.banned_at}>ban</button>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        {/* Ban reason input — reason lands verbatim in audit_events (LLM01 sink). */}
        <div style={{ marginTop: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
          <label className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>ban reason:</label>
          <input
            className="ss-lane__input"
            placeholder="verbatim into audit_events → LLM01 log-injection sink"
            value={banReason}
            onChange={(e) => setBanReason(e.target.value)}
            style={{ flex: 1, maxWidth: 640 }}
            aria-label="Ban reason (audit-log)"
          />
        </div>

        {/* Pagination */}
        <div style={{ marginTop: 16, display: 'flex', gap: 12, alignItems: 'center', justifyContent: 'space-between' }}>
          <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6 }}>
            {currentError ? 'Pagination unavailable' : !currentData ? 'Loading pagination…' : `page ${page} of ${visiblePages} · ${visibleTotal} total`}
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              className="ss-btn ss-btn--ghost"
              disabled={page <= 1 || busy || !!currentError || !currentData}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              style={{ padding: '4px 12px', fontSize: 12 }}
            >← prev</button>
            <button
              className="ss-btn ss-btn--ghost"
              disabled={page >= visiblePages || busy || !!currentError || !currentData}
              onClick={() => setPage(p => Math.min(visiblePages, p + 1))}
              style={{ padding: '4px 12px', fontSize: 12 }}
            >next →</button>
          </div>
        </div>
      </section>

      {/* User details side sheet */}
      {createPortal(<AnimatePresence>
        {visibleSelected && (
          <>
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 0.35 }} exit={{ opacity: 0 }}
              onClick={() => setSelected(null)}
              style={{ position: 'fixed', inset: 0, background: '#000', zIndex: 40 }}
            />
            <motion.aside
              className="ss-root"
              initial={{ x: 480, opacity: 0.5 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: 480, opacity: 0 }}
              transition={{ duration: 0.32, ease: [0.34, 1.56, 0.64, 1] }}
              style={{
                position: 'fixed', top: 0, right: 0, bottom: 0, width: 'min(480px, 100vw)',
                boxSizing: 'border-box', zIndex: 41,
                background: 'var(--paper)', borderLeft: '1px solid var(--rule)',
                padding: 24, overflowY: 'auto', boxShadow: '-8px 0 24px rgba(0,0,0,0.12)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <h3 className="ss-display" style={{ fontSize: 22, margin: 0 }}>User #{visibleSelected.id}</h3>
                <button onClick={() => setSelected(null)} className="ss-btn ss-btn--ghost" aria-label="Close details" style={{ padding: '4px 10px' }}>×</button>
              </div>
              <SheetField label="username" value={visibleSelected.username} />
              <SheetField label="email" value={visibleSelected.email} />
              <SheetField label="full name" value={visibleSelected.full_name} />
              <SheetField label="role" value={visibleSelected.role} />
              <SheetField label="banned" value={visibleSelected.banned_at || 'active'} />
              <SheetField label="api key" mono value={visibleSelected.api_key} />
              <SheetField label="session token" mono value={visibleSelected.session_token} />
              <SheetField label="pii_json" mono value={visibleSelected.pii_json} pre />
              <SheetField label="created" value={visibleSelected.created_at} />
              <p className="ss-mono" style={{ opacity: 0.55, fontSize: 11, marginTop: 20, color: 'var(--rust)' }}>
                Full PII exposure here mirrors the LLM02 sink — anything an LLM turn returns from user-management.lookup lands with the same fields.
              </p>
            </motion.aside>
          </>
        )}
      </AnimatePresence>, document.body)}

      {/* Toasts now render via <ToastProvider> at the Shell level (Wave 3A). */}
    </PageTransition>
  );
}

function SheetField({ label, value, mono, pre }) {
  const displayVal = value == null || value === '' ? '—' : String(value);
  return (
    <div style={{ marginBottom: 12, paddingBottom: 12, borderBottom: '1px solid var(--rule)' }}>
      <div className="ss-mono" style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.06em', opacity: 0.55, marginBottom: 4 }}>{label}</div>
      {pre ? (
        <pre className="ss-mono" style={{ fontSize: 11, background: 'color-mix(in srgb, var(--paper) 88%, var(--carbon))', padding: 8, border: '1px solid var(--rule)', overflowX: 'auto', margin: 0 }}>
          {displayVal}
        </pre>
      ) : (
        <div style={{ fontFamily: mono ? 'var(--mono)' : 'inherit', fontSize: mono ? 12 : 14, wordBreak: 'break-all' }}>
          {displayVal}
        </div>
      )}
    </div>
  );
}

function _truncKey(k) {
  if (!k) return '—';
  return String(k).length > 12 ? `${String(k).slice(0, 10)}…` : k;
}
