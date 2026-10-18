import React, { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { getBridgeFetchMetadata } from '../../bridge/fetchAdapter.mjs';
import { readAclPending, saveAclPending, clearAclPending, assertAclReceipt } from './aclOperation.js';
import PageTransition from '../../components/PageTransition.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { useToast } from '../../context/ToastContext.jsx';

/**
 * Admin — AccessControl.jsx (M14).
 *
 * Renders the tool_permissions matrix (Layer B ACL) and the
 * system_config.enforce_tool_acl toggle. Admins can:
 *   - see every tool × role permission row
 *   - flip a single cell (POST /admin/access-control/permission)
 *   - toggle the global enforcement flag
 *     (POST /admin/access-control/enforcement)
 *
 * This is the SETTINGS surface for the M14 RBAC layer. Toggling enforcement
 * off is the LLM06 teaching mode ("policy said no, runtime said yes"); on
 * closes the chain at Layer B.
 */
export default function AdminAccessControl() {
  const [tools, setTools] = useState([]);
  const [enforceOn, setEnforceOn] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const mutationPending = useRef(false);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [saving, setSaving] = useState(null);   // 'enforcement' | tool_name
  const toast = useToast();
  const [policy, setPolicy] = useState(null);
  const [pending, setPending] = useState(null);
  const [notice, setNotice] = useState(null);
  const token = useContext(AuthCtx)?.token;
  const transport = globalThis.fetch;
  const bound = useRef(false);
  if (getBridgeFetchMetadata(transport)?.boundReviews) bound.current = true;
  const epoch = useRef(0);
  const current = generation => epoch.current === generation && globalThis.fetch === transport;


  const load = useCallback(async () => {
    const generation = epoch.current;
    setLoading(true);
    setLoadError(null);
    try {
      const r = await transport('/api/secureshop/admin/access-control');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      if (!j || j.ok !== true || typeof j.enforcement_enabled !== 'boolean'
        || !Array.isArray(j.tools) || j.tools.some(t => !t || typeof t.tool_name !== 'string'
          || ['customer', 'merchant', 'admin'].some(role => ![0, 1, false, true].includes(t[role])))) {
        throw new Error('Invalid ACL response');
      }
      if (!current(generation)) return;
      const capability = j.administration?.versionedPolicy === true;
      if (capability && (typeof j.administration.scopeKey !== 'string' || !j.administration.scopeKey
        || typeof j.version !== 'string' || !/^[1-9]\d{0,18}$/.test(j.version)
        || !/^[0-9a-f]{64}$/.test(j.registrySha256)
        || j.tools.some(t => typeof t.supported !== 'boolean' || typeof t.readOnly !== 'boolean'
          || ['customer', 'merchant', 'admin'].some(role => typeof t.applicable_roles?.[role] !== 'boolean')))) {
        throw new Error('Invalid versioned ACL response');
      }
      const nextPolicy = capability ? { version: j.version, registrySha256: j.registrySha256, scopeKey: j.administration.scopeKey } : null;
      setPolicy(nextPolicy);
      setPending(nextPolicy ? readAclPending(nextPolicy.scopeKey) : null);
      setTools(j.tools);
      setEnforceOn(j.enforcement_enabled);
    } catch (e) {
      if (!current(generation)) return;
      setPolicy(null);
      setPending(null);
      setTools([]);
      setEnforceOn(null);
      setLoadError(e.message);
      toast.error(`Failed to load ACL: ${e.message}`);
    } finally {
      if (current(generation)) setLoading(false);
    }
  }, [toast, transport, token]);

  useEffect(() => { load(); return () => { epoch.current += 1; }; }, [load]);

  const versionedWrite = async (kind, body) => {
    if (!policy || pending || mutationPending.current) return;
    const generation = epoch.current;
    const intent = { kind, scopeKey: policy.scopeKey, registrySha256: policy.registrySha256,
      body: { ...body, operationId: crypto.randomUUID(), expectedVersion: policy.version } };
    mutationPending.current = true;
    let dispatched = false;
    setSaving(kind); setNotice(null);
    try {
      await saveAclPending(intent);
      if (!current(generation)) return;
      setPending(intent);
      dispatched = true;
      const r = await transport(`/api/secureshop/admin/access-control/${kind}`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(intent.body) });
      const result = await r.json();
      if (!current(generation)) return;
      if (r.status === 409 && result?.code === 'ACL_VERSION_CONFLICT') {
        await clearAclPending(intent);
        if (!current(generation)) return;
        setPending(null); setNotice('Policy changed. Review the current permissions before making another change.');
        await load(); return;
      }
      if (!r.ok || result?.ok !== true) throw new Error(`HTTP ${r.status}`);
      assertAclReceipt(result.receipt, intent);
      await clearAclPending(intent);
      if (!current(generation)) return;
      setPending(null); await load();
    } catch (e) {
      if (!dispatched) {
        // No request was sent. Remove the unsent intent where storage remains available.
        try { await clearAclPending(intent); } catch { /* Storage remains unavailable; never send a write. */ }
        if (current(generation)) {
          setPending(null); setPolicy(null); setEnforceOn(null); setTools([]);
          setLoadError('State storage unavailable; no ACL change was sent. Reload before making changes');
        }
      } else if (current(generation)) setNotice('Change outcome unknown. Read the saved receipt before making another change.');
    } finally {
      mutationPending.current = false;
      if (current(generation)) setSaving(null);
    }
  };

  const recover = async () => {
    if (!pending || mutationPending.current) return;
    const generation = epoch.current;
    mutationPending.current = true; setSaving('receipt');
    try {
      const r = await transport(`/api/secureshop/admin/access-control/operations/${pending.body.operationId}`);
      if (r.status === 401 || r.status === 403) throw new Error('Sign in again to read this receipt. The change outcome is still unknown.');
      if (!r.ok) throw new Error('Receipt unavailable. The change outcome is still unknown.');
      const result = await r.json();
      if (!current(generation)) return;
      if (result?.ok !== true) throw new Error('Receipt unavailable.');
      assertAclReceipt(result.receipt, pending);
      await clearAclPending(pending);
      if (!current(generation)) return;
      setPending(null); setNotice(null); await load();
    } catch (e) { if (current(generation)) setNotice(e.message); }
    finally { mutationPending.current = false; if (current(generation)) setSaving(null); }
  };
  const unavailable = (bound.current && !policy) || pending !== null;


  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return tools;
    return tools.filter((t) => t.tool_name.toLowerCase().includes(q));
  }, [tools, filter]);

  const flip = useCallback(async (tool_name, role, current) => {
    if (loading || enforceOn === null || mutationPending.current || unavailable) return;
    if (policy) return versionedWrite('permission', { tool_name, role, allowed: !current });
    mutationPending.current = true;
    setSaving(`${tool_name}:${role}`);
    try {
      const r = await fetch('/api/secureshop/admin/access-control/permission', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tool_name, role, allowed: !current }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const result = await r.json();
      if (result?.ok !== true || result.tool_name !== tool_name || result.role !== role
        || typeof result.allowed !== 'boolean' || result.allowed !== !current) {
        throw new Error('Permission update not confirmed');
      }
      // Apply only an acknowledged update
      setTools((prev) => prev.map((t) => t.tool_name === tool_name
        ? { ...t, [role]: result.allowed ? 1 : 0 }
        : t));
    } catch (e) {
      setEnforceOn(null);
      setTools([]);
      setLoadError('Permission update not confirmed; reload current state before retrying');
      toast.error(`Failed to save: ${e.message}`);
    } finally {
      mutationPending.current = false;
      setSaving(null);
    }
  }, [toast, loading, enforceOn, policy, pending, transport]);

  const flipEnforcement = useCallback(async () => {
    if (loading || enforceOn === null || mutationPending.current || unavailable) return;
    if (policy) return versionedWrite('enforcement', { enabled: !enforceOn });
    mutationPending.current = true;
    setSaving('enforcement');
    try {
      const r = await fetch('/api/secureshop/admin/access-control/enforcement', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ enabled: !enforceOn }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const result = await r.json();
      if (result?.ok !== true || typeof result.enforce_tool_acl !== 'boolean'
        || result.enforce_tool_acl !== !enforceOn) {
        throw new Error('Enforcement update not confirmed');
      }
      setEnforceOn(result.enforce_tool_acl);
      toast.success(`Enforcement ${result.enforce_tool_acl ? 'ENABLED' : 'DISABLED'}`);
    } catch (e) {
      setEnforceOn(null);
      setTools([]);
      setLoadError('Enforcement update not confirmed; reload current state before retrying');
      toast.error(`Failed to toggle enforcement: ${e.message}`);
    } finally {
      mutationPending.current = false;
      setSaving(null);
    }
  }, [enforceOn, toast, loading, policy, pending, transport]);

  const enforcementDisabled = loading || enforceOn === null || saving !== null || unavailable;

  return (
    <PageTransition>
      <div style={{ maxWidth: 1100, margin: '0 auto', padding: '32px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div>
            <div className="ss-eyebrow">M14 · RBAC</div>
            <h1 className="ss-display" style={{ fontSize: 44, margin: '4px 0 4px' }}>Access Control</h1>
            <p style={{ fontSize: 14, opacity: 0.75, maxWidth: '58ch' }}>
              This matrix configures tool permissions for supported supervisor workflows. When
              enforcement is <strong>off</strong>, denied calls execute anyway and the trace
              is stamped <code>denied-by-acl</code> (the excessive-agency lesson, LLM03:2026). Flip
              enforcement on to close the chain at Layer B.
            </p>
          </div>
          <div
            data-testid="acl-enforcement-toggle"
            onClick={enforcementDisabled ? undefined : flipEnforcement}
            role="switch"
            aria-checked={enforceOn === null ? undefined : enforceOn}
            aria-disabled={enforcementDisabled}
            aria-label="Toggle ACL enforcement"
            tabIndex={enforcementDisabled ? -1 : 0}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); if (!enforcementDisabled) flipEnforcement(); } }}
            style={{
              padding: '12px 18px',
              border: `2px solid ${enforceOn ? 'var(--kelp)' : 'var(--rust)'}`,
              background: enforceOn
                ? 'color-mix(in srgb, var(--kelp) 12%, transparent)'
                : 'color-mix(in srgb, var(--rust) 12%, transparent)',
              cursor: enforcementDisabled ? 'default' : 'pointer',
              minWidth: 220, textAlign: 'center',
            }}
          >
            <div style={{ fontSize: 11, opacity: 0.7, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              SS_ENFORCE_TOOL_ACL
            </div>
            <div style={{ fontFamily: 'var(--display)', fontSize: 22, fontWeight: 700, marginTop: 4 }}>
              {loading ? 'LOADING' : enforceOn === null ? 'UNAVAILABLE' : enforceOn ? 'ON' : 'OFF'}
            </div>
            <div style={{ fontSize: 11, opacity: 0.6, marginTop: 4 }}>
              {enforceOn === null ? 'Enforcement state has not been verified' : enforceOn ? 'Layer B blocks denied calls' : 'Layer B logs only (LLM03:2026 excessive agency)'}
            </div>
          </div>
        </div>

        <div style={{ marginBottom: 16 }}>
          <input
            className="ss-input"
            placeholder="Filter tools (e.g. user-management, listing.import_bulk)"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ width: '100%', padding: 12 }}
          />
        </div>

        {(notice || pending || (bound.current && !policy && !loading)) && <div role="status">
          {notice || (pending ? 'An ACL change is awaiting receipt verification.' : 'ACL changes are unavailable for this launch.')}
          {pending && <button className="ss-btn" disabled={saving !== null} onClick={recover}>Read change receipt</button>}
        </div>}
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', opacity: 0.7 }}>Loading ACL matrix…</div>
        ) : loadError ? (
          <div role="alert" style={{ padding: 40, textAlign: 'center' }}>
            ACL unavailable: {loadError}.{' '}
            <button className="ss-btn" onClick={load}>Retry</button>
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', opacity: 0.7 }}>No tools match "{filter}".</div>
        ) : (
          <div style={{ border: '1px solid var(--rule)', overflow: 'hidden' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '2fr 1fr 1fr 1fr',
                background: 'var(--carbon)', color: 'var(--paper)',
                fontFamily: 'var(--mono)', fontSize: 12, padding: '10px 14px',
                letterSpacing: '0.08em', textTransform: 'uppercase',
              }}
            >
              <div>Tool</div>
              <div style={{ textAlign: 'center' }}>Customer</div>
              <div style={{ textAlign: 'center' }}>Merchant</div>
              <div style={{ textAlign: 'center' }}>Admin</div>
            </div>
            {filtered.map((t) => (
              <div
                key={t.tool_name}
                data-testid={`acl-row-${t.tool_name}`}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '2fr 1fr 1fr 1fr',
                  padding: '10px 14px',
                  borderTop: '1px solid var(--rule)',
                  fontSize: 13,
                  alignItems: 'center',
                }}
              >
                <div className="ss-mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.tool_name}</div>
                {['customer', 'merchant', 'admin'].map((role) => (
                  <div key={role} style={{ textAlign: 'center' }}>
                    <PermissionCell
                      allowed={!!t[role]}
                      onFlip={() => flip(t.tool_name, role, !!t[role])}
                      busy={saving !== null}
                      disabled={unavailable || t.readOnly === true || t.supported === false || (policy && t.applicable_roles?.[role] !== true)}
                      testId={`acl-cell-${t.tool_name}-${role}`}
                    />
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}

        <div style={{ marginTop: 20, fontSize: 12, opacity: 0.65, lineHeight: 1.5 }}>
          <strong>How this maps to the three layers:</strong>
          <ul style={{ marginTop: 6, paddingLeft: 20 }}>
            <li>Layer A (REST): <code>requireRole()</code> — orthogonal to this matrix. HTTP endpoints have their own middleware.</li>
            <li>Layer B (supervisor): reads this matrix before every <code>tool_use</code> dispatch. Off = log, On = block.</li>
            <li>Layer C (agent-host): each tool server may or may not double-check. <code>user-management.set_role</code> deliberately does <strong>not</strong> — that's the excessive-agency sink (LLM03:2026).</li>
          </ul>
        </div>
      </div>
    </PageTransition>
  );
}

function PermissionCell({ allowed, onFlip, busy, disabled, testId }) {
  return (
    <button
      type="button"
      data-testid={testId}
      data-allowed={allowed ? 'true' : 'false'}
      onClick={onFlip}
      disabled={busy || disabled}
      style={{
        border: `1px solid ${allowed ? 'var(--kelp)' : 'var(--rust)'}`,
        background: allowed
          ? 'color-mix(in srgb, var(--kelp) 15%, transparent)'
          : 'color-mix(in srgb, var(--rust) 15%, transparent)',
        color: allowed ? 'var(--kelp)' : 'var(--rust)',
        padding: '4px 12px', minWidth: 68, fontWeight: 600,
        cursor: busy ? 'wait' : 'pointer',
        fontFamily: 'var(--mono)', fontSize: 11, letterSpacing: '0.06em',
      }}
    >
      {busy ? '…' : (allowed ? 'ALLOW' : 'DENY')}
    </button>
  );
}
