import React, { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import PageTransition from '../../components/PageTransition.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { getBridgeFetchMetadata } from '../../bridge/fetchAdapter.mjs';
import { isPolicyVersion, isPolicyName, readPolicyState, readForgettablePolicyReferences, forgetPolicyReference, acknowledgePolicyPending, savePolicyPending, assertPolicyPendingCurrent, clearPolicyPending, markPolicyRevisionConflict, policyMutationDigests, assertPolicyReceipt } from './policyOperation.js';
import { useToast } from '../../context/ToastContext.jsx';

/**
 * Admin — Policies.jsx (Wave 2C).
 *
 * Full CRUD editor for platform policies. Preserves the two intentional
 * vulnerabilities:
 *   - LLM04 policy poisoning (policies re-read on every supervisor turn)
 *   - SSTI (update_policy runs input through the unsafe Nunjucks env)
 *
 * Layout:
 *   Left rail: policy list with "poisoned" badge for suspicious tokens.
 *   Right pane: split editor / preview; multi-select "inject into"; save,
 *   test render, delete confirmation, new policy modal.
 */

const SUSPICIOUS = /SYSTEM:|\[HIDDEN\]|DV-AI\{|process\.mainModule|\{\{\s*constructor/i;
const SUPERVISOR_ROLES = Object.freeze(['customer', 'merchant', 'admin']);
const TASK_TARGETS = Object.freeze(['summarizer', 'review-moderator', 'listing']);
const BOUND_POLICY_TARGETS = Object.freeze([...SUPERVISOR_ROLES, ...TASK_TARGETS]);
const HISTORICAL_POLICY_TARGETS = Object.freeze(['admin', 'analytics', 'customer', 'inventory',
  'listing', 'merchant', 'review-moderator', 'summarizer']);
const LEGACY_AGENT_ROLES = Object.freeze([...BOUND_POLICY_TARGETS, 'price-advisor', 'analytics']);

function exactTargets(value, allowed, required = false) {
  return Array.isArray(value) && (!required || value.length > 0) && new Set(value).size === value.length
    && value.every(target => allowed.includes(target));
}

function policyTargets(policy, allowed) {
  if (!policy || !isPolicyName(policy.name) || typeof policy.markdown_source !== 'string'
      || typeof policy.injected_into_json !== 'string') throw new Error('Unable to load policies');
  let targets;
  try { targets = JSON.parse(policy.injected_into_json); } catch { throw new Error('Unable to load policies'); }
  if (!exactTargets(targets, allowed, true)) throw new Error('Unable to load policies');
  return targets;
}

export default function AdminPolicies() {
  const [policies, setPolicies] = useState([]);
  const [selected, setSelected] = useState(null);
  const [draft, setDraft] = useState('');
  const [injectedInto, setInjectedInto] = useState([]);
  const [testResult, setTestResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showDelete, setShowDelete] = useState(false);
  const [newForm, setNewForm] = useState({ name: '', markdown: '', injected_into: ['customer'] });
  const [viewMode, setViewMode] = useState('split'); // split | source | preview

  const toastApi = useToast();
  const showToast = useCallback((msg, kind = 'info') => {
    if (kind === 'success') toastApi.success(msg);
    else if (kind === 'error') toastApi.error(msg);
    else if (kind === 'warn') toastApi.warn(msg);
    else toastApi.info(msg);
  }, [toastApi]);

  const authToken = useContext(AuthCtx)?.token;
  const transport = globalThis.fetch;
  const isBound = !!getBridgeFetchMetadata(transport)?.boundReviews;
  const [policyState, setPolicyState] = useState(null);
  const [supported, setSupported] = useState(['customer', 'merchant', 'admin']);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [readiness, setReadiness] = useState(isBound ? 'checking' : 'ready');
  const [notice, setNotice] = useState(null);
  const [pending, setPending] = useState(null);
  const [acknowledged, setAcknowledged] = useState([]);
  const [showDismiss, setShowDismiss] = useState(false);
  const [forgetSelection, setForgetSelection] = useState(null);
  const epoch = useRef(0), lock = useRef(false), selectedRef = useRef(null), editorVersion = useRef(null), controllers = useRef(new Set());
  const live = useRef({ authToken, transport }); live.current = { authToken, transport };
  const current = generation => epoch.current === generation && live.current.authToken === authToken
    && live.current.transport === transport && globalThis.fetch === transport;
  const request = async (url, options = {}) => {
    const controller = new AbortController(); controllers.current.add(controller);
    try { return await transport(url, { ...options, signal: controller.signal }); }
    finally { controllers.current.delete(controller); }
  };
  const openPolicy = (p, version = policyState?.version) => {
    editorVersion.current = version || null;
    selectedRef.current = p; setSelected(p); setDraft(p?.markdown_source || ''); setTestResult(null);
    let targets = []; try { targets = JSON.parse(p?.injected_into_json || '[]'); } catch { /* validated load */ }
    setInjectedInto(targets);
  };
  const load = useCallback(async () => {
    const generation = epoch.current;
    let readyConfirmed = !isBound;
    setLoading(true); setLoadError(null); setReadiness(isBound ? 'checking' : 'ready');
    try {
      if (isBound) {
        const readyResponse = await request('/api/secureshop/admin/policies/readiness');
        const readyValue = await readyResponse.json();
        if (!readyResponse.ok || !readyValue || Object.keys(readyValue).length !== 1
          || typeof readyValue.ready !== 'boolean') throw new Error('Policy readiness check failed');
        if (!current(generation)) return;
        if (readyValue.ready === false) {
          setReadiness('setup-required');
          setLoadError('Policy renderer configuration is required before policy editing is available.');
          return;
        }
        readyConfirmed = true;
        setReadiness('ready');
      }
      const response = await request('/api/secureshop/admin/policies');
      const value = await response.json();
      if (!response.ok || !Array.isArray(value?.policies)) throw new Error('Unable to load policies');
      const versioned = typeof value.version === 'string';
      if ((isBound && !versioned) || (versioned && (!isPolicyVersion(value.version)
        || typeof value.administration?.scopeKey !== 'string' || !/^[0-9a-f]{64}$/.test(value.administration.scopeKey) || value.administration.versionedPolicy !== true
        || !exactTargets(value.supported_targets, SUPERVISOR_ROLES)
        || value.supported_targets.length !== SUPERVISOR_ROLES.length
        || (Object.hasOwn(value, 'supported_task_targets') && (!exactTargets(value.supported_task_targets, TASK_TARGETS, true)))))) throw new Error('Policy administration unavailable');
      const supportedTasks = versioned ? (value.supported_task_targets || []) : [];
      const advertised = versioned ? [...value.supported_targets, ...supportedTasks] : LEGACY_AGENT_ROLES;
      value.policies.forEach(policy => policyTargets(policy,
        versioned ? HISTORICAL_POLICY_TARGETS : advertised));
      const state = versioned ? { version: value.version, scopeKey: value.administration.scopeKey } : null;
      const recovered = state ? readPolicyState(state.scopeKey) : {pending:null,history:[]};
      if (!current(generation)) return;
      setPolicyState(state); setPending(recovered.pending); setAcknowledged(recovered.history); setSupported(advertised); setPolicies(value.policies);
      // A refresh never replaces a selected dirty editor. A disappeared row is
      // retained for review; its next CAS must use the explicitly refreshed head.
      if (!selectedRef.current && value.policies.length) openPolicy(value.policies[0], state?.version);
    } catch (error) {
      if (!current(generation)) return;
      setReadiness(readyConfirmed ? 'ready' : 'error');
      setLoadError(error.message); setPolicyState(null); showToast(`load failed: ${error.message}`, 'error');
    } finally { if (current(generation)) setLoading(false); }
  // Selection/draft intentionally do not trigger background reloads.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [transport, authToken, isBound, showToast]);
  useEffect(() => {
    openPolicy(null); setPolicies([]); setPolicyState(null); setPending(null); setAcknowledged([]); setShowDismiss(false); setForgetSelection(null); setNotice(null); setBusy(false); lock.current = false;
    load();
    return () => { epoch.current += 1; for (const controller of controllers.current) controller.abort(); controllers.current.clear(); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);
  const disabled = busy || loading || !!loadError || !!pending || (isBound && (readiness !== 'ready' || !policyState));
  const targetChoices = isBound ? HISTORICAL_POLICY_TARGETS : LEGACY_AGENT_ROLES;
  // Read local metadata only; no recovery endpoint is called by this panel.
  let forgettable = [];
  if (policyState) {
    try { forgettable = readForgettablePolicyReferences(policyState.scopeKey); }
    catch { /* The existing load/recovery error keeps malformed storage fail-closed. */ }
  }
  const forgetSelectedReference = async () => {
    const selection = forgetSelection, generation = epoch.current;
    if (!selection || lock.current || !policyState || selection.currentScopeKey !== policyState.scopeKey || !current(generation)) return;
    lock.current = true; setBusy(true);
    try {
      await forgetPolicyReference(selection.reference, selection.currentScopeKey);
      if (!current(generation)) return;
      const saved = readPolicyState(policyState.scopeKey);
      setPending(saved.pending); setAcknowledged(saved.history); setForgetSelection(null);
      setNotice('Local recovery reference forgotten. The operation outcome was not verified.');
    } catch (error) {
      if (current(generation)) setNotice(error.message);
    } finally {
      if (current(generation)) { lock.current = false; setBusy(false); }
    }
  };
  const complete = async (receipt, operation, generation) => {
    const historical = acknowledged.some(row => row.operationId === operation.operationId);
    await assertPolicyReceipt(receipt, operation);
    if (!current(generation)) return;
    await clearPolicyPending(operation);
    if (!current(generation)) return;
    const saved = readPolicyState(operation.scopeKey); setPending(saved.pending); setAcknowledged(saved.history); setNotice(null);
    if (historical) { showToast('Prior operation verified; current policy state will be reloaded.', 'info'); await load(); return; }
    if (selectedRef.current?.name === operation.name) editorVersion.current = receipt.version;
    if (operation.action === 'delete') { if (selectedRef.current?.name === operation.name) openPolicy(null); setShowDelete(false); }
    else { setTestResult(receipt.renderResult); if (operation.action === 'create') { setShowNew(false); setNewForm({ name: '', markdown: '', injected_into: ['customer'] }); } }
    showToast(operation.action === 'preview' ? 'rendered — not persisted' : 'Policy operation verified', operation.action === 'preview' ? 'info' : 'success');
    await load();
  };
  const change = async (action, name, markdown, targets) => {
    if (disabled || lock.current) return;
    const generation = epoch.current;
    lock.current = true; setBusy(true); setNotice(null);
    const versioned = policyState;
    const label = { save:'save', preview:'render', create:'create', delete:'delete' }[action];
    let operation, dispatched = false, knownConflict = false;
    try {
      const body = action === 'delete' ? {} : { markdown, injected_into: [...targets] };
      if (action === 'save' || action === 'create') body.name = name;
      if (versioned) {
        const operationId = crypto.randomUUID();
        const digests = action === 'delete' ? { requestSha256: null }
          : await policyMutationDigests({ operationId, name, markdown, injected_into: targets }, supported.filter(target => TASK_TARGETS.includes(target)));
        operation = { scopeKey: versioned.scopeKey, operationId, expectedVersion: action === 'create' ? versioned.version : editorVersion.current, action, name, ...digests };
        if (!current(generation)) return;
        await savePolicyPending(operation);
        if (!current(generation)) return;
        assertPolicyPendingCurrent(operation);
        setPending(operation); Object.assign(body, { operationId, expectedVersion: operation.expectedVersion });
      } else if (action === 'preview') delete body.injected_into;
      if (!current(generation)) return;
      const url = action === 'preview' ? `/api/secureshop/admin/policies/${encodeURIComponent(name)}/render`
        : action === 'delete' ? `/api/secureshop/admin/policies/${encodeURIComponent(name)}` : '/api/secureshop/admin/policies';
      dispatched = true;
      const response = await request(url, { method: action === 'delete' ? 'DELETE' : 'POST',
        ...(action !== 'delete' || versioned ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {}) });
      const value = await response.json();
      if (!current(generation)) return;
      if (versioned) {
        if (response.status === 409 && value?.code === 'REVISION_CONFLICT') {
          knownConflict = true;
          const rejected = { ...operation, outcome: 'revision_conflict' };
          setPending(rejected);
          setNotice('Policy change was not published because its version is stale. The renderer may have run. Review the current version before a separate new attempt.');
          await markPolicyRevisionConflict(operation);
          return;
        }
        if (response.status === 503 && value?.code === 'POLICY_RENDER_BUSY') {
          await clearPolicyPending(operation);
          if (!current(generation)) return;
          setPending(null); setNotice('Renderer busy; operation was not admitted. You may retry manually.'); return;
        }
        if (response.status === 202 || !response.ok || value?.ok !== true) throw new Error('Outcome not confirmed. Read the saved operation status; do not submit another render.');
        await complete(value.receipt, operation, generation);
      } else {
        if (!response.ok || value?.ok !== true) throw new Error(value?.error || `Policy ${label} failed`);
        if (action === 'delete') { openPolicy(null); setShowDelete(false); }
        else { setTestResult(value); if (action === 'create') setShowNew(false); }
        showToast(action === 'save' ? `saved — rendered length ${value.rendered_length}` : action === 'preview' ? 'rendered — not persisted' : `${label}d ${name}`, action === 'preview' ? 'info' : 'success');
        if (action !== 'preview') await load();
      }
    } catch (error) {
      if (!current(generation)) return;
      if (versioned) setNotice(knownConflict ? 'Policy change was not published. The renderer may have run. Saving this conflict status failed; review the current version before a separate new attempt.' : dispatched ? 'Outcome unknown. Refresh operation status; no automatic retry or new render.' : `Operation was not sent: ${error.message}`);
      showToast(`${label} failed: ${error.message}`, 'error');
    } finally { if (current(generation)) { lock.current = false; setBusy(false); } }
  };
  const recover = async (operation = pending) => {
    if (!operation || lock.current) return;
    const generation = epoch.current;
    lock.current = true; setBusy(true);
    try {
      const response = await request(`/api/secureshop/admin/policies/operations/${operation.operationId}`);
      const value = await response.json();
      if (!current(generation)) return;
      if (response.status === 202) { setNotice('Operation remains pending. No render will be repeated.'); return; }
      if (response.status === 404) { setNotice('Operation not observed. Outcome remains unknown; do not submit another render.'); return; }
      if (!response.ok || value?.ok !== true) throw new Error('Operation recovery unavailable for this session');
      await complete(value.receipt, operation, generation);
    } catch (error) { if (current(generation)) setNotice(error.message); }
    finally { if (current(generation)) { lock.current = false; setBusy(false); } }
  };
  const refreshPending = async (knownConflict = false) => {
    if (!pending || !policyState || lock.current) return;
    if (knownConflict !== (pending.outcome === 'revision_conflict')) return;
    const operation = pending, generation = epoch.current;
    lock.current = true; setBusy(true);
    try {
      const response = await request('/api/secureshop/admin/policies');
      const value = await response.json();
      if (!current(generation)) return;
      const expectedTasks = supported.filter(target => TASK_TARGETS.includes(target));
      if (!response.ok || value?.administration?.versionedPolicy !== true
        || value.administration.scopeKey !== operation.scopeKey || typeof value.version !== 'string'
        || !isPolicyVersion(value.version) || !Array.isArray(value.policies)
        || !exactTargets(value.supported_targets, SUPERVISOR_ROLES)
        || value.supported_targets.length !== SUPERVISOR_ROLES.length
        || JSON.stringify(value.supported_task_targets || []) !== JSON.stringify(expectedTasks)) throw new Error('Current policy head or original session could not be verified; operation remains locked.');
      try { value.policies.forEach(policy => policyTargets(policy, HISTORICAL_POLICY_TARGETS)); }
      catch { throw new Error('Current policy head or original session could not be verified; operation remains locked.'); }
      if (knownConflict) await clearPolicyPending(operation);
      else await acknowledgePolicyPending(operation);
      if (!current(generation)) return;
      const saved = readPolicyState(operation.scopeKey); setPending(saved.pending); setAcknowledged(saved.history);
      setPolicyState({ scopeKey: operation.scopeKey, version: value.version }); editorVersion.current = value.version;
      setPolicies(value.policies); setShowDismiss(false);
      setNotice(knownConflict ? 'Policy change was not published. Current version reviewed; your draft and targets are retained. A separate Save starts a new attempt; no render was repeated.' : 'Unknown outcome acknowledged. Review your draft against the refreshed policy head before a separate new attempt. The prior operation may still publish or fail its version check.');
    } catch (error) { if (current(generation)) setNotice(error.message); }
    finally { if (current(generation)) { lock.current = false; setBusy(false); } }
  };
  const dismiss = () => refreshPending(false);
  const save = () => selected && change('save', selected.name, draft, injectedInto);
  const testRender = () => selected && change('preview', selected.name, draft, injectedInto);
  const doDelete = () => selected && change('delete', selected.name);
  const createNew = event => { event.preventDefault(); if (newForm.name.trim()) change('create', newForm.name, newForm.markdown, newForm.injected_into); };

  const draftPoisoned = useMemo(() => SUSPICIOUS.test(draft), [draft]);
  const currentPolicyVersion = policies.find(policy => policy.name === selected?.name)?.policy_version;

  const toggleInject = (role) => {
    setInjectedInto(prev => prev.includes(role) ? prev.filter(r => r !== role) : [...prev, role]);
  };

  return (
    <PageTransition>
      <header className="ss-admin-policies__header">
        <div className="ss-admin-policies__intro">
          <div className="ss-card__meta">ADMIN LENS</div>
          <h1 className="ss-display" style={{ fontSize: 36, margin: '4px 0 6px 0' }}>Policies</h1>
          <p className="ss-mono" style={{ opacity: 0.7, fontSize: 12, maxWidth: '70ch' }}>
            Policies render through unsafe Nunjucks (SSTI). Saved content can influence agents
            that consume the selected role or task policies (LLM05:2026 data and model poisoning). Check the run trace for actual inclusion.
          </p>
        </div>
        <div className="ss-admin-policies__actions"><button className="ss-btn ss-btn--ghost" onClick={load} disabled={busy || loading}>Reload policies</button><button className="ss-btn" onClick={() => setShowNew(true)} disabled={disabled}>+ new policy</button></div>
      </header>

      {(loadError || notice || pending || acknowledged.length > 0) && <div className="ss-mono" role="alert" style={{ marginBottom: 12 }}>
        {loadError || notice || (pending ? pending.outcome === 'revision_conflict' ? 'Policy change was not published. The renderer may have run. Review the current version before a separate new attempt.' : 'A saved policy operation awaits verification.' : 'Previous operations have acknowledged unknown outcomes.')}
        {pending?.outcome === 'revision_conflict' && <button className="ss-btn ss-btn--ghost" onClick={() => refreshPending(true)} disabled={busy}>Review current policy version</button>}
        {pending && pending.outcome !== 'revision_conflict' && <><button className="ss-btn ss-btn--ghost" onClick={() => recover()} disabled={busy}>Refresh operation status</button><button className="ss-btn ss-btn--ghost" onClick={() => setShowDismiss(true)} disabled={busy}>Dismiss pending operation…</button></>}
        {acknowledged.map(operation => <div key={operation.operationId}>
          {operation.name} · {operation.operationId} · outcome unknown (acknowledged)
          <button className="ss-btn ss-btn--ghost" disabled={busy} onClick={() => recover(operation)}>Check prior operation status</button>
        </div>)}
      </div>}
      {forgettable.length > 0 && <details className="ss-mono" style={{ marginBottom: 12 }}>
        <summary>Local recovery references ({forgettable.length})</summary>
        <p>Copy these nonsecret IDs before forgetting a reference. Original session authority may be required for later readback.</p>
        {forgettable.map(reference => <div key={`${reference.operation.scopeKey}:${reference.operation.operationId}:${reference.kind}`} style={{ marginBottom: 8 }}>
          <p style={{ overflowWrap: 'anywhere', userSelect: 'text' }}>
            Operation: {reference.operation.operationId}<br />Scope: {reference.operation.scopeKey}<br />
            {reference.kind === 'history' ? 'Acknowledged outcome reference' : 'Retained reference from a different session'}
          </p>
          <button className="ss-btn ss-btn--ghost" disabled={busy || loading} onClick={() => setForgetSelection({ currentScopeKey: policyState.scopeKey, reference })}>Forget local reference…</button>
        </div>)}
      </details>}
      <div className="ss-admin-policies__grid">
        {/* Policy list */}
        <aside style={{ border: '1px solid var(--rule)', maxHeight: '75vh', overflowY: 'auto' }}>
          <div className="ss-mono" style={{ padding: '8px 12px', borderBottom: '1px solid var(--rule)', fontSize: 11, opacity: 0.6, textTransform: 'uppercase' }}>
            {loading ? 'loading policies…' : loadError ? 'policies unavailable' : <>{policies.length} polic{policies.length === 1 ? 'y' : 'ies'}</>}
          </div>
          <AnimatePresence>
            {policies.map((p, i) => {
              const isPoisoned = p.poisoned || SUSPICIOUS.test(p.markdown_source || '');
              return (
                <motion.button
                  key={p.name}
                  initial={{ opacity: 0, x: -6 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.24, delay: i * 0.035 }}
                  onClick={() => openPolicy(p)}
                  disabled={busy || !!pending}
                  aria-label={`Open policy ${p.name}`}
                  style={{
                    display: 'block', width: '100%', textAlign: 'left', padding: '12px 14px',
                    background: selected?.name === p.name ? 'color-mix(in srgb, var(--paper) 82%, var(--carbon))' : 'transparent',
                    border: 'none', borderBottom: '1px solid var(--rule)', cursor: 'pointer',
                    fontFamily: 'inherit', color: 'var(--ink)',
                  }}
                >
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>{p.name}</div>
                  <div className="ss-mono" style={{ fontSize: 10, opacity: 0.65, display: 'flex', gap: 8, alignItems: 'center' }}>
                    {isPoisoned ? (
                      <span style={{ color: 'var(--rust)', fontWeight: 600 }}>● poisoned</span>
                    ) : (
                      <span style={{ opacity: 0.6 }}>○ clean</span>
                    )}
                    <span style={{ opacity: 0.5 }}>{isBound
                      ? `· ${isPolicyVersion(p.policy_version) ? `version ${p.policy_version}` : 'version unavailable'}`
                      : `· ${_fmtTs(p.updated_at)}`}</span>
                  </div>
                </motion.button>
              );
            })}
          </AnimatePresence>
          {!loading && !loadError && policies.length === 0 && (
            <div className="ss-mono" style={{ padding: 20, opacity: 0.55, fontSize: 12 }}>no policies yet — click new</div>
          )}
        </aside>

        {/* Editor pane */}
        <section className="ss-admin-policies__editor">
          {!selected ? (
            <div className="ss-mono" style={{ padding: 40, opacity: 0.55, border: '1px solid var(--rule)', textAlign: 'center' }}>
              {isBound && readiness !== 'ready'
                ? 'Policy editing will be available after the renderer is ready.'
                : 'select a policy on the left, or create a new one'}
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 12 }}>
                <div>
                  <h2 style={{ margin: 0, fontFamily: 'var(--display)', fontSize: 22 }}>{selected.name}</h2>
                  <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55, marginTop: 4 }}>
                    {isBound
                      ? `current policy ${isPolicyVersion(currentPolicyVersion) ? `version ${currentPolicyVersion}` : 'version unavailable'}`
                      : `last updated ${_fmtTs(selected.updated_at)}`} · {(selected.markdown_source || '').length} chars
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 4 }}>
                  <ViewToggle value={viewMode} onChange={setViewMode} />
                </div>
              </div>

              {/* Inject-into multi-select */}
              <div style={{ marginBottom: 12, padding: 10, border: '1px solid var(--rule)', background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))' }}>
                <div className="ss-mono" style={{ fontSize: 11, opacity: 0.65, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Inject into supervisors</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {targetChoices.map(r => (
                    <label
                      key={r}
                      className="ss-mono"
                      style={{
                        padding: '4px 10px', border: `1px solid ${injectedInto.includes(r) ? 'var(--signal)' : 'var(--rule)'}`,
                        color: injectedInto.includes(r) ? 'var(--signal)' : 'var(--ink)',
                        background: injectedInto.includes(r) ? 'color-mix(in srgb, var(--signal) 8%, transparent)' : 'transparent',
                        cursor: 'pointer', fontSize: 12, userSelect: 'none',
                      }}
                    >
                      <input
                        type="checkbox"
                          disabled={disabled || (!supported.includes(r) && !injectedInto.includes(r))}
                        checked={injectedInto.includes(r)}
                        onChange={() => toggleInject(r)}
                        style={{ marginRight: 6 }}
                      />
                      {r}{!supported.includes(r) ? ' (unavailable)' : ''}
                    </label>
                  ))}
                </div>
              </div>

              {/* Split editor */}
              <div style={{ display: 'grid', gridTemplateColumns: viewMode === 'split' ? '1fr 1fr' : '1fr', gap: 12, marginBottom: 12 }}>
                {(viewMode === 'split' || viewMode === 'source') && (
                  <div>
                    <div className="ss-mono" style={{ fontSize: 10, opacity: 0.6, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>source (markdown + jinja)</div>
                    <textarea
                      value={draft}
                      disabled={busy || !!pending}
                      onChange={(e) => setDraft(e.target.value)}
                      rows={22}
                      spellCheck={false}
                      aria-label="Policy markdown source"
                      style={{
                        width: '100%', fontFamily: 'var(--mono)', fontSize: 12, lineHeight: 1.55,
                        padding: 12, border: '1px solid var(--rule)', background: 'var(--paper)',
                        resize: 'vertical',
                      }}
                    />
                  </div>
                )}
                {(viewMode === 'split' || viewMode === 'preview') && (
                  <div>
                    <div className="ss-mono" style={{ fontSize: 10, opacity: 0.6, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      live preview {testResult && <span style={{ opacity: 0.55 }}>· last render {_fmtTs(new Date().toISOString())}</span>}
                    </div>
                    <div
                      style={{
                        padding: 12, border: '1px solid var(--rule)',
                        background: 'color-mix(in srgb, var(--paper) 96%, var(--carbon))',
                        fontFamily: 'var(--body)', fontSize: 13, lineHeight: 1.55,
                        minHeight: 340, whiteSpace: 'pre-wrap',
                      }}
                    >
                      {testResult?.rendered ?? renderMarkdownPreview(draft)}
                    </div>
                  </div>
                )}
              </div>

              {/* Action bar */}
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <button className="ss-btn" onClick={save} disabled={disabled}>{busy ? 'saving…' : 'save (renders → persists)'}</button>
                <button className="ss-btn ss-btn--ghost" onClick={testRender} disabled={disabled}>test render (no persist)</button>
                <button className="ss-btn ss-btn--ghost" onClick={() => setShowDelete(true)} disabled={disabled} style={{ color: 'var(--rust)', borderColor: 'var(--rust)' }}>delete</button>
                {draftPoisoned && (
                  <div className="ss-mono" style={{ color: 'var(--rust)', fontSize: 11, marginLeft: 'auto' }}>
                    ⚠ draft contains suspicious tokens — indicator only, no enforcement
                  </div>
                )}
              </div>

              {/* SSTI render output */}
              <AnimatePresence>
                {testResult && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    style={{ marginTop: 12 }}
                  >
                    <div className="ss-mono" style={{ fontSize: 11, opacity: 0.65, marginBottom: 6 }}>
                      rendered result ({testResult.rendered_length ?? testResult.rendered?.length ?? 0} chars)
                      {testResult.kind === 'literal' ? ' · literal policy text; no template execution' :
                        testResult.kind === 'isolated_template' ? ` · isolated template result; command effect ${testResult.effectWitness.commandEffectObserved ? 'observed' : 'not observed'}` :
                          testResult.version === 1 ? ' · historical renderer receipt' : ' · local preview'}
                      {(testResult.rendered || '').length > 4000 ? ' · first 4,000 characters shown' : ''}
                    </div>
                    <pre className="ss-mono" style={{
                      background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 12,
                      border: '1px solid var(--rule)', fontSize: 12, margin: 0,
                      whiteSpace: 'pre-wrap', maxHeight: 300, overflowY: 'auto',
                    }}>
                      {(testResult.rendered || testResult.error || '').slice(0, 4000)}
                    </pre>
                  </motion.div>
                )}
              </AnimatePresence>
            </>
          )}
        </section>
      </div>

      {/* New policy modal */}
      <AnimatePresence>
        {showNew && (
          <ModalBackdrop onClose={() => setShowNew(false)}>
            <motion.div
              initial={{ scale: 0.96, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.96, opacity: 0 }}
              transition={{ duration: 0.24, ease: [0.34, 1.56, 0.64, 1] }}
              onClick={(e) => e.stopPropagation()}
              className="ss-role-modal"
              style={{ minWidth: 540, maxWidth: 720 }}
            >
              <h3>New policy</h3>
              <form onSubmit={createNew} style={{ display: 'grid', gap: 12 }}>
                <label className="ss-mono" style={{ fontSize: 12 }}>
                  name
                  <input
                    required
                    className="ss-lane__input"
                    value={newForm.name}
                    disabled={busy || !!pending}
                    onChange={(e) => setNewForm({ ...newForm, name: e.target.value })}
                    placeholder="e.g. return_policy"
                    autoFocus
                  />
                </label>
                <label className="ss-mono" style={{ fontSize: 12 }}>
                  markdown source
                  <textarea
                    className="ss-lane__input"
                    rows={10}
                    value={newForm.markdown}
                    disabled={busy || !!pending}
                    onChange={(e) => setNewForm({ ...newForm, markdown: e.target.value })}
                    style={{ fontFamily: 'var(--mono)', fontSize: 12 }}
                  />
                </label>
                <div className="ss-mono" style={{ fontSize: 12 }}>
                  inject into
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                    {targetChoices.map(r => (
                      <label
                        key={r}
                        style={{
                          padding: '3px 8px', border: `1px solid ${newForm.injected_into.includes(r) ? 'var(--signal)' : 'var(--rule)'}`,
                          color: newForm.injected_into.includes(r) ? 'var(--signal)' : 'var(--ink)',
                          fontSize: 11, cursor: 'pointer',
                        }}
                      >
                        <input
                          type="checkbox"
                          disabled={disabled || !supported.includes(r)}
                          checked={newForm.injected_into.includes(r)}
                          onChange={() => setNewForm(f => ({
                            ...f,
                            injected_into: f.injected_into.includes(r)
                              ? f.injected_into.filter(x => x !== r)
                              : [...f.injected_into, r],
                          }))}
                          style={{ marginRight: 4 }}
                        />
                        {r}{!supported.includes(r) ? ' (unavailable)' : ''}
                      </label>
                    ))}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                  <button type="button" className="ss-btn ss-btn--ghost" onClick={() => setShowNew(false)}>cancel</button>
                  <button type="submit" className="ss-btn" disabled={disabled || !newForm.name.trim() || !newForm.injected_into.length}>{busy ? 'creating…' : 'create'}</button>
                </div>
              </form>
            </motion.div>
          </ModalBackdrop>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showDismiss && pending && <ModalBackdrop onClose={() => !busy && setShowDismiss(false)}>
          <motion.div className="ss-role-modal" onClick={event => event.stopPropagation()} style={{ minWidth: 420 }}>
            <h3>Dismiss pending operation?</h3>
            <p className="ss-mono" style={{ fontSize: 12 }}>{pending.operationId} · outcome unknown</p>
            <p className="ss-mono" style={{ fontSize: 12 }}>The prior render may have executed and may still publish or fail its version check. Dismissal does not cancel it or prove failure. Its ID remains available for readback. A new attempt requires a separate action.</p>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="ss-btn ss-btn--ghost" disabled={busy} onClick={() => setShowDismiss(false)}>cancel</button>
              <button className="ss-btn" disabled={busy} onClick={dismiss}>Acknowledge unknown outcome</button>
            </div>
          </motion.div>
        </ModalBackdrop>}
      </AnimatePresence>

      <AnimatePresence>
        {forgetSelection && <ModalBackdrop onClose={() => !busy && setForgetSelection(null)}>
          <motion.div className="ss-role-modal" onClick={event => event.stopPropagation()} style={{ minWidth: 'min(420px, 92vw)', maxHeight: '90vh', overflowY: 'auto' }}>
            <h3>Forget local recovery reference?</h3>
            <p className="ss-mono" style={{ overflowWrap: 'anywhere', userSelect: 'text' }}>Operation: {forgetSelection.reference.operation.operationId}<br />Scope: {forgetSelection.reference.operation.scopeKey}</p>
            <p>This removes only this browser's local reference. It does not cancel, publish, or verify the operation, and does not delete its server receipt. The operation may still complete. Original session authority may be required to recover it later. Copy the IDs above if you need them.</p>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="ss-btn ss-btn--ghost" disabled={busy} onClick={() => setForgetSelection(null)}>cancel</button>
              <button className="ss-btn" disabled={busy} onClick={forgetSelectedReference}>Forget this local reference</button>
            </div>
          </motion.div>
        </ModalBackdrop>}
      </AnimatePresence>

      {/* Delete confirmation */}
      <AnimatePresence>
        {showDelete && selected && (
          <ModalBackdrop onClose={() => setShowDelete(false)}>
            <motion.div
              initial={{ scale: 0.96, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.96, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="ss-role-modal"
              style={{ minWidth: 420 }}
            >
              <h3>Delete policy?</h3>
              <p className="ss-mono" style={{ fontSize: 12, opacity: 0.75, marginBottom: 20 }}>
                <b style={{ color: 'var(--rust)' }}>{selected.name}</b> will be removed. Supervisor prompts on the next turn will not include it.
              </p>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button className="ss-btn ss-btn--ghost" onClick={() => setShowDelete(false)}>cancel</button>
                <button className="ss-btn" style={{ background: 'var(--rust)' }} onClick={doDelete} disabled={disabled}>{busy ? 'deleting…' : 'delete'}</button>
              </div>
            </motion.div>
          </ModalBackdrop>
        )}
      </AnimatePresence>

      {/* Toasts now render via <ToastProvider> at the Shell level (Wave 3A). */}
    </PageTransition>
  );
}

function ModalBackdrop({ children, onClose }) {
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      onClick={onClose}
      className="ss-role-modal-backdrop"
      style={{ zIndex: 60 }}
    >{children}</motion.div>
  );
}

function ViewToggle({ value, onChange }) {
  const opts = [
    { k: 'source', label: 'source' },
    { k: 'split',  label: 'split' },
    { k: 'preview',label: 'preview' },
  ];
  return (
    <div style={{ display: 'flex', border: '1px solid var(--rule)' }}>
      {opts.map(o => (
        <button
          key={o.k}
          onClick={() => onChange(o.k)}
          className="ss-mono"
          style={{
            padding: '4px 10px', border: 'none', fontSize: 11, cursor: 'pointer',
            background: value === o.k ? 'color-mix(in srgb, var(--paper) 82%, var(--carbon))' : 'transparent',
            color: 'var(--ink)',
          }}
        >{o.label}</button>
      ))}
    </div>
  );
}

// Minimal in-memory markdown-esque preview (headings + bold). Not real
// markdown — just a hint so authors can eyeball layout without SSTI eval.
function renderMarkdownPreview(md) {
  if (!md) return '(empty)';
  return String(md)
    .replace(/^# (.+)$/gm, '## $1')
    .replace(/\*\*(.+?)\*\*/g, '$1'); // strip markers
}

function _fmtTs(ts) {
  if (!ts) return '—';
  return String(ts).replace('T', ' ').replace('Z', '').slice(0, 19);
}
