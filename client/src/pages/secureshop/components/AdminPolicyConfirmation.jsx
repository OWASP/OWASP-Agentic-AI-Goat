import React, { useEffect, useRef, useState } from 'react';
import { decodeRolePolicyProposal, sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { assertPolicyPendingCurrent, assertPolicyReceipt, clearPolicyPending,
  policyMutationDigests, readSavedPolicyPending, savePolicyPending } from '../pages/admin/policyOperation.js';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const TASK_TARGETS = ['summarizer', 'review-moderator', 'listing'];
const same = (a, b) => a && b && JSON.stringify(a) === JSON.stringify(b);

function PolicySource({ heading, source }) {
  if (!source) return null;
  return <div className="ss-admin-policy-review__source">
    <strong>{heading}</strong>
    <p>Shown to: {source.targets.join(', ')}</p>
    <pre style={{ maxHeight: 260, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
      border: '1px solid var(--rule)', borderRadius: 8, padding: 12 }}>{source.markdown}</pre>
  </div>;
}

export default function AdminPolicyConfirmation({ proposal = null, sessionId = null, requestId = null,
  authorityKey, transport = globalThis.fetch, locked = false, onOutcomeChange }) {
  const [scope, setScope] = useState(null);
  const [pending, setPending] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [receipt, setReceipt] = useState(null);
  const [storageFault, setStorageFault] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), mountedRef = useRef(false);
  const proposalId = proposal?.proposalId || null;
  useEffect(() => { onOutcomeChange?.(value => value + 1); }, [pending, receipt, notice, onOutcomeChange]);

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current, controller = new AbortController();
    activeRef.current?.abort(); activeRef.current = null;
    setScope(null); setPending(null); setBusy(false); setReceipt(null); setNotice(''); setStorageFault(false);
    const current = () => mountedRef.current && epochRef.current === epoch
      && !controller.signal.aborted && globalThis.fetch === transport;
    try {
      const rows = readSavedPolicyPending();
      if (rows.length === 1) { setPending(rows[0]); setNotice('A policy operation is saved. Check its exact outcome before another render.'); }
      else if (rows.length > 1) { setStorageFault(true); setNotice('Multiple saved policy operations need review in Policies. No new render can be sent here.'); }
    } catch { setStorageFault(true); setNotice('Saved policy state is unavailable. No new render can be sent.'); }
    Promise.resolve().then(async () => {
      const response = await transport('/api/secureshop/admin/policies', { signal: controller.signal });
      if (!response.ok) throw Error('Policy availability is unavailable.');
      const value = await response.json();
      if (!current()) return;
      const tasks = Object.hasOwn(value, 'supported_task_targets') ? value.supported_task_targets : [];
      if (value?.administration?.versionedPolicy !== true || !SHA.test(value.administration.scopeKey)
        || !Array.isArray(tasks) || (Object.hasOwn(value, 'supported_task_targets') && !tasks.length)
        || new Set(tasks).size !== tasks.length || tasks.some(target => !TASK_TARGETS.includes(target))) {
        throw Error('Policy availability is unavailable.');
      }
      const currentScope = value.administration.scopeKey;
      setScope({ key: currentScope, taskTargets: tasks });
    }).catch(error => {
      if (!current()) return;
      if (/Saved policy/.test(error.message)) setStorageFault(true);
      setNotice(error.message || 'Policy availability is unavailable.');
    });
    return () => { mountedRef.current = false; epochRef.current += 1; controller.abort();
      activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, proposalId, requestId, sessionId, transport]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/admin/policies/operations/${saved.operationId}`,
      { signal });
    if (response.status === 404) return { state: 'not_found' };
    if (response.status === 202) return { state: 'pending' };
    if (!response.ok) throw Error(`Saved policy lookup failed (${response.status})`);
    const value = await response.json();
    if (value?.ok !== true) throw Error('Saved policy receipt is unavailable.');
    return { state: 'completed', receipt: await assertPolicyReceipt(value.receipt, saved) };
  };

  const run = async confirm => {
    if (activeRef.current) return;
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setBusy(true); setNotice('');
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted
      && globalThis.fetch === transport;
    let saved = null;
    const show = async (reference, result) => {
      if (!current()) return;
      if (!scope) throw Error('Policy availability is unavailable. Check the saved operation when it returns.');
      if (scope.key !== reference.scopeKey) {
        throw Error('Saved policy operation belongs to another policy scope. Use its original session to check it.');
      }
      if (result.state !== 'completed') {
        setPending(reference);
        setNotice(result.state === 'pending' ? 'Policy render is still pending. Check the saved operation again.'
          : 'Policy outcome is unconfirmed. Check the saved operation; no render will be repeated.');
        return;
      }
      await clearPolicyPending(reference);
      if (!current()) return;
      setPending(null); setReceipt(result.receipt);
      setNotice(reference.action === 'preview' ? 'Policy preview completed. The policy was not published.'
        : reference.action === 'delete' ? 'Policy deletion confirmed from the saved receipt.'
          : 'Policy change confirmed from the saved receipt.');
    };
    try {
      if (storageFault) throw Error('Saved policy state is unavailable.');
      const rows = readSavedPolicyPending();
      if (rows.length > 1) throw Error('Multiple saved policy operations need review in Policies.');
      saved = rows[0] || null;
      if (saved) {
        setPending(saved);
        if (!scope) throw Error('Policy availability is unavailable. Check the saved operation when it returns.');
        if (scope.key !== saved.scopeKey) {
          throw Error('Saved policy operation belongs to another policy scope. Use its original session to check it.');
        }
        await show(saved, await readExact(saved, controller.signal));
        return;
      }
      if (!scope) throw Error('Policy availability is unavailable.');
      if (!confirm || locked || !proposal || !UUID.test(sessionId || '') || !UUID.test(requestId || '')) return;
      const candidate = await decodeRolePolicyProposal(proposal);
      if (!current()) return;
      if (candidate.scopeKey !== scope.key) throw Error('Policy scene changed. Request a fresh review.');
      const sourceResponse = await transport(`/api/secureshop/agents/admin/assistant/operations/${sessionId}/${requestId}`,
        { signal: controller.signal });
      if (!sourceResponse.ok) throw Error('Saved assistant proposal unavailable. No render was submitted.');
      const source = await sourceResponse.json();
      if (!current()) return;
      const savedProposal = await decodeRolePolicyProposal(source.policyProposal);
      if (!current()) return;
      if (source.sessionId !== sessionId || source.requestId !== requestId
        || source.status !== 'completed' || source.replayed !== true
        || source.stopReason !== 'end_turn' || !sameRolePolicyMode(source.modeCapability, candidate.modeCapability)
        || !same(savedProposal, candidate)) {
        throw Error('Saved policy proposal changed. No render was submitted.');
      }
      const digests = candidate.action === 'delete' ? { requestSha256: null }
        : await policyMutationDigests({ operationId: candidate.proposalId, name: candidate.name,
          markdown: candidate.after.markdown, injected_into: candidate.after.targets }, scope.taskTargets);
      if (!current()) return;
      saved = { scopeKey: candidate.scopeKey, operationId: candidate.proposalId,
        expectedVersion: candidate.expectedVersion, action: candidate.action === 'edit' ? 'save' : candidate.action,
        name: candidate.name, ...digests };
      await savePolicyPending(saved);
      if (!current()) return;
      assertPolicyPendingCurrent(saved);
      setPending(saved);
      const prior = await readExact(saved, controller.signal);
      if (!current()) return;
      if (prior.state !== 'not_found') { await show(saved, prior); return; }
      assertPolicyPendingCurrent(saved);
      try {
        await transport('/api/secureshop/agents/admin/assistant/policies/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId, requestId, proposalId: saved.operationId }),
          signal: controller.signal,
        });
      } catch { /* Only the exact saved operation GET confirms the outcome. */ }
      if (!current()) return;
      await show(saved, await readExact(saved, controller.signal));
    } catch (error) {
      if (!current()) return;
      try { setPending(readSavedPolicyPending()[0] || saved); }
      catch { setStorageFault(true); if (saved) setPending(saved); }
      setNotice(error?.message || 'Policy outcome unavailable. Check the saved operation.');
    } finally {
      if (current()) { activeRef.current = null; setBusy(false); }
    }
  };

  if (!proposal && !pending && !receipt && !notice) return null;
  return <section className="ss-card ss-admin-policy-review" aria-label="Admin policy review"
    style={{ padding: 14, marginTop: 12, border: '1px solid var(--rule)' }}>
    {proposal && !pending && !receipt && <>
      <h3 style={{ fontFamily: 'var(--display)', margin: '4px 0 10px' }}>Review policy {proposal.action}</h3>
      <p><strong>{proposal.name}</strong> · {proposal.action === 'preview'
        ? 'Preview only; no publication' : proposal.action === 'delete'
          ? 'Delete after confirmation' : 'Publish after confirmation'}</p>
      <PolicySource heading="Current policy" source={proposal.before} />
      <PolicySource heading="Proposed policy" source={proposal.after} />
      <button className="ss-btn" type="button" disabled={busy || locked || !scope
        || scope.key !== proposal.scopeKey || storageFault} onClick={() => void run(true)}>
        {proposal.action === 'preview' ? 'Preview policy' : proposal.action === 'delete'
          ? 'Delete policy' : 'Save policy'}
      </button>
    </>}
    {pending && <button className="ss-btn ss-btn--ghost" type="button" disabled={busy || !scope || storageFault}
      onClick={() => void run(false)}>Check saved policy operation</button>}
    {receipt && <div role="status">
      <p>{notice}</p>
      {receipt.renderResult && <div>
        <strong>Saved policy renderer output</strong>
        <p className="ss-mono">{receipt.renderResult.kind === 'literal'
          ? 'Literal policy text; no template execution.'
          : receipt.renderResult.kind === 'isolated_template'
            ? `Isolated template result. Command effect ${receipt.renderResult.effectWitness.commandEffectObserved ? 'observed' : 'not observed'}.`
            : 'Historical renderer receipt.'}</p>
        <pre style={{ maxHeight: 320, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
          border: '1px solid var(--rule)', borderRadius: 8, padding: 12 }}>{receipt.renderResult.rendered}</pre>
      </div>}
    </div>}
    {notice && !receipt && <p role="status">{notice}</p>}
  </section>;
}
