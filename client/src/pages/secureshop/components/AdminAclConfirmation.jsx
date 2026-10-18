import React, { useEffect, useRef, useState } from 'react';
import { decodeRoleAclProposal, aclProposalPending, decodeAclAdministration, verifyAclOperation } from '../utils/roleAclProposal.mjs';
import { sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { readAclPending, saveAclPending, clearAclPending } from '../pages/admin/aclOperation.js';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export default function AdminAclConfirmation({ proposal = null, sessionId = null, requestId = null,
  authorityKey, transport = globalThis.fetch, locked = false, onOutcomeChange }) {
  const [candidate, setCandidate] = useState(null), [scope, setScope] = useState(null);
  const [pending, setPending] = useState(null), [receipt, setReceipt] = useState(null);
  const [notice, setNotice] = useState(''), [busy, setBusy] = useState(false);
  const epoch = useRef(0), mounted = useRef(false), active = useRef(null);
  useEffect(() => { onOutcomeChange?.(v => v + 1); }, [pending, receipt, notice, onOutcomeChange]);
  useEffect(() => {
    mounted.current = true;
    const generation = ++epoch.current, controller = new AbortController();
    active.current?.abort(); active.current = null;
    setCandidate(null); setScope(null); setPending(null); setReceipt(null); setNotice(''); setBusy(false);
    const current = () => mounted.current && epoch.current === generation
      && !controller.signal.aborted && globalThis.fetch === transport;
    (async () => {
      const decoded = await decodeRoleAclProposal(proposal);
      if (!current()) return;
      setCandidate(decoded);
      const response = await transport('/api/secureshop/admin/access-control', { signal: controller.signal });
      if (!response.ok) throw Error('Access-control availability is unavailable.');
      const head = decodeAclAdministration(await response.json());
      if (!current()) return;
      setScope(head); setPending(readAclPending(head.scopeKey));
    })().catch(error => { if (current()) setNotice(error.message); });
    return () => { mounted.current = false; epoch.current += 1; controller.abort(); active.current?.abort(); active.current = null; };
  }, [authorityKey, proposal, sessionId, requestId, transport]);

  const run = async confirm => {
    if (active.current) return;
    const generation = epoch.current, controller = new AbortController();
    active.current = controller; setBusy(true); setNotice('');
    const current = () => mounted.current && epoch.current === generation && active.current === controller
      && !controller.signal.aborted && globalThis.fetch === transport;
    const assertRef = saved => {
      if (!current()) throw Error('Shop authority changed.');
      if (!same(readAclPending(saved.scopeKey), saved)) throw Error('Saved ACL change was replaced.');
    };
    const read = async saved => {
      const response = await transport(`/api/secureshop/admin/access-control/operations/${saved.body.operationId}`,
        { signal: controller.signal });
      if (response.status === 404) return null;
      if (!response.ok) throw Error(`Saved ACL lookup unavailable (${response.status}). The outcome remains unknown.`);
      return verifyAclOperation(await response.json(), saved);
    };
    let verifiedTerminal = false;
    const finish = async (saved, result) => {
      if (!current()) return;
      assertRef(saved);
      if (!result) { setNotice('ACL outcome is unconfirmed. Check the saved change; it will not be resent.'); return; }
      verifiedTerminal = true; setReceipt(result);
      // Only an exact terminal GET allows removal. A failed parent ACK keeps the
      // verified result visible and never causes another mutation POST.
      await clearAclPending(saved, current);
      if (!current()) return;
      setPending(null); setNotice('ACL change confirmed from the saved receipt.');
    };
    let saved = null;
    try {
      if (!scope) throw Error('Access-control availability is unavailable.');
      saved = readAclPending(scope.scopeKey);
      if (saved) { setPending(saved); await finish(saved, await read(saved)); return; }
      if (!confirm || locked || !candidate || !UUID.test(sessionId || '') || !UUID.test(requestId || '')) return;
      if (candidate.scopeKey !== scope.scopeKey || candidate.expectedVersion !== scope.version
        || candidate.registrySha256 !== scope.registrySha256) throw Error('Access control changed. Request a fresh review.');
      const response = await transport(`/api/secureshop/agents/admin/assistant/operations/${sessionId}/${requestId}`,
        { signal: controller.signal });
      if (!response.ok) throw Error('Saved ACL proposal is unavailable.');
      const source = await response.json();
      if (!current()) return;
      const actual = await decodeRoleAclProposal(source.aclProposal);
      if (!current()) return;
      if (source.sessionId !== sessionId || source.requestId !== requestId || source.status !== 'completed'
        || source.replayed !== true || source.stopReason !== 'end_turn'
        || !sameRolePolicyMode(source.modeCapability, candidate.modeCapability) || !same(actual, candidate)) {
        throw Error('Saved ACL proposal changed. No change was submitted.');
      }
      saved = aclProposalPending(candidate);
      await saveAclPending(saved);
      if (!current()) return;
      assertRef(saved); setPending(saved);
      const prior = await read(saved);
      if (!current()) return;
      if (prior) { await finish(saved, prior); return; }
      assertRef(saved);
      try {
        await transport('/api/secureshop/agents/admin/assistant/acl/confirm', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ sessionId, requestId, proposalId: candidate.proposalId }), signal: controller.signal,
        });
      } catch { /* Exact immutable GET owns recovery, including a lost POST ACK. */ }
      if (!current()) return;
      await finish(saved, await read(saved));
    } catch (error) {
      if (!current()) return;
      try { setPending(readAclPending(scope?.scopeKey) || (verifiedTerminal ? null : saved)); }
      catch { setPending(verifiedTerminal ? null : saved); }
      setNotice(error.message || 'ACL outcome is unavailable.');
    } finally { if (current()) { active.current = null; setBusy(false); } }
  };

  if (!candidate && !pending && !receipt && !notice) return null;
  return <section aria-label="Admin access control review" className="ss-card" style={{ padding: 14, marginTop: 12 }}>
    {candidate && !pending && !receipt && <>
      <h3>Review access control</h3>
      {candidate.action === 'permission' ? <>
        <p><strong>{candidate.tool.toolKey}</strong> · {candidate.tool.role}</p>
        <p>Permission: {candidate.before.allowed ? 'Allowed' : 'Denied'} → {candidate.after.allowed ? 'Allowed' : 'Denied'}</p>
        <p>Enforcement: {candidate.before.enforcement ? 'On' : 'Off'} (unchanged)</p>
      </> : <p>Enforcement: {candidate.before.enforcement ? 'On' : 'Off'} → {candidate.after.enforcement ? 'On' : 'Off'}</p>}
      <p>Policy version {candidate.expectedVersion}. No change occurs before confirmation.</p>
      <button type="button" className="ss-btn" disabled={busy || locked || !scope || scope.scopeKey !== candidate.scopeKey}
        onClick={() => void run(true)}>Confirm ACL change</button>
    </>}
    {pending && <button type="button" className="ss-btn" disabled={busy || !scope}
      onClick={() => void run(false)}>Check saved ACL change</button>}
    {notice && <p role="status">{notice}</p>}
    {receipt && <p role="status">Saved policy version {receipt.version} · enforcement {receipt.enforcement ? 'on' : 'off'}</p>}
  </section>;
}
