import React, { useEffect, useRef, useState } from 'react';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { decodeMerchantMailOperation, decodeMerchantMailProposal,
  merchantMailChatReference, merchantMailExpectedSendOperationId,
  merchantMailProposalDigest } from '../utils/merchantMailAction.mjs';
import MerchantMailHtmlAssessment from './MerchantMailHtmlAssessment.jsx';
import { merchantMailHtmlAssessmentStore } from '../utils/merchantMailHtmlAssessmentReference.mjs';
import { assertMerchantMailPending, clearMerchantMailPending, readMerchantMailPending,
  saveMerchantMailPending } from '../utils/merchantMailReference.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const base = '/api/secureshop/agents/merchant/assistant';
const subjectControl = /[\u0000-\u001f\u007f]/;
const visibleSubject = value => {
  if (!subjectControl.test(value) && !value.includes('\\')) return value;
  return value.replace(/\\/g, '\\\\').replace(/[\u0000-\u001f\u007f]/g, character => {
    if (character === '\r') return '\\r';
    if (character === '\n') return '\\n';
    if (character === '\t') return '\\t';
    return `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`;
  });
};

export default function MerchantMailConfirmation({ proposal = null, sessionId = null,
  requestId = null, authorityKey, locked = false, transport = globalThis.fetch,
  onOutcomeChange, htmlAssessmentStore = merchantMailHtmlAssessmentStore }) {
  const [scopeKey, setScopeKey] = useState(null);
  const [reference, setReference] = useState(null);
  const [operation, setOperation] = useState(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [storageFault, setStorageFault] = useState(false);
  const [htmlAssessmentReady, setHtmlAssessmentReady] = useState(false);
  const [dismissedId, setDismissedId] = useState(null);
  const epochRef = useRef(0), mountedRef = useRef(false), activeRef = useRef(null);
  const activeScopeRef = useRef(null);
  const recoveringRef = useRef(false);
  const proposalKey = JSON.stringify([proposal?.proposalId ?? null, sessionId, requestId]);
  const liveProposalKey = useRef(proposalKey);
  liveProposalKey.current = proposalKey;
  let selected = null;
  try { selected = decodeMerchantMailProposal(proposal); }
  catch { /* Invalid saved proposals cannot be confirmed. */ }

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current, controller = new AbortController();
    activeRef.current?.abort(); activeRef.current = null;
    activeScopeRef.current = null;
    setScopeKey(null); setReference(null); setOperation(null); setNotice('');
    setStorageFault(false); setHtmlAssessmentReady(false); setBusy(false); setDismissedId(null);
    void (async () => {
      try {
        const response = await transport('/api/secureshop/email/readiness', { signal: controller.signal });
        if (!response.ok) {
          try { await response.body?.cancel(); } catch { /* Preserve the readiness error. */ }
          throw new Error('Mail authority is unavailable.');
        }
        const value = await response.json();
        if (value?.ready !== true || typeof value.scopeKey !== 'string'
          || !SHA.test(value.scopeKey)) throw new Error('Mail authority is unavailable.');
        if (!mountedRef.current || epochRef.current !== epoch || controller.signal.aborted
          || globalThis.fetch !== transport) return;
        const saved = readMerchantMailPending(value.scopeKey);
        activeScopeRef.current = value.scopeKey;
        setScopeKey(value.scopeKey); setReference(saved);
        setHtmlAssessmentReady(value.objectiveReadiness?.ss_mail_agent_html_injection === true);
        if (saved) setNotice(saved.chatSource
          ? 'A saved assistant mail operation needs an exact status check.'
          : 'A mail operation is saved in Inbox. Resolve it there before confirming another.');
      } catch (error) {
        if (!mountedRef.current || epochRef.current !== epoch || controller.signal.aborted) return;
        setStorageFault(true);
        setNotice(error instanceof Error ? error.message : 'Saved mail state is unavailable.');
      }
    })();
    const changed = event => {
      if (event.detail !== activeScopeRef.current || !mountedRef.current
        || epochRef.current !== epoch) return;
      try { setReference(readMerchantMailPending(event.detail)); }
      catch { setStorageFault(true); setNotice('Saved mail state is unavailable.'); }
    };
    window.addEventListener('secureshop-mail-pending', changed);
    return () => { mountedRef.current = false; ++epochRef.current; controller.abort();
      activeRef.current?.abort(); activeRef.current = null; activeScopeRef.current = null;
      window.removeEventListener('secureshop-mail-pending', changed); };
  }, [authorityKey, transport]);

  useEffect(() => {
    // A pending operation is bound to its persisted source, independently of
    // the last assistant page hydrating after reload. Only a fresh confirmation
    // follows the currently displayed proposal.
    if (activeRef.current && recoveringRef.current) return;
    if (!activeRef.current && reference?.chatSource) return;
    if (!activeRef.current && operation
      && (!proposal || proposal.proposalId === operation.proposalId)) return;
    activeRef.current?.abort(); activeRef.current = null;
    setBusy(false); setOperation(null); setNotice(''); setDismissedId(null);
  }, [proposalKey]);

  const readSource = async (saved, signal) => {
    merchantMailChatReference(saved);
    const { sessionId: sourceSessionId, requestId: sourceRequestId } = saved.chatSource;
    const response = await transport(`${base}/operations/${sourceSessionId}/${sourceRequestId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) throw new Error('The original saved assistant proposal is unavailable.');
    const value = await response.json();
    const sourceProposal = decodeMerchantMailProposal(value?.mailProposal);
    if (value?.sessionId !== sourceSessionId || value?.requestId !== sourceRequestId
      || value.status !== 'completed' || value.replayed !== true
      || value.stopReason !== 'end_turn'
      || trustedTurnMode(value.modeCapability)?.featureId !== 'merchant_assistant'
      || !sourceProposal || sourceProposal.proposalId !== saved.requestId
      || sourceProposal.action !== (saved.action === 'send' ? 'send' : 'reply')
      || await merchantMailProposalDigest(sourceProposal) !== saved.digest) {
      throw new Error('The saved mail proposal changed. Its outcome could not be verified.');
    }
    return sourceProposal;
  };

  const readOperation = async (saved, sourceProposal, signal) => {
    const { sessionId: sourceSessionId, requestId: sourceRequestId } = saved.chatSource;
    const response = await transport(`${base}/mail/operations/${sourceSessionId}/${sourceRequestId}/${saved.requestId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok && response.status !== 202) throw new Error('Saved mail outcome is unavailable.');
    const value = decodeMerchantMailOperation(await response.json(), saved.requestId,
      sourceProposal.action);
    if (['saved', 'saved_unattributed'].includes(value.status)
      && value.sendOperationId !== await merchantMailExpectedSendOperationId(
        saved.requestId, sourceProposal.action)) {
      throw new Error('Saved mail operation identity is invalid.');
    }
    if (value.status === 'unconfirmed' && response.status !== 202) {
      throw new Error('Saved mail outcome is invalid.');
    }
    if (value.status !== 'unconfirmed' && response.status !== 200) {
      throw new Error('Saved mail outcome is invalid.');
    }
    return value;
  };

  const run = async confirm => {
    if (activeRef.current || !scopeKey || storageFault) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted
      && globalThis.fetch === transport
      && (recoveringRef.current || liveProposalKey.current === proposalKey);
    activeRef.current = controller; setBusy(true); setNotice('');
    let saved = null;
    try {
      saved = readMerchantMailPending(scopeKey);
      recoveringRef.current = !!saved;
      if (saved && !saved.chatSource) {
        setReference(saved); setNotice('Resolve the saved Inbox operation before confirming another.'); return;
      }
      if (!saved) {
        if (!confirm || !selected || !UUID.test(sessionId || '') || !UUID.test(requestId || '')) return;
        saved = { action: selected.action === 'send' ? 'send' : 'autoReply',
          requestId: selected.proposalId, digest: await merchantMailProposalDigest(selected),
          chatSource: { sessionId, requestId } };
        if (!current()) return;
        const original = await readSource(saved, controller.signal);
        if (!current() || await merchantMailProposalDigest(original) !== saved.digest)
          throw new Error('The saved mail proposal changed. Its outcome could not be verified.');
        const prior = await readOperation(saved, original, controller.signal);
        if (!current()) return;
        if (prior.status !== 'unconfirmed') {
          setOperation(prior); setNotice('A saved mail outcome already exists. No new confirmation was sent.');
          onOutcomeChange?.(); return;
        }
        if (readMerchantMailPending(scopeKey)) throw new Error('Another mail operation was saved. Check it first.');
        await saveMerchantMailPending(scopeKey, saved, current);
        if (!current()) return;
        setReference(saved);
        // Recheck the exact parent slot and immutable proposal immediately
        // before the sole effect POST. A lost response is resolved by GET only.
        const finalSource = await readSource(saved, controller.signal);
        const finalDigest = await merchantMailProposalDigest(finalSource);
        if (!current() || finalDigest !== saved.digest)
          throw new Error('The saved mail proposal changed. Its outcome could not be verified.');
        assertMerchantMailPending(scopeKey, saved, current);
        try {
          await transport(`${base}/mail/confirm`, { method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ sessionId, requestId, proposalId: saved.requestId }),
            signal: controller.signal });
        } catch { /* Never replay confirmation. Exact GET remains authority. */ }
      }
      if (!current()) return;
      assertMerchantMailPending(scopeKey, saved, current);
      const original = await readSource(saved, controller.signal);
      if (!current()) return;
      const result = await readOperation(saved, original, controller.signal);
      if (!current()) return;
      assertMerchantMailPending(scopeKey, saved, current);
      setOperation(result); onOutcomeChange?.();
      if (result.status === 'saved' && original.action === 'send' && htmlAssessmentReady) {
        await htmlAssessmentStore.prepare(scopeKey, { requestId: crypto.randomUUID(),
          sourceSessionId: saved.chatSource.sessionId, sourceRequestId: saved.chatSource.requestId, sendOperationId: result.sendOperationId,
          messageId: result.emailId, startedAt: Date.now() }, current);
        if (!current()) return;
        window.dispatchEvent(new CustomEvent('secureshop-mail-html-assessment', { detail: scopeKey }));
      }
      if (result.status === 'unconfirmed') {
        setReference(saved); setNotice('Mail outcome is unconfirmed. Check this saved operation; confirmation will not be repeated.');
        return;
      }
      try { await clearMerchantMailPending(scopeKey, saved, current); }
      catch { setReference(readMerchantMailPending(scopeKey));
        setNotice('The saved result is verified, but cleanup needs checking.'); return; }
      if (!current()) return;
      setReference(null);
      setNotice(result.status === 'saved' ? 'Message saved to lab mail.'
        : result.status === 'saved_unattributed'
          ? 'A mail operation was saved, but it could not be verified as this chat action. Review the saved details; do not resend.'
        : result.status === 'declined' ? 'The reply agent finished without a saved message.'
          : 'The mail action was rejected before execution.');
    } catch (error) {
      if (!current()) return;
      try { saved = readMerchantMailPending(scopeKey); setReference(saved); }
      catch { setStorageFault(true); }
      setNotice(error instanceof Error ? error.message : 'Saved mail outcome is unavailable.');
    } finally { if (current()) { activeRef.current = null; setBusy(false); } }
  };

  if (!selected && !reference && !notice) return null;
  return <section aria-label="Merchant mail confirmation" className="ss-card"
    style={{ padding: 12, marginTop: 12 }}>
    {selected && selected.proposalId !== dismissedId && <>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>
        SAVED MAIL PROPOSAL
      </div>
      {selected.action === 'send' ? <>
        <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review message to send</h3>
        <p>To: {selected.recipient.username} &lt;{selected.recipient.email}&gt;</p>
        <p>Subject: {visibleSubject(selected.subject)}</p>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{selected.body_markdown}</pre>
        <p className="ss-mono">Sending this proposed subject and body requires confirmation.</p>
      </> : <>
        <h3 style={{ fontFamily: 'var(--display)', margin: '8px 0' }}>Review reply-agent launch</h3>
        <p>Message from {selected.source.from}</p>
        <p>Subject: {visibleSubject(selected.source.subject)}</p>
        <p className="ss-mono">{selected.source.createdAt}</p>
        <p>The reply agent will generate and decide its response after you run it. No reply body is approved here.</p>
      </>}
      {!reference && !operation && <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button className="ss-btn ss-btn--sm" type="button" disabled={busy || locked || storageFault || !scopeKey}
          onClick={() => void run(true)}>{selected.action === 'send' ? 'Send message' : 'Run reply agent'}</button>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy}
          onClick={() => { setDismissedId(selected.proposalId); setNotice('Mail proposal dismissed. No confirmation was sent.'); }}>
          Cancel proposal</button>
      </div>}
    </>}
    {reference?.chatSource && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={busy || storageFault || !scopeKey} onClick={() => void run(false)}>Check saved mail operation</button>}
    {['saved', 'saved_unattributed'].includes(operation?.status) && <section aria-label="Saved merchant mail result">
      <p role="status">{operation.status === 'saved'
        ? 'Message saved to lab mail.'
        : 'A mail operation was saved, but it could not be verified as this chat action. Review the saved details; do not resend.'}</p>
      <p>To: {operation.savedSend.to}</p><p>Subject: {visibleSubject(operation.savedSend.subject)}</p>
      <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{operation.savedSend.body_markdown}</pre>
    </section>}
    {operation?.status === 'declined' && <p role="status">The reply agent finished without a saved message.</p>}
    {operation?.status === 'rejected_before_execution' && <p role="status">Mail action rejected before execution. No message was sent.</p>}
    {scopeKey && <MerchantMailHtmlAssessment scopeKey={scopeKey} authorityKey={authorityKey} transport={transport} store={htmlAssessmentStore} locked={locked} />}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
