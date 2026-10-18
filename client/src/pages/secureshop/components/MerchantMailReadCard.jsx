import React, { useEffect, useRef, useState } from 'react';
import { decodeMailReferences, updateMailReference } from '../bridge/mailReferences.mjs';
import { shopStorage, flushShopStorage, SHOP_MAIL_KEY } from '../utils/shopStorage.mjs';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';
import V11MailReadAssessment from './V11MailReadAssessment.jsx';

const sourceStyle = { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
  border: '1px solid var(--rule)', borderRadius: 8, padding: 12,
  maxHeight: 300, overflow: 'auto' };
const displayDate = value => new Date(value).toLocaleString();
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const utf8 = value => new TextEncoder().encode(value).byteLength;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const sameReference = (left, right) => !!left && !!right
  && left.requestId === right.requestId && left.readOperationId === right.readOperationId
  && left.messageId === right.messageId
  && !!left.assessmentAttempted === !!right.assessmentAttempted;
const savedReference = scope => decodeMailReferences(shopStorage.getItem(SHOP_MAIL_KEY)).scopes[scope]?.inlineSummary || null;
const setReference = (scope, reference) => {
  const raw = updateMailReference(shopStorage.getItem(SHOP_MAIL_KEY), scope, 'inlineSummary', reference);
  if (raw === null) shopStorage.removeItem(SHOP_MAIL_KEY); else shopStorage.setItem(SHOP_MAIL_KEY, raw);
};

function decodeSummary(value, requestId) {
  if (exact(value, ['ok','status','requestId']) && value.ok === true
    && value.status === 'unconfirmed' && value.requestId === requestId) return value;
  if (exact(value, ['ok','status','requestId','sessionId','text','replayed','assessmentStatus'])
    && value.ok === true && value.status === 'completed' && value.requestId === requestId
    && UUID.test(value.sessionId || '') && typeof value.text === 'string'
    && value.text.isWellFormed() && !value.text.includes('\0') && utf8(value.text) <= 32768
    && typeof value.replayed === 'boolean' && value.assessmentStatus === 'pending') return value;
  throw new Error('Saved mail summary outcome is invalid');
}
function decodeAssessment(value) {
  if (exact(value, ['completed','status','modelEvaluated']) && value.completed === false
    && value.modelEvaluated === false && ['ineligible','unconfirmed'].includes(value.status)) return value;
  if (!exact(value, ['completed','judgment','replayed']) || typeof value.completed !== 'boolean'
    || typeof value.replayed !== 'boolean' || !exact(value.judgment, ['verdict','evaluationId','canRetry'])
    || !['pass','fail','inconclusive','unavailable'].includes(value.judgment.verdict)
    || !UUID.test(value.judgment.evaluationId || '') || typeof value.judgment.canRetry !== 'boolean'
    || value.completed && value.judgment.verdict !== 'pass') throw new Error('Saved mail assessment outcome is invalid');
  return value;
}

export default function MerchantMailReadCard({ read, active = false, locked = false, shopUserId = null, source = null,
  transport = globalThis.fetch, agentAssessmentStore }) {
  const [scope, setScope] = useState(null);
  const [reference, setLocalReference] = useState(null);
  const [summary, setSummary] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [assessmentBusy, setAssessmentBusy] = useState(false);
  const epoch = useRef(0);
  const actionController = useRef(null);
  const result = read?.result || null;
  const eligible = result?.kind === 'detail' && result.status === 'complete' && result.message !== null;
  const agentAssessmentCandidate = eligible && Number.isSafeInteger(shopUserId) && shopUserId > 0
    && Number.isSafeInteger(result.recipient?.id) && result.recipient.id > 0 && result.recipient.id !== shopUserId
    && [result.message?.bodyMarkdown,result.message?.bodyHtml].some(value => typeof value === 'string' && value.trim())
    && UUID.test(source?.sessionId || '') && UUID.test(source?.requestId || '');

  useEffect(() => {
    const currentEpoch = ++epoch.current, controller = new AbortController();
    actionController.current?.abort(); actionController.current = null;
    setScope(null); setLocalReference(null); setSummary(null); setAssessment(null); setNotice(''); setBusy(false); setAssessmentBusy(false);
    if (!active && !agentAssessmentCandidate) return () => controller.abort();
    void (async () => {
      try {
        const response = await transport('/api/secureshop/email/readiness', { signal: controller.signal });
        const value = await response.json();
        if (!response.ok || value?.ready !== true || !SHA.test(value.scopeKey || '')) throw new Error('Mail authority is unavailable.');
        if (controller.signal.aborted || epoch.current !== currentEpoch || globalThis.fetch !== transport) return;
        const saved = savedReference(value.scopeKey);
        if (active && saved && (saved.readOperationId !== result.readOperationId || saved.messageId !== result.messageId)) {
          setNotice('A different saved mail summary needs its original selected message.');
          return;
        }
        setScope(value.scopeKey); if (active) setLocalReference(saved);
      } catch (error) {
        if (!controller.signal.aborted && epoch.current === currentEpoch) {
          setNotice(error instanceof Error ? error.message : 'Mail authority is unavailable.');
        }
      }
    })();
    return () => controller.abort();
  }, [active, eligible, agentAssessmentCandidate, result?.readOperationId, result?.messageId, transport]);

  useEffect(() => () => {
    actionController.current?.abort();
    actionController.current = null;
  }, []);

  const runSummary = async () => {
    if (!scope || busy || locked || !eligible || actionController.current) return;
    const currentEpoch = epoch.current, controller = new AbortController();
    actionController.current = controller;
    const current = () => epoch.current === currentEpoch && !controller.signal.aborted
      && actionController.current === controller && globalThis.fetch === transport;
    setBusy(true); setNotice('');
    let saved = null;
    const clear = async () => {
      if (!saved || !current() || !sameReference(savedReference(scope), saved)) throw new Error('Saved mail summary reference changed');
      setReference(scope, null); await flushShopStorage();
      if (!current() || savedReference(scope) !== null) throw new Error('Saved mail summary reference changed');
      setLocalReference(null);
    };
    const recover = async () => {
      const response = await transport(`/api/secureshop/email/inline/summary/${saved.requestId}`, { signal: controller.signal });
      const value = decodeSummary(await response.json(), saved.requestId);
      if ((value.status === 'unconfirmed' && response.status !== 202)
        || (value.status === 'completed' && response.status !== 200)) throw new Error('Saved mail summary outcome is unavailable');
      if (!current() || !sameReference(savedReference(scope), saved)) throw new Error('Saved mail summary reference changed');
      if (value.status === 'completed') { setLocalReference(saved); setSummary(value); setAssessment(null); }
      else { setLocalReference(saved); setSummary(null); setAssessment(null); setNotice('Summary outcome is unconfirmed. Check this saved summary; it will not run again.'); }
    };
    try {
      saved = savedReference(scope);
      if (saved && (saved.readOperationId !== result.readOperationId || saved.messageId !== result.messageId)) {
        throw new Error('A different saved mail summary needs its original selected message.');
      }
      if (!saved) {
        saved = { requestId: crypto.randomUUID().toLowerCase(), readOperationId: result.readOperationId,
          messageId: result.messageId, assessmentAttempted: false };
        setReference(scope, saved); await flushShopStorage();
        if (!current() || !sameReference(savedReference(scope), saved)) throw new Error('Saved mail summary reference changed');
        setLocalReference(saved);
        let response;
        try {
          const { requestId, readOperationId, messageId } = saved;
          response = await transport('/api/secureshop/email/inline/summary', { method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ requestId, readOperationId, messageId }), signal: controller.signal });
        } catch { /* Only the exact saved GET may recover a lost acknowledgement. */ }
        if (response?.status === 403) {
          const value = await response.json().catch(() => null);
          if (!exact(value, ['ok','code','error']) || value.ok !== false || value.code !== 'MAIL_INLINE_FIXED_DENIED'
            || value.error !== 'Inline image fetch blocked in fixed mode') throw new Error('Mail summary denial is invalid');
          await clear(); setNotice(value.error); return;
        }
      }
      if (!current()) return;
      await recover();
    } catch (error) {
      if (current()) setNotice(error instanceof Error ? error.message : 'Saved mail summary outcome is unavailable.');
    } finally {
      if (current()) setBusy(false);
      if (actionController.current === controller) actionController.current = null;
    }
  };
  const runAssessment = async () => {
    if (!scope || !summary || assessmentBusy || locked || actionController.current) return;
    const currentEpoch = epoch.current, controller = new AbortController();
    actionController.current = controller;
    const current = () => epoch.current === currentEpoch && !controller.signal.aborted
      && actionController.current === controller && globalThis.fetch === transport;
    setAssessmentBusy(true); setNotice('');
    let saved = null;
    try {
      saved = savedReference(scope);
      if (!saved || saved.requestId !== summary.requestId || !sameReference(saved, reference))
        throw new Error('Saved mail summary reference changed');
      const readOutcome = async () => {
        const response = await transport(`/api/secureshop/email/inline/assessment/${summary.sessionId}/${summary.requestId}`,
          { signal: controller.signal });
        const value = decodeAssessment(await response.json());
        if (!response.ok || !current() || !sameReference(savedReference(scope), saved))
          throw new Error('Saved mail assessment outcome is unavailable');
        setAssessment(value);
        if (value.completed === false && value.status === 'unconfirmed')
          setNotice('Assessment outcome is unconfirmed. Check this saved assessment; it will not run again.');
      };
      if (!saved.assessmentAttempted) {
        saved = { ...saved, assessmentAttempted: true };
        setReference(scope, saved); await flushShopStorage();
        if (!current() || !sameReference(savedReference(scope), saved)) throw new Error('Saved mail summary reference changed');
        setLocalReference(saved);
        try {
          await transport('/api/secureshop/email/inline/assessment', { method: 'POST',
            headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sessionId: summary.sessionId,
              requestId: summary.requestId }), signal: controller.signal });
        } catch { /* The persisted pair can only recover through its exact saved GET. */ }
      }
      if (current()) await readOutcome();
    } catch (error) {
      if (current()) setNotice(error instanceof Error ? error.message : 'Saved mail assessment outcome is unavailable.');
    } finally {
      if (current()) setAssessmentBusy(false);
      if (actionController.current === controller) actionController.current = null;
    }
  };
  if (!read) return null;
  return <section className="ss-card" aria-label="Merchant saved mail read"
    style={{ padding: 14, marginTop: 12, overflowWrap: 'anywhere' }}>
    <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>SAVED MAIL READ</div>
    {result.kind === 'recipients' && <>
      <h3>Named mail recipients</h3>
      {result.recipients.length === 0 && <p>No matching recipients in this shop.</p>}
      {result.recipients.length > 0 && <p>Select a named recipient above to view a mailbox.</p>}
      {result.hasMore && <p role="status">More recipients match. Refine the name search.</p>}
    </>}
    {result.kind === 'list' && <>
      <h3>{result.recipient.username}’s mailbox</h3>
      <p>{result.recipient.email} · {result.total} saved messages</p>
      {result.headers.length === 0 ? <p>No messages on this saved page.</p>
        : <ol start={result.offset + 1}>
          {result.headers.map(header => <li key={header.id} style={{ marginBottom: 10 }}>
            <strong>{header.subject}</strong>
            <div>From {header.from} · To {header.to}</div>
            <time dateTime={header.createdAt}>{displayDate(header.createdAt)}</time>
          </li>)}
        </ol>}
      {result.hasMore && <p role="status">Older messages are available.</p>}
    </>}
    {result.kind === 'detail' && <>
      <h3>{result.message?.subject || 'Selected message'}</h3>
      {result.message && <p>From {result.message.from} · To {result.message.to}
        {' · '}<time dateTime={result.message.createdAt}>
          {displayDate(result.message.createdAt)}</time></p>}
      {result.status === 'oversized' ? <p role="status">
        This message is too large for a verified chat answer. View the full source in the protected Inbox.
      </p> : <>
        <h4>Message body</h4>
        <pre style={sourceStyle}>{result.message.bodyMarkdown || '(No text body)'}</pre>
        {result.message.bodyHtml && <details>
          <summary>HTML source</summary><pre style={sourceStyle}>{result.message.bodyHtml}</pre>
        </details>}
        {result.message.headersRaw && <details>
          <summary>Raw headers</summary><pre style={sourceStyle}>{result.message.headersRaw}</pre>
        </details>}
      </>}
    </>}
    {active && eligible && <div style={{ marginTop: 12 }}>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={locked || busy || !scope} onClick={() => void runSummary()}>
        {busy ? 'Checking saved summary…' : reference ? 'Check saved summary' : 'Summarize selected message'}
      </button>
      {summary && <section aria-label="Saved merchant mail summary" style={{ marginTop: 10 }}>
        <h4>Saved summary</h4><pre style={sourceStyle}>{summary.text}</pre>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          disabled={locked || assessmentBusy} onClick={() => void runAssessment()}>
          {assessmentBusy ? 'Checking saved assessment…' : reference?.assessmentAttempted
            ? 'Check saved assessment' : 'Assess saved summary'}
        </button>
        {assessment?.judgment && <p role="status">
          {assessment.completed ? 'Objective completed.'
            : assessment.judgment.verdict === 'unavailable' ? 'Grading is unavailable; the saved summary remains available.'
              : 'The Judge did not award objective credit.'}
          {assessment.judgment.canRetry && isStandaloneShopFrame() && <button type="button"
            className="ss-btn ss-btn--ghost ss-btn--sm" onClick={() => openStandaloneAssessments(assessment.judgment.evaluationId)}>
            Open saved assessments
          </button>}
        </p>}
        {assessment && assessment.completed === false && !assessment.judgment && <p role="status">
          {assessment.status === 'ineligible' ? 'This saved summary is not eligible for objective credit.'
            : 'Assessment outcome is unconfirmed.'}
        </p>}
      </section>}
      {notice && <p role="status">{notice}</p>}
    </div>}
    {agentAssessmentCandidate && scope && <V11MailReadAssessment scopeKey={scope} shopUserId={shopUserId}
      source={source} currentTurn={active} locked={locked} transport={transport} {...(agentAssessmentStore ? {store: agentAssessmentStore} : {})} />}
  </section>;
}
