import React, { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { SafeChatBody } from '../../../components/workshop/WorkshopExperience.js';
import { useRegisteredAdminStream } from '../hooks/useRegisteredAdminStream.js';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';

function SavedRegisteredAssessment({ reference, onRead, onRetry }) {
  const [state, setState] = useState({ kind: 'ready' });
  useEffect(() => { setState({ kind: 'ready' }); }, [reference.sessionId, reference.requestId]);
  const check = async retry => {
    if (state.kind === 'checking') return;
    setState({ kind: 'checking' });
    const result = await (retry ? onRetry(reference) : onRead(reference));
    setState(result?.kind === 'stale' ? { kind: 'error', message: 'The saved result changed. Check it again.' }
      : result || { kind: 'error', message: 'Saved registered-tools assessment unavailable.' });
  };
  const judgment = state.kind === 'judgment' ? state.judgment : null;
  return <section className="ss-card" aria-label="Saved registered-tools assessment"
    style={{ padding: 12, marginTop: 10 }}>
    <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={state.kind === 'checking'} onClick={() => void check(false)}>
      {state.kind === 'checking' ? 'Checking saved assessment…' : 'Check saved assessment'}
    </button>
    {state.kind === 'ready' && <p role="status">Check this saved result without running registered tools again.</p>}
    {state.kind === 'unconfirmed' && <p role="status">Assessment not confirmed. The saved registered-tools result remains available.</p>}
    {state.kind === 'unconfirmed' && <button className="ss-btn ss-btn--ghost ss-btn--sm"
      type="button" onClick={() => void check(true)}>Retry saved assessment</button>}
    {state.kind === 'ineligible' && <p role="status">This saved result is not eligible for objective credit.</p>}
    {state.kind === 'error' && <p role="status">{state.message}</p>}
    {judgment && <p role="status">{judgment.verdict === 'unavailable'
      ? 'Grading unavailable. The saved registered-tools result remains available.'
      : state.completed === true && judgment.verdict === 'pass' ? 'Objective completed.'
        : 'Assessment completed without awarding objective credit.'}</p>}
    {judgment?.verdict === 'unavailable' && <button className="ss-btn ss-btn--ghost ss-btn--sm"
      type="button" onClick={() => openStandaloneAssessments(judgment.evaluationId)}>
      {isStandaloneShopFrame() ? 'Open saved assessments' : 'Saved assessment available'}
    </button>}
  </section>;
}

function SavedDescriptionAssessment({ reference, onRead, onSubmit }) {
  const [state, setState] = useState({ kind: 'ready' });
  const [submitted, setSubmitted] = useState(false);
  useEffect(() => { setState({ kind: 'ready' }); setSubmitted(false); }, [reference.sessionId, reference.requestId]);
  const check = async submit => {
    if (state.kind === 'checking' || (submit && submitted)) return;
    if (submit) setSubmitted(true);
    setState({ kind: 'checking' });
    const result = await (submit ? onSubmit(reference) : onRead(reference));
    setState(result?.kind === 'stale' ? { kind: 'error', message: 'The saved result changed. Check it again.' }
      : result || { kind: 'error', message: 'Saved description assessment unavailable.' });
  };
  const judgment = state.kind === 'judgment' ? state.judgment : null;
  return <section className="ss-card" aria-label="Saved registered-description assessment"
    style={{ padding: 12, marginTop: 10 }}>
    <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={state.kind === 'checking'} onClick={() => void check(false)}>
      {state.kind === 'checking' ? 'Checking description assessment…' : 'Check saved description assessment'}
    </button>
    {!submitted && ['ready', 'unconfirmed'].includes(state.kind) && <button
      className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      onClick={() => void check(true)}>Assess description adoption</button>}
    {state.kind === 'unconfirmed' && <p role="status">Description assessment is unconfirmed. Check the saved assessment again.</p>}
    {state.kind === 'ineligible' && <p role="status">This saved turn is not eligible for description-adoption credit.</p>}
    {state.kind === 'error' && <p role="status">{state.message}</p>}
    {judgment && <p role="status">{judgment.verdict === 'unavailable'
      ? 'Description grading unavailable. The saved turn remains available.'
      : state.completed === true && judgment.verdict === 'pass' ? 'Description objective completed.'
        : 'Description assessment completed without awarding objective credit.'}</p>}
    {judgment?.verdict === 'unavailable' && <button className="ss-btn ss-btn--ghost ss-btn--sm"
      type="button" onClick={() => openStandaloneAssessments(judgment.evaluationId)}>
      {isStandaloneShopFrame() ? 'Open saved assessments' : 'Saved assessment available'}
    </button>}
  </section>;
}

const RegisteredAdminConversation = forwardRef(function RegisteredAdminConversation({
  shopUserId, authorityKey, transport = globalThis.fetch, visible = false,
  composerTarget = null, onPendingChange,
}, ref) {
  const stream = useRegisteredAdminStream({ shopUserId, authorityKey, transport });
  const [message, setMessage] = useState('');
  const revisionRef = useRef(0);
  const locked = stream.status === 'thinking' || stream.status === 'recovering' || !!stream.pending;
  useEffect(() => { onPendingChange?.(!!stream.pending || stream.status === 'thinking'); },
    [onPendingChange, stream.pending, stream.status]);
  useImperativeHandle(ref, () => ({ ask: (text, setup) => stream.send(text, setup) }), [stream.send]);
  const submit = event => {
    event.preventDefault();
    if (!message.trim() || locked) return;
    const revision = revisionRef.current, text = message;
    void stream.send(text).then(sent => {
      if (sent && revisionRef.current === revision) setMessage('');
    });
  };
  const composer = <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={submit}>
    <label htmlFor="registered-admin-message">Message to registered tools</label>
    <textarea id="registered-admin-message" className="ss-lane__input" rows={3}
      value={message} maxLength={8192} placeholder="Ask the registered tools…"
      onChange={event => { revisionRef.current += 1; setMessage(event.target.value); }}
      style={{ width: '100%', boxSizing: 'border-box', marginTop: 5 }}
      onKeyDown={event => {
        if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
          event.preventDefault(); submit(event);
        }
      }} />
    <span className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>Complete registered-tool manifest · Enter to send</span>
    <button className="ss-btn" type="submit" disabled={locked || !message.trim()}>
      {stream.status === 'thinking' ? 'Working…' : 'Send to registered tools'}
    </button>
  </form>;
  return <div hidden={!visible} className="ss-role-assistant" data-testid="registered-admin-conversation">
    <p>This conversation can use the complete registered-tool manifest. It is separate from Admin assistant.</p>
    <div role="log" aria-label="Registered tools conversation" aria-live="polite">
      {stream.turns.length === 0 && <p className="ss-mono">Ask a question to start the registered-tools conversation.</p>}
      {stream.turns.map(turn => <article className="ss-turn" key={turn.requestId}>
        <div className="ss-turn__you">YOU</div><div className="ss-turn__msg">{turn.user}</div>
        <div className="ss-turn__supervisor">REGISTERED TOOLS · {turn.status}</div>
        {turn.modeCapability && <div className="ss-mono" aria-label="Registered tools mode">
          Registered tools · {turn.modeCapability.effectiveMode === 'fixed' ? 'Fixed mode' : 'Vulnerable mode'}
        </div>}
        {turn.reply && <div className="ss-turn__reply"><div className="ss-turn__you">REGISTERED TOOLS · reply</div>
          <SafeChatBody content={turn.reply} /></div>}
        {turn.hops?.length > 0 && <details><summary>Technical tool activity ({turn.hops.length})</summary>
          <div role="list">{turn.hops.map((hop, index) => <div className="ss-card ss-mono"
            role="listitem" key={index} style={{ padding: 8, marginTop: 6, overflowWrap: 'anywhere' }}>
            {hop.tool || 'Registered tool'} · {hop.error ? 'Failed' : 'Observed'}
          </div>)}</div></details>}
        {turn.status === 'done' && turn.stopReason === 'end_turn' && !stream.pending
          && <SavedRegisteredAssessment key={`${turn.sessionId}:${turn.requestId}`}
            reference={{ sessionId: turn.sessionId, requestId: turn.requestId }}
            onRead={stream.readAssessment} onRetry={stream.retryAssessment} />}
        {turn.status === 'done' && turn.stopReason === 'end_turn' && !stream.pending
          && <SavedDescriptionAssessment key={`description:${turn.sessionId}:${turn.requestId}`}
            reference={{ sessionId: turn.sessionId, requestId: turn.requestId }}
            onRead={stream.readDescriptionAssessment} onSubmit={stream.submitDescriptionAssessment} />}
      </article>)}
    </div>
    {stream.pending && <section className="ss-card" aria-label="Saved registered-tools request"
      style={{ padding: 12, marginTop: 12 }}>
      <p>The request may have completed. Check its saved outcome before sending another.</p>
      <button className="ss-btn ss-btn--ghost" type="button"
        disabled={stream.status === 'recovering' || stream.pending.shopUserId !== shopUserId}
        onClick={() => void stream.recover()}>Check saved registered-tools request</button>
    </section>}
    {!stream.pending && stream.completedPage && !stream.turns.some(turn => turn.requestId === stream.completedPage.requestId)
      && <section className="ss-card" aria-label="Saved registered-tools page" style={{ padding: 12, marginTop: 12 }}>
        <p>The last saved result could not be shown. Check its exact saved page.</p>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          disabled={stream.status === 'recovering'} onClick={() => void stream.recoverCompleted()}>
          Check saved registered-tools page</button>
      </section>}
    {stream.error && <p role="alert" style={{ color: 'var(--rust)' }}>{stream.error}</p>}
    {visible && (composerTarget ? createPortal(composer, composerTarget) : composer)}
  </div>;
});

export default RegisteredAdminConversation;
