import React, { useEffect, useRef, useState } from 'react';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const ADDRESS = /^[a-z0-9][a-z0-9._+-]{0,63}@sharklasers\.com$/;
const validAddress = value => ADDRESS.test(value) && !value.split('@')[0].endsWith('.') && !value.includes('..');
const keyFor = principalId => `owasp-ai-goat:secureshop:external-mail:v1:${principalId}`;
const terminal = state => ['cancelled', 'expired', 'rejected_before_dispatch', 'smtp_accepted'].includes(state);

function readReference(storage, principalId) {
  const raw = storage.getItem(keyFor(principalId));
  if (raw === null) return null;
  if (raw.length > 512) throw new Error('Saved external test send could not be verified.');
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error('Saved external test send could not be verified.'); }
  if (!value || Object.keys(value).sort().join(',') !== 'operationId,phase,principalId,scopeKey,version'
    || value.version !== 1 || value.principalId !== principalId
    || !UUID.test(value.operationId) || !SHA.test(value.scopeKey)
    || !['prepare_submitted', 'prepared', 'confirm_submitted', 'cancel_submitted', 'terminal'].includes(value.phase)) {
    throw new Error('Saved external test send belongs to a different or unverifiable shop session.');
  }
  return value;
}

export default function SecureShopStandaloneExternalMail({ controller, user, open, onClose }) {
  const [recipient, setRecipient] = useState('');
  const [readiness, setReadiness] = useState(null);
  const [reference, setReference] = useState(null);
  const [operation, setOperation] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [problem, setProblem] = useState(false);
  const lock = useRef(false);
  const alive = useRef(true);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const dialogRef = useRef(null);
  const priorFocus = useRef(null);
  const openRef = useRef(open);
  const interaction = useRef({ open, epoch: 0 });
  const stageRef = useRef(null);
  const storageRef = useRef(null);
  openRef.current = open;
  if (interaction.current.open !== open) interaction.current = { open, epoch: interaction.current.epoch + 1 };
  if (!storageRef.current) {
    try { storageRef.current = window.sessionStorage; } catch { /* Fail closed below. */ }
  }
  useEffect(() => { alive.current = true; return () => { alive.current = false; stageRef.current = null; }; }, []);
  const current = (stage, epoch = interaction.current.epoch) => alive.current && openRef.current
    && interaction.current.epoch === epoch && stageRef.current === stage;
  const persist = stage => {
    const storage = storageRef.current;
    if (!storage) throw new Error('Recovery storage is unavailable. No external test send was requested.');
    const previous = readReference(storage, user.principalId);
    if (previous && stageRef.current?.operationId !== previous.operationId) {
      throw new Error('Check the saved external test send first.');
    }
    const bytes = JSON.stringify(stage);
    storage.setItem(keyFor(user.principalId), bytes);
    if (storage.getItem(keyFor(user.principalId)) !== bytes) throw new Error('External test send reference was not saved.');
    stageRef.current = stage;
    setReference(stage);
    return () => storage.getItem(keyFor(user.principalId)) === bytes && current(stage);
  };

  useEffect(() => {
    if (!open || !controller || user?.role !== 'merchant') return undefined;
    let active = true;
    const abort = new AbortController();
    setError(''); setProblem(false); setOperation(null); setReadiness(null);
    (async () => {
      try {
        if (!storageRef.current) throw new Error('Recovery storage is unavailable.');
        const saved = readReference(storageRef.current, user.principalId);
        if (!active) return;
        if (!saved) setRecipient('');
        stageRef.current = saved; setReference(saved);
        if (saved) {
          const value = await controller.getExternalMailOperation(saved.operationId, saved.scopeKey, abort.signal);
          if (active && !abort.signal.aborted && stageRef.current === saved) {
            setOperation(value);
            if (saved.phase === 'prepare_submitted' && value.state === 'prepared') {
              persist({ ...saved, phase: 'prepared' });
            } else if (terminal(value.state) && saved.phase !== 'terminal') {
              persist({ ...saved, phase: 'terminal' });
            }
          }
          try {
            const currentReadiness = await controller.getExternalMailReadiness(abort.signal);
            if (active && !abort.signal.aborted && stageRef.current?.operationId === saved.operationId) setReadiness(currentReadiness);
          } catch { /* Old operation remains readable even when current send readiness is unavailable. */ }
        } else {
          const value = await controller.getExternalMailReadiness(abort.signal);
          if (active && !abort.signal.aborted) setReadiness(value);
        }
      } catch (reason) {
        if (active && !abort.signal.aborted) { setProblem(true); setError(reason.message || 'External test send unavailable.'); }
      }
    })();
    return () => { active = false; abort.abort(); };
  }, [open, controller, user?.principalId, user?.role]);

  useEffect(() => {
    if (!open) return undefined;
    priorFocus.current = document.activeElement;
    dialogRef.current?.querySelector('button:not(:disabled), input:not(:disabled)')?.focus();
    const onKey = event => {
      if (event.key === 'Escape' && !lock.current) { closeRef.current(); return; }
      if (event.key !== 'Tab') return;
      const controls = [...(dialogRef.current?.querySelectorAll('button:not(:disabled), input:not(:disabled)') || [])];
      if (!controls.length) return;
      if (event.shiftKey && document.activeElement === controls[0]) {
        event.preventDefault(); controls[controls.length - 1].focus();
      } else if (!event.shiftKey && document.activeElement === controls[controls.length - 1]) {
        event.preventDefault(); controls[0].focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('keydown', onKey); priorFocus.current?.focus?.(); };
  }, [open]);

  const prepare = async (expectedEpoch, expectedReadiness) => {
    if (lock.current || !openRef.current || interaction.current.epoch !== expectedEpoch
      || readiness !== expectedReadiness || stageRef.current || reference || problem
      || readiness?.available !== true || !validAddress(recipient)
      || typeof globalThis.crypto?.randomUUID !== 'function') return;
    lock.current = true; setBusy(true); setError('');
    const openedAt = interaction.current.epoch;
    let stage;
    try {
      stage = { version: 1, principalId: user.principalId, scopeKey: readiness.scopeKey,
        operationId: globalThis.crypto.randomUUID().toLowerCase(), phase: 'prepare_submitted' };
      const saved = persist(stage);
      const verify = () => current(stage, openedAt) && saved();
      const value = await controller.prepareExternalMail({ operationId: stage.operationId,
        recipient, scopeKey: stage.scopeKey }, verify);
      if (!current(stage, openedAt)) return;
      setOperation(value); setRecipient('');
      if (value.state === 'prepared') persist({ ...stage, phase: 'prepared' });
      else if (terminal(value.state)) persist({ ...stage, phase: 'terminal' });
    } catch (reason) {
      if ((!stage || current(stage, openedAt)) && alive.current) setError(`The draft outcome is uncertain. Check its saved status. ${reason.message || ''}`);
    } finally { lock.current = false; if (alive.current) setBusy(false); }
  };

  const act = async (kind, expectedStage, expectedOperation, openedAt) => {
    const stage = stageRef.current;
    if (lock.current || !current(stage, openedAt) || stage !== expectedStage
      || operation !== expectedOperation || !stage || stage.phase !== 'prepared'
      || operation?.state !== 'prepared' || operation.operationId !== stage.operationId
      || operation.scopeKey !== stage.scopeKey || !SHA.test(operation.requestSha256)
      || readiness?.scopeKey !== stage.scopeKey
      || (kind === 'confirm' && Date.parse(operation.expiresAt) <= Date.now())) return;
    lock.current = true; setBusy(true); setError('');
    const next = { ...stage, phase: kind === 'confirm' ? 'confirm_submitted' : 'cancel_submitted' };
    try {
      const saved = persist(next);
      const verify = () => current(next, openedAt) && saved();
      const value = await (kind === 'confirm' ? controller.confirmExternalMail : controller.cancelExternalMail)({
        operationId: stage.operationId, scopeKey: stage.scopeKey,
        requestSha256: operation.requestSha256 }, verify);
      if (!current(next, openedAt)) return;
      setOperation(value);
      if (terminal(value.state)) persist({ ...next, phase: 'terminal' });
    } catch (reason) {
      if (current(next, openedAt)) setError(`The ${kind} outcome is uncertain. Check the saved status; no request will be repeated. ${reason.message || ''}`);
    } finally { lock.current = false; if (alive.current) setBusy(false); }
  };

  const check = async (expectedStage, openedAt) => {
    const stage = stageRef.current;
    if (lock.current || !current(stage, openedAt) || stage !== expectedStage || !stage) return;
    lock.current = true; setBusy(true); setError('');
    try {
      const value = await controller.getExternalMailOperation(stage.operationId, stage.scopeKey);
      if (!current(stage, openedAt)) return;
      setOperation(value);
      if (stage.phase === 'prepare_submitted' && value.state === 'prepared') persist({ ...stage, phase: 'prepared' });
      else if (terminal(value.state)) persist({ ...stage, phase: 'terminal' });
    } catch (reason) {
      if (current(stage, openedAt)) setError(`Status is unavailable. No send was retried. ${reason.message || ''}`);
    } finally { lock.current = false; if (alive.current) setBusy(false); }
  };

  const dismiss = (expectedStage, openedAt) => {
    const stage = stageRef.current;
    if (!stage || stage !== expectedStage || lock.current || !current(stage, openedAt) || stage.phase !== 'terminal'
      || !terminal(operation?.state)) return;
    const storage = storageRef.current;
    if (!storage || readReference(storage, user.principalId)?.operationId !== stage.operationId) return;
    storage.removeItem(keyFor(user.principalId));
    if (storage.getItem(keyFor(user.principalId)) !== null) { setError('Saved result could not be cleared.'); return; }
    stageRef.current = null; setReference(null); setOperation(null); setReadiness(null);
    setRecipient(''); onClose();
  };

  if (!open || user?.role !== 'merchant') return null;
  const review = reference?.phase === 'prepared' && operation?.state === 'prepared'
    && readiness?.scopeKey === reference.scopeKey;
  const previewExpired = operation?.state === 'prepared'
    && Number.isFinite(Date.parse(operation.expiresAt)) && Date.parse(operation.expiresAt) <= Date.now();
  const renderedEpoch = interaction.current.epoch;
  const accepted = operation?.state === 'smtp_accepted';
  return <div className="ss-root ss-modal-backdrop" style={{ position: 'absolute', zIndex: 6 }}>
    <section ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="external-mail-title" className="ss-modal"
      style={{ maxWidth: 560 }}>
      <h2 id="external-mail-title" className="ss-display">External test send</h2>
      <p>This merchant-only action uses a fixed synthetic plaintext message. It sends to a SharkLasers address outside the lab.
        Review the server-prepared recipient and message before confirming. An accepted SMTP submission does not prove mailbox delivery.</p>
      {error && <p role="alert">{error}</p>}
      {problem ? <p>Saved status cannot be verified. Do not prepare another message from this session.</p>
        : reference ? <>
          {operation?.preview && <div aria-label="Server-prepared message" style={{ overflowWrap: 'anywhere' }}>
            <p><strong>From:</strong> {operation.preview.sender}</p>
            <p><strong>To:</strong> {operation.preview.recipient}</p>
            <p><strong>Subject:</strong> {operation.preview.subject}</p>
            <pre style={{ whiteSpace: 'pre-wrap' }}>{operation.preview.text}</pre>
          </div>}
          {accepted && <p role="status">Gmail SMTP accepted this message. Delivery to the SharkLasers mailbox is not confirmed.</p>}
          {operation?.state === 'cancelled' && <p role="status">The prepared send was cancelled before dispatch.</p>}
          {operation?.state === 'expired' && <p role="status">The service confirms this prepared draft expired without dispatch. You may dismiss it and start a new draft explicitly.</p>}
          {operation?.state === 'rejected_before_dispatch' && <p role="status">The service rejected this send before dispatch.</p>}
          {reference.phase === 'confirm_submitted' && !accepted && <p role="status">A send was submitted. Its outcome is unresolved; checking status will not resend it.</p>}
          {operation?.state === 'not_found' && <p role="status">This saved operation was not found. Its earlier request outcome is still uncertain; no new send is allowed.</p>}
          <button type="button" className="ss-btn ss-btn--ghost" disabled={busy}
            onClick={() => check(reference, renderedEpoch)}>Check saved status</button>
          {reference.phase === 'prepared' && readiness && readiness.scopeKey !== reference.scopeKey
            && <p role="status">This prepared message belongs to an earlier shop practice. Status is read-only here.</p>}
          {review && <>{!previewExpired && <button type="button" className="ss-btn" disabled={busy}
            onClick={() => act('confirm', reference, operation, renderedEpoch)}>Confirm external send</button>}
            <button type="button" className="ss-btn ss-btn--ghost" disabled={busy}
              onClick={() => act('cancel', reference, operation, renderedEpoch)}>Cancel prepared send</button></>}
          {review && previewExpired && <p role="status">This preview is past its expiry. Check saved status for the service-confirmed result, or cancel while this original merchant session remains current. No send will be started from this preview.</p>}
          {reference.phase === 'terminal' && terminal(operation?.state) && <button type="button" className="ss-btn ss-btn--ghost"
            disabled={busy} onClick={() => dismiss(reference, renderedEpoch)}>Dismiss result</button>}
        </> : readiness?.available === true ? <>
          <label>SharkLasers recipient <input type="email" autoComplete="off" value={recipient}
            placeholder="yourname@sharklasers.com" onChange={event => {
              if (openRef.current && interaction.current.epoch === renderedEpoch && !stageRef.current) {
                setRecipient(event.target.value);
              }
            }} /></label>
          <p>Sender: {readiness.sender}. Limit: {readiness.limits.ownerPerHour} per owner per hour.</p>
          <button type="button" className="ss-btn" disabled={busy || !validAddress(recipient)}
            onClick={() => prepare(renderedEpoch, readiness)}>Review synthetic message</button>
        </> : readiness?.available === false ? <p role="status">External test send is not configured.</p>
          : <p role="status">Checking external send availability…</p>}
      <button type="button" className="ss-btn ss-btn--ghost" disabled={busy}
        onClick={() => { if (interaction.current.epoch === renderedEpoch) onClose(); }}>Close panel</button>
    </section>
  </div>;
}
