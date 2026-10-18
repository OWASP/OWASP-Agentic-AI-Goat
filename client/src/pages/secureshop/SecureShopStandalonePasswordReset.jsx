import React, { useEffect, useRef, useState } from 'react';
import { REGISTERED_PASSWORD_RESET_KEY as KEY, notifyRegisteredPasswordResetResolved } from './bridge/registeredPasswordResetRecovery.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION = /^[1-9][0-9]{0,18}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const safeSessionStorage = () => {
  try { return globalThis.window?.sessionStorage || null; } catch { return null; }
};

function readSaved(storage, principalId) {
  let raw;
  try {
    if (!storage) throw new Error('Storage unavailable');
    raw = storage.getItem(KEY);
  } catch {
    return { pending: null, problem: 'Recovery storage is unavailable; no password reset can be sent.', dismissable: false };
  }
  if (!raw) return { pending: null, problem: '', dismissable: false };
  if (raw.length > 4096) return { pending: null, problem: 'Saved reset reference is invalid.', dismissable: true };
  try {
    const value = JSON.parse(raw);
    if (value?.version === 2) {
      if (!exact(value, ['version', 'adminPrincipalId', 'scopeKey', 'sceneId', 'channel', 'source',
        'targetId', 'operationId', 'expectedCredentialVersion', 'expectedAuthorityVersion',
        'expectedMembershipVersion']) || !UUID.test(value.adminPrincipalId)
        || !UUID.test(value.sceneId) || !UUID.test(value.operationId)
        || value.operationId !== value.operationId.toLowerCase()
        || typeof value.scopeKey !== 'string' || !value.scopeKey || value.scopeKey.length > 1024
        || !['bound_persona', 'protected_account'].includes(value.channel)
        || !exact(value.source, value.source?.kind === 'chat'
          ? ['kind', 'sessionId', 'requestId', 'choiceId'] : ['kind', 'targetId'])
        || !['chat', 'registered_manual', 'teaching_manual'].includes(value.source.kind)
        || (value.source.kind === 'registered_manual' && value.channel !== 'protected_account')
        || (value.source.kind === 'teaching_manual' && value.channel !== 'bound_persona')
        || (value.source.kind === 'chat'
          ? ![value.source.sessionId, value.source.requestId, value.source.choiceId]
            .every(item => typeof item === 'string' && UUID.test(item) && item === item.toLowerCase())
          : value.source.targetId !== value.targetId)
        || !Number.isSafeInteger(value.targetId) || value.targetId < 1 || value.targetId > 2147483647
        || !VERSION.test(value.expectedCredentialVersion) || !VERSION.test(value.expectedAuthorityVersion)
        || (value.channel === 'bound_persona' ? value.expectedMembershipVersion !== null
          : !VERSION.test(value.expectedMembershipVersion))) {
        return { pending: null, problem: 'Saved reset reference is invalid.', dismissable: false };
      }
    } else if (!value || Object.keys(value).sort().join(',') !== 'adminPrincipalId,expectedAuthorityVersion,expectedCredentialVersion,expectedMembershipVersion,operationId,targetId'
      || !UUID.test(value.adminPrincipalId) || !UUID.test(value.operationId)
      || !Number.isSafeInteger(value.targetId) || value.targetId < 1 || value.targetId > 2147483647
      || !VERSION.test(value.expectedCredentialVersion) || !VERSION.test(value.expectedAuthorityVersion)
      || !VERSION.test(value.expectedMembershipVersion)) {
      return { pending: null, problem: 'Saved reset reference is invalid.', dismissable: true };
    }
    if (value.adminPrincipalId !== principalId) {
      return { pending: null, problem: 'Saved reset belongs to another administrator. Its outcome is unknown.', dismissable: true };
    }
    return { pending: value, problem: '', dismissable: false };
  } catch { return { pending: null, problem: 'Saved reset reference is invalid.', dismissable: true }; }
}

function verifyReceipt(result, pending) {
  const receipt = result?.receipt;
  if (!receipt || receipt.operationId !== pending.operationId || receipt.targetId !== pending.targetId
    || receipt.credentialVersion !== String(BigInt(pending.expectedCredentialVersion) + 1n)
    || receipt.authorityVersion !== String(BigInt(pending.expectedAuthorityVersion) + 1n)
    || !DIGEST.test(receipt.receiptSha256) || !Number.isFinite(Date.parse(receipt.expiresAt))) {
    throw new Error('Password reset receipt could not be verified. Read its status before another action.');
  }
}

export default function SecureShopStandalonePasswordReset({ client, user, targetId, onClose,
  controller = null, request = null, storage = safeSessionStorage() }) {
  const [restored] = useState(() => readSaved(storage, user?.principalId));
  const [pending, setPending] = useState(restored.pending);
  const [problem, setProblem] = useState(restored.problem);
  const [target, setTarget] = useState(null);
  const [metadata, setMetadata] = useState(null);
  const [secret, setSecret] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const lock = useRef(false);
  const alive = useRef(true);
  const currentPrincipal = useRef(user?.principalId);
  currentPrincipal.current = user?.principalId;

  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    setTarget(null);
    if (pending || problem || (!request && (!Number.isSafeInteger(targetId) || targetId < 1))) return undefined;
    const aborter = new AbortController();
    setError('');
    (request ? controller?.preparePasswordReset(request, aborter.signal)
      : client.getResetReadiness(targetId, aborter.signal)).then(value => {
      if (alive.current && !aborter.signal.aborted) setTarget(value);
    }).catch(reason => {
      if (alive.current && !aborter.signal.aborted) setError(reason.message || 'Password reset readiness is unavailable.');
    });
    return () => aborter.abort();
  }, [client, controller, request, targetId, pending, problem]);

  const run = async kind => {
    if (lock.current || problem || (kind === 'reset' ? !target || pending : !pending)) return;
    lock.current = true; setBusy(true); setError(''); setNotice(''); setSecret(null);
    let operation = pending;
    let dispatched = false;
    const principalAtStart = user?.principalId;
    try {
      if (kind === 'reset') {
        if (!storage || typeof globalThis.crypto?.randomUUID !== 'function') throw new Error('Recovery storage unavailable; no reset was sent.');
        if (storage.getItem(KEY) !== null) throw new Error('Check the saved password reset before another reset');
        operation = { adminPrincipalId: principalAtStart, targetId: target.id,
          operationId: globalThis.crypto.randomUUID().toLowerCase(),
          expectedCredentialVersion: target.credentialVersion,
          expectedAuthorityVersion: target.authorityVersion,
          expectedMembershipVersion: target.membershipVersion ?? null,
          ...(request ? { version: 2, scopeKey: target.scopeKey, sceneId: target.sceneId,
            channel: target.channel, source: target.request } : {}) };
        try { storage.setItem(KEY, JSON.stringify(operation)); }
        catch { throw new Error('Recovery storage is unavailable; no password reset was sent.'); }
        if (storage.getItem(KEY) !== JSON.stringify(operation)) {
          throw new Error('Saved reset reference changed before confirmation');
        }
        setPending(operation);
      }
      if (currentPrincipal.current !== principalAtStart) throw new Error('Administrator session changed. Reset outcome is unknown.');
      if (storage?.getItem(KEY) !== JSON.stringify(operation)) {
        throw new Error('Saved reset reference changed before confirmation');
      }
      dispatched = true;
      const result = kind === 'reset'
        ? operation.version === 2 ? await controller.resetPasswordFromParent(operation, undefined,
          () => alive.current && currentPrincipal.current === principalAtStart
            && storage?.getItem(KEY) === JSON.stringify(operation))
          : await client.resetUserPassword(operation.targetId, operation)
        : operation.version === 2 ? await controller.savedPasswordResetFromParent(operation, kind)
          : kind === 'read' ? await client.getPasswordResetStatus(operation.targetId, operation.operationId)
            : kind === 'reveal' ? await client.revealPasswordReset(operation.targetId, operation.operationId)
              : await client.acknowledgePasswordReset(operation.targetId, operation.operationId);
      if (storage?.getItem(KEY) !== JSON.stringify(operation)) {
        throw new Error('Saved reset reference changed before result could be displayed');
      }
      verifyReceipt(result, operation);
      if (!alive.current || currentPrincipal.current !== principalAtStart) return;
      if (kind === 'reveal') {
        setSecret(result.temporaryPassword);
        setMetadata(result);
      } else if (kind === 'acknowledge' || result.secretAvailable === false) {
        if (storage?.getItem(KEY) !== JSON.stringify(operation)) throw new Error('Saved reset reference changed');
        storage?.removeItem(KEY);
        if (storage?.getItem(KEY) !== null) throw new Error('Saved reset reference was not cleared');
        notifyRegisteredPasswordResetResolved();
        setPending(null); setMetadata(null);
        setNotice('Password reset recovery is closed. The temporary password is no longer available here.');
        onClose();
      } else {
        setMetadata(result);
        setNotice(kind === 'reset' ? 'Password reset confirmed. Reveal the temporary password only when ready to record it privately.'
          : 'Reset receipt confirmed.');
      }
    } catch (reason) {
      if (!dispatched && kind === 'reset' && operation && storage) {
        try {
          if (storage.getItem(KEY) === JSON.stringify(operation)) storage.removeItem(KEY);
        } catch { /* Leave the reference for explicit recovery. */ }
        if (alive.current) setPending(null);
      }
      if (alive.current) setError(reason.message || 'Reset outcome is unknown. Read its status before another reset.');
    } finally { lock.current = false; if (alive.current) setBusy(false); }
  };

  const dismissReference = () => {
    if (lock.current || !storage) return;
    try {
      storage.removeItem(KEY);
      setPending(null); setProblem(''); setMetadata(null); setSecret(null); setTarget(null);
      setNotice('Local recovery reference dismissed. This does not undo a password reset.');
      onClose();
    } catch { setError('Local recovery reference could not be cleared. Reload before continuing.'); }
  };

  if (user?.role !== 'admin' || (!targetId && !request && !pending && !problem && !notice)) return null;
  return <section className="ss-shelf" aria-label="Protected password reset" style={{ padding: 16, marginTop: 16 }}>
    <div className="ss-card__meta">ACCOUNT RECOVERY</div>
    <h2 className="ss-shelf__title" style={{ fontSize: 16, margin: '6px 0 10px' }}>Password reset</h2>
    {problem && <p role="alert" style={{ color: 'var(--rust)' }}>{problem}{restored.dismissable && ' Dismiss the local reference to inspect a new target.'}</p>}
    {error && <p role="alert" style={{ color: 'var(--rust)' }}>{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {!pending && !problem && (targetId || request) && !target && !error && <p role="status">Checking selected account…</p>}
    {!pending && !problem && target && <>
      <p>Reset the {target.channel === 'bound_persona' ? 'teaching persona' : 'registered account'} for <strong>{target.username}</strong> ({target.email}). This changes its password and revokes its existing shop sessions and API keys.</p>
      <button type="button" className="ss-btn ss-btn--sm" disabled={busy || !!error}
        onClick={() => run('reset')}>Confirm password reset</button>
    </>}
    {pending && <>
      <p>Saved reset for user #{pending.targetId}. Keep this administrator session to recover the temporary password. No reset is repeated when you read status.</p>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={busy}
          onClick={() => run('read')}>Read reset status</button>
        {metadata?.secretAvailable === true && <button type="button" className="ss-btn ss-btn--sm"
          disabled={busy} onClick={() => run('reveal')}>Reveal temporary password</button>}
      </div>
      {secret && <div style={{ marginTop: 12 }}>
        <div className="ss-mono" style={{ fontSize: 11 }}>TEMPORARY PASSWORD — RECORD PRIVATELY</div>
        <output aria-label="Temporary password" style={{ display: 'block', overflowWrap: 'anywhere', margin: '8px 0' }}>{secret}</output>
        <button type="button" className="ss-btn ss-btn--sm" disabled={busy}
          onClick={() => run('acknowledge')}>Acknowledge and clear password</button>
      </div>}
    </>}
    {((problem && restored.dismissable) || (pending && error && pending.version !== 2)) && <p style={{ fontSize: 12 }}>Dismissal clears only this local reference; it does not undo a reset. Recheck the account before starting another.</p>}
    {((problem && restored.dismissable) || (pending && error && pending.version !== 2)) && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
      disabled={busy} onClick={dismissReference}>Dismiss local reference</button>}
    {!pending && !problem && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
      disabled={busy} onClick={onClose} style={{ marginLeft: 8 }}>Close</button>}
  </section>;
}
