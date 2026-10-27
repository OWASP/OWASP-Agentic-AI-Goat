import React, { useEffect, useRef, useState } from 'react';
import {
  addressFieldsDigest, clearAddressReference, decodeAddressForm, decodeAddressOperation,
  decodeAddressSetup, normalizeAddressFields, readAddressReference, saveAddressReference,
} from '../utils/addressSetupOperation.mjs';

const FIELDS = [
  ['label', 'Label'], ['line1', 'Street address'], ['line2', 'Apt / suite'],
  ['city', 'City'], ['state', 'State'], ['zip', 'ZIP'], ['phone', 'Phone'],
];
const same = (a, b) => a && b && JSON.stringify(a) === JSON.stringify(b);
const message = error => error instanceof Error ? error.message : 'Saved address outcome unavailable.';

export default function PracticeAddressSetup({ setup = null, entryPoint = 'chat', action = 'create',
  choiceId = null, initialFields = null, authorityKey, transport = globalThis.fetch,
  onConfirmed, onStale, onCancel, interactionBlocked = false }) {
  const [preflight, setPreflight] = useState(null);
  const [fields, setFields] = useState(null);
  const [review, setReview] = useState(false);
  const [reference, setReference] = useState(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [storageFault, setStorageFault] = useState(false);
  const epochRef = useRef(0), activeRef = useRef(null), mountedRef = useRef(false);
  if (!['chat', 'account', 'checkout'].includes(entryPoint)) throw new TypeError('Trusted address entry point required');
  let handoff = null, handoffError = false;
  try { handoff = decodeAddressSetup(setup); } catch { handoffError = true; }
  const desired = entryPoint === 'chat' ? handoff : { action, choiceId, draft: initialFields || {} };
  const desiredKey = JSON.stringify(desired);

  useEffect(() => {
    mountedRef.current = true;
    const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    setPreflight(null); setFields(null); setReview(false); setReference(null);
    setNotice(''); setBusy(false); setCompleted(false); setStorageFault(false);
    try {
      const saved = readAddressReference();
      if (saved) { setReference(saved); setNotice('An address change is saved. Check its exact outcome before another save.'); }
    } catch { setStorageFault(true); setNotice('Saved address state is unavailable. Saving is blocked.'); }
    if (desired && !handoffError) {
      const controller = new AbortController(); activeRef.current = controller;
      const current = () => mountedRef.current && epochRef.current === epoch
        && activeRef.current === controller && !controller.signal.aborted;
      setBusy(true);
      const query = desired.action === 'update'
        ? `?action=update&choiceId=${encodeURIComponent(desired.choiceId || '')}` : '?action=create';
      Promise.resolve().then(async () => {
        const response = await transport(`/api/secureshop/customer/commerce/address-form${query}`,
          { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
        if (!response.ok) throw Error(`Current address form unavailable (${response.status}).`);
        const value = decodeAddressForm(await response.json());
        if (value.action !== desired.action || value.choiceId !== desired.choiceId)
          throw Error('Current address selection changed. Choose it again.');
        if (!current()) return;
        setPreflight(value);
        setFields({ ...value.fields, ...desired.draft,
          isDefault: value.fields.isDefault });
      }).catch(error => { if (current()) setNotice(message(error)); })
        .finally(() => { if (current()) { setBusy(false); activeRef.current = null; } });
    }
    return () => { mountedRef.current = false; epochRef.current += 1;
      activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, transport, entryPoint, desiredKey, handoffError]);

  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/customer/commerce/operations/${saved.operationId}`,
      { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) throw Error(`Saved address lookup failed (${response.status}).`);
    return decodeAddressOperation(await response.json(), saved);
  };
  const finish = async (saved, outcome, current) => {
    if (!current()) return;
    if (outcome.status === 'not_found') {
      setReference(saved);
      setNotice('Address outcome is not recorded yet. Check the saved address; the save will not be retried.');
      return;
    }
    await clearAddressReference(saved, current);
    if (!current()) return;
    setReference(null); setCompleted(true); setReview(false);
    if (outcome.status === 'stale') {
      setPreflight(null); setFields(null);
      setNotice('The address changed before saving. No address was saved. Start a fresh review.');
      Promise.resolve().then(() => onStale?.()).catch(() => {});
      return;
    }
    setNotice(saved.action === 'create' ? 'Address saved.' : 'Address updated.');
    Promise.resolve().then(() => onConfirmed?.()).catch(() => { /* The saved receipt remains authoritative. */ });
  };
  const run = async (recover = false) => {
    if (interactionBlocked || activeRef.current) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const current = () => mountedRef.current && epochRef.current === epoch
      && activeRef.current === controller && !controller.signal.aborted;
    activeRef.current = controller; setBusy(true); setNotice('');
    let saved = null;
    try {
      saved = readAddressReference();
      if (saved || recover) {
        if (!saved) throw Error('Saved address reference is unavailable.');
        setReference(saved);
        await finish(saved, await readExact(saved, controller.signal), current);
        return;
      }
      if (storageFault || !preflight || !fields || !review || handoffError) return;
      const normalized = normalizeAddressFields(fields);
      const fieldsSha256 = await addressFieldsDigest(normalized);
      if (!current()) return;
      saved = { version: 1, scopeKey: preflight.scopeKey,
        operationId: globalThis.crypto.randomUUID().toLowerCase(), action: preflight.action,
        choiceId: preflight.choiceId, expectedSnapshotSha256: preflight.expectedSnapshotSha256,
        defaultSetSha256: preflight.defaultSetSha256, fieldsSha256 };
      await saveAddressReference(saved);
      if (!current()) return;
      if (!same(readAddressReference(), saved)) throw Error('Saved address changed. No address was submitted.');
      setReference(saved);
      const prior = await readExact(saved, controller.signal);
      if (!current()) return;
      if (prior.status !== 'not_found') { await finish(saved, prior, current); return; }
      if (!same(readAddressReference(), saved)) throw Error('Saved address changed. No address was submitted.');
      try {
        await transport('/api/secureshop/customer/commerce/addresses', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ operationId: saved.operationId, action: saved.action,
            choiceId: saved.choiceId, expectedSnapshotSha256: saved.expectedSnapshotSha256,
            defaultSetSha256: saved.defaultSetSha256, fields: normalized }), signal: controller.signal,
        });
      } catch { /* An unknown POST outcome is resolved only by exact GET. */ }
      if (!current()) return;
      await finish(saved, await readExact(saved, controller.signal), current);
    } catch (error) {
      if (!current()) return;
      try { saved = readAddressReference(); } catch { setStorageFault(true); }
      if (saved) setReference(saved);
      setNotice(message(error));
    } finally { if (current()) { activeRef.current = null; setBusy(false); } }
  };
  if (!desired && !reference && !notice && !handoffError) return null;
  return <section className="ss-card" aria-label="Address setup" style={{ padding: 14, marginTop: 12 }}>
    <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>DELIVERY ADDRESS</div>
    {handoffError && <p role="alert">Saved address suggestion is unavailable.</p>}
    {desired && !completed && !reference && preflight && fields && <>
      <p>{preflight.action === 'update' ? 'Review the saved address and your changes.' : 'Enter and review your delivery address.'}</p>
      <div style={{ display: 'grid', gap: 8 }}>
        {FIELDS.map(([key, label]) => <label key={key}>{label}
          <input className="ss-lane__input" aria-label={label} value={fields[key] ?? ''}
            maxLength={key === 'line1' || key === 'line2' ? 1024 : key === 'city' ? 256 : key === 'label' || key === 'state' || key === 'phone' ? 128 : 64}
            disabled={interactionBlocked || busy || review} onChange={event => setFields(value => ({ ...value, [key]: event.target.value }))}
            style={{ display: 'block', width: '100%', boxSizing: 'border-box' }} />
        </label>)}
        <label><input type="checkbox" checked={fields.isDefault} disabled={interactionBlocked || busy || review}
          onChange={event => setFields(value => ({ ...value, isDefault: event.target.checked }))} /> Set as default</label>
      </div>
      {!fields.line1?.trim() && <p role="status">Street address is required before review.</p>}
      {review && <div aria-label="Address changes to confirm" style={{ marginTop: 10 }}>
        {FIELDS.map(([key, label]) => <p key={key} style={{ overflowWrap: 'anywhere' }}>
          <strong>{label}:</strong> {preflight.action === 'update' ? <><span>{preflight.fields[key] || '—'}</span> → </> : null}
          <span>{fields[key] || '—'}</span>
        </p>)}
        <p><strong>Default:</strong> {fields.isDefault ? 'Yes' : 'No'}</p>
      </div>}
      <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
        {!review ? <button className="ss-btn" type="button" disabled={interactionBlocked || busy || storageFault || !fields.line1?.trim()}
          onClick={() => { try { normalizeAddressFields(fields); setReview(true); setNotice(''); }
            catch (error) { setNotice(message(error)); } }}>Review address</button>
          : <><button className="ss-btn" type="button" disabled={interactionBlocked || busy || storageFault}
            onClick={() => void run()}>Confirm {preflight.action === 'update' ? 'address update' : 'address save'}</button>
            <button className="ss-btn ss-btn--ghost" type="button" disabled={interactionBlocked || busy} onClick={() => setReview(false)}>Edit fields</button></>}
        {onCancel && <button className="ss-btn ss-btn--ghost" type="button" disabled={interactionBlocked || busy} onClick={onCancel}>Cancel</button>}
      </div>
    </>}
    {notice && <p role={storageFault ? 'alert' : 'status'}>{notice}</p>}
    {interactionBlocked && <p role="status">Wait for the current conversation to finish restoring or responding before checking or changing an address.</p>}
    {reference && <button className="ss-btn ss-btn--ghost" type="button" disabled={interactionBlocked || busy}
      onClick={() => void run(true)}>Check saved address</button>}
  </section>;
}
