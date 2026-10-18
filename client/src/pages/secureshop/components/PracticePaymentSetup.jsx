import React, { useEffect, useRef, useState } from 'react';
import { clearPracticePaymentReference, decodePracticePaymentMethods, decodePracticePaymentOperation,
  decodePracticePaymentSetup, readPracticePaymentReference, savePracticePaymentReference } from '../utils/practicePaymentOperation.mjs';

export default function PracticePaymentSetup({ setup = null, entryPoint = 'chat', authorityKey, transport = globalThis.fetch, onConfirmed }) {
  const [reference, setReference] = useState(null), [scenario, setScenario] = useState(null);
  const [notice, setNotice] = useState(''), [busy, setBusy] = useState(false), [storageFault, setStorageFault] = useState(false), [completed, setCompleted] = useState(false);
  const activeRef = useRef(null), epochRef = useRef(0), mountedRef = useRef(false);
  if (!['chat', 'checkout'].includes(entryPoint)) throw new TypeError('Trusted payment entry point required');
  let handoff = null; try { handoff = decodePracticePaymentSetup(setup); } catch { handoff = null; }
  const suggested = handoff?.suggestedScenario || null;
  useEffect(() => {
    mountedRef.current = true; const epoch = ++epochRef.current; activeRef.current?.abort(); activeRef.current = null;
    setReference(null); setScenario(null); setNotice(''); setBusy(false); setStorageFault(false); setCompleted(false);
    try { const saved = readPracticePaymentReference(); if (saved) { setReference(saved); setNotice('A practice payment is saved. Check its exact outcome before creating another.'); } }
    catch { setStorageFault(true); setNotice('Saved practice payment state is unavailable. Creation is blocked.'); }
    return () => { mountedRef.current = false; epochRef.current += 1; activeRef.current?.abort(); activeRef.current = null; };
  }, [authorityKey, entryPoint, suggested, transport]);
  const readExact = async (saved, signal) => {
    const response = await transport(`/api/secureshop/customer/commerce/operations/${saved.operationId}`, { method: 'GET', headers: { accept: 'application/json' }, signal });
    if (!response.ok) throw Error(`Saved practice payment lookup failed (${response.status}).`);
    return decodePracticePaymentOperation(await response.json(), saved);
  };
  const showOutcome = async (saved, outcome, current) => {
    if (!current()) return;
    if (outcome.status === 'not_found') { setReference(saved); setNotice('Practice payment outcome is not recorded yet. Check the saved payment; creation will not be retried.'); return; }
    await clearPracticePaymentReference(saved, current); if (!current()) return;
    setReference(null); setCompleted(true); setNotice('Practice payment created from the saved result.');
    Promise.resolve(onConfirmed?.(outcome.cards)).catch(() => { /* The confirmed receipt remains authoritative. */ });
  };
  const run = async selectedScenario => {
    if (activeRef.current) return;
    const controller = new AbortController(), epoch = epochRef.current;
    const current = () => mountedRef.current && epochRef.current === epoch && activeRef.current === controller && !controller.signal.aborted;
    activeRef.current = controller; setBusy(true); setNotice(''); let saved = null;
    try {
      saved = readPracticePaymentReference();
      if (saved) { if (current()) setReference(saved); await showOutcome(saved, await readExact(saved, controller.signal), current); return; }
      if ((entryPoint === 'chat' && !handoff) || !['approved', 'declined'].includes(selectedScenario) || storageFault) return;
      const choicesResponse = await transport('/api/secureshop/customer/commerce/payment-methods', { method: 'GET', headers: { accept: 'application/json' }, signal: controller.signal });
      if (!choicesResponse.ok) throw Error('Practice payment choices are unavailable.');
      const choices = decodePracticePaymentMethods(await choicesResponse.json()); if (!current()) return;
      saved = { version: 1, scopeKey: choices.scopeKey, operationId: globalThis.crypto.randomUUID().toLowerCase(), scenario: selectedScenario };
      await savePracticePaymentReference(saved); if (!current()) return;
      const persisted = readPracticePaymentReference(); if (!persisted || JSON.stringify(persisted) !== JSON.stringify(saved)) throw Error('Saved practice payment changed. No payment was created.');
      setReference(saved); const prior = await readExact(saved, controller.signal); if (!current()) return;
      if (prior.status !== 'not_found') { await showOutcome(saved, prior, current); return; }
      if (!readPracticePaymentReference() || JSON.stringify(readPracticePaymentReference()) !== JSON.stringify(saved)) throw Error('Saved practice payment changed. No payment was created.');
      try { await transport('/api/secureshop/customer/commerce/payment-methods', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ operationId: saved.operationId, scenario: saved.scenario }), signal: controller.signal }); }
      catch { /* The exact operation GET decides a lost response. */ }
      if (!current()) return; await showOutcome(saved, await readExact(saved, controller.signal), current);
    } catch (error) {
      if (!current()) return; try { saved = readPracticePaymentReference(); } catch { setStorageFault(true); }
      if (saved) setReference(saved); setNotice(error instanceof Error ? error.message : 'Practice payment outcome unavailable.');
    } finally { if (current()) { activeRef.current = null; setBusy(false); } }
  };
  const canStart = entryPoint === 'checkout' || handoff !== null;
  if (!canStart && !reference && !notice) return null;
  return <section className="ss-card" aria-label="Practice payment setup" style={{ padding: 14, marginTop: 12 }}>
    {canStart && <><div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>PRACTICE PAYMENT · CHOOSE A SYNTHETIC OUTCOME</div>
      <p>Choose a named synthetic practice payment. No personal payment details are collected.</p>
      {!reference && !completed && <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {['approved', 'declined'].map(value => <button key={value} className={`ss-btn ${scenario === value ? '' : 'ss-btn--ghost'}`} type="button" disabled={busy || storageFault}
          aria-pressed={scenario === value}
          onClick={() => setScenario(value)}>{value === 'approved' ? 'Use approved practice payment' : 'Use declined practice payment'}{suggested === value ? ' (suggested)' : ''}</button>)}
      </div>}
      {!reference && !completed && scenario && <button className="ss-btn" type="button" disabled={busy || storageFault} style={{ marginTop: 8 }} onClick={() => void run(scenario)}>Create selected practice payment</button>}</>}
    {notice && <p role="status">{notice}</p>}
    {reference && <button className="ss-btn ss-btn--ghost" type="button" disabled={busy} onClick={() => void run(null)}>Check saved practice payment</button>}
  </section>;
}
