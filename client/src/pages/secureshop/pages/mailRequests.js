import { useEffect, useRef, useState } from 'react';
import { decodeMailReferences, keepUnresolvedMailReference, updateMailReference } from '../bridge/mailReferences.mjs';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { isStandaloneShopFrame } from '../bridge/assessmentPanelIntent.mjs';
import { SHOP_MAIL_KEY, shopStorage, flushShopStorage } from '../utils/shopStorage.mjs';

export function useRequests() {
  const controllers = useRef(new Set());
  useEffect(() => () => {
    controllers.current.forEach(controller => controller.abort());
    controllers.current.clear();
  }, []);
  return () => {
    const controller = new AbortController();
    controllers.current.add(controller);
    return { signal: controller.signal, finish: () => controllers.current.delete(controller) };
  };
}

export async function readResponse(response) {
  const data = await response.json();
  if (!response.ok || data?.ok !== true) throw new Error(data?.error || 'Mail operation unavailable');
  return data;
}
export const persistedId = value => Number.isSafeInteger(value) && value > 0;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');

async function requestDigest(action, threadId, payload) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify([action, threadId || null, payload])));
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}


// Bound mutations retain only opaque IDs and a digest. Response loss is recovered
// by GET; an uncertain POST is never repeated automatically.
export function useMailCommands() {
  const [pending, setPending] = useState(null);
  const [unresolved, setUnresolved] = useState([]);
  const [unresolvedOutcomes, setUnresolvedOutcomes] = useState({});
  const unresolvedOutcomesRef = useRef({});
  const [modelCapabilities, setModelCapabilities] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [headerAssessment, setHeaderAssessment] = useState(null);
  const [disclosureAssessment, setDisclosureAssessment] = useState(null);
  const [browserAssessment, setBrowserAssessment] = useState(null);
  const [inlineTeaching, setInlineTeaching] = useState(null);
  const [browserAssessmentReady, setBrowserAssessmentReady] = useState(false);
  const readinessVersion = useRef(0);
  const unacknowledgedDisclosures = useRef(new Set());
  const alive = useRef(false);
  const activeScope = useRef(null);
  const bound = !!getBridgeFetchMetadata(fetch);
  useEffect(() => {
    alive.current = true;
    const controller = new AbortController();
    if (bound) void readiness(controller.signal).then(status => {
      if (alive.current && !controller.signal.aborted) { setPending(readPending(status.scopeKey)); setUnresolved(readUnresolved(status.scopeKey)); setAssessment(readAssessment(status.scopeKey)); setHeaderAssessment(readReference(status.scopeKey, 'headerAssessment')); setDisclosureAssessment(disclosureReference(status.scopeKey)); setBrowserAssessment(readReference(status.scopeKey, 'browserAssessment')); setInlineTeaching(readReference(status.scopeKey, 'inlineTeaching')); }
    }).catch(() => {});
    const changed = event => {
      if (alive.current && event.detail === activeScope.current) {
        try { setPending(readPending(activeScope.current)); setUnresolved(readUnresolved(activeScope.current)); setAssessment(readAssessment(activeScope.current)); setHeaderAssessment(readReference(activeScope.current, 'headerAssessment')); setDisclosureAssessment(disclosureReference(activeScope.current)); setBrowserAssessment(readReference(activeScope.current, 'browserAssessment')); setInlineTeaching(readReference(activeScope.current, 'inlineTeaching')); } catch {}
      }
    };
    window.addEventListener('secureshop-mail-pending', changed);
    return () => { alive.current = false; controller.abort(); window.removeEventListener('secureshop-mail-pending', changed); };
  }, [bound]);
  function assertScope(scope, signal) {
    signal?.throwIfAborted();
    if (!alive.current || activeScope.current !== scope) throw new DOMException('Mail session changed', 'AbortError');
  }
  async function readiness(signal) {
    const version=++readinessVersion.current;
    try {
    const response = await fetch('/api/secureshop/email/readiness', { signal });
    const result = await response.json();
    if (!response.ok || result.ready !== true || !/^[a-f0-9]{64}$/.test(result.scopeKey || '')) throw new Error('Bound mail is unavailable');
    signal?.throwIfAborted();
    if (!alive.current || version!==readinessVersion.current) throw new DOMException('Mail session changed', 'AbortError');
    if (activeScope.current !== result.scopeKey) { setPending(null); setUnresolved([]); unresolvedOutcomesRef.current = {}; setUnresolvedOutcomes({}); setAssessment(null); setHeaderAssessment(null); setDisclosureAssessment(null); setBrowserAssessment(null); setInlineTeaching(null); }
    activeScope.current = result.scopeKey;
    setModelCapabilities(result.modelCapabilities || null);
    setBrowserAssessmentReady(result.objectiveReadiness?.ss_mail_stored_browser_execution === true);
    return result;
    } catch(error) { if(alive.current && version===readinessVersion.current) { setModelCapabilities(null); setDisclosureAssessment(null); setBrowserAssessmentReady(false); } throw error; }
  }
  function readReference(scope, kind) {
    return decodeMailReferences(shopStorage.getItem(SHOP_MAIL_KEY)).scopes[scope]?.[kind] || null;
  }
  function disclosureReference(scope) {
    const reference=readReference(scope,'disclosureAssessment');
    return reference&&unacknowledgedDisclosures.current.has(reference.readOperationId)?{...reference,confirmed:false}:reference;
  }
  const readPending = scope => readReference(scope, 'pending');
  const readUnresolved = scope => decodeMailReferences(shopStorage.getItem(SHOP_MAIL_KEY)).scopes[scope]?.unresolved || [];
  const readAssessment = scope => readReference(scope, 'assessment');
  function writeReference(scope,kind,value) {
    const encoded=updateMailReference(shopStorage.getItem(SHOP_MAIL_KEY),scope,kind,value);
    if(encoded===null)shopStorage.removeItem(SHOP_MAIL_KEY);else shopStorage.setItem(SHOP_MAIL_KEY,encoded);
  }
  async function remember(scope, value, expectedPending) {
    if(expectedPending)assertReference(scope,'pending',expectedPending);
    else if(readPending(scope)!==null)throw new Error('Check the pending mail request before sending another message');
    assertScope(scope);
    writeReference(scope,'pending',value);
    await flushShopStorage();
    assertScope(scope);
    if(value)assertReference(scope,'pending',value);
    else if(readPending(scope)!==null)throw new DOMException('Saved mail reference changed','AbortError');
    setPending(value);
    window.dispatchEvent(new CustomEvent('secureshop-mail-pending', { detail: scope }));
  }
  async function saveAssessment(scope, replyOperationId, threadId, expectedPending) {
    if(expectedPending)assertReference(scope,'pending',expectedPending);
    const old = readAssessment(scope);
    const value = old?.replyOperationId === replyOperationId && old.threadId === threadId ? old : { requestId: crypto.randomUUID(), replyOperationId, threadId };
    assertScope(scope);
    writeReference(scope,'assessment',value);
    await flushShopStorage();
    assertScope(scope);
    if(expectedPending)assertReference(scope,'pending',expectedPending);
    setAssessment(value);
    window.dispatchEvent(new CustomEvent('secureshop-mail-pending', { detail: scope }));
  }
  async function saveHeaderAssessment(scope, sendOperationId, expectedPending) {
    if(expectedPending)assertReference(scope,'pending',expectedPending);
    assertScope(scope);
    const old=readReference(scope,'headerAssessment');
    const value=old?.sendOperationId===sendOperationId?old:{requestId:crypto.randomUUID(),sendOperationId};
    writeReference(scope,'headerAssessment',value);await flushShopStorage();assertScope(scope);
    if(expectedPending)assertReference(scope,'pending',expectedPending);
    setHeaderAssessment(value);window.dispatchEvent(new CustomEvent('secureshop-mail-pending',{detail:scope}));
  }
  async function saveBrowserAssessment(scope, sendOperationId, messageId, expectedPending) {
    assertReference(scope,'pending',expectedPending);
    const old=readReference(scope,'browserAssessment');
    const value=old?.sendOperationId===sendOperationId&&old.messageId===messageId?old:{requestId:crypto.randomUUID(),sendOperationId,messageId};
    writeReference(scope,'browserAssessment',value);await flushShopStorage();assertScope(scope);
    assertReference(scope,'pending',expectedPending);
    setBrowserAssessment(value);window.dispatchEvent(new CustomEvent('secureshop-mail-pending',{detail:scope}));
  }
  function assertReference(scope, kind, expected, signal) {
    assertScope(scope,signal);
    const current=readReference(scope,kind);
    if(!current||Object.keys(current).length!==Object.keys(expected).length||Object.keys(expected).some(key=>current[key]!==expected[key]))throw new DOMException('Saved mail reference changed','AbortError');
  }
  async function assessSaved(kind,path,signal) {
    const status=await readiness(signal),reference=readReference(status.scopeKey,kind);
    if(!reference||(kind==='disclosureAssessment'&&(!reference.confirmed||unacknowledgedDisclosures.current.has(reference.readOperationId))))throw new Error(kind==='headerAssessment'?'No saved headers are available for assessment':'No saved reply is available for assessment');
    if(reference.evaluationId&&isStandaloneShopFrame())throw new Error('Open saved assessments to review Judge retry eligibility.');
    assertReference(status.scopeKey,kind,reference,signal);
    if(kind==='browserAssessment'&&status.objectiveReadiness?.ss_mail_stored_browser_execution!==true)return {ok:true,json:async()=>({ok:true,status:'disabled',completed:false,modelEvaluated:false})};
    if(kind==='headerAssessment'&&status.objectiveReadiness?.ss_mail_header_construction!==true)return {ok:true,json:async()=>({ok:true,status:'disabled',completed:false,modelEvaluated:false})};
    // Parent acknowledgement, response parsing and retry acknowledgement each
    // cross an async boundary: recheck both authority and exact opaque identity.
    await flushShopStorage();assertReference(status.scopeKey,kind,reference,signal);
    const response=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(kind==='disclosureAssessment'?{requestId:reference.requestId,readOperationId:reference.readOperationId,...(reference.evaluationId?{evaluationId:reference.evaluationId}:{})}:reference),signal});
    const result=await response.clone().json().catch(()=>({}));assertReference(status.scopeKey,kind,reference,signal);
    if(response.ok&&result.ok===true&&result.judgment?.canRetry===true&&/^[a-f0-9-]{36}$/.test(result.judgment.evaluationId||'')){
      const retry={...reference,requestId:crypto.randomUUID(),evaluationId:result.judgment.evaluationId};
      writeReference(status.scopeKey,kind,retry);await flushShopStorage();assertReference(status.scopeKey,kind,retry,signal);
      (kind==='browserAssessment'?setBrowserAssessment:kind==='headerAssessment'?setHeaderAssessment:kind==='disclosureAssessment'?setDisclosureAssessment:setAssessment)(retry);
    }
    return response;
  }
  const assessHeader=signal=>assessSaved('headerAssessment','/api/secureshop/email/header-assessment',signal);
  const assess=signal=>assessSaved('assessment','/api/secureshop/email/reply-assessment',signal);
  async function finish(scope, response, expectedReference) {
    const result = await response.clone().json().catch(() => ({}));
    assertScope(scope);
    const reference = readPending(scope);
    try { assertReference(scope,'pending',expectedReference); } catch { return response; }
    if (result.requestId !== undefined && result.requestId !== expectedReference.requestId)
      throw new Error('Mail operation receipt did not match the pending request');
    if(response.ok&&result.ok===true&&persistedId(result.email_id)&&reference.action==='send'){
      try { await saveHeaderAssessment(scope,reference.requestId,reference); await saveBrowserAssessment(scope,reference.requestId,result.email_id,reference); } catch { return response; }
    }
    if (response.ok && result.ok === true && persistedId(result.sent_email_id) && persistedId(result.thread_id) && reference?.action === 'autoReply') {
      if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(result.sendOperationId||''))return response;
      try { await saveAssessment(scope, reference.requestId, result.thread_id,reference); await saveHeaderAssessment(scope,result.sendOperationId,reference); await saveBrowserAssessment(scope,result.sendOperationId,result.sent_email_id,reference); } catch { return response; }
    }
    const rejectedBeforeExecution = reference?.action === 'autoReply' && response.ok && result.ok === true
      && result.status === 'rejected_before_execution' && result.terminalRejected === true
      && result.requestId === reference.requestId;
    const terminalNoSend = reference?.action === 'autoReply' && response.ok && result.ok === true
      && result.status === 'declined' && result.terminalNoSend === true
      && result.requestId === reference.requestId && persistedId(result.threadId)
      && result.threadId <= 2147483647
      && reference.digest === await requestDigest('autoReply', result.threadId, {});
    if ((response.status === 400 && result.terminalRejected === true) || rejectedBeforeExecution || terminalNoSend
      || (response.ok && result.ok === true && (persistedId(result.email_id) || persistedId(result.sent_email_id)))) {
      try { await remember(scope, null,reference); } catch { /* Confirmed persistence remains a successful save; recovery can clear stale local refs. */ }
    }
    return response;
  }
  async function recover(signal) {
    const status = await readiness(signal), reference = readPending(status.scopeKey);
    if (!reference) throw new Error('No pending mail request');
    if (reference.chatSource) throw new Error('Open the Merchant assistant to check its saved mail operation.');
    signal?.throwIfAborted();
    return finish(status.scopeKey, await fetch(`/api/secureshop/email/operations/${reference.action}/${reference.requestId}`, { signal }), reference);
  }
  async function keepUnresolved(threadId, signal) {
    if (!bound || !persistedId(threadId) || threadId > 2147483647) throw new Error('Select the original thread to keep its request unresolved');
    const status = await readiness(signal), reference = readPending(status.scopeKey);
    if (reference?.chatSource) throw new Error('Open the Merchant assistant to check its saved mail operation.');
    if (reference?.action !== 'autoReply') throw new Error('No pending auto-reply request');
    assertReference(status.scopeKey, 'pending', reference, signal);
    const response = await fetch(`/api/secureshop/email/operations/autoReply/${reference.requestId}/keep-unresolved`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ threadId }), signal,
    });
    const receipt = await response.clone().json().catch(() => ({}));
    assertReference(status.scopeKey, 'pending', reference, signal);
    if (!response.ok || receipt.ok !== true || receipt.status !== 'kept_unresolved'
      || receipt.requestId !== reference.requestId || receipt.threadId !== threadId) {
      throw new Error(receipt.error || 'The unresolved request was not confirmed');
    }
    const encoded = keepUnresolvedMailReference(shopStorage.getItem(SHOP_MAIL_KEY), status.scopeKey, reference, threadId);
    shopStorage.setItem(SHOP_MAIL_KEY, encoded);
    await flushShopStorage();
    assertScope(status.scopeKey, signal);
    const saved = readUnresolved(status.scopeKey);
    if (readPending(status.scopeKey) !== null || !saved.some(item => item.requestId === reference.requestId
      && item.digest === reference.digest && item.threadId === threadId)) throw new DOMException('Saved mail reference changed', 'AbortError');
    setPending(null); setUnresolved(saved);
    window.dispatchEvent(new CustomEvent('secureshop-mail-pending', { detail: status.scopeKey }));
    return receipt;
  }
  async function checkUnresolved(reference, signal) {
    const status = await readiness(signal);
    const saved = readUnresolved(status.scopeKey).find(item => item.requestId === reference?.requestId);
    if (!saved || saved.action !== 'autoReply' || saved.digest !== reference.digest || saved.threadId !== reference.threadId)
      throw new Error('This unresolved request is no longer available');
    assertScope(status.scopeKey, signal);
    const response = await fetch(`/api/secureshop/email/operations/autoReply/${saved.requestId}`, { signal });
    const result = await response.clone().json().catch(() => ({}));
    assertScope(status.scopeKey, signal);
    if (response.ok && result.ok === true && result.requestId !== saved.requestId)
      throw new Error('Mail operation receipt did not match the unresolved request');
    if (response.ok && result.ok === true) {
      const terminal = result.status === 'saved' && persistedId(result.sent_email_id) ? 'saved'
        : result.status === 'declined' && result.terminalNoSend === true
          && result.requestId === saved.requestId && result.threadId === saved.threadId ? 'declined'
          : result.status === 'rejected_before_execution' && result.terminalRejected === true ? 'rejected_before_execution'
            : null;
      const next = { ...unresolvedOutcomesRef.current };
      if (terminal) next[saved.requestId] = terminal;
      else delete next[saved.requestId];
      unresolvedOutcomesRef.current = next;
      setUnresolvedOutcomes(next);
    }
    return response;
  }
  async function disclose(userId,signal) {
    if(!bound)throw new Error('Bound disclosure assessment is unavailable');
    const status=await readiness(signal);
    const old=readReference(status.scopeKey,'disclosureAssessment');
    const reference=old?.userId===userId&&(!old.confirmed||unacknowledgedDisclosures.current.has(old.readOperationId))?{...old,confirmed:false}:{requestId:crypto.randomUUID(),readOperationId:crypto.randomUUID(),userId,confirmed:false};
    assertScope(status.scopeKey,signal);
    writeReference(status.scopeKey,'disclosureAssessment',reference);
    await flushShopStorage();assertReference(status.scopeKey,'disclosureAssessment',reference,signal);
    setDisclosureAssessment(reference);
    const response=await fetch('/api/secureshop/email/disclosure',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({requestId:reference.readOperationId,userId}),signal});
    const result=await response.clone().json();assertReference(status.scopeKey,'disclosureAssessment',reference,signal);
    if(response.ok&&result.ok===true&&(result.operationId!==reference.readOperationId||result.receipt?.userId!==userId||!Array.isArray(result.emails)))throw new Error('Saved disclosure was not confirmed');
    if(response.ok&&result.ok===true){
      const confirmed={...reference,confirmed:true};unacknowledgedDisclosures.current.add(reference.readOperationId);writeReference(status.scopeKey,'disclosureAssessment',confirmed);
      await flushShopStorage();assertReference(status.scopeKey,'disclosureAssessment',confirmed,signal);unacknowledgedDisclosures.current.delete(reference.readOperationId);setDisclosureAssessment(confirmed);
      window.dispatchEvent(new CustomEvent('secureshop-mail-pending',{detail:status.scopeKey}));
    }
    return response;
  }
  function decodeInlineTeaching(value, requestId) {
    if (exact(value, ['ok','status','requestId']) && value.ok === true
      && value.status === 'unconfirmed' && value.requestId === requestId) return value;
    if (exact(value, ['ok','status','requestId','messageId','threadId','replayed'])
      && value.ok === true && value.status === 'saved' && value.requestId === requestId
      && persistedId(value.messageId) && persistedId(value.threadId)
      && typeof value.replayed === 'boolean') return value;
    throw new Error('Saved teaching message outcome is invalid');
  }
  async function checkInlineTeaching(signal) {
    const status = await readiness(signal), reference = readReference(status.scopeKey, 'inlineTeaching');
    if (!reference) throw new Error('No saved teaching message is available');
    assertReference(status.scopeKey, 'inlineTeaching', reference, signal);
    const response = await fetch(`/api/secureshop/email/inline/teaching-message/${reference.requestId}`, { signal });
    const value = decodeInlineTeaching(await response.json().catch(() => ({})), reference.requestId);
    if ((value.status === 'unconfirmed' && response.status !== 202)
      || (value.status === 'saved' && response.status !== 200)) throw new Error('Saved teaching message outcome is unavailable');
    assertReference(status.scopeKey, 'inlineTeaching', reference, signal);
    if (value.status === 'saved') {
      writeReference(status.scopeKey, 'inlineTeaching', null); await flushShopStorage();
      assertScope(status.scopeKey, signal);
      if (readReference(status.scopeKey, 'inlineTeaching') !== null) throw new DOMException('Saved mail reference changed', 'AbortError');
      setInlineTeaching(null); window.dispatchEvent(new CustomEvent('secureshop-mail-pending', { detail: status.scopeKey }));
    }
    return { response, value };
  }
  async function saveTeachingMessage(signal) {
    const status = await readiness(signal);
    if (readPending(status.scopeKey) !== null) throw new Error('Check the pending mail request before saving a teaching message');
    const existing = readReference(status.scopeKey, 'inlineTeaching');
    if (existing) return checkInlineTeaching(signal);
    const reference = { requestId: crypto.randomUUID().toLowerCase() };
    assertScope(status.scopeKey, signal); writeReference(status.scopeKey, 'inlineTeaching', reference);
    await flushShopStorage(); assertReference(status.scopeKey, 'inlineTeaching', reference, signal);
    setInlineTeaching(reference); window.dispatchEvent(new CustomEvent('secureshop-mail-pending', { detail: status.scopeKey }));
    try {
      await fetch('/api/secureshop/email/inline/teaching-message', { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(reference), signal });
    } catch { /* The saved GET is the only recovery path; never replay this POST. */ }
    return checkInlineTeaching(signal);
  }
  return { browserAssessment, browserAssessmentReady, assessBrowser:signal=>assessSaved('browserAssessment','/api/secureshop/email/browser-assessment',signal), pending, unresolved, unresolvedOutcomes, keepUnresolved, checkUnresolved, assessment, assess, disclosureAssessment, disclose, assessDisclosure:signal=>assessSaved('disclosureAssessment','/api/secureshop/email/disclosure-assessment',signal), headerAssessment, assessHeader, modelCapabilities, scopeKey:activeScope.current,
    inlineTeaching, saveTeachingMessage, checkInlineTeaching,
    read(userId, signal) {
      return fetch(`/api/secureshop/email/inbox/${userId}${bound ? `?requestId=${crypto.randomUUID()}` : ''}`, { signal });
    },
    recover,
    async command(action, payload, signal, threadId, retrySameId = false) {
      const path = action === 'send' ? '/api/secureshop/email/send' : `/api/secureshop/email/auto-reply/${threadId}`;
      if (!bound) return fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload), signal });
      const status = await readiness(signal);
      if (action === 'autoReply' && readUnresolved(status.scopeKey).some(item => item.threadId === threadId && !unresolvedOutcomesRef.current[item.requestId]))
        throw new Error('This thread has an unresolved auto-reply; check its saved status instead');
      const digest = await requestDigest(action, threadId, payload);
      const old = readPending(status.scopeKey);
      if (old) {
        if (old.chatSource) throw new Error('Open the Merchant assistant to check its saved mail operation before sending another message.');
        if (old.action !== action || old.digest !== digest) throw new Error('Check the pending mail request before sending another message');
        const recovered = await recover(signal);
        const recovery = await recovered.clone().json();
        if (!retrySameId || !recovered.ok || recovery.status !== 'unconfirmed' || recovery.canRetrySameId !== true) return recovered;
        signal?.throwIfAborted();
        return finish(status.scopeKey, await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...payload, requestId: old.requestId }), signal }), old);
      }
      const reference = { action, requestId: crypto.randomUUID(), digest };
      signal?.throwIfAborted();await remember(status.scopeKey, reference);signal?.throwIfAborted();
      return finish(status.scopeKey, await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...payload, requestId: reference.requestId }), signal }), reference);
    },
  };
}
