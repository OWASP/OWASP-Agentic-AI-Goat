import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useMailCommands } from './mailRequests';
import { decodeMailReferences, keepUnresolvedMailReference } from '../bridge/mailReferences.mjs';
import { matchOperationRequest } from '../bridge/operations.mjs';
let current;
const mockStore = new Map();
const mockFlush = jest.fn();
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => ({ bound: true }) }));
jest.mock('../utils/shopStorage.mjs', () => ({ SHOP_MAIL_KEY: 'secureshop.mail.operations.v1', shopStorage: { getItem: k => mockStore.get(k) || null, setItem: (k,v) => mockStore.set(k,v), removeItem: k => mockStore.delete(k) }, flushShopStorage: () => mockFlush() }));
function Probe() { current = useMailCommands(); return <span>{current.pending?.requestId || 'none'}</span>; }
const scope = 'a'.repeat(64);
function response(body, ok = true) { return { ok, json: async () => body, clone: () => response(body, ok) }; }
let root, node;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true; mockStore.clear(); mockFlush.mockReset(); mockFlush.mockResolvedValue();
  Object.defineProperty(global, 'crypto', { configurable: true, value: require('node:crypto').webcrypto }); global.TextEncoder = require('node:util').TextEncoder;
  global.fetch = jest.fn(async url => url.endsWith('readiness') ? response({ ready: true, scopeKey: scope }) : response({ ok: true, status: 'unconfirmed' }));
  node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });
const mount = async () => { await act(async () => root.render(<Probe />)); };
const payload = { from: 'merchant@lab', to: 'customer@lab', subject: 'Owned', body_markdown: '<b>private source</b>' };
test('mail history migration preserves the exact opaque pending identity and closed bridge route', () => {
  const pending = { action: 'autoReply', requestId: '11111111-1111-4111-8111-111111111111', digest: 'b'.repeat(64) };
  const old = JSON.stringify({ version: 2, scopes: { [scope]: { pending, assessment: null } } });
  const kept = decodeMailReferences(keepUnresolvedMailReference(old, scope, pending, 5));
  expect(kept).toEqual({ version: 3, scopes: { [scope]: { pending: null, assessment: null,
    unresolved: [{ ...pending, threadId: 5 }] } } });
  expect(() => keepUnresolvedMailReference(old, scope, { ...pending, digest: 'c'.repeat(64) }, 5)).toThrow();
  expect(matchOperationRequest({ pathname: `/api/secureshop/email/operations/autoReply/${pending.requestId}/keep-unresolved`,
    method: 'POST', body: { threadId: 5 } }).name).toBe('email.keepUnresolved');
  expect(() => matchOperationRequest({ pathname: `/api/secureshop/email/operations/autoReply/${pending.requestId}/keep-unresolved`,
    method: 'POST', body: { threadId: 5, requestId: pending.requestId } })).toThrow();
});
test('manual Inbox recognizes a chat-origin pending mail ref and cannot retry or clear it', async () => {
  const chat = { action: 'send', requestId: '11111111-1111-5111-a111-111111111111',
    digest: 'd'.repeat(64), chatSource: { sessionId: '22222222-2222-4222-8222-222222222222',
      requestId: '33333333-3333-4333-8333-333333333333' } };
  mockStore.set('secureshop.mail.operations.v1', JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: chat, assessment: null } } }));
  await mount();
  expect(current.pending).toEqual(chat);
  await act(async () => {
    await expect(current.recover()).rejects.toThrow('Merchant assistant');
    await expect(current.command('send', payload)).rejects.toThrow('Merchant assistant');
  });
  expect(fetch.mock.calls.filter(([,options]) => options?.method === 'POST')).toHaveLength(0);
  expect(current.pending).toEqual(chat);
  expect(decodeMailReferences(mockStore.get('secureshop.mail.operations.v1')).scopes[scope].pending).toEqual(chat);
});
test('response loss retains only opaque reference and repeat action does GET recovery without second POST', async () => {
  await mount(); const base = fetch.getMockImplementation(); fetch.mockImplementation(async (url,options) => options?.method === 'POST' ? Promise.reject(Error('lost')) : base(url,options));
  await act(async () => { await expect(current.command('send', payload)).rejects.toThrow('lost'); });
  const reference = JSON.parse([...mockStore.values()][0]).scopes[scope].pending; expect(Object.keys(reference).sort()).toEqual(['action','digest','requestId']); expect([...mockStore.values()].join('')).not.toContain('private source');
  await act(async () => { await current.command('send', payload); });
  expect(fetch.mock.calls.filter(([,o]) => o?.method === 'POST')).toHaveLength(1);
  expect(fetch.mock.calls.some(([url]) => url.endsWith(`/send/${reference.requestId}`))).toBe(true);
});
test('remount recovers saved mail and clears reference only after confirmed persistence', async () => {
  await mount(); await act(async () => { await current.command('send', payload); });
  const reference = current.pending; await act(async () => root.unmount()); root = createRoot(node); await mount(); expect(current.pending.requestId).toBe(reference.requestId);
  const base = fetch.getMockImplementation(); fetch.mockImplementation((url,o) => url.includes('/operations/') ? Promise.resolve(response({ ok: true, status: 'saved', email_id: 8 })) : base(url,o));
  await act(async () => { await current.recover(); }); expect(current.pending).toBeNull(); expect(current.headerAssessment.sendOperationId).toBe(reference.requestId); expect([...mockStore.values()].join('')).not.toContain('private source');
});
test('storage failure prevents dispatch and a different pending payload cannot become another send', async () => {
  await mount(); mockFlush.mockRejectedValueOnce(Error('storage failed'));
  await act(async () => { await expect(current.command('send', payload)).rejects.toThrow('storage failed'); });
  expect(fetch.mock.calls.filter(([,o]) => o?.method === 'POST')).toHaveLength(0);
  await act(async () => { await expect(current.command('send', { ...payload, subject: 'changed' })).rejects.toThrow('pending'); });
  expect(fetch.mock.calls.filter(([,o]) => o?.method === 'POST')).toHaveLength(0);
});
test('explicit pre-effect rejection clears pending and permits a corrected new command', async () => {
  await mount(); const base = fetch.getMockImplementation(); let posts = 0;
  fetch.mockImplementation((url,o) => o?.method === 'POST' ? Promise.resolve({ ...response({ ok: false, terminalRejected: true }, false), status: 400 }) : base(url,o));
  await act(async () => { await current.command('send', payload); }); expect(current.pending).toBeNull();
  fetch.mockImplementation((url,o) => { if (o?.method === 'POST') { posts++; return Promise.resolve(response({ ok: true, email_id: 8 })); } return base(url,o); });
  await act(async () => { await current.command('send', { ...payload, subject: 'corrected' }); }); expect(posts).toBe(1);
});
test('bare or mismatched declined recovery retains pending; exact no-send receipt clears it', async () => {
  await mount(); const base = fetch.getMockImplementation();
  fetch.mockImplementation((url,o) => o?.method === 'POST' ? Promise.resolve({ ...response({ ok: false, error: 'after effect' }, false), status: 400 }) : base(url,o));
  await act(async () => { await current.command('autoReply', {}, undefined, 5); });
  const reference = current.pending;
  fetch.mockImplementation((url,o) => url.includes('/operations/') ? Promise.resolve(response({ ok: true, status: 'declined' })) : base(url,o));
  await act(async () => { await current.recover(); }); expect(current.pending).toEqual(reference);
  fetch.mockImplementation((url,o) => url.includes('/operations/') ? Promise.resolve(response({ ok: true, status: 'declined',
    requestId: reference.requestId, threadId: 6, terminalNoSend: true })) : base(url,o));
  await act(async () => { await current.recover(); }); expect(current.pending).toEqual(reference);
  fetch.mockImplementation((url,o) => url.includes('/operations/') ? Promise.resolve(response({ ok: true, status: 'declined',
    requestId: reference.requestId, threadId: 5, terminalNoSend: true })) : base(url,o));
  await act(async () => { await current.recover(); }); expect(current.pending).toBeNull();
});
test('remounted no-send recovery supplies the original thread without resending', async () => {
  await mount();
  const base = fetch.getMockImplementation();
  fetch.mockImplementation((url, options) => options?.method === 'POST'
    ? Promise.reject(Error('response lost')) : base(url, options));
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('response lost'); });
  const reference = current.pending;
  await act(async () => root.unmount()); root = createRoot(node); await mount();
  expect(current.pending).toEqual(reference);
  fetch.mockImplementation((url, options) => url.endsWith(`/autoReply/${reference.requestId}`)
    ? Promise.resolve(response({ ok: true, status: 'declined', requestId: reference.requestId,
      threadId: 5, terminalNoSend: true })) : base(url, options));
  let recovered;
  await act(async () => { recovered = await current.recover(); });
  expect(await recovered.json()).toMatchObject({ requestId: reference.requestId, threadId: 5, terminalNoSend: true });
  expect(current.pending).toBeNull();
  expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
});
test('authoritative pre-execution rejection clears only its exact pending auto-reply', async () => {
  await mount();
  const base = fetch.getMockImplementation();
  fetch.mockImplementation((url, options) => options?.method === 'POST'
    ? Promise.reject(Error('response lost')) : base(url, options));
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('response lost'); });
  const reference = current.pending;
  fetch.mockImplementation((url, options) => url.endsWith(`/autoReply/${reference.requestId}`)
    ? Promise.resolve(response({ ok: true, status: 'rejected_before_execution', requestId: reference.requestId, terminalRejected: true }))
    : base(url, options));
  await act(async () => { await current.recover(); });
  expect(current.pending).toBeNull();
  expect(JSON.stringify([...mockStore.values()])).not.toContain(reference.requestId);
});

test('server-attested keep-unresolved retains opaque history and blocks only the old thread', async () => {
  await mount();
  const base = fetch.getMockImplementation();
  let status = 'unconfirmed';
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/auto-reply/5') && options?.method === 'POST') return Promise.reject(Error('response lost'));
    if (url.includes('/keep-unresolved')) {
      const requestId = url.split('/').at(-2);
      expect(options.method).toBe('POST');
      expect(JSON.parse(options.body)).toEqual({ threadId: 5 });
      return Promise.resolve(response({ ok: true, status: 'kept_unresolved', requestId, threadId: 5 }));
    }
    if (url.includes('/operations/autoReply/')) return Promise.resolve(response({ ok: true, status, requestId: url.split('/').at(-1) }));
    if (url.endsWith('/auto-reply/6') && options?.method === 'POST') return Promise.reject(Error('new response lost'));
    return base(url, options);
  });
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('response lost'); });
  const original = current.pending;
  await act(async () => { await current.recover(); });
  expect(current.pending).toEqual(original);
  await act(async () => { await current.keepUnresolved(5); });
  expect(current.pending).toBeNull();
  expect(current.unresolved).toEqual([{ ...original, threadId: 5 }]);
  expect(JSON.stringify([...mockStore.values()])).not.toContain('body_markdown');
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('unresolved auto-reply'); });
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/auto-reply/5') && !url.includes('/operations/'))).toHaveLength(1);
  status = 'saved';
  let late;
  await act(async () => { late = await current.checkUnresolved(current.unresolved[0]); });
  expect((await late.json()).status).toBe('saved');
  expect(current.unresolved).toHaveLength(1);
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 6)).rejects.toThrow('new response lost'); });
  expect(current.pending.requestId).not.toBe(original.requestId);
  expect(current.unresolved).toHaveLength(1);
});

test('denied keep-unresolved receipt never clears pending or starts another auto-reply', async () => {
  await mount();
  const base = fetch.getMockImplementation();
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/auto-reply/5') && options?.method === 'POST') return Promise.reject(Error('response lost'));
    if (url.includes('/keep-unresolved')) return Promise.resolve(response({ ok: false, error: 'Wrong original thread' }, false));
    return base(url, options);
  });
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('response lost'); });
  const reference = current.pending;
  await act(async () => { await expect(current.keepUnresolved(6)).rejects.toThrow('Wrong original thread'); });
  expect(current.pending).toEqual(reference);
  expect(current.unresolved).toEqual([]);
  expect(JSON.parse(mockStore.get('secureshop.mail.operations.v1')).scopes[scope].pending).toEqual(reference);
});
test('late keep-unresolved receipt cannot clear a newer pending request in the same scope', async () => {
  await mount();
  const base = fetch.getMockImplementation();
  let completeKeep;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/auto-reply/5') && options?.method === 'POST') return Promise.reject(Error('response lost'));
    if (url.includes('/keep-unresolved')) return new Promise(resolve => { completeKeep = resolve; });
    return base(url, options);
  });
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('response lost'); });
  const original = current.pending;
  let pendingKeep;
  await act(async () => { pendingKeep = current.keepUnresolved(5); await Promise.resolve(); });
  expect(completeKeep).toBeDefined();
  const newer = { action: 'send', requestId: '22222222-2222-4222-8222-222222222222', digest: 'c'.repeat(64) };
  const stored = JSON.parse(mockStore.get('secureshop.mail.operations.v1'));
  stored.scopes[scope].pending = newer;
  mockStore.set('secureshop.mail.operations.v1', JSON.stringify(stored));
  await act(async () => {
    completeKeep(response({ ok: true, status: 'kept_unresolved', requestId: original.requestId, threadId: 5 }));
    await expect(pendingKeep).rejects.toMatchObject({ name: 'AbortError' });
  });
  const final = JSON.parse(mockStore.get('secureshop.mail.operations.v1')).scopes[scope];
  expect(final.pending).toEqual(newer);
  expect(final.unresolved).toBeUndefined();
});
test('later terminal readback releases only the exact unresolved thread while retaining history', async () => {
  const old = { action: 'autoReply', requestId: '11111111-1111-4111-8111-111111111111', digest: 'b'.repeat(64), threadId: 5 };
  mockStore.set('secureshop.mail.operations.v1', JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: null, assessment: null, unresolved: [old] } } }));
  const base = fetch.getMockImplementation();
  fetch.mockImplementation((url, options) => {
    if (url.endsWith(`/autoReply/${old.requestId}`)) return Promise.resolve(response({ ok: true, status: 'saved', requestId: old.requestId, sent_email_id: 9 }));
    if (url.endsWith('/auto-reply/5') && options?.method === 'POST') return Promise.reject(Error('new response lost'));
    return base(url, options);
  });
  await mount();
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('unresolved auto-reply'); });
  await act(async () => { await current.checkUnresolved(old); });
  expect(current.unresolvedOutcomes[old.requestId]).toBe('saved');
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('new response lost'); });
  expect(current.pending.requestId).not.toBe(old.requestId);
  expect(current.unresolved).toEqual([old]);
});
test('bare historical declined never releases an unresolved thread', async () => {
  const old = { action: 'autoReply', requestId: '11111111-1111-4111-8111-111111111111', digest: 'b'.repeat(64), threadId: 5 };
  mockStore.set('secureshop.mail.operations.v1', JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: null, assessment: null, unresolved: [old] } } }));
  const base = fetch.getMockImplementation();
  let affirmative = false;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith(`/autoReply/${old.requestId}`)) return Promise.resolve(response({ ok: true, status: 'declined',
      requestId: old.requestId, threadId: 5, ...(affirmative ? { terminalNoSend: true } : {}) }));
    if (url.endsWith('/auto-reply/5') && options?.method === 'POST') return Promise.reject(Error('new response lost'));
    return base(url, options);
  });
  await mount();
  await act(async () => { await current.checkUnresolved(old); });
  expect(current.unresolvedOutcomes[old.requestId]).toBeUndefined();
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('unresolved auto-reply'); });
  affirmative = true;
  await act(async () => { await current.checkUnresolved(old); });
  expect(current.unresolvedOutcomes[old.requestId]).toBe('declined');
  await act(async () => { await expect(current.command('autoReply', {}, undefined, 5)).rejects.toThrow('new response lost'); });
});
test('retry needs explicit action and authoritative same-ID permission; never allocates another operation', async () => {
  await mount(); const base = fetch.getMockImplementation();
  fetch.mockImplementation((url,o) => o?.method === 'POST' ? Promise.reject(Error('lost')) : base(url,o));
  await act(async () => { await expect(current.command('send', payload)).rejects.toThrow('lost'); }); const requestId = current.pending.requestId;
  fetch.mockImplementation((url,o) => url.includes('/operations/') ? Promise.resolve(response({ ok: true, status: 'unconfirmed', canRetrySameId: true })) : o?.method === 'POST' ? Promise.resolve(response({ ok: true, email_id: 9 })) : base(url,o));
  await act(async () => { await current.command('send', payload); }); expect(fetch.mock.calls.filter(([,o]) => o?.method === 'POST')).toHaveLength(1);
  await act(async () => { await current.command('send', payload, undefined, undefined, true); });
  const posts = fetch.mock.calls.filter(([,o]) => o?.method === 'POST'); expect(posts).toHaveLength(2); expect(JSON.parse(posts[1][1].body).requestId).toBe(requestId); expect(current.pending).toBeNull();
});
test('saved reply retains opaque assessment IDs; response loss and disabled replay use the same request', async () => {
  await mount(); const base = fetch.getMockImplementation(); let assessmentCalls = 0;
  fetch.mockImplementation(async (url, options) => {
    if (url.includes('/auto-reply/')) return response({ ok: true, sent_email_id: 9, thread_id: 5, sendOperationId: "11111111-1111-4111-8111-111111111111" });
    if (url.endsWith('/reply-assessment')) { assessmentCalls++; if (assessmentCalls === 1) throw Error('Judge response lost'); return response({ ok: true, completed: false, status: 'disabled' }); }
    return base(url, options);
  });
  await act(async () => { await current.command('autoReply', {}, undefined, 5); });
  expect(current.pending).toBeNull(); const ref = current.assessment;
  expect(Object.keys(ref).sort()).toEqual(['replyOperationId','requestId','threadId']); expect(ref.requestId).not.toBe(ref.replyOperationId);
  await act(async () => { await expect(current.assess()).rejects.toThrow('lost'); });
  await act(async () => { await current.assess(); });
  const bodies = fetch.mock.calls.filter(([url]) => url.endsWith('/reply-assessment')).map(([,o]) => JSON.parse(o.body));
  expect(bodies).toEqual([ref, ref]); expect(current.assessment).toEqual(ref);
  expect(fetch.mock.calls.filter(([url]) => url.includes('/auto-reply/'))).toHaveLength(1);
});
test('assessment reference persistence failure never changes a confirmed reply into a failed save', async () => {
  await mount(); const base = fetch.getMockImplementation();
  fetch.mockImplementation(async (url,options) => {
    if (url.includes('/auto-reply/')) { mockFlush.mockRejectedValueOnce(Error('storage failed')); return response({ ok: true, sent_email_id: 9, thread_id: 5, sendOperationId: "11111111-1111-4111-8111-111111111111" }); }
    return base(url,options);
  });
  let saved;await act(async () => { saved = await current.command('autoReply', {}, undefined, 5); });
  expect((await saved.json()).sent_email_id).toBe(9);expect(current.pending.action).toBe('autoReply');
});
test('Judge retry persists a new stable request bound to canonical evaluation without repeating mail', async () => {
  await mount();const base=fetch.getMockImplementation(),evaluationId=crypto.randomUUID();let grading=0;
  fetch.mockImplementation(async(url,options)=>{
    if(url.includes('/auto-reply/'))return response({ok:true,sent_email_id:9,thread_id:5,sendOperationId:"11111111-1111-4111-8111-111111111111"});
    if(url.endsWith('/reply-assessment')){grading++;return response({ok:true,completed:false,judgment:{verdict:'unavailable',canRetry:grading===1,evaluationId}});}
    return base(url,options);
  });
  await act(async()=>{await current.command('autoReply',{},undefined,5);});const initial=current.assessment;
  await act(async()=>{await current.assess();});const retry=current.assessment;expect(retry.requestId).not.toBe(initial.requestId);expect(retry.replyOperationId).toBe(initial.replyOperationId);expect(retry.evaluationId).toBe(evaluationId);
  await act(async()=>{await current.assess();await current.assess();});const bodies=fetch.mock.calls.filter(([url])=>url.endsWith('/reply-assessment')).map(([,o])=>JSON.parse(o.body));expect(bodies).toEqual([initial,retry,retry]);expect(fetch.mock.calls.filter(([url])=>url.includes('/auto-reply/'))).toHaveLength(1);
});
test('manual save retains header IDs only; disabled header never dispatches Judge or enables reply',async()=>{
 await mount();const base=fetch.getMockImplementation();fetch.mockImplementation((url,o)=>url.endsWith('/send')?Promise.resolve(response({ok:true,email_id:8})):base(url,o));
 await act(async()=>{await current.command('send',payload);});const ref=current.headerAssessment;expect(Object.keys(ref).sort()).toEqual(['requestId','sendOperationId']);expect(ref.requestId).not.toBe(ref.sendOperationId);expect(current.assessment).toBeNull();expect(JSON.parse([...mockStore.values()][0]).version).toBe(3);
 let result;await act(async()=>{result=await current.assessHeader();});expect((await result.json()).status).toBe('disabled');expect(fetch.mock.calls.some(([u])=>u.endsWith('/header-assessment'))).toBe(false);expect([...mockStore.values()].join('')).not.toContain(payload.subject);
});
test('header grading lost response replays same IDs then canonical unavailable retry uses new stable request',async()=>{
 await mount();let grade=0;const evaluationId=crypto.randomUUID();fetch.mockImplementation(async(url,o)=>{
  if(url.endsWith('readiness'))return response({ready:true,scopeKey:scope,objectiveReadiness:{ss_mail_header_construction:true}});
  if(url.endsWith('/send'))return response({ok:true,email_id:8});
  if(url.endsWith('/header-assessment')){grade++;if(grade===1)throw Error('lost');return response({ok:true,completed:false,judgment:{verdict:'unavailable',canRetry:grade===2,evaluationId}});}
 });
 await act(async()=>{await current.command('send',payload);});const initial=current.headerAssessment;
 await act(async()=>{await expect(current.assessHeader()).rejects.toThrow('lost');});expect(current.headerAssessment).toEqual(initial);
 await act(async()=>{await current.assessHeader();});const retry=current.headerAssessment;expect(retry.sendOperationId).toBe(initial.sendOperationId);expect(retry.requestId).not.toBe(initial.requestId);expect(retry.evaluationId).toBe(evaluationId);
 await act(async()=>{await current.assessHeader();});expect(fetch.mock.calls.filter(([u])=>u.endsWith('/header-assessment')).map(([,o])=>JSON.parse(o.body))).toEqual([initial,initial,retry]);expect(fetch.mock.calls.filter(([u])=>u.endsWith('/send'))).toHaveLength(1);
});
test('header reference flush failure keeps confirmed send successful and pending recoverable',async()=>{
 await mount();const base=fetch.getMockImplementation();fetch.mockImplementation(async(url,o)=>{if(url.endsWith('/send')){mockFlush.mockRejectedValueOnce(Error('parent ack failed'));return response({ok:true,email_id:8});}return base(url,o);});
 let saved;await act(async()=>{saved=await current.command('send',payload);});expect((await saved.json()).email_id).toBe(8);expect(current.pending.action).toBe('send');
});
test('new scope never reuses old header reference and stale Judge response cannot persist retry',async()=>{
 await mount();let scopeKey=scope,resolve;const pending=new Promise(r=>{resolve=r;});fetch.mockImplementation(async(url,o)=>{
  if(url.endsWith('readiness'))return response({ready:true,scopeKey,objectiveReadiness:{ss_mail_header_construction:true}});
  if(url.endsWith('/send'))return response({ok:true,email_id:8});if(url.endsWith('/header-assessment'))return pending;
 });
 await act(async()=>{await current.command('send',payload);});let grading;await act(async()=>{grading=current.assessHeader();});scopeKey='b'.repeat(64);
 await act(async()=>{await expect(current.assessHeader()).rejects.toThrow('No saved headers');});
 await act(async()=>{resolve(response({ok:true,completed:true,judgment:{canRetry:true,evaluationId:crypto.randomUUID()}}));await expect(grading).rejects.toMatchObject({name:'AbortError'});});expect(current.headerAssessment).toBeNull();expect(JSON.parse([...mockStore.values()][0]).scopes[scope].headerAssessment.evaluationId).toBeUndefined();
});
test('paused reply grading rejects same-mounted replacement scope before publishing retry or result',async()=>{
 await mount();let scopeKey=scope,resolve;const paused=new Promise(r=>{resolve=r;});fetch.mockImplementation(async url=>{
  if(url.endsWith('readiness'))return response({ready:true,scopeKey});
  if(url.includes('/auto-reply/'))return response({ok:true,sent_email_id:9,thread_id:5,sendOperationId:"11111111-1111-4111-8111-111111111111"});
  if(url.endsWith('/reply-assessment'))return paused;
 });
 await act(async()=>{await current.command('autoReply',{},undefined,5);});const original=current.assessment;let grading;await act(async()=>{grading=current.assess();});scopeKey='b'.repeat(64);
 await act(async()=>{await expect(current.assess()).rejects.toThrow('No saved reply');});
 await act(async()=>{resolve(response({ok:true,completed:true,judgment:{canRetry:true,evaluationId:crypto.randomUUID()}}));await expect(grading).rejects.toMatchObject({name:'AbortError'});});
 expect(current.assessment).toBeNull();expect(JSON.parse([...mockStore.values()][0]).scopes[scope].assessment).toEqual(original);
});
test('paused header grading cannot replace newer same-scope saved-send reference or return its old success',async()=>{
 await mount();let resolve;const paused=new Promise(r=>{resolve=r;});fetch.mockImplementation(async url=>{
  if(url.endsWith('readiness'))return response({ready:true,scopeKey:scope,objectiveReadiness:{ss_mail_header_construction:true}});
  if(url.endsWith('/send'))return response({ok:true,email_id:8});if(url.endsWith('/header-assessment'))return paused;
 });
 await act(async()=>{await current.command('send',payload);});const old=current.headerAssessment;let grading;await act(async()=>{grading=current.assessHeader();});
 await act(async()=>{await current.command('send',{...payload,subject:'new saved message'});});const newer=current.headerAssessment;expect(newer.sendOperationId).not.toBe(old.sendOperationId);
 await act(async()=>{resolve(response({ok:true,completed:true,judgment:{canRetry:true,evaluationId:crypto.randomUUID()}}));await expect(grading).rejects.toMatchObject({name:'AbortError'});});expect(current.headerAssessment).toEqual(newer);expect(JSON.parse([...mockStore.values()][0]).scopes[scope].headerAssessment).toEqual(newer);
});

test('saved actor reply persists both assessment refs and missing ID retains GET recovery',async()=>{
 await mount();const base=fetch.getMockImplementation();
 fetch.mockImplementation((url,o)=>url.includes('/auto-reply/')?Promise.resolve(response({ok:true,sent_email_id:9,thread_id:5})):base(url,o));
 await act(async()=>{await current.command('autoReply',{},undefined,5);});expect(current.pending).not.toBeNull();expect(current.headerAssessment).toBeNull();
 fetch.mockImplementation((url,o)=>url.includes('/operations/')?Promise.resolve(response({ok:true,sent_email_id:9,thread_id:5,sendOperationId:'11111111-1111-4111-8111-111111111111'})):base(url,o));
 await act(async()=>{await current.recover();});expect(current.pending).toBeNull();expect(current.assessment.threadId).toBe(5);expect(current.headerAssessment.sendOperationId).toBe('11111111-1111-4111-8111-111111111111');
 expect(fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(1);
});
test('header reference acknowledgement failure retains actor reply for read-only recovery',async()=>{
 await mount();const base=fetch.getMockImplementation();
 fetch.mockImplementation((url,o)=>{if(url.includes('/auto-reply/')){mockFlush.mockResolvedValueOnce().mockRejectedValueOnce(Error('header ack lost'));return Promise.resolve(response({ok:true,sent_email_id:9,thread_id:5,sendOperationId:'11111111-1111-4111-8111-111111111111'}));}return base(url,o);});
 await act(async()=>{await current.command('autoReply',{},undefined,5);});expect(current.pending.action).toBe('autoReply');expect(current.assessment.threadId).toBe(5);
 fetch.mockImplementation((url,o)=>url.includes('/operations/')?Promise.resolve(response({ok:true,sent_email_id:9,thread_id:5,sendOperationId:'11111111-1111-4111-8111-111111111111'})):base(url,o));
 await act(async()=>{await current.recover();});expect(current.pending).toBeNull();expect(current.headerAssessment.sendOperationId).toBe('11111111-1111-4111-8111-111111111111');
 expect(fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(1);
});
test.each([1,2])('old actor finish cannot overwrite a newer request after acknowledgement %i',async pausedAck=>{
 await mount();const base=fetch.getMockImplementation();let release,entered;const waiting=new Promise(r=>entered=r);let acknowledgements=0;
 fetch.mockImplementation((url,o)=>{if(url.includes('/auto-reply/')){mockFlush.mockImplementation(()=>{acknowledgements++;if(acknowledgements===pausedAck){entered();return new Promise(r=>release=r);}return Promise.resolve();});return Promise.resolve(response({ok:true,sent_email_id:9,thread_id:5,sendOperationId:'11111111-1111-4111-8111-111111111111'}));}return base(url,o);});
 let old;await act(async()=>{old=current.command('autoReply',{},undefined,5);await waiting;});
 // Another mounted hook completed the same recovery and began a new request.
 const key='secureshop.mail.operations.v1',state=JSON.parse(mockStore.get(key));const newer={action:'send',requestId:'22222222-2222-4222-8222-222222222222',digest:'b'.repeat(64)};state.scopes[scope].pending=newer;state.scopes[scope].headerAssessment={requestId:'33333333-3333-4333-8333-333333333333',sendOperationId:'44444444-4444-4444-8444-444444444444'};mockStore.set(key,JSON.stringify(state));
 await act(async()=>{window.dispatchEvent(new CustomEvent('secureshop-mail-pending',{detail:scope}));release();await old;});
 expect(JSON.parse(mockStore.get(key)).scopes[scope].pending).toEqual(newer);expect(current.pending.requestId).toBe(newer.requestId);expect(current.headerAssessment.sendOperationId).toBe('44444444-4444-4444-8444-444444444444');
});

test('unavailable model capability does not block saved request GET recovery',async()=>{
 await mount();await act(async()=>{await current.command('send',payload);});const pending=current.pending;
 fetch.mockImplementation(async url=>url.endsWith('readiness')?response({ready:true,scopeKey:scope,modelCapabilities:{actor:{status:'unavailable',canAttempt:false},judge:{status:'unavailable',canAttempt:false}}}):response({ok:true,status:'saved',requestId:pending.requestId,email_id:12,thread_id:12}));
 await act(async()=>{await current.recover();});expect(current.pending).toBeNull();expect(current.modelCapabilities.judge.status).toBe('unavailable');expect(fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(1);
});
test('stale readiness cannot replace new scope capabilities and failed current readiness clears status',async()=>{
 await mount();let release;fetch.mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));let stale;await act(async()=>{stale=current.command('send',payload).catch(e=>e);});
 fetch.mockImplementation(async url=>url.endsWith('readiness')?response({ready:true,scopeKey:'b'.repeat(64),modelCapabilities:{judge:{status:'configured_unprobed',canAttempt:true}}}):response({ok:true,status:'unconfirmed'}));
 await act(async()=>{await current.command('send',payload);});await act(async()=>{release(response({ready:true,scopeKey:scope,modelCapabilities:{judge:{status:'available'}}}));await stale;});expect(current.scopeKey).toBe('b'.repeat(64));expect(current.modelCapabilities.judge.status).toBe('configured_unprobed');
 fetch.mockImplementation(async()=>response({ready:false},false));await act(async()=>{await expect(current.recover()).rejects.toThrow('unavailable');});expect(current.modelCapabilities).toBeNull();
});

test('explicit disclosure preserves read ID after loss and distinct assessment ID; reload never assesses', async()=>{
  await mount(); const base=fetch.getMockImplementation(); let lost=true;
  fetch.mockImplementation(async(url,o)=>{
    if(url.endsWith('/disclosure')){if(lost){lost=false;throw Error('lost');}const b=JSON.parse(o.body);return response({ok:true,operationId:b.requestId,receipt:{userId:b.userId},emails:[]});}
    if(url.endsWith('/disclosure-assessment'))return response({ok:true,completed:false});
    return base(url,o);
  });
  await act(async()=>{await expect(current.disclose(99)).rejects.toThrow('lost');});
  const saved=current.disclosureAssessment;expect(saved.requestId).not.toBe(saved.readOperationId);
  await act(async()=>{await current.disclose(99);await current.assessDisclosure();await current.read(99);});
  const posts=fetch.mock.calls.filter(([,o])=>o?.method==='POST');
  expect(JSON.parse(posts[0][1].body)).toEqual(JSON.parse(posts[1][1].body));
  expect(JSON.parse(posts[2][1].body)).toEqual({requestId:saved.requestId,readOperationId:saved.readOperationId});
  expect(posts).toHaveLength(3);expect([...mockStore.values()].join('')).not.toContain('emails');
});

test('disclosure scope change prevents old assessment and stale read publication',async()=>{
  await mount();const base=fetch.getMockImplementation();let resolve;
  fetch.mockImplementation((url,o)=>url.endsWith('/disclosure')?new Promise(r=>{resolve=r;}):base(url,o));
  let work;await act(async()=>{work=current.disclose(99);await Promise.resolve();});
  const saved=current.disclosureAssessment;
  fetch.mockImplementation(async url=>url.endsWith('/readiness')?response({ready:true,scopeKey:'b'.repeat(64)}):response({ok:true}));
  await act(async()=>{await expect(current.assessDisclosure()).rejects.toThrow();});
  await act(async()=>{resolve(response({ok:true,operationId:saved.readOperationId,receipt:{userId:99},emails:[]}));await expect(work).rejects.toMatchObject({name:'AbortError'});});
});

test('unconfirmed read cannot be assessed; confirmed explicit new read creates a new snapshot identity',async()=>{
  await mount();const base=fetch.getMockImplementation();fetch.mockImplementation((url,o)=>url.endsWith('/disclosure')?Promise.reject(Error('lost')):base(url,o));
  await act(async()=>{await expect(current.disclose(99)).rejects.toThrow('lost');await expect(current.assessDisclosure()).rejects.toThrow();});
  expect(current.disclosureAssessment.confirmed).toBe(false);const original=current.disclosureAssessment.readOperationId;
  fetch.mockImplementation((url,o)=>{if(url.endsWith('/disclosure')){const b=JSON.parse(o.body);return Promise.resolve(response({ok:true,operationId:b.requestId,receipt:{userId:b.userId},emails:[]}));}return base(url,o);});
  await act(async()=>{await current.disclose(99);});expect(current.disclosureAssessment.readOperationId).toBe(original);expect(current.disclosureAssessment.confirmed).toBe(true);
  await act(async()=>{await current.disclose(99);});expect(current.disclosureAssessment.readOperationId).not.toBe(original);
});
test('assessment response loss retries same assessment ID and abort after storage prevents disclosure POST',async()=>{
 await mount();const base=fetch.getMockImplementation();fetch.mockImplementation(async(url,o)=>{if(url.endsWith('/disclosure')){const b=JSON.parse(o.body);return response({ok:true,operationId:b.requestId,receipt:{userId:b.userId},emails:[]});}if(url.endsWith('/disclosure-assessment'))throw Error('lost assessment');return base(url,o);});
 await act(async()=>{await current.disclose(99);await expect(current.assessDisclosure()).rejects.toThrow('lost assessment');await expect(current.assessDisclosure()).rejects.toThrow('lost assessment');});
 const posts=fetch.mock.calls.filter(([url])=>url.endsWith('/disclosure-assessment'));expect(posts[0][1].body).toBe(posts[1][1].body);
 const controller=new AbortController();mockFlush.mockImplementationOnce(async()=>{controller.abort();});const count=fetch.mock.calls.length;
 await act(async()=>{await expect(current.disclose(88,controller.signal)).rejects.toMatchObject({name:'AbortError'});});expect(fetch.mock.calls.slice(count).filter(([,o])=>o?.method==='POST')).toHaveLength(0);
});
test('rejected confirmation acknowledgment preserves read identity until acknowledged recovery',async()=>{
 await mount();const base=fetch.getMockImplementation();fetch.mockImplementation(async(url,o)=>{if(url.endsWith('/disclosure')){const b=JSON.parse(o.body);return response({ok:true,operationId:b.requestId,receipt:{userId:b.userId},emails:[]});}return base(url,o);});
 mockFlush.mockResolvedValueOnce().mockRejectedValueOnce(Error('confirmation ack lost'));
 await act(async()=>{await expect(current.disclose(99)).rejects.toThrow('confirmation ack lost');});
 const first=JSON.parse(fetch.mock.calls.find(([u])=>u.endsWith('/disclosure'))[1].body);expect(current.disclosureAssessment.confirmed).toBe(false);
 await act(async()=>{await expect(current.assessDisclosure()).rejects.toThrow();await current.disclose(99);});
 const reads=fetch.mock.calls.filter(([u])=>u.endsWith('/disclosure'));expect(JSON.parse(reads[1][1].body)).toEqual(first);expect(current.disclosureAssessment.confirmed).toBe(true);
});
test('unavailable readiness hides disclosure assessment and sends no read or assessment',async()=>{
 await mount();const base=fetch.getMockImplementation();fetch.mockImplementation(async(url,o)=>{if(url.endsWith('/disclosure')){const b=JSON.parse(o.body);return response({ok:true,operationId:b.requestId,receipt:{userId:b.userId},emails:[]});}return base(url,o);});await act(async()=>{await current.disclose(99);});expect(current.disclosureAssessment.confirmed).toBe(true);
 fetch.mockImplementation(async()=>response({ready:false},false));const count=fetch.mock.calls.length;
 await act(async()=>{await expect(current.assessDisclosure()).rejects.toThrow('unavailable');});expect(current.disclosureAssessment).toBeNull();expect(fetch.mock.calls.slice(count).filter(([,o])=>o?.method==='POST')).toHaveLength(0);
});
test('pending confirmation acknowledgment cannot be advertised by storage-change events',async()=>{
 await mount();const base=fetch.getMockImplementation();fetch.mockImplementation(async(url,o)=>{if(url.endsWith('/disclosure')){const b=JSON.parse(o.body);return response({ok:true,operationId:b.requestId,receipt:{userId:b.userId},emails:[]});}return base(url,o);});
 let release;mockFlush.mockResolvedValueOnce().mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));let work;
 await act(async()=>{work=current.disclose(99);await Promise.resolve();await Promise.resolve();});
 await act(async()=>{window.dispatchEvent(new CustomEvent('secureshop-mail-pending',{detail:scope}));});expect(current.disclosureAssessment.confirmed).toBe(false);
 await act(async()=>{await expect(current.assessDisclosure()).rejects.toThrow();release();await work;});expect(current.disclosureAssessment.confirmed).toBe(true);
});

test('browser assessment stores identifiers only, gates dispatch and reuses exact request after response loss', async () => {
  await mount(); const base=fetch.getMockImplementation();
  fetch.mockImplementation((url,o)=>url.endsWith('/send')?Promise.resolve(response({ok:true,email_id:12})):base(url,o));
  await act(async()=>{await current.command('send',payload);});
  const reference=current.browserAssessment;
  expect(Object.keys(reference).sort()).toEqual(['messageId','requestId','sendOperationId']);
  expect(reference.messageId).toBe(12);expect(reference.requestId).not.toBe(reference.sendOperationId);
  await act(async()=>{expect(await (await current.assessBrowser()).json()).toMatchObject({status:'disabled'});});
  expect(fetch.mock.calls.some(([url])=>url.endsWith('/browser-assessment'))).toBe(false);
  fetch.mockImplementation((url,o)=>url.endsWith('readiness')?Promise.resolve(response({ready:true,scopeKey:scope,objectiveReadiness:{ss_mail_stored_browser_execution:true}})):url.endsWith('/browser-assessment')?Promise.reject(Error('lost')):base(url,o));
  for(let i=0;i<2;i++)await act(async()=>{await expect(current.assessBrowser()).rejects.toThrow('lost');});
  const calls=fetch.mock.calls.filter(([url])=>url.endsWith('/browser-assessment'));
  expect(calls).toHaveLength(2);expect(calls.map(([,o])=>JSON.parse(o.body))).toEqual([reference,reference]);
  expect([...mockStore.values()].join('')).not.toContain('private source');
});

test('browser canonical unavailable retry retains evaluation and saved message with a new assessment ID',async()=>{
 const evaluationId=crypto.randomUUID();
 fetch.mockImplementation(async(url,o)=>url.endsWith('readiness')?response({ready:true,scopeKey:scope,objectiveReadiness:{ss_mail_stored_browser_execution:true}}):url.endsWith('/send')?response({ok:true,email_id:17}):response({ok:true,completed:false,judgment:{verdict:'unavailable',canRetry:true,evaluationId}}));
 await mount();await act(async()=>{await current.command('send',payload);});const original=current.browserAssessment;
 await act(async()=>{await current.assessBrowser();});const retry=current.browserAssessment;
 expect(retry).toMatchObject({sendOperationId:original.sendOperationId,messageId:17,evaluationId});expect(retry.requestId).not.toBe(original.requestId);
 fetch.mockImplementation(async(url,o)=>url.endsWith('readiness')?response({ready:true,scopeKey:scope,objectiveReadiness:{ss_mail_stored_browser_execution:true}}):response({ok:true,completed:true}));
 await act(async()=>{await current.assessBrowser();});
  const posted=fetch.mock.calls.filter(([url])=>url.endsWith('/browser-assessment')).map(([,o])=>JSON.parse(o.body));expect(posted).toEqual([original,retry]);
});

test('server-owned teaching-message save persists only its opaque request and completes through saved GET',async()=>{
  await mount(); const base=fetch.getMockImplementation(); let requestId;
  const exactResponse=(body,status)=>({ok:status>=200&&status<300,status,json:async()=>body});
  fetch.mockImplementation((url,options={})=>{
    if(url.endsWith('readiness'))return Promise.resolve(response({ready:true,scopeKey:scope}));
    if(url.endsWith('/inline/teaching-message')&&options.method==='POST'){
      requestId=JSON.parse(options.body).requestId;
      return Promise.resolve(exactResponse({ok:true,status:'unconfirmed',requestId},202));
    }
    if(requestId&&url.endsWith(`/inline/teaching-message/${requestId}`))return Promise.resolve(exactResponse({
      ok:true,status:'saved',requestId,messageId:17,threadId:9,replayed:false,
    },200));
    return base(url,options);
  });
  let outcome;await act(async()=>{outcome=await current.saveTeachingMessage();});
  expect(outcome.value).toMatchObject({status:'saved',messageId:17,threadId:9,replayed:false});
  expect(current.inlineTeaching).toBeNull();
  const posted=fetch.mock.calls.filter(([url,options])=>url.endsWith('/inline/teaching-message')&&options?.method==='POST');
  expect(posted).toHaveLength(1);expect(JSON.parse(posted[0][1].body)).toEqual({requestId});
  expect([...mockStore.values()].join('')).not.toMatch(/messageId|threadId|issuance|nonce|url/i);
});
