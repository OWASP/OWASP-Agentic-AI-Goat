import React, { act } from 'react';
const { webcrypto } = require('node:crypto');
import { createRoot } from 'react-dom/client';
import MerchantListingCreateConfirmation from './MerchantListingCreateConfirmation.jsx';
import { attachShopStorage, SHOP_LISTING_CREATE_KEY } from '../utils/shopStorage.mjs';
import { listingCreateRequestDigest, listingCreateSourceDigest } from '../pages/merchant/listingCreateOperation.mjs';
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const scopeKey = 'a'.repeat(64), requestSha256 = 'b'.repeat(64);
const chatMode = { version: 1, featureId: 'merchant_assistant', effectiveMode: 'vuln', policyVersion: '1', scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
let proposal;
const makeProposal = async () => { const preview = { version: 1, listing: { name: 'Practice mug', description: null, category: null, price: 12.5 }, currency: 'USD', initialStock: 0, status: 'active', scopeKey }; preview.requestSha256 = await listingCreateRequestDigest(preview); return { version: 1, proposalId, preview }; };
const json = value => ({ ok: true, status: 200, json: async () => value });
let root, node, values, release;
const render = (transport, authorityKey = 'merchant', sourceProposal = proposal) => act(async () => root.render(
 <MerchantListingCreateConfirmation proposal={sourceProposal} sessionId={sourceProposal ? sessionId : null}
   requestId={sourceProposal ? requestId : null} authorityKey={authorityKey} transport={transport} />));
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
const waitFor = async assertion => {
 for (let attempt = 0; attempt < 50; attempt += 1) {
  try { assertion(); return; } catch (error) { if (attempt === 49) throw error; await settle(); }
 }
};
beforeEach(async () => { Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true }); globalThis.IS_REACT_ACT_ENVIRONMENT = true; proposal = await makeProposal(); node = document.createElement('div'); document.body.append(node); root = createRoot(node); values = new Map(); release = attachShopStorage({ getItem:key=>values.get(key)??null, setItem:(key,value)=>values.set(key,value), removeItem:key=>values.delete(key), flush:async()=>{} }); });
afterEach(async () => { await act(async () => root.unmount()); release(); node.remove(); });
const source = () => json({ sessionId, requestId, status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: chatMode, listingCreateProposal: proposal });
const receipt = () => ({ version:1, operationId:proposalId, status:'completed', productId:7, scopeKey, requestSha256: proposal.preview.requestSha256, sourceSha256:'c'.repeat(64), receiptSha256:'d'.repeat(64), replayed:false });
const htmlProposal = async (mode = 'fixed') => { const source = { version: 1, kind: 'merchant_authored_html',
  listing: { name: 'Rendered mug', description: '<img src="x" onerror="alert(1)">', category: 'home', price: 12.5, presentation: 'html' },
  authoredHtml: '<img src="x" onerror="alert(1)">', storedHtml: mode === 'vuln' ? '<img src="x" onerror="alert(1)">' : '&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;',
  preparation: { sessionId, requestId, step: 1, callId: 'listing-create-v2', message: 'Create <img src="x" onerror="alert(1)">.' },
  execution: { version: 1, featureId: 'listings', policyVersion: 'owned-listing-import-v1', mode, generation: 3, modeStamp: 'mode-3',
    scope: { launchId: '11111111-1111-4111-8111-111111111111', scenarioId: '22222222-2222-4222-8222-222222222222', generation: 3, platformOwnerId: 11, platformSessionId: 12 } } };
 const preview = { version: 2, listing: source.listing, currency: 'USD', initialStock: 0, status: 'active', scopeKey, source };
 preview.requestSha256 = await listingCreateRequestDigest(preview); return { version: 1, proposalId, preview }; };

test('shows a human-readable zero-stock draft and resolves a lost POST only through exact GET', async () => {
 let posts=0, completed=false;
 const transport=jest.fn(async (url, options={})=>{
  if(url.includes(`/assistant/operations/${sessionId}/${requestId}`)) return source();
  if(url.endsWith(`/listing-create/operations/${proposalId}`)) return json(completed?receipt():{operationId:proposalId,status:'not_found',scopeKey});
  if(url.endsWith('/listing-create/confirm')) { posts++; expect(JSON.parse(options.body)).toEqual({sessionId,requestId,proposalId}); completed=true; throw Error('lost'); }
  throw Error(`Unexpected ${url}`);
 });
 const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
 let releaseDigest;
 const digestGate = new Promise(resolve => { releaseDigest = resolve; });
 try {
  Object.defineProperty(globalThis, 'crypto', { value: { subtle: { digest: async (...args) => {
   await digestGate; return webcrypto.subtle.digest(...args);
  } } }, configurable: true });
  await render(transport); await settle(); expect(node.textContent).toContain('Practice mug'); expect(node.textContent).toContain('Initial stock: 0'); expect(node.textContent).toContain('Not provided');
  await act(async()=>node.querySelector('button').click());
  expect(posts).toBe(0);
  releaseDigest();
  await waitFor(() => expect(posts).toBe(1));
  await waitFor(() => expect(node.textContent).toContain('Listing created from the saved result.'));
  expect(values.has(SHOP_LISTING_CREATE_KEY)).toBe(false);
  expect(transport.mock.calls.map(([url, options]) => ({ url, method: options.method }))).toEqual([
   { url: `/api/secureshop/agents/merchant/assistant/operations/${sessionId}/${requestId}`, method: 'GET' },
   { url: `/api/secureshop/agents/merchant/assistant/listing-create/operations/${proposalId}`, method: 'GET' },
   { url: '/api/secureshop/agents/merchant/assistant/listing-create/confirm', method: 'POST' },
   { url: `/api/secureshop/agents/merchant/assistant/listing-create/operations/${proposalId}`, method: 'GET' },
  ]);
 } finally {
  releaseDigest();
  if (cryptoDescriptor) Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
  else delete globalThis.crypto;
 }
});

test('retains a parent-acknowledged ref when post-confirm GET remains absent and never repeats POST', async () => {
 let posts=0; const transport=jest.fn(async (url, options={})=>{
  if(url.includes(`/assistant/operations/${sessionId}/${requestId}`)) return source();
  if(url.endsWith(`/listing-create/operations/${proposalId}`)) return json({operationId:proposalId,status:'not_found',scopeKey});
  if(url.endsWith('/listing-create/confirm')) { posts++; return {ok:false,status:503,json:async()=>({})}; }
  throw Error(`Unexpected ${url}`);
 });
 await render(transport); await settle(); await act(async()=>node.querySelector('button').click()); await settle();
 expect(posts).toBe(1); expect(values.has(SHOP_LISTING_CREATE_KEY)).toBe(true); expect(node.textContent).toContain('confirmation will not be retried');
 await act(async()=>node.querySelector('button').click()); await settle(); expect(posts).toBe(1);
});


test('renders v2 HTML source and stored presentation as escaped text without creating markup', async () => {
 proposal = await htmlProposal(); await render(jest.fn()); await settle();
 expect(node.textContent).toContain('Presentation: HTML · Execution mode: fixed');
 expect(node.querySelector('[aria-label="Authored HTML source"]').textContent).toBe('<img src="x" onerror="alert(1)">');
 expect(node.querySelector('[aria-label="Stored listing presentation"]').textContent).toBe('&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;');
 expect(node.querySelector('img')).toBeNull();
});


test('automatically assesses only a confirmed raw v2 receipt and reload recovery only reads saved status', async () => {
 proposal = await htmlProposal('vuln'); let completed = false, creates = 0, assessments = 0;
 const calls = [];
 const rawReceipt = async () => ({ version: 2, operationId: proposalId, status: 'completed', productId: 7, scopeKey,
   requestSha256: proposal.preview.requestSha256, sourceSha256: 'c'.repeat(64), receiptSha256: 'd'.repeat(64), replayed: false,
   source: proposal.preview.source, sourceDocumentSha256: await listingCreateSourceDigest(proposal.preview.source) });
 const transport = jest.fn(async (url, options = {}) => {
   calls.push({ url, method: options.method || 'GET' });
   if (url.includes(`/assistant/operations/${sessionId}/${requestId}`)) return source();
   if (url.endsWith(`/listing-create/operations/${proposalId}`)) return json(completed ? await rawReceipt() : { operationId: proposalId, status: 'not_found', scopeKey });
   if (url.endsWith('/listing-create/confirm')) { creates++; completed = true; return json(await rawReceipt()); }
   if (url.endsWith('/listing-create/assess')) { assessments++; expect(JSON.parse(options.body)).toEqual({ operationId: proposalId }); return json({ operationId: proposalId, completed: false, judgment: { verdict: 'unavailable', evaluationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', canRetry: true }, replayed: false }); }
   if (url.endsWith(`/listing-create/assessment/${proposalId}`)) return json({ operationId: proposalId, completed: false, judgment: { verdict: 'unavailable', evaluationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', canRetry: true }, replayed: true });
   throw Error(`Unexpected ${url}`);
 });
 await render(transport); await settle(); await act(async () => node.querySelector('button').click()); await settle();
 await waitFor(() => expect(assessments).toBe(1));
 expect(creates).toBe(1); expect(transport.mock.calls.map(([url]) => url)).toContain('/api/secureshop/agents/merchant/assistant/listing-create/assess'); expect(values.has(SHOP_LISTING_CREATE_KEY)).toBe(true);
 expect(node.textContent).toContain('Judge unavailable');
 const beforeRemount = calls.length;
 await act(async () => root.render(null)); await render(transport); await waitFor(() => expect(calls.length).toBe(beforeRemount + 1));
 expect(calls.slice(beforeRemount)).toEqual([{ url: `/api/secureshop/agents/merchant/assistant/listing-create/assessment/${proposalId}`, method: 'GET' }]);
 await act(async () => node.querySelector('button').click()); await settle();
 await waitFor(() => expect(calls.length).toBe(beforeRemount + 3));
 expect(calls.slice(beforeRemount + 1)).toEqual([
  { url: `/api/secureshop/agents/merchant/assistant/listing-create/operations/${proposalId}`, method: 'GET' },
  { url: `/api/secureshop/agents/merchant/assistant/listing-create/assessment/${proposalId}`, method: 'GET' },
 ]);
 expect(creates).toBe(1); expect(assessments).toBe(1);
});

test('ignores a deferred prior assessment after authority rotation', async () => {
 proposal = await htmlProposal('vuln');
 values.set(SHOP_LISTING_CREATE_KEY, JSON.stringify({ version: 1, scopeKey, operationId: proposalId,
  requestSha256: proposal.preview.requestSha256 }));
 let resolvePrior; let assessmentReads = 0;
 const transport = jest.fn((url, options = {}) => {
  if (!url.endsWith(`/listing-create/assessment/${proposalId}`)) throw Error(`Unexpected ${url}`);
  assessmentReads += 1;
  if (assessmentReads === 1) return new Promise(resolve => { resolvePrior = resolve; });
  return Promise.resolve(json({ operationId: proposalId, completed: false, status: 'unconfirmed', modelEvaluated: false }));
 });
 await render(transport, 'original'); await waitFor(() => expect(assessmentReads).toBe(1));
 await render(transport, 'rotated'); await waitFor(() => expect(assessmentReads).toBe(2));
 await waitFor(() => expect(node.textContent).toContain('Assessment is not confirmed yet'));
 await act(async () => resolvePrior(json({ operationId: proposalId, completed: true,
  judgment: { verdict: 'pass', evaluationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', canRetry: false }, replayed: false })));
 await settle();
 expect(node.textContent).toContain('Assessment is not confirmed yet');
 expect(node.textContent).not.toContain('Objective completed.');
});

test('late source hydration preserves a saved listing GET and cannot repeat create POST', async () => {
 values.set(SHOP_LISTING_CREATE_KEY, JSON.stringify({ version:1, scopeKey,
   operationId:proposalId, requestSha256:proposal.preview.requestSha256 }));
 let finishRead, savedSignal;
 const transport=jest.fn((url, options={})=>{
   if(url.endsWith(`/listing-create/assessment/${proposalId}`)) return Promise.resolve(json({
     operationId:proposalId, completed:false, status:'unconfirmed', modelEvaluated:false }));
   if(url.endsWith(`/listing-create/operations/${proposalId}`)) {
     savedSignal=options.signal;
     return new Promise(resolve=>{ finishRead=resolve; });
   }
   throw Error(`Unexpected ${url}`);
 });
 await render(transport, 'merchant', null); await settle();
 await act(async()=>node.querySelector('button').click());
 expect(finishRead).toBeDefined();
 await render(transport, 'merchant', proposal);
 expect(savedSignal.aborted).toBe(false);
 await act(async()=>finishRead(json(receipt())));
 expect(node.textContent).toContain('Listing created from the saved result.');
 expect(values.has(SHOP_LISTING_CREATE_KEY)).toBe(false);
 expect(transport.mock.calls.some(([url])=>url.endsWith('/listing-create/confirm'))).toBe(false);
});

test('a different draft fences an uncommitted create preflight', async () => {
 let finishSource;
 const transport=jest.fn(url=>{
   if(url.includes(`/assistant/operations/${sessionId}/${requestId}`))
     return new Promise(resolve=>{ finishSource=resolve; });
   throw Error(`Unexpected ${url}`);
 });
 await render(transport); await settle();
 await act(async()=>node.querySelector('button').click());
 const replacement={...proposal,proposalId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'};
 await render(transport,'merchant',replacement);
 await act(async()=>finishSource(source()));
 expect(values.has(SHOP_LISTING_CREATE_KEY)).toBe(false);
 expect(transport.mock.calls.some(([url])=>url.endsWith('/listing-create/confirm'))).toBe(false);
 expect(node.querySelector('button').disabled).toBe(false);
});

test('a new listing draft remains creatable after the prior completed receipt clears', async () => {
 const secondId='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
 const completed=new Set(), posts=[];
 const transport=jest.fn(async (url,options={})=>{
   if(url.includes(`/assistant/operations/${sessionId}/${requestId}`)) return source();
   const operationId=url.split('/listing-create/operations/')[1];
   if(operationId) return json(completed.has(operationId)
     ? {...receipt(),operationId} : {operationId,status:'not_found',scopeKey});
   if(url.endsWith('/listing-create/confirm')) {
     const body=JSON.parse(options.body); posts.push(body.proposalId);
     completed.add(body.proposalId); return json({});
   }
   throw Error(`Unexpected ${url}`);
 });
 await render(transport); await settle();
 await act(async()=>node.querySelector('button').click()); await settle();
 expect(posts).toEqual([proposalId]);
 proposal={...proposal,proposalId:secondId};
 await render(transport); await settle();
 expect(node.querySelector('button').textContent).toBe('Create listing');
 expect(node.querySelector('button').disabled).toBe(false);
 await act(async()=>node.querySelector('button').click()); await settle();
 expect(posts).toEqual([proposalId,secondId]);
});

test('authority rotation aborts a saved create operation GET and ignores its late result', async () => {
 values.set(SHOP_LISTING_CREATE_KEY, JSON.stringify({version:1,scopeKey,
   operationId:proposalId,requestSha256:proposal.preview.requestSha256}));
 let finishRead,savedSignal;
 const transport=jest.fn((url,options={})=>{
   if(url.endsWith(`/listing-create/assessment/${proposalId}`)) return Promise.resolve(json({
     operationId:proposalId,completed:false,status:'unconfirmed',modelEvaluated:false}));
   if(url.endsWith(`/listing-create/operations/${proposalId}`)) {
     savedSignal=options.signal; return new Promise(resolve=>{finishRead=resolve;});
   }
   throw Error(`Unexpected ${url}`);
 });
 await render(transport,'original',null); await settle();
 await act(async()=>node.querySelector('button').click());
 expect(finishRead).toBeDefined();
 await render(transport,'rotated',null);
 expect(savedSignal.aborted).toBe(true);
 await act(async()=>finishRead(json(receipt())));
 expect(values.has(SHOP_LISTING_CREATE_KEY)).toBe(true);
 expect([...node.querySelectorAll('p[role="status"]')]
   .some(item=>item.textContent==='Listing created from the saved result.')).toBe(false);
});
