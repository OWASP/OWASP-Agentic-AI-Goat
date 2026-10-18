import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MerchantMailConfirmation from './MerchantMailConfirmation.jsx';
import { SHOP_MAIL_KEY } from '../utils/shopStorage.mjs';
import { merchantMailProposalDigest } from '../utils/merchantMailAction.mjs';

const scope = 'a'.repeat(64);
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-5ccc-accc-cccccccccccc';
const proposal = { version: 1, kind: 'merchant_mail_proposal', action: 'send', proposalId,
  recipient: { username: 'Named customer', email: 'named@example.test' },
  subject: '<img src=x onerror=alert(1)>', body_markdown: '<script>source()</script>', source: null };
const modeCapability = { version: 1, featureId: 'merchant_assistant',
  policyVersion: 'owned-merchant-read-and-confirmation-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
const source = { sessionId, requestId, status: 'completed', replayed: true,
  stopReason: 'end_turn', modeCapability, mailProposal: proposal };
const saved = { version: 1, kind: 'merchant_mail_operation', action: 'send', proposalId,
  status: 'saved', sendOperationId: proposalId, emailId: 31, threadId: 32,
  savedSend: { recipientId: 33, to: proposal.recipient.email, subject: proposal.subject,
    body_markdown: proposal.body_markdown }, canRetrySameId: false };
const unconfirmed = { ...saved, status: 'unconfirmed', sendOperationId: null,
  emailId: null, threadId: null, savedSend: null, canRetrySameId: true };
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300,
  status, json: async () => body });
let node, root;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: require('node:crypto').webcrypto });
  localStorage.clear();
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); localStorage.clear(); });
const mount = async (props = {}) => act(async () => root.render(<MerchantMailConfirmation
  proposal={Object.hasOwn(props, 'proposal') ? props.proposal : proposal}
  sessionId={Object.hasOwn(props, 'sessionId') ? props.sessionId : sessionId}
  requestId={Object.hasOwn(props, 'requestId') ? props.requestId : requestId}
  authorityKey={props.authorityKey ?? 'current'} transport={globalThis.fetch} />));
const click = async label => act(async () => {
  const button = [...node.querySelectorAll('button')].find(item => item.textContent === label);
  expect(button).toBeDefined(); expect(button.disabled).toBe(false); button.click();
});
const settle = async () => act(async () => { await new Promise(resolve => setTimeout(resolve, 15)); });
const stored = () => localStorage.getItem(SHOP_MAIL_KEY);

test('failed mail readiness cancels its body and preserves the authority error', async () => {
  const cancel = jest.fn(async () => { throw Error('reader closed'); });
  globalThis.fetch = jest.fn(async url => {
    if (url.endsWith('/email/readiness')) return { ok: false, status: 503, body: { cancel } };
    throw Error(`Unexpected request: ${url}`);
  });
  await mount(); await settle();
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Mail authority is unavailable.');
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
});

test('pending recovery survives completed-page hydration while its exact GET is deferred', async () => {
  const reference = { action: 'send', requestId: proposalId,
    digest: await merchantMailProposalDigest(proposal), chatSource: { sessionId, requestId } };
  localStorage.setItem(SHOP_MAIL_KEY, JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: reference, assessment: null } } }));
  let release, signal;
  const deferred = new Promise(resolve => { release = resolve; });
  globalThis.fetch = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) { signal = init.signal; return deferred; }
    throw Error(`Unexpected request: ${url}`);
  });
  await mount({ proposal: null, sessionId: null, requestId: null });
  await click('Check saved mail operation'); await settle();
  expect(signal).toBeDefined();
  await mount();
  expect(signal.aborted).toBe(false);
  await act(async () => release(response(saved))); await settle();
  expect(node.querySelector('[aria-label="Saved merchant mail result"]')?.textContent)
    .toContain(proposal.body_markdown);
  expect(stored()).toBeNull();
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
});

test('late page hydration preserves a recovered result after pending cleanup, but an unrelated proposal does not reuse it', async () => {
  const reference = { action: 'send', requestId: proposalId,
    digest: await merchantMailProposalDigest(proposal), chatSource: { sessionId, requestId } };
  localStorage.setItem(SHOP_MAIL_KEY, JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: reference, assessment: null } } }));
  globalThis.fetch = jest.fn(async url => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) return response(saved);
    throw Error(`Unexpected request: ${url}`);
  });
  await mount({ proposal: null, sessionId: null, requestId: null });
  await click('Check saved mail operation'); await settle();
  expect(stored()).toBeNull();
  await mount();
  expect(node.querySelector('[aria-label="Saved merchant mail result"]')).not.toBeNull();
  const different = { ...proposal, proposalId: 'dddddddd-dddd-5ddd-addd-dddddddddddd' };
  await mount({ proposal: different });
  expect(node.querySelector('[aria-label="Saved merchant mail result"]')).toBeNull();
  expect(node.textContent).toContain('Send message');
  await click('Cancel proposal');
  expect(node.textContent).not.toContain('Review message to send');
  await mount();
  expect(node.textContent).toContain('Review message to send');
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
});

test.each(['authority', 'transport', 'reference'])('%s replacement fences a deferred pending GET', async change => {
  const reference = { action: 'send', requestId: proposalId,
    digest: await merchantMailProposalDigest(proposal), chatSource: { sessionId, requestId } };
  const store = pending => localStorage.setItem(SHOP_MAIL_KEY, JSON.stringify({ version: 3,
    scopes: { [scope]: { pending, assessment: null } } }));
  store(reference);
  let release, signal;
  const deferred = new Promise(resolve => { release = resolve; });
  const fetcher = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) { signal = init.signal; return deferred; }
    throw Error(`Unexpected request: ${url}`);
  });
  globalThis.fetch = fetcher;
  await mount({ proposal: null, sessionId: null, requestId: null });
  await click('Check saved mail operation'); await settle();
  expect(signal).toBeDefined();
  const foreign = { action: 'send', requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', digest: 'd'.repeat(64) };
  if (change === 'reference') store(foreign);
  else {
    if (change === 'transport') globalThis.fetch = jest.fn(async () => response({ ready: true, scopeKey: scope }));
    await mount({ proposal: null, sessionId: null, requestId: null,
      authorityKey: change === 'authority' ? 'changed' : 'current' });
    expect(signal.aborted).toBe(true);
  }
  await act(async () => release(response(saved))); await settle();
  expect(node.querySelector('[aria-label="Saved merchant mail result"]')).toBeNull();
  expect(JSON.parse(stored()).scopes[scope].pending).toEqual(change === 'reference' ? foreign : reference);
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
});

test('fresh confirmation is cancelled when its displayed proposal changes during source GET', async () => {
  let release, signal;
  const deferred = new Promise(resolve => { release = resolve; });
  globalThis.fetch = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) { signal = init.signal; return deferred; }
    throw Error(`Unexpected request: ${url}`);
  });
  await mount(); await click('Send message'); await settle();
  expect(signal).toBeDefined();
  await mount({ proposal: { ...proposal, proposalId: 'dddddddd-dddd-5ddd-addd-dddddddddddd' } });
  expect(signal.aborted).toBe(true);
  await act(async () => release(response(source))); await settle();
  expect(stored()).toBeNull();
  expect(fetch.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
});

test('authority change clears an already displayed saved outcome', async () => {
  let reads = 0;
  globalThis.fetch = jest.fn(async url => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) return response(++reads === 1 ? unconfirmed : saved, reads === 1 ? 202 : 200);
    if (url.endsWith('/mail/confirm')) return response(saved);
    throw Error(`Unexpected request: ${url}`);
  });
  await mount(); await click('Send message'); await settle();
  expect(node.querySelector('[aria-label="Saved merchant mail result"]')).not.toBeNull();
  await mount({ authorityKey: 'changed' });
  expect(node.querySelector('[aria-label="Saved merchant mail result"]')).toBeNull();
});

test('physical Send preserves escaped frozen subject/body and performs one source-bound confirmation', async () => {
  let reads = 0;
  globalThis.fetch = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) return response(++reads === 1 ? unconfirmed : saved,
      reads === 1 ? 202 : 200);
    if (url.endsWith('/mail/confirm') && init.method === 'POST') return response(saved);
    throw Error(`Unexpected request: ${url}`);
  });
  await mount();
  expect(node.querySelector('script')).toBeNull();
  expect(node.querySelector('img')).toBeNull();
  expect(node.textContent).toContain(proposal.body_markdown);
  await click('Send message'); await settle();
  const posts = fetch.mock.calls.filter(([,init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(posts[0][1].body)).toEqual({ sessionId, requestId, proposalId });
  expect(node.textContent).not.toContain('NOTHING SENT');
  expect(node.textContent).not.toContain('This exact subject and body will be sent only after confirmation.');
  expect(stored()).toBeNull();
  expect(node.querySelector('[aria-label="Saved merchant mail result"]').textContent)
    .toContain(proposal.body_markdown);
});

test('subject controls are visible in the review and saved result without changing mail bytes', async () => {
  const originalSubject = 'Agenda\\draft\r\nBcc: reader@example.test\tDone';
  const controlledProposal = { ...proposal, subject: originalSubject };
  const controlledSource = { ...source, mailProposal: controlledProposal };
  const controlledSaved = { ...saved, savedSend: { ...saved.savedSend, subject: originalSubject } };
  let reads = 0;
  globalThis.fetch = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(controlledSource);
    if (url.includes('/mail/operations/')) return response(++reads === 1 ? unconfirmed : controlledSaved,
      reads === 1 ? 202 : 200);
    if (url.endsWith('/mail/confirm') && init.method === 'POST') return response(controlledSaved);
    throw Error(`Unexpected request: ${url}`);
  });
  await mount({ proposal: controlledProposal });
  const subjectLine = () => [...node.querySelectorAll('p')]
    .find(item => item.textContent.startsWith('Subject: '));
  expect(subjectLine().textContent).toBe('Subject: Agenda\\\\draft\\r\\nBcc: reader@example.test\\tDone');
  expect(subjectLine().textContent).not.toContain('\r');
  expect(subjectLine().textContent).not.toContain('\n');
  await click('Send message'); await settle();
  const savedResult = node.querySelector('[aria-label="Saved merchant mail result"]');
  expect([...savedResult.querySelectorAll('p')].find(item => item.textContent.startsWith('Subject: ')).textContent)
    .toBe('Subject: Agenda\\\\draft\\r\\nBcc: reader@example.test\\tDone');
  expect(controlledSource.mailProposal.subject).toBe(originalSubject);
  expect(controlledSaved.savedSend.subject).toBe(originalSubject);
  const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(posts[0][1].body)).toEqual({ sessionId, requestId, proposalId });
});

test.each([
  ['literal backslashes', String.raw`A\r\nB`, String.raw`A\\r\\nB`],
  ['real CRLF', 'A\r\nB', String.raw`A\r\nB`],
])('%s and real control bytes have distinct preview but unchanged saved bytes', async (_kind, originalSubject, preview) => {
  const selectedProposal = { ...proposal, subject: originalSubject };
  const selectedSource = { ...source, mailProposal: selectedProposal };
  const selectedSaved = { ...saved, savedSend: { ...saved.savedSend, subject: originalSubject } };
  let reads = 0;
  globalThis.fetch = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(selectedSource);
    if (url.includes('/mail/operations/')) return response(++reads === 1 ? unconfirmed : selectedSaved,
      reads === 1 ? 202 : 200);
    if (url.endsWith('/mail/confirm') && init.method === 'POST') return response(selectedSaved);
    throw Error(`Unexpected request: ${url}`);
  });
  await mount({ proposal: selectedProposal });
  expect([...node.querySelectorAll('p')].find(item => item.textContent.startsWith('Subject: ')).textContent)
    .toBe(`Subject: ${preview}`);
  await click('Send message'); await settle();
  const savedResult = node.querySelector('[aria-label="Saved merchant mail result"]');
  expect([...savedResult.querySelectorAll('p')].find(item => item.textContent.startsWith('Subject: ')).textContent)
    .toBe(`Subject: ${preview}`);
  expect(selectedSource.mailProposal.subject).toBe(originalSubject);
  expect(selectedSaved.savedSend.subject).toBe(originalSubject);
  const posts = fetch.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(posts[0][1].body)).toEqual({ sessionId, requestId, proposalId });
});

test('ordinary and reply-source subjects retain their readable text', async () => {
  globalThis.fetch = jest.fn(async url => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    throw Error(`Unexpected request: ${url}`);
  });
  await mount();
  expect(node.textContent).toContain(`Subject: ${proposal.subject}`);
  const reply = { ...proposal, action: 'reply', recipient: null, subject: null,
    body_markdown: null, source: { from: 'sender@example.test',
      subject: 'First line\rSecond line', createdAt: '2026-10-12T00:00:00.000Z' } };
  await mount({ proposal: reply });
  expect(node.textContent).toContain('Subject: First line\\rSecond line');
  expect(node.textContent).not.toContain('First line\rSecond line');
});

test('lost confirmation response uses exact GET and a ref-only reload never re-POSTs', async () => {
  let reads = 0;
  globalThis.fetch = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) return response(++reads === 1 ? unconfirmed : saved,
      reads === 1 ? 202 : 200);
    if (url.endsWith('/mail/confirm') && init.method === 'POST') throw Error('lost response');
    throw Error(`Unexpected request: ${url}`);
  });
  await mount(); await click('Send message'); await settle();
  expect(node.textContent).toContain('Message saved to lab mail.');
  expect(fetch.mock.calls.filter(([,init]) => init?.method === 'POST')).toHaveLength(1);
  expect(stored()).toBeNull();
});

test('foreign manual pending slot blocks chat confirmation and does not overwrite its identity', async () => {
  const manual = { action: 'send', requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    digest: 'd'.repeat(64) };
  localStorage.setItem(SHOP_MAIL_KEY, JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: manual, assessment: null } } }));
  globalThis.fetch = jest.fn(async url => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    throw Error(`Unexpected request: ${url}`);
  });
  await mount();
  expect(node.textContent).toContain('Resolve it there');
  expect([...node.querySelectorAll('button')].some(item => item.textContent === 'Send message')).toBe(false);
  expect(JSON.parse(stored()).scopes[scope].pending).toEqual(manual);
});

test('ref-only reload checks the original saved turn and actual saved effect without a POST', async () => {
  const reference = { action: 'send', requestId: proposalId,
    digest: await merchantMailProposalDigest(proposal), chatSource: { sessionId, requestId } };
  localStorage.setItem(SHOP_MAIL_KEY, JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: reference, assessment: null } } }));
  const actual = { ...saved, status: 'saved_unattributed', savedSend: { ...saved.savedSend,
    to: 'different@example.test', subject: 'Preempting direct send', body_markdown: 'Actual saved body' } };
  globalThis.fetch = jest.fn(async url => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) return response(actual);
    throw Error(`Unexpected request: ${url}`);
  });
  await mount({ proposal: null, sessionId: null, requestId: null });
  await click('Check saved mail operation'); await settle();
  expect(fetch.mock.calls.some(([,init]) => init?.method === 'POST')).toBe(false);
  expect(node.querySelector('[aria-label="Saved merchant mail result"]').textContent)
    .toContain('Actual saved body');
  expect(node.textContent).toContain('could not be verified as this chat action');
  expect(node.textContent).not.toContain('This exact subject and body will be sent');
  expect(stored()).toBeNull();
});

test('unconfirmed saved operation retains the exact reference and offers GET-only recovery', async () => {
  globalThis.fetch = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) return response(unconfirmed, 202);
    if (url.endsWith('/mail/confirm') && init.method === 'POST') return response(unconfirmed, 202);
    throw Error(`Unexpected request: ${url}`);
  });
  await mount(); await click('Send message'); await settle();
  expect(node.textContent).toContain('Mail outcome is unconfirmed');
  expect(node.textContent).toContain('Check saved mail operation');
  expect(JSON.parse(stored()).scopes[scope].pending.chatSource).toEqual({ sessionId, requestId });
  await click('Check saved mail operation'); await settle();
  expect(fetch.mock.calls.filter(([,init]) => init?.method === 'POST')).toHaveLength(1);
});

test('replacement of the parent reference during final digest prevents confirmation POST', async () => {
  const subtle = require('node:crypto').webcrypto.subtle;
  let digests = 0, releaseDigest;
  const delayed = new Promise(resolve => { releaseDigest = resolve; });
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { subtle: { digest: async (...args) => {
      if (++digests === 5) await delayed;
      return subtle.digest(...args);
    } } } });
  globalThis.fetch = jest.fn(async (url, init) => {
    if (url.endsWith('/email/readiness')) return response({ ready: true, scopeKey: scope });
    if (url.endsWith(`/operations/${sessionId}/${requestId}`)) return response(source);
    if (url.includes('/mail/operations/')) return response(unconfirmed, 202);
    if (url.endsWith('/mail/confirm') && init.method === 'POST') return response(saved);
    throw Error(`Unexpected request: ${url}`);
  });
  await mount(); await click('Send message');
  for (let index = 0; index < 20 && digests < 5; index++) await settle();
  expect(digests).toBe(5);
  const foreign = { action: 'send', requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    digest: 'd'.repeat(64) };
  localStorage.setItem(SHOP_MAIL_KEY, JSON.stringify({ version: 3,
    scopes: { [scope]: { pending: foreign, assessment: null } } }));
  await act(async () => { releaseDigest(); await delayed; });
  await settle();
  expect(fetch.mock.calls.filter(([,init]) => init?.method === 'POST')).toHaveLength(0);
  expect(JSON.parse(stored()).scopes[scope].pending).toEqual(foreign);
});

test.each(['saved','saved_unattributed','unconfirmed'])('proposal label does not claim nothing sent after %s readback',async status=>{
 const reference={action:'send',requestId:proposalId,digest:await merchantMailProposalDigest(proposal),chatSource:{sessionId,requestId}};
 localStorage.setItem(SHOP_MAIL_KEY,JSON.stringify({version:3,scopes:{[scope]:{pending:reference,assessment:null}}}));
 const result=status==='unconfirmed'?unconfirmed:{...saved,status};
 globalThis.fetch=jest.fn(async url=>{
  if(url.endsWith('/email/readiness'))return response({ready:true,scopeKey:scope});
  if(url.endsWith(`/operations/${sessionId}/${requestId}`))return response(source);
  if(url.includes('/mail/operations/'))return response(result,status==='unconfirmed'?202:200);
  throw Error(`Unexpected request ${url}`);
 });
 await mount();await click('Check saved mail operation');await settle();
 expect(node.textContent).toContain('SAVED MAIL PROPOSAL');
 expect(node.textContent).not.toMatch(/nothing (was )?sent/i);
 if(status==='saved_unattributed')expect(node.textContent).toContain('could not be verified as this chat action');
 if(status==='unconfirmed')expect(node.textContent).toContain('Mail outcome is unconfirmed');
 expect(fetch.mock.calls.filter(([,init])=>init?.method==='POST')).toHaveLength(0);
});
