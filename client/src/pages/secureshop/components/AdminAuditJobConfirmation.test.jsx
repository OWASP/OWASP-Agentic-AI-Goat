import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminAuditJobConfirmation from './AdminAuditJobConfirmation.jsx';
import { decodeRoleAuditJobProposal, decodeAuditJobOperation } from '../utils/roleAuditJob.mjs';
import { readAuditJobReference, saveAuditJobReference, assertAuditJobReference,
  clearAuditJobReference } from '../utils/auditJobReference.mjs';

jest.mock('../utils/roleAuditJob.mjs', () => ({ decodeRoleAuditJobProposal: jest.fn(),
  decodeAuditJobOperation: jest.fn() }));
jest.mock('../utils/auditJobReference.mjs', () => ({
  readAuditJobReference: jest.fn(), saveAuditJobReference: jest.fn(),
  assertAuditJobReference: jest.fn(), clearAuditJobReference: jest.fn(),
  sameAuditJobReference: jest.fn(),
}));

const sourceSessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const sourceRequestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-5ccc-8ccc-cccccccccccc';
const jobSessionId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const mode = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const candidate = { version: 1, kind: 'audit_job', proposalId, scopeKey: 'a'.repeat(64),
  action: 'agent', sessionId: jobSessionId, requestId: proposalId,
  input: { message: 'Inspect owned audit' }, modeCapability: { ...mode, featureId: 'audit',
    policyVersion: 'raw-audit-query-disabled-v1', scope: { kind: 'launch_feature', id: 'audit' } },
  source: { sessionId: sourceSessionId, requestId: sourceRequestId }, requestSha256: 'b'.repeat(64) };
const reference = { version: 1, scopeKey: candidate.scopeKey, sourceSessionId, sourceRequestId,
  proposalId, jobSessionId, jobRequestId: proposalId, requestSha256: candidate.requestSha256 };
const json = (value, status = 200) => ({ ok: status >= 200 && status < 300, status,
  headers: { get: () => 'application/json' }, json: async () => value });
const source = { sessionId: sourceSessionId, requestId: sourceRequestId, status: 'completed',
  replayed: true, stopReason: 'end_turn', modeCapability: mode, auditJobProposal: candidate };
const read = status => ({ version: 1, kind: 'audit_job', action: 'agent',
  sessionId: jobSessionId, requestId: proposalId, status,
  result: status === 'completed' ? { text: 'Verified audit result', provider: 'real provider',
    model: 'configured model', assessment: {}, evidence: null } : null });
let node, root, transport, saved, originalFetch;
async function render(proposal = candidate, authorityKey = 'current-admin') {
  await act(async () => root.render(<AdminAuditJobConfirmation proposal={proposal}
    sessionId={proposal ? sourceSessionId : null} requestId={proposal ? sourceRequestId : null}
    authorityKey={authorityKey} transport={transport} />));
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
}
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  originalFetch = globalThis.fetch;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  saved = null;
  readAuditJobReference.mockImplementation(() => saved);
  saveAuditJobReference.mockImplementation(async ref => { saved = ref; return ref; });
  assertAuditJobReference.mockImplementation(ref => {
    if (JSON.stringify(saved) !== JSON.stringify(ref)) throw Error('Saved audit job reference changed');
  });
  clearAuditJobReference.mockImplementation(async () => { saved = null; });
  decodeRoleAuditJobProposal.mockImplementation(async value => value && candidate);
  decodeAuditJobOperation.mockImplementation(async (proposal, value) => ({
    status: value.status, result: value.result,
  }));
  transport = jest.fn(async (url, options) => {
    if (url.includes('/assistant/operations/')) return json(source);
    if (url.includes('/audit/job/operations/')) return json(read('not_found'), 202);
    if (url.endsWith('/audit/job/run')) return json(read('unconfirmed'), 202);
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
});
afterEach(async () => { await act(async () => root.unmount()); node.remove();
  globalThis.fetch = originalFetch; jest.clearAllMocks(); });

test('parent ACK precedes sole Run and pending result remains GET-only', async () => {
  let acknowledge;
  saveAuditJobReference.mockImplementation(ref => new Promise(resolve => {
    acknowledge = () => { saved = ref; resolve(ref); };
  }));
  await render();
  await act(async () => node.querySelector('button').click());
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/audit/job/run'))).toHaveLength(0);
  await act(async () => acknowledge());
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/audit/job/run'))).toHaveLength(1);
  expect(node.textContent).toContain('Check saved audit job');
  await act(async () => node.querySelector('button').click());
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/audit/job/run'))).toHaveLength(1);
  expect(saved).toEqual(reference);
});

test('reference replacement during pre-dispatch GET prevents Run', async () => {
  let release;
  transport.mockImplementation(async url => {
    if (url.includes('/assistant/operations/')) return json(source);
    if (url.includes('/audit/job/operations/')) return new Promise(resolve => { release = resolve; });
    throw Error(`Unexpected ${url}`);
  });
  await render();
  await act(async () => node.querySelector('button').click());
  saved = { ...reference, requestSha256: 'f'.repeat(64) };
  await act(async () => release(json(read('not_found'), 202)));
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/audit/job/run'))).toHaveLength(0);
  expect(node.textContent).toContain('reference changed');
});

test('ref-only reload uses exact GET and renders verified trace without another Run', async () => {
  saved = reference;
  const proof = { trace: [{ step: 1, phase: 'decision', provider: 'real provider',
    model: 'configured model', tool: 'audit.search_by_user' },
  { step: 2, phase: 'final', provider: 'real provider', model: 'configured model', tool: null }] };
  transport.mockImplementation(async url => {
    if (url.includes('/assistant/operations/')) return json(source);
    if (url.includes('/audit/job/operations/')) return json({ ...read('completed'),
      result: { ...read('completed').result, evidence: proof } });
    throw Error(`Unexpected ${url}`);
  });
  await render(null);
  await act(async () => node.querySelector('button').click());
  expect(node.textContent).toContain('Verified audit result');
  expect(node.textContent).toContain('audit.search_by_user');
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/audit/job/run'))).toHaveLength(0);
  expect(clearAuditJobReference).toHaveBeenCalledTimes(1);
});

test('transport replacement while original source read waits blocks old-transport Run', async () => {
  let release;
  transport.mockImplementation(async url => {
    if (url.includes('/assistant/operations/')) return new Promise(resolve => { release = resolve; });
    throw Error(`Unexpected ${url}`);
  });
  await render();
  await act(async () => node.querySelector('button').click());
  globalThis.fetch = jest.fn();
  await act(async () => release(json(source)));
  expect(saveAuditJobReference).not.toHaveBeenCalled();
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/audit/job/run'))).toHaveLength(0);
  expect(node.querySelector('button').disabled).toBe(false);
});

test('failed clear acknowledgment retains verified result and recoverable GET control', async () => {
  saved = reference;
  transport.mockImplementation(async url => {
    if (url.includes('/assistant/operations/')) return json(source);
    if (url.includes('/audit/job/operations/')) return json(read('completed'));
    throw Error(`Unexpected ${url}`);
  });
  clearAuditJobReference.mockRejectedValueOnce(Error('Parent clear acknowledgment unavailable'));
  await render(null);
  await act(async () => node.querySelector('button').click());
  expect(node.textContent).toContain('Verified audit result');
  expect(node.textContent).toContain('Check saved audit job');
  expect(saved).toEqual(reference);
  await act(async () => node.querySelector('button').click());
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/audit/job/run'))).toHaveLength(0);
  expect(clearAuditJobReference).toHaveBeenCalledTimes(2);
});

test.each(['source', 'result'])('saved audit %s GET survives source hydration under unchanged authority', async stage => {
  saved = reference;
  let release, signal;
  transport.mockImplementation(async (url, options) => {
    const delayed = stage === 'source' ? url.includes('/assistant/operations/') : url.includes('/audit/job/operations/');
    if (delayed) { signal = options.signal; return new Promise(resolve => { release = resolve; }); }
    if (url.includes('/assistant/operations/')) return json(source);
    if (url.includes('/audit/job/operations/')) return json(read('completed'));
    throw Error(`Unexpected ${url}`);
  });
  await render(null);
  await act(async () => node.querySelector('button').click());
  await render(candidate);
  expect(signal.aborted).toBe(false);
  await act(async () => release(json(stage === 'source' ? source : read('completed'))));
  expect(node.textContent).toContain('Verified audit result');
  expect(saved).toBe(null);
  expect(transport.mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true);
});

test.each(['source', 'result'])('authority replacement cancels saved audit %s GET', async stage => {
  saved = reference;
  let release, signal;
  transport.mockImplementation(async (url, options) => {
    const delayed = stage === 'source' ? url.includes('/assistant/operations/') : url.includes('/audit/job/operations/');
    if (delayed) { signal = options.signal; return new Promise(resolve => { release = resolve; }); }
    return json(source);
  });
  await render(null);
  await act(async () => node.querySelector('button').click());
  await render(null, 'replacement-session-or-reset');
  expect(signal.aborted).toBe(true);
  await act(async () => release(json(stage === 'source' ? source : read('completed'))));
  expect(node.textContent).not.toContain('Verified audit result');
  expect(clearAuditJobReference).not.toHaveBeenCalled();
  expect(saved).toEqual(reference);
  expect(node.querySelector('button').disabled).toBe(false);
  expect(transport.mock.calls.every(([, options]) => !options?.method)).toBe(true);
});

test('changed source during fresh confirmation blocks persistence and releases busy', async () => {
  let release;
  transport.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  await render();
  await act(async () => node.querySelector('button').click());
  await render({ ...candidate, requestSha256: 'e'.repeat(64) });
  await act(async () => release(json(source)));
  expect(saveAuditJobReference).not.toHaveBeenCalled();
  expect(transport).toHaveBeenCalledTimes(1);
  expect(node.querySelector('button').disabled).toBe(false);
});

test('source change during pre-dispatch result GET keeps persisted reference check-only', async () => {
  let release;
  transport.mockImplementation(async url => {
    if (url.includes('/assistant/operations/')) return json(source);
    return new Promise(resolve => { release = resolve; });
  });
  await render();
  await act(async () => node.querySelector('button').click());
  await render({ ...candidate, requestSha256: 'e'.repeat(64) });
  await act(async () => release(json(read('not_found'), 202)));
  expect(saved).toEqual(reference);
  expect(node.querySelector('button').textContent).toBe('Check saved audit job');
  expect(node.querySelector('button').disabled).toBe(false);
  expect(transport.mock.calls.every(([, options]) => !options?.method)).toBe(true);
  transport.mockImplementation(async url => url.includes('/assistant/operations/')
    ? json(source) : json(read('not_found'), 202));
  await act(async () => node.querySelector('button').click());
  expect(transport.mock.calls.every(([, options]) => !options?.method)).toBe(true);
});

test('persisted reference survives rejected save flush after source removal', async () => {
  let rejectFlush;
  saveAuditJobReference.mockImplementation(ref => {
    saved = ref;
    return new Promise((resolve, reject) => { rejectFlush = reject; });
  });
  await render();
  await act(async () => node.querySelector('button').click());
  await render(null);
  await act(async () => rejectFlush(Error('Saved audit job reference changed')));
  expect(saved).toEqual(reference);
  expect(node.querySelector('button').textContent).toBe('Check saved audit job');
  expect(node.querySelector('button').disabled).toBe(false);
  expect(transport).toHaveBeenCalledTimes(1);
  await act(async () => node.querySelector('button').click());
  expect(transport.mock.calls.every(([, options]) => !options?.method)).toBe(true);
});

test('source hydration after dispatch preserves exact readback without another Run', async () => {
  let releasePost, resultReads = 0;
  transport.mockImplementation(async url => {
    if (url.includes('/assistant/operations/')) return json(source);
    if (url.includes('/audit/job/operations/')) return json(read(++resultReads === 1 ? 'not_found' : 'completed'));
    if (url.endsWith('/audit/job/run')) return new Promise(resolve => { releasePost = resolve; });
    throw Error(`Unexpected ${url}`);
  });
  await render();
  await act(async () => node.querySelector('button').click());
  await render({ ...candidate, requestSha256: 'e'.repeat(64) });
  await act(async () => releasePost(json(read('unconfirmed'), 202)));
  expect(node.textContent).toContain('Verified audit result');
  const posts = transport.mock.calls.filter(([, options]) => options?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(posts[0][1].body)).toEqual({ sessionId: sourceSessionId,
    requestId: sourceRequestId, proposalId });
  expect(saved).toBe(null);
});

test('authority change during Run aborts settlement and preserves saved reference', async () => {
  let releasePost, signal;
  transport.mockImplementation(async (url, options) => {
    if (url.includes('/assistant/operations/')) return json(source);
    if (url.includes('/audit/job/operations/')) return json(read('not_found'), 202);
    signal = options.signal;
    return new Promise(resolve => { releasePost = resolve; });
  });
  await render();
  await act(async () => node.querySelector('button').click());
  await render(candidate, 'replacement-session-or-reset');
  expect(signal.aborted).toBe(true);
  await act(async () => releasePost(json(read('completed'))));
  expect(transport).toHaveBeenCalledTimes(3);
  expect(clearAuditJobReference).not.toHaveBeenCalled();
  expect(saved).toEqual(reference);
  expect(node.querySelector('button').disabled).toBe(false);
  expect(node.textContent).not.toContain('Verified audit result');
});

test('a stale Run click finding a stored reference performs only exact saved GETs', async () => {
  await render();
  saved = reference;
  await act(async () => node.querySelector('button').click());
  expect(saveAuditJobReference).not.toHaveBeenCalled();
  expect(transport.mock.calls.map(([url]) => url)).toEqual([
    `/api/secureshop/agents/admin/assistant/operations/${sourceSessionId}/${sourceRequestId}`,
    `/api/secureshop/agents/admin/assistant/audit/job/operations/${sourceSessionId}/${sourceRequestId}/${proposalId}`,
  ]);
  expect(transport.mock.calls.every(([, options]) => !options?.method)).toBe(true);
});
