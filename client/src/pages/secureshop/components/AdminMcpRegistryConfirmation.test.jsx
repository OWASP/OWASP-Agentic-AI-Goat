import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminMcpRegistryConfirmation from './AdminMcpRegistryConfirmation.jsx';
import { decodeRoleMcpRegistryProposal } from '../utils/roleMcpRegistry.mjs';
import { readAnyPending, savePending, assertPendingCurrent,
  clearPending, verifyReceipt } from '../pages/admin/mcpRegistryOperation.mjs';
import { createAdminMcpManifestAssessmentStore } from '../utils/adminMcpManifestAssessmentReference.mjs';
const { webcrypto, createHash } = require('node:crypto');

jest.mock('../utils/roleMcpRegistry.mjs', () => ({ decodeRoleMcpRegistryProposal: jest.fn() }));
jest.mock('../pages/admin/mcpRegistryOperation.mjs', () => ({
  administration: value => value?.registryVersion ? null : value,
  readAnyPending: jest.fn(), savePending: jest.fn(), assertPendingCurrent: jest.fn(),
  clearPending: jest.fn(), verifyReceipt: jest.fn(),
  verifiedImportEntityReads: jest.requireActual('../pages/admin/mcpRegistryOperation.mjs').verifiedImportEntityReads,
}));
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const scopeKey = 'a'.repeat(64);
const mode = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const proposal = { version: 1, proposalId, choiceId: null, action: 'register', before: null,
  request: { version: 1, action: 'register', operationId: proposalId, expectedVersion: '4',
    name: 'Owned tools', transport: 'sse', url: 'http://owned.invalid/mcp', stdio_cmd: '' },
  scopeKey, modeCapability: mode, registryMode: 'fixed', sourceSnapshotSha256: null,
  requestSha256: 'b'.repeat(64), proposalSha256: 'c'.repeat(64) };
let root, node, transport;
const json = value => ({ ok: true, json: async () => value });
const render = async (candidate, authorityKey = 'admin-credential', assessment = {}) => act(async () => root.render(
  <AdminMcpRegistryConfirmation proposal={candidate} sessionId={sessionId}
    requestId={requestId} authorityKey={authorityKey} transport={transport} {...assessment} />));
const settle = async predicate => {
  for (let attempt = 0; attempt < 40 && !predicate(); attempt++)
    await act(async () => new Promise(resolve => setTimeout(resolve, 25)));
  if (!predicate()) throw Error(`Expected settled view; got ${node.textContent}; calls ${transport.mock.calls.map(([url]) => url).join(',')}`);
};
const assessmentStore = () => {
  const values = new Map();
  return createAdminMcpManifestAssessmentStore({ storage: {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  }, flush: async () => {} });
};
const submittedReference = async store => {
  let saved = await store.save({ shopUserId: 7, scopeKey, sessionId, requestId, proposalId,
    operationId: proposalId, requestSha256: 'b'.repeat(64),
    stage: 'awaiting_import', startedAt: 123 });
  saved = await store.advance(saved, 'ready');
  return store.advance(saved, 'submitted');
};
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  readAnyPending.mockResolvedValue(null); savePending.mockResolvedValue(); clearPending.mockResolvedValue();
  assertPendingCurrent.mockImplementation(() => {});
  decodeRoleMcpRegistryProposal.mockResolvedValue(proposal);
  verifyReceipt.mockImplementation(value => value);
  transport = jest.fn(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '4', scopeKey } });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: mode,
      mcpRegistryProposal: proposal });
    if (url.includes('/admin/mcp/operations/')) return { status: 404, ok: false };
    if (url.endsWith('/assistant/mcp/confirm')) return json({ ok: false });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });

test('parent ACK finishes before one MCP confirm POST and unknown remains GET-only', async () => {
  let acknowledge;
  savePending.mockImplementation(() => new Promise(resolve => { acknowledge = resolve; }));
  await render(proposal);
  let click;
  await act(async () => { click = node.querySelector('button').click(); });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/assistant/mcp/confirm'))).toHaveLength(0);
  await act(async () => acknowledge());
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/assistant/mcp/confirm'))).toHaveLength(1);
  expect(transport.mock.calls.filter(([url]) => url.includes('/admin/mcp/operations/'))).toHaveLength(2);
  expect(node.textContent).toContain('Check saved MCP registry operation');
  expect(clearPending).not.toHaveBeenCalled();
});

test('a replaced reference during delayed exact preflight GET blocks dispatch', async () => {
  let resolveRead;
  let pending = null;
  savePending.mockImplementation(async value => { pending = value; });
  readAnyPending.mockImplementation(async () => pending);
  assertPendingCurrent.mockImplementation(() => {
    if (pending?.requestSha256 !== proposal.requestSha256) throw Error('Registry recovery authority changed');
  });
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '4', scopeKey } });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: mode,
      mcpRegistryProposal: proposal });
    if (url.includes('/admin/mcp/operations/')) return new Promise(resolve => { resolveRead = resolve; });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(proposal);
  await act(async () => { node.querySelector('button').click(); });
  pending = { ...pending, requestSha256: 'd'.repeat(64) };
  await act(async () => resolveRead({ status: 404, ok: false }));
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/assistant/mcp/confirm'))).toHaveLength(0);
  expect(clearPending).not.toHaveBeenCalled();
});

test('a saved operation remains recoverable at the terminal registry version', async () => {
  const saved = { scopeKey, request: { ...proposal.request }, requestSha256: proposal.requestSha256 };
  readAnyPending.mockResolvedValue(saved);
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '9007199254740991', scopeKey } });
    if (url.includes('/admin/mcp/operations/')) return json({ state: 'completed',
      operationId: proposalId, action: 'register', requestSha256: proposal.requestSha256 });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(null);
  const check = [...node.querySelectorAll('button')].find(button =>
    button.textContent.includes('Check saved MCP registry operation'));
  expect(check.disabled).toBe(false);
  await act(async () => check.click());
  expect(transport.mock.calls.filter(([url]) => url.includes('/admin/mcp/operations/'))).toHaveLength(1);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/assistant/mcp/confirm'))).toHaveLength(0);
  expect(clearPending).toHaveBeenCalledWith(saved, expect.any(Function));
  expect(node.textContent).toContain('confirmed from the saved receipt');
});

test('saved import receipt shows verified entity value as text without an HTML sink', async () => {
  const value = '<img src=x onerror=alert(1)>', bytes = new TextEncoder().encode(value);
  const saved = { scopeKey, request: { version: 1, action: 'import', operationId: proposalId,
    expectedVersion: '4', xml_url: 'http://owned.invalid/manifest.xml' }, requestSha256: proposal.requestSha256 };
  readAnyPending.mockResolvedValue(saved);
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '5', scopeKey } });
    if (url.includes('/admin/mcp/operations/')) return json({ state: 'completed',
      action: 'import', changes: [{ name: 'owned', effect: {
        isolation: 'owned-mcp-registry-v1', mode: 'vuln', entityReads: [{
          path: '/owned-mcp-files/admin-token.txt', value, bytes: bytes.length,
          sha256: createHash('sha256').update(bytes).digest('hex'),
        }] } }] });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(null);
  const check = [...node.querySelectorAll('button')].find(button =>
    button.textContent.includes('Check saved MCP registry operation'));
  await act(async () => check.click());
  await settle(() => !!node.querySelector('[aria-label="Imported MCP entity reads"]'));
  expect(node.querySelector('[aria-label="Imported MCP entity reads"]')).not.toBeNull();
  expect(node.textContent).toContain(value);
  expect(node.querySelector('[aria-label="Imported MCP entity reads"] img')).toBeNull();
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/assistant/mcp/confirm'))).toHaveLength(0);
  await render(null, 'renewed-admin-credential');
  expect(node.querySelector('[aria-label="Imported MCP entity reads"]')).toBeNull();
});

test('verified import saves IDs before one assessment POST; lost ACK and reload use only GET', async () => {
  const store = assessmentStore();
  const candidate = { ...proposal, action: 'import', request: {
    version: 1, action: 'import', operationId: proposalId, expectedVersion: '4',
    xml_url: 'http://owned.invalid/manifest.xml' } };
  decodeRoleMcpRegistryProposal.mockResolvedValue(candidate);
  let operationReads = 0, postCount = 0, outcome = {
    completed: false, status: 'unconfirmed', modelEvaluated: false };
  transport.mockImplementation(async (url, options) => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '4', scopeKey } });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: mode,
      mcpRegistryProposal: candidate });
    if (url.includes('/admin/mcp/operations/')) return ++operationReads === 1
      ? { status: 404, ok: false } : json({ state: 'completed', action: 'import',
        changes: [{ name: 'owned', action: 'import' }] });
    if (url.endsWith('/assistant/mcp/confirm')) return json({ ok: true });
    if (url.endsWith('/mcp-manifest/assess')) {
      postCount++;
      expect(store.read(7).stage).toBe('submitted');
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId });
      throw Error('lost assessment acknowledgement');
    }
    if (url.endsWith(`/mcp-manifest/${proposalId}/assessment`)) return json(outcome);
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(candidate, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await act(async () => node.querySelector('button').click());
  await settle(() => !![...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Check MCP manifest assessment'));
  expect(store.read(7).stage).toBe('ready');
  const grade = [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Check MCP manifest assessment');
  await act(async () => grade.click());
  await settle(() => node.textContent.includes('Assessment not confirmed'));
  expect(postCount).toBe(1);
  await act(async () => root.unmount()); root = createRoot(node);
  outcome = { completed: true, judgment: { evaluationId: sessionId,
    verdict: 'pass', canRetry: false }, replayed: true };
  await render(null, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await settle(() => node.textContent.includes('Objective completed.'));
  const savedCheck = [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Check saved MCP manifest assessment');
  await act(async () => savedCheck.click());
  expect(postCount).toBe(1);
  expect(store.read(7).stage).toBe('submitted');
  expect(transport.mock.calls.filter(([url]) =>
    url.endsWith(`/mcp-manifest/${proposalId}/assessment`)).length).toBeGreaterThanOrEqual(2);
});

test('revoked admin assessment GET clears saved IDs and previously shown receipt', async () => {
  const store = assessmentStore();
  await submittedReference(store);
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '5', scopeKey } });
    if (url.endsWith(`/mcp-manifest/${proposalId}/assessment`)) return { ok: false, status: 401 };
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(null, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await settle(() => store.read(7) === null);
  expect(node.textContent).not.toContain('Objective completed.');
  expect(node.querySelector('[aria-label="Imported MCP entity reads"]')).toBeNull();
  expect(transport.mock.calls.filter(([url, options]) =>
    url.endsWith('/mcp-manifest/assess') && options?.method === 'POST')).toHaveLength(0);
});

test('a delayed old assessment body cannot publish after administrator authority rotates', async () => {
  const store = assessmentStore(); await submittedReference(store);
  let releaseOld, reads = 0;
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '5', scopeKey } });
    if (url.endsWith(`/mcp-manifest/${proposalId}/assessment`)) {
      reads++;
      if (reads === 1) return { ok: true, json: () => new Promise(resolve => { releaseOld = resolve; }) };
      return json({ completed: false, status: 'ineligible', modelEvaluated: false });
    }
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(null, 'admin-original', { shopUserId: 7, assessmentStore: store });
  await settle(() => typeof releaseOld === 'function');
  await render(null, 'admin-renewed', { shopUserId: 7, assessmentStore: store });
  await settle(() => node.textContent.includes('not eligible'));
  await act(async () => releaseOld({ completed: true, judgment: {
    evaluationId: sessionId, verdict: 'pass', canRetry: false }, replayed: true }));
  expect(node.textContent).not.toContain('Objective completed.');
  expect(node.textContent).toContain('not eligible');
});

test('a terminal protected assessment can be retired explicitly for a different import', async () => {
  const store = assessmentStore(); await submittedReference(store);
  const nextProposal = { ...proposal, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '5', scopeKey } });
    if (url.endsWith(`/mcp-manifest/${proposalId}/assessment`)) return json({ completed: true,
      judgment: { evaluationId: sessionId, verdict: 'pass', canRetry: false }, replayed: true });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(nextProposal, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await settle(() => node.textContent.includes('Review another MCP import'));
  expect(store.read(7).proposalId).toBe(proposalId);
  const retire = [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Review another MCP import');
  await act(async () => retire.click());
  expect(store.read(7)).toBeNull();
  expect(node.textContent).not.toContain('Objective completed.');
});

test('an unresolved prior import reference cannot be retired for a new proposal', async () => {
  const store = assessmentStore();
  await store.save({ shopUserId: 7, scopeKey, sessionId, requestId, proposalId,
    operationId: proposalId, requestSha256: 'b'.repeat(64),
    stage: 'awaiting_import', startedAt: 123 });
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '5', scopeKey } });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render({ ...proposal, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' },
    'admin-credential', { shopUserId: 7, assessmentStore: store });
  expect(node.textContent).not.toContain('Review another MCP import');
  expect(store.read(7).stage).toBe('awaiting_import');
});

test('a late failed preflight cannot project pending state into renewed authority', async () => {
  let resolveOldRead;
  const oldRead = new Promise(resolve => { resolveOldRead = resolve; });
  readAnyPending.mockResolvedValueOnce(null).mockResolvedValueOnce(null)
    .mockImplementationOnce(() => oldRead).mockResolvedValueOnce(null);
  decodeRoleMcpRegistryProposal.mockRejectedValueOnce(Error('Old proposal is unavailable'));
  await render(proposal);
  await act(async () => { node.querySelector('button').click(); });
  expect(readAnyPending).toHaveBeenCalledTimes(3);
  await render(proposal, 'renewed-admin-credential');
  await act(async () => resolveOldRead({ scopeKey, request: proposal.request,
    requestSha256: proposal.requestSha256 }));
  expect(node.textContent).not.toContain('Old proposal is unavailable');
  expect(node.textContent).not.toContain('Check saved MCP registry operation');
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/assistant/mcp/confirm'))).toHaveLength(0);
});

test('ordinary registration preserves the existing flow when discovery assessment capability is absent', async () => {
  const store = assessmentStore(); let reads = 0;
  const original = transport.getMockImplementation();
  transport.mockImplementation(async (url, options) => url.includes('/admin/mcp/operations/')
    ? ++reads === 1 ? { status: 404, ok: false } : json({ state: 'completed', action: 'register', changes: [] })
    : original(url, options));
  globalThis.fetch = transport;
  await render(proposal, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await act(async () => node.querySelector('button').click());
  await settle(() => node.textContent.includes('Registry register confirmed'));
  expect(store.read(7)).toBeNull();
  expect(node.textContent).not.toContain('discovery assessment');
  expect(transport.mock.calls.some(([url]) => url.includes('/mcp-discovery/'))).toBe(false);
});

test('enabled discovery assessment saves original IDs before confirmation and recovers lost grading acknowledgement by GET after reload', async () => {
  const store = assessmentStore(); let operationReads = 0, assessmentPosts = 0;
  let outcome = { completed: false, status: 'unconfirmed', modelEvaluated: false };
  transport.mockImplementation(async (url, options) => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '4', scopeKey }, registry_discovery_assessment: { ready: true } });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: mode,
      mcpRegistryProposal: proposal });
    if (url.includes('/admin/mcp/operations/')) return ++operationReads === 1
      ? { status: 404, ok: false } : json({ state: 'completed', action: 'register', changes: [] });
    if (url.endsWith('/assistant/mcp/confirm')) {
      expect(store.read(7)).toMatchObject({ version: 2, kind: 'discovery', stage: 'awaiting_registration',
        sessionId, requestId, proposalId });
      return json({ ok: true });
    }
    if (url.endsWith('/mcp-discovery/assess')) {
      assessmentPosts++; expect(store.read(7).stage).toBe('submitted');
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId });
      throw Error('lost acknowledgement');
    }
    if (url.endsWith(`/mcp-discovery/${proposalId}/assessment`)) return json(outcome);
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(proposal, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await act(async () => node.querySelector('button').click());
  await settle(() => node.textContent.includes('Check MCP discovery assessment'));
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Check MCP discovery assessment').click());
  await settle(() => node.textContent.includes('Assessment not confirmed'));
  expect(assessmentPosts).toBe(1);
  await act(async () => root.unmount()); root = createRoot(node);
  outcome = { completed: true, judgment: { evaluationId: sessionId, verdict: 'pass', canRetry: false }, replayed: true };
  await render(null, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await settle(() => node.textContent.includes('Objective completed.'));
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Check saved MCP discovery assessment').click());
  expect(assessmentPosts).toBe(1);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/assistant/mcp/confirm'))).toHaveLength(1);
  expect(transport.mock.calls.some(([url]) => url.includes('/mcp-manifest/'))).toBe(false);
});

test('revoked discovery assessment clears saved references without confirming or grading again', async () => {
  const store = assessmentStore();
  const saved = await store.save({ version: 2, kind: 'discovery', shopUserId: 7, scopeKey,
    sessionId, requestId, proposalId, operationId: proposalId, requestSha256: 'b'.repeat(64),
    stage: 'awaiting_registration', startedAt: 123 });
  await store.advance(await store.advance(saved, 'ready'), 'submitted');
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: { ready: true, version: '5', scopeKey },
      registry_discovery_assessment: { ready: true } });
    if (url.endsWith(`/mcp-discovery/${proposalId}/assessment`)) return { ok: false, status: 401 };
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(null, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await settle(() => store.read(7) === null);
  expect(node.textContent).not.toContain('Objective completed.');
  expect(transport.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});

test('mode-fenced prior discovery remains protected while a current registration is visible', async () => {
  const store = assessmentStore();
  let saved = await store.save({ version: 2, kind: 'discovery', shopUserId: 7, scopeKey,
    sessionId, requestId, proposalId, operationId: proposalId, requestSha256: 'b'.repeat(64),
    stage: 'awaiting_registration', startedAt: 123 });
  saved = await store.advance(await store.advance(saved, 'ready'), 'submitted');
  const nextId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const next = { ...proposal, proposalId: nextId, request: { ...proposal.request,
    operationId: nextId, expectedVersion: '5' } };
  decodeRoleMcpRegistryProposal.mockResolvedValue(next);
  transport.mockImplementation(async url => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '5', scopeKey }, registry_discovery_assessment: { ready: true } });
    if (url.endsWith(`/mcp-discovery/${proposalId}/assessment`)) return {
      ok: false, status: 409, json: async () => ({ error: 'Role assistant reference conflicts' }) };
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: mode,
      mcpRegistryProposal: next });
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(next, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await settle(() => node.textContent.includes('Saved MCP discovery assessment unavailable.'));
  expect(node.textContent).not.toContain('Review another MCP registration');
  expect(store.read(7)).toEqual(saved);
  const confirm = [...node.querySelectorAll('button')].find(button => button.textContent === 'Register MCP server');
  expect(confirm.disabled).toBe(false);
  await act(async () => confirm.click());
  await settle(() => node.textContent.includes('Check the saved MCP discovery assessment before another registration.'));
  expect(transport.mock.calls.some(([url]) => url.endsWith('/assistant/mcp/confirm'))).toBe(false);
  expect(store.read(7)).toEqual(saved);
});

test('authoritative fixed ineligibility permits explicit prior discovery retirement before current physical confirmation', async () => {
  const store = assessmentStore();
  let saved = await store.save({ version: 2, kind: 'discovery', shopUserId: 7, scopeKey,
    sessionId, requestId, proposalId, operationId: proposalId, requestSha256: 'b'.repeat(64),
    stage: 'awaiting_registration', startedAt: 123 });
  saved = await store.advance(await store.advance(saved, 'ready'), 'submitted');
  const nextId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  const next = { ...proposal, proposalId: nextId, request: { ...proposal.request,
    operationId: nextId, expectedVersion: '5' } };
  decodeRoleMcpRegistryProposal.mockResolvedValue(next);
  let confirmations = 0, operationReads = 0;
  transport.mockImplementation(async (url, options) => {
    if (url.endsWith('/admin/mcp/servers')) return json({ registry_administration: {
      ready: true, version: '5', scopeKey }, registry_discovery_assessment: { ready: true } });
    if (url.endsWith(`/mcp-discovery/${proposalId}/assessment`)) return json({
      completed: false, status: 'ineligible', modelEvaluated: false });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId,
      status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability: mode,
      mcpRegistryProposal: next });
    if (url.endsWith(`/admin/mcp/operations/${nextId}`)) return ++operationReads === 1
      ? { ok: false, status: 404 } : json({ state: 'failed' });
    if (url.endsWith('/assistant/mcp/confirm')) {
      confirmations++;
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId: nextId });
      expect(store.read(7)).toMatchObject({ proposalId: nextId, stage: 'awaiting_registration' });
      return { ok: false, status: 403, json: async () => ({ ok: false,
        error: 'MCP registration destination denied in Fixed mode',
        code: 'MCP_REGISTRY_FIXED_DESTINATION_DENIED', automaticRetry: false }) };
    }
    throw Error(`Unexpected ${url}`);
  });
  globalThis.fetch = transport;
  await render(next, 'admin-credential', { shopUserId: 7, assessmentStore: store });
  await settle(() => node.textContent.includes('Review another MCP registration'));
  expect(store.read(7)).toEqual(saved);expect(confirmations).toBe(0);
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Review another MCP registration').click());
  expect(store.read(7)).toBeNull();expect(confirmations).toBe(0);
  await act(async () => [...node.querySelectorAll('button')].find(button =>
    button.textContent === 'Register MCP server').click());
  await settle(() => node.textContent.includes('The saved registry change was refused.'));
  expect(confirmations).toBe(1);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/mcp-discovery/assess'))).toBe(false);
});
