import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminSystemDiagnosticConfirmation from './AdminSystemDiagnosticConfirmation.jsx';
import { decodeRoleSystemDiagnosticProposal } from '../utils/roleSystemDiagnosticProposal.mjs';
import { decodeRoleSystemDiagnosticOutcome } from '../utils/roleSystemDiagnosticOutcome.mjs';

jest.mock('../utils/roleSystemDiagnosticProposal.mjs', () => ({
  decodeRoleSystemDiagnosticProposal: jest.fn(),
}));
jest.mock('../utils/roleSystemDiagnosticOutcome.mjs', () => ({
  decodeRoleSystemDiagnosticOutcome: jest.fn(),
}));

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const mode = effectiveMode => ({ version: 1, featureId: 'system_diagnostic',
  policyVersion: 'owned-system-diagnostic-shell-v1', effectiveMode,
  scope: { kind: 'launch_feature', id: 'system_diagnostic' } });
const json = (value, status = 200) => ({ status, ok: status >= 200 && status < 300,
  headers: { get: () => 'application/json' }, json: async () => value });
const BASE = '/api/secureshop/agents/admin/assistant/system/diagnostic/confirm';
const SOURCE = `/api/secureshop/agents/admin/assistant/operations/${sessionId}/${requestId}`;
const SAVED = `${BASE}/${sessionId}/${requestId}/${proposalId}`;
let node, root, candidate, transport, store, retained;

async function render(proposal = candidate, authorityKey = 'admin-current') {
  await act(async () => root.render(<AdminSystemDiagnosticConfirmation proposal={proposal}
    sessionId={proposal ? sessionId : null} requestId={proposal ? requestId : null}
    shopUserId={7} authorityKey={authorityKey} transport={transport} referenceStore={store} />));
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
}

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  candidate = { version: 1, proposalId, action: 'system_diagnostic',
    cmd_template: 'echo', args: "<img src=x onerror=alert('test')>",
    scopeKey: 'a'.repeat(64), diagnosticCapability: 'secureshop-owned-system-diagnostic.v1',
    sourceSnapshotSha256: 'b'.repeat(64), modeCapability: mode('vuln'),
    requestSha256: 'c'.repeat(64), proposalSha256: 'd'.repeat(64) };
  retained = null;
  store = { read: jest.fn(() => retained),
    save: jest.fn(async value => { retained = { version: 1, ...value }; return retained; }),
    clear: jest.fn(async saved => {
      if (JSON.stringify(saved) !== JSON.stringify(retained)) throw Error('Saved reference changed');
      retained = null;
    }) };
  decodeRoleSystemDiagnosticProposal.mockImplementation(async value => value);
  decodeRoleSystemDiagnosticOutcome.mockImplementation(async value => value);
  transport = jest.fn(async (path, options = {}) => {
    if (path === '/api/secureshop/admin/system/diagnostic') return json({ ok: true,
      administration: { diagnosticCapability: candidate.diagnosticCapability,
        scopeKey: candidate.scopeKey, modeCapability: candidate.modeCapability } });
    if (path === SOURCE) return json({ sessionId, requestId, status: 'completed',
      replayed: true, stopReason: 'end_turn', systemDiagnosticProposal: candidate });
    if (path === SAVED) return json({ state: 'not_found', proposal: candidate });
    if (path === BASE && options.method === 'POST') return json({ state: 'pending' }, 202);
    throw Error(`Unexpected ${path}`);
  });
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });

test('shows exact proposed bytes as text and saves opaque IDs before one confirmation POST', async () => {
  const trace = [];
  store.save.mockImplementation(async value => { trace.push('saved'); retained = { version: 1, ...value }; return retained; });
  const original = transport;
  transport = jest.fn(async (...args) => { if (args[0] === BASE) trace.push('post'); return original(...args); });
  await render();
  expect(node.textContent).toContain(candidate.args);
  expect(node.querySelector('img')).toBeNull();
  await act(async () => node.querySelector('button').click());
  expect(trace).toEqual(['saved', 'post']);
  const confirm = transport.mock.calls.find(([path]) => path === BASE);
  expect(JSON.parse(confirm[1].body)).toEqual({ sessionId, requestId, proposalId });
  expect(node.textContent).toContain('Check saved System diagnostic');
  await act(async () => node.querySelector('button').click());
  expect(transport.mock.calls.filter(([path]) => path === BASE)).toHaveLength(1);
});

test('reference-only remount reads the saved operation and never confirms again', async () => {
  retained = { version: 1, shopUserId: 7, sessionId, requestId, proposalId,
    scopeKey: candidate.scopeKey, proposalSha256: candidate.proposalSha256, startedAt: 123 };
  await render(null);
  expect(node.textContent).toContain('Check saved System diagnostic');
  await act(async () => node.querySelector('button').click());
  expect(transport.mock.calls.filter(([path]) => path === SOURCE)).toHaveLength(0);
  expect(transport.mock.calls.filter(([path]) => path === SAVED)).toHaveLength(1);
  expect(transport.mock.calls.some(([path]) => path === BASE)).toBe(false);
});

test('late source hydration does not abort an in-flight saved GET or repeat confirmation', async () => {
  retained = { version: 1, shopUserId: 7, sessionId, requestId, proposalId,
    scopeKey: candidate.scopeKey, proposalSha256: candidate.proposalSha256, startedAt: 123 };
  let finishSaved;
  const original = transport;
  transport = jest.fn((path, options) => path === SAVED
    ? new Promise(resolve => { finishSaved = resolve; }) : original(path, options));
  await render(null);
  await act(async () => node.querySelector('button').click());
  const savedCall = transport.mock.calls.find(([path]) => path === SAVED);
  expect(savedCall).toBeDefined();
  await render(candidate);
  expect(savedCall[1].signal.aborted).toBe(false);
  await act(async () => finishSaved(json({ state: 'completed', proposal: candidate,
    stdout: 'original output', stderr: '' })));
  expect(node.textContent).toContain('original output');
  expect(transport.mock.calls.filter(([path]) => path === SAVED)).toHaveLength(1);
  expect(transport.mock.calls.some(([path]) => path === BASE)).toBe(false);
});

test('a different proposal fences uncommitted confirmation preflight', async () => {
  let finishSource;
  const original = transport;
  transport = jest.fn((path, options) => path === SOURCE
    ? new Promise(resolve => { finishSource = resolve; })
    : path.startsWith(`${BASE}/`) ? json({ state: 'not_found', proposal: candidate })
      : original(path, options));
  await render();
  await act(async () => node.querySelector('button').click());
  expect(finishSource).toBeDefined();
  const replacement = { ...candidate, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  await render(replacement);
  await act(async () => finishSource(json({ sessionId, requestId, status: 'completed',
    replayed: true, stopReason: 'end_turn', systemDiagnosticProposal: candidate })));
  expect(store.save).not.toHaveBeenCalled();
  expect(transport.mock.calls.some(([path]) => path === BASE)).toBe(false);
  candidate = replacement;
  await act(async () => node.querySelector('button').click());
  await act(async () => finishSource(json({ sessionId, requestId, status: 'completed',
    replayed: true, stopReason: 'end_turn', systemDiagnosticProposal: replacement })));
  expect(store.save).toHaveBeenCalledTimes(1);
  await act(async () => finishSource(json({ sessionId, requestId, status: 'completed',
    replayed: true, stopReason: 'end_turn', systemDiagnosticProposal: replacement })));
  expect(transport.mock.calls.filter(([path]) => path === BASE)).toHaveLength(1);
});

test('a proposal arriving during reference save leaves the saved command check-only', async () => {
  let finishSave;
  store.save.mockImplementation(async value => {
    retained = { version: 1, ...value };
    await new Promise(resolve => { finishSave = resolve; });
    return retained;
  });
  await render();
  await act(async () => { node.querySelector('button').click();
    await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(finishSave).toBeDefined();
  const replacement = { ...candidate, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  await render(replacement);
  await act(async () => finishSave());
  expect(node.textContent).toContain('Check saved System diagnostic');
  expect(node.textContent).not.toContain('Confirm System diagnostic');
  expect(transport.mock.calls.some(([path]) => path === BASE)).toBe(false);
});

test('a newly hydrated proposal refreshes current diagnostic mode without clearing saved state', async () => {
  await render();
  const fixed = { ...candidate, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    proposalSha256: 'e'.repeat(64), modeCapability: mode('fixed') };
  candidate = fixed;
  await render(fixed);
  expect(transport.mock.calls.filter(([path]) => path === '/api/secureshop/admin/system/diagnostic'))
    .toHaveLength(2);
  expect(node.textContent).toContain('Review proposed System diagnostic');
  expect(node.querySelector('button').disabled).toBe(false);
});

test('a late old administration response cannot overwrite the new proposal mode', async () => {
  let finishOld;
  const original = transport;
  let administrations = 0;
  transport = jest.fn((path, options) => {
    if (path === '/api/secureshop/admin/system/diagnostic' && ++administrations === 1)
      return new Promise(resolve => { finishOld = resolve; });
    if (path.startsWith(`${BASE}/`)) return json({ state: 'not_found', proposal: candidate });
    return original(path, options);
  });
  await render();
  const old = candidate;
  candidate = { ...candidate, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    proposalSha256: 'e'.repeat(64), modeCapability: mode('fixed') };
  await render(candidate);
  await act(async () => finishOld(json({ ok: true, administration: {
    diagnosticCapability: old.diagnosticCapability, scopeKey: old.scopeKey,
    modeCapability: old.modeCapability } })));
  expect(node.querySelector('button').disabled).toBe(false);
  await act(async () => { node.querySelector('button').click();
    await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(store.save).toHaveBeenCalledTimes(1);
  expect(transport.mock.calls.some(([path]) => path === BASE)).toBe(true);
});

test('historical vulnerable receipt remains GET-only after current mode switches to Fixed', async () => {
  const historical = candidate;
  retained = { version: 1, shopUserId: 7, sessionId, requestId, proposalId,
    scopeKey: candidate.scopeKey, proposalSha256: candidate.proposalSha256, startedAt: 123 };
  candidate = { ...candidate, modeCapability: mode('fixed') };
  const original = transport;
  transport = jest.fn(async (path, options) => path === SAVED
    ? json({ state: 'completed', proposal: historical }) : original(path, options));
  await render(null, 'admin-after-mode-switch');
  await act(async () => node.querySelector('button').click());
  expect(node.textContent).toContain('System diagnostic completed');
  expect(transport.mock.calls.some(([path]) => path === BASE || path === SOURCE)).toBe(false);
  expect(transport.mock.calls.filter(([path]) => path === SAVED)).toHaveLength(1);
});

test('completed saved diagnostic offers an IDs-only assessment without repeating its command', async () => {
  retained = { version: 1, shopUserId: 7, sessionId, requestId, proposalId,
    scopeKey: candidate.scopeKey, proposalSha256: candidate.proposalSha256, startedAt: 123 };
  const assess = '/api/secureshop/agents/admin/assistant/system/diagnostic/assess';
  const savedAssessment = `${assess}/${sessionId}/${requestId}/${proposalId}`;
  let reads = 0;
  const original = transport;
  transport = jest.fn(async (path, options) => {
    if (path === SAVED) return json({ state: 'completed', proposal: candidate });
    if (path === savedAssessment) return json(++reads === 1
      ? { completed: false, status: 'unconfirmed', modelEvaluated: false }
      : { completed: true, replayed: false, judgment: {
        verdict: 'pass', evaluationId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', canRetry: false } });
    if (path === assess) return json({ completed: true, replayed: false });
    return original(path, options);
  });
  await render(null);
  await act(async () => [...node.querySelectorAll('button')].find(item =>
    item.textContent === 'Check saved System diagnostic').click());
  const assessment = node.querySelector('[aria-label="Admin System diagnostic assessment"]');
  expect(assessment).not.toBeNull();
  await act(async () => [...assessment.querySelectorAll('button')].find(item =>
    item.textContent === 'Check saved System diagnostic assessment').click());
  await act(async () => [...assessment.querySelectorAll('button')].find(item =>
    item.textContent === 'Check System diagnostic objective').click());
  expect(JSON.parse(transport.mock.calls.find(([path]) => path === assess)[1].body))
    .toEqual({ sessionId, requestId, proposalId });
  expect(transport.mock.calls.filter(([path]) => path === BASE)).toHaveLength(0);
  expect(transport.mock.calls.filter(([path]) => path === savedAssessment)).toHaveLength(2);
  expect(node.textContent).toContain('Objective completed.');
});

test('fixed-mode denial is shown only after exact saved GET proves no command', async () => {
  candidate = { ...candidate, modeCapability: mode('fixed') };
  const original = transport;
  transport = jest.fn(async (path, options) => path === BASE
    ? json({ code: 'SYSTEM_DIAGNOSTIC_FIXED_DENIED' }, 403) : original(path, options));
  await render();
  await act(async () => node.querySelector('button').click());
  expect(node.textContent).toContain('Fixed mode denied this diagnostic before execution');
  expect(retained).toBeNull();
  expect(transport.mock.calls.filter(([path]) => path === BASE)).toHaveLength(1);
});

test('a replacing saved reference is never cleared after fixed denial', async () => {
  candidate = { ...candidate, modeCapability: mode('fixed') };
  const original = transport;
  transport = jest.fn(async (path, options) => {
    if (path === BASE) {
      retained = { ...retained, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
      return json({ code: 'SYSTEM_DIAGNOSTIC_FIXED_DENIED' }, 403);
    }
    return original(path, options);
  });
  await render();
  await act(async () => node.querySelector('button').click());
  expect(retained.proposalId).toBe('dddddddd-dddd-4ddd-8ddd-dddddddddddd');
  expect(store.clear).toHaveBeenCalledWith(expect.objectContaining({ proposalId }), expect.any(Function));
});
