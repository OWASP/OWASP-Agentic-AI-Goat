import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import AdminSystemRestartConfirmation from './AdminSystemRestartConfirmation.jsx';
import { restartHash } from '../pages/admin/systemRestartOperation.mjs';
import { decodeRoleSystemRestartProposal } from '../utils/roleSystemRestartProposal.mjs';
import { readSystemRestartReferences, saveSystemRestartReference,
  forgetSystemRestartReference } from '../pages/admin/systemRestartRecovery.js';

jest.mock('../utils/roleSystemRestartProposal.mjs', () => ({ decodeRoleSystemRestartProposal: jest.fn() }));
jest.mock('../pages/admin/systemRestartRecovery.js', () => ({
  readSystemRestartReferences: jest.fn(), saveSystemRestartReference: jest.fn(),
  forgetSystemRestartReference: jest.fn(),
}));

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const operationId = 'cccccccc-cccc-5ccc-8ccc-cccccccccccc';
const targetId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const mode = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const json = value => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => value });
let node, root, transport, readOperation, confirmOperation, reference, candidate, refs;

async function render(proposal = candidate, authorityKey = 'current-admin', identity = {}) {
  const renderedSessionId = Object.hasOwn(identity, 'sessionId') ? identity.sessionId
    : proposal ? sessionId : null;
  const renderedRequestId = Object.hasOwn(identity, 'requestId') ? identity.requestId
    : proposal ? requestId : null;
  await act(async () => root.render(<AdminSystemRestartConfirmation proposal={proposal}
    sessionId={renderedSessionId} requestId={renderedRequestId}
    authorityKey={authorityKey} transport={transport} confirmOperation={confirmOperation}
    readOperation={readOperation} />));
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
}

beforeEach(async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  const scopeKey = await restartHash({ restartTargetId: targetId });
  candidate = { version: 1, proposalId: operationId, action: 'restart', name: 'owned service',
    targetId, scopeKey, sourceSnapshotSha256: 'a'.repeat(64), modeCapability: mode,
    requestSha256: 'b'.repeat(64), proposalSha256: 'c'.repeat(64) };
  reference = { scopeKey, operationId, state: 'pending' };
  refs = [];
  readSystemRestartReferences.mockImplementation(() => refs.map(row => ({ ...row })));
  saveSystemRestartReference.mockImplementation(async value => { refs = [value]; return refs; });
  forgetSystemRestartReference.mockImplementation(async () => { refs = []; return refs; });
  decodeRoleSystemRestartProposal.mockImplementation(async () => candidate);
  transport = jest.fn(async url => {
    if (url === '/api/secureshop/admin/system/restart') return json({ ok: true,
      administration: { restartCapability: 'secureshop-owned-system-restart.v1', targetId } });
    if (url.includes('/assistant/operations/')) return json({ sessionId, requestId, status: 'completed',
      replayed: true, stopReason: 'end_turn', modeCapability: mode,
      systemRestartProposal: candidate });
    throw Error(`Unexpected ${url}`);
  });
  readOperation = jest.fn(async () => ({ state: 'not_found' }));
  confirmOperation = jest.fn(async () => ({}));
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });

test('saved parent ACK precedes one confirm; unresolved outcome stays GET-only', async () => {
  let acknowledge;
  saveSystemRestartReference.mockImplementation(value => new Promise(resolve => {
    acknowledge = () => { refs = [value]; resolve(refs); };
  }));
  await render();
  expect(node.querySelector('button').disabled).toBe(false);
  await act(async () => node.querySelector('button').click());
  expect(confirmOperation).not.toHaveBeenCalled();
  await act(async () => acknowledge());
  expect(confirmOperation).toHaveBeenCalledTimes(1);
  expect(readOperation).toHaveBeenCalledTimes(2);
  expect(node.textContent).toContain('Check saved System restart');
  expect(forgetSystemRestartReference).not.toHaveBeenCalled();
  await act(async () => node.querySelector('button').click());
  expect(confirmOperation).toHaveBeenCalledTimes(1);
  expect(readOperation).toHaveBeenCalledTimes(3);
});

test('replacement during awaited preflight read prevents restart POST', async () => {
  let release;
  readOperation.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  await render();
  expect(node.querySelector('button').disabled).toBe(false);
  await act(async () => node.querySelector('button').click());
  refs = [{ ...reference, operationId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' }];
  await act(async () => release({ state: 'not_found' }));
  expect(confirmOperation).not.toHaveBeenCalled();
  expect(node.textContent).toContain('Saved System restart reference changed');
});

test('ref-only reload exposes exact GET recovery without a new POST', async () => {
  refs = [reference];
  await render(null);
  expect(node.textContent).toContain('Check saved System restart');
  await act(async () => node.querySelector('button').click());
  expect(readOperation).toHaveBeenCalledWith(operationId, expect.anything());
  expect(confirmOperation).not.toHaveBeenCalled();
});

test('saved recovery survives same-authority proposal hydration while its exact GET is pending', async () => {
  refs = [reference];
  let release, observedSignal;
  readOperation.mockImplementationOnce((_operationId, signal) => {
    observedSignal = signal;
    return new Promise(resolve => { release = resolve; });
  });
  await render(null);
  await act(async () => node.querySelector('button').click());
  await render(candidate);
  expect(observedSignal.aborted).toBe(false);
  const outputText = 'owned restart complete\n';
  const outputSha256 = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(outputText))), byte => byte.toString(16).padStart(2, '0')).join('');
  await act(async () => release({ ok: true, state: 'completed', operationId, targetId,
    requestSha256: 'b'.repeat(64), receipt: {
      beforeInstanceId: '11111111-1111-4111-8111-111111111111',
      afterInstanceId: '22222222-2222-4222-8222-222222222222',
      beforeGeneration: 1, afterGeneration: 2, effectSha256: 'e'.repeat(64),
      outputSha256, outputBytes: new TextEncoder().encode(outputText).length, outputText,
    } }));
  for (let attempt = 0; attempt < 20 && !node.textContent.includes('Owned service restarted'); attempt += 1) {
    await act(async () => new Promise(resolve => setTimeout(resolve, 0)));
  }
  expect(node.textContent).toContain('Owned service restarted. Saved receipt verified.');
  expect(forgetSystemRestartReference).toHaveBeenCalledTimes(1);
  expect(confirmOperation).not.toHaveBeenCalled();
});

test('saved recovery aborts on authority replacement', async () => {
  refs = [reference];
  let observedSignal;
  readOperation.mockImplementationOnce((_operationId, signal) => {
    observedSignal = signal;
    return new Promise(() => {});
  });
  await render(null);
  await act(async () => node.querySelector('button').click());
  await render(null, 'replacement-admin');
  expect(observedSignal.aborted).toBe(true);
});

test('saved recovery aborts when hydration selects a distinct proposal identity', async () => {
  refs = [reference];
  let observedSignal;
  readOperation.mockImplementationOnce((_operationId, signal) => {
    observedSignal = signal;
    return new Promise(() => {});
  });
  await render(null);
  await act(async () => node.querySelector('button').click());
  await render({ ...candidate, proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' });
  expect(observedSignal.aborted).toBe(true);
});

test('saved recovery aborts when non-null request identity changes during proposal restoration', async () => {
  refs = [reference];
  let observedSignal;
  readOperation.mockImplementationOnce((_operationId, signal) => {
    observedSignal = signal;
    return new Promise(() => {});
  });
  await render(null, 'current-admin', { sessionId: '33333333-3333-4333-8333-333333333333',
    requestId: '44444444-4444-4444-8444-444444444444' });
  await act(async () => node.querySelector('button').click());
  await render(candidate);
  expect(observedSignal.aborted).toBe(true);
});

test('post-effect OUTCOME_UNCERTAIN retains the exact reference for GET-only checks', async () => {
  refs = [reference];
  readOperation.mockResolvedValue({ ok: false, state: 'failed', operationId,
    automaticRetry: false, failureCode: 'OUTCOME_UNCERTAIN' });
  await render(null);
  await act(async () => node.querySelector('button').click());
  expect(node.textContent).toContain('Restart outcome is uncertain');
  expect(node.textContent).toContain('Check saved System restart');
  expect(forgetSystemRestartReference).not.toHaveBeenCalled();
  expect(confirmOperation).not.toHaveBeenCalled();
  expect(refs).toEqual([reference]);
});
