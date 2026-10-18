import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminSystemRestartAssessment, { decodeSystemRestartAssessment } from './AdminSystemRestartAssessment.jsx';
import { decodeRoleSystemRestartProposal } from '../utils/roleSystemRestartProposal.mjs';
import { verifiedRestartResult } from '../pages/admin/systemRestartOperation.mjs';
import { readRoleAssistantCompletedReference, markRoleAssistantRestartAssessmentAttempted } from '../utils/roleAssistantCompletedReferences.mjs';

jest.mock('../utils/roleSystemRestartProposal.mjs', () => ({ decodeRoleSystemRestartProposal: jest.fn() }));
jest.mock('../pages/admin/systemRestartOperation.mjs', () => ({ verifiedRestartResult: jest.fn() }));
jest.mock('../utils/roleAssistantCompletedReferences.mjs', () => ({
  readRoleAssistantCompletedReference: jest.fn(), markRoleAssistantRestartAssessmentAttempted: jest.fn(),
}));
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const targetId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const mode = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const proposal = { proposalId, proposalSha256: 'a'.repeat(64), scopeKey: 'b'.repeat(64),
  targetId, requestSha256: 'c'.repeat(64), modeCapability: mode };
const administration = { targetId, scopeKey: proposal.scopeKey };
const json = value => ({ ok: true, headers: { get: () => 'application/json' },
  json: async () => value, text: async () => JSON.stringify(value) });
let root, node, transport, readOperation;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  readRoleAssistantCompletedReference.mockReturnValue({ role: 'admin', shopUserId: 7, sessionId, requestId });
  markRoleAssistantRestartAssessmentAttempted.mockResolvedValue({ role: 'admin', shopUserId: 7, sessionId, requestId, restartAssessmentAttempted: true });
  decodeRoleSystemRestartProposal.mockResolvedValue(proposal);
  verifiedRestartResult.mockResolvedValue({ state: 'completed' });
  readOperation = jest.fn(async () => ({ state: 'completed', operationId: proposalId }));
  transport = jest.fn(async (url, options) => {
    if (url.endsWith(`/assistant/operations/${sessionId}/${requestId}`)) return json({
      sessionId, requestId, status: 'completed', replayed: true, stopReason: 'end_turn',
      modeCapability: mode, systemRestartProposal: proposal,
    });
    if (url.endsWith(`/system/restart/assessment/${sessionId}/${requestId}`))
      return json({ completed: false, status: 'unconfirmed', modelEvaluated: false });
    if (url.endsWith('/system/restart/assess')) {
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId });
      return json({ completed: false, status: 'unconfirmed', modelEvaluated: false });
    }
    throw Error(`Unexpected ${url}`);
  });
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });
const button = text => [...node.querySelectorAll('button')].find(item => item.textContent.trim() === text);
async function render(authorityKey = 'current', operationState = null) {
  await act(async () => root.render(<AdminSystemRestartAssessment proposal={proposal}
    sessionId={sessionId} requestId={requestId} administration={administration} shopUserId={7}
    authorityKey={authorityKey} transport={transport} readOperation={readOperation} operationState={operationState} />));
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
}

test('verified completed saved restart offers GET first and one IDs-only explicit assessment', async () => {
  await render();
  expect(button('Check saved System restart assessment')).toBeDefined();
  expect(button('Assess System restart')).toBeUndefined();
  await act(async () => button('Check saved System restart assessment').click());
  expect(button('Assess System restart')).toBeDefined();
  await act(async () => button('Assess System restart').click());
  expect(button('Assess System restart')).toBeUndefined();
  expect(markRoleAssistantRestartAssessmentAttempted).toHaveBeenCalledWith(expect.objectContaining({ role: 'admin', shopUserId: 7, sessionId, requestId }), expect.any(Function));
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/system/restart/assess'))).toHaveLength(1);
  expect(readOperation).toHaveBeenCalledWith(proposalId, expect.anything());
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/system/restart/confirm'))).toHaveLength(0);
});

test('unverified restart receipt cannot expose assessment controls or dispatch POST', async () => {
  verifiedRestartResult.mockResolvedValue({ state: 'running' });
  await render();
  expect(node.querySelector('[aria-label="Admin System restart assessment"]')).toBeNull();
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/system/restart/assess'))).toHaveLength(0);
});

test('canonical assessment decoder rejects extra fields and false completion claims', () => {
  expect(() => decodeSystemRestartAssessment({ completed: false, status: 'unconfirmed',
    modelEvaluated: false, command: 'forged' })).toThrow();
  expect(() => decodeSystemRestartAssessment({ completed: true, replayed: false,
    judgment: { verdict: 'fail', evaluationId: proposalId, canRetry: false } })).toThrow();
});


test('completed receipt triggers a new protected read before exposing assessment controls', async () => {
  verifiedRestartResult.mockResolvedValue({ state: 'running' });
  await render('current', 'running');
  expect(node.querySelector('[aria-label="Admin System restart assessment"]')).toBeNull();
  verifiedRestartResult.mockResolvedValue({ state: 'completed' });
  await render('current', 'completed');
  expect(button('Check saved System restart assessment')).toBeDefined();
  expect(readOperation).toHaveBeenCalledTimes(2);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/system/restart/assess'))).toHaveLength(0);
});
