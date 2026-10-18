import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useRegisteredAdminStream } from './useRegisteredAdminStream.js';
import { readRegisteredAdminChatReference, saveRegisteredAdminChatReference,
  clearRegisteredAdminChatReference } from '../utils/registeredAdminChatReference.mjs';
import { readRegisteredAdminCompletedReference, saveRegisteredAdminCompletedReference,
  clearRegisteredAdminCompletedReference } from '../utils/registeredAdminCompletedReference.mjs';
const { webcrypto } = require('node:crypto');

jest.mock('../utils/registeredAdminChatReference.mjs', () => ({
  readRegisteredAdminChatReference: jest.fn(), saveRegisteredAdminChatReference: jest.fn(),
  clearRegisteredAdminChatReference: jest.fn(), assertRegisteredAdminChatReference: jest.fn(),
}));
jest.mock('../utils/registeredAdminCompletedReference.mjs', () => ({
  readRegisteredAdminCompletedReference: jest.fn(), saveRegisteredAdminCompletedReference: jest.fn(),
  clearRegisteredAdminCompletedReference: jest.fn(),
}));
const sid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const mode = { version: 1, featureId: 'registered_mcp',
  policyVersion: 'registered-schema-approval-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'registered_mcp' } };
const json = value => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => value });
const stream = () => ({ ok: true, headers: { get: () => 'text/event-stream; charset=utf-8' },
  body: { getReader: () => ({ read: async () => ({ done: false,
    value: new TextEncoder().encode('event: done\ndata: {}\n\n') }), cancel: async () => {} }) } });
let root, node, current;
function Probe({ transport, authorityKey = 'parent-credential' }) {
  current = useRegisteredAdminStream({ shopUserId: 7, authorityKey, transport });
  return <span>{current.status}</span>;
}
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  readRegisteredAdminChatReference.mockReturnValue(null);
  readRegisteredAdminCompletedReference.mockReturnValue(null);
  saveRegisteredAdminChatReference.mockResolvedValue();
  clearRegisteredAdminChatReference.mockResolvedValue();
  saveRegisteredAdminCompletedReference.mockResolvedValue();
  clearRegisteredAdminCompletedReference.mockResolvedValue(true);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });

test('parent ACK precedes the sole registered POST and exact saved GET owns the answer', async () => {
  let acknowledge;
  saveRegisteredAdminChatReference.mockImplementation(() => new Promise(resolve => { acknowledge = resolve; }));
  const calls = [];
  const transport = jest.fn(async (url, options) => {
    calls.push({ url, body: options?.body });
    if (url.endsWith('/session')) return json({ sessionId: sid });
    if (url.endsWith('/chat')) return stream();
    if (url.includes('/chat/requests/')) return json({ sessionId: sid,
      requestId: saveRegisteredAdminChatReference.mock.calls[0][0].requestId,
      status: 'completed', replayed: true, result: { sessionId: sid,
        text: 'Verified registered result', stopReason: 'end_turn', hops: [], steps: 1,
        modeCapability: mode } });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  let sending;
  await act(async () => { sending = current.send('Ask the complete registered manifest'); });
  expect(calls.map(call => call.url)).toEqual(['/api/secureshop/agents/admin/session']);
  expect(saveRegisteredAdminChatReference.mock.calls[0][0]).toEqual({ shopUserId: 7,
    sessionId: sid, requestId: expect.any(String), startedAt: expect.any(Number) });
  await act(async () => acknowledge());
  await act(async () => expect(await sending).toBe(true));
  expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(1);
  expect(calls.find(call => call.url.endsWith('/chat')).body).toContain('Ask the complete registered manifest');
  expect(current.turns[0].reply).toBe('Verified registered result');
  expect(saveRegisteredAdminCompletedReference).toHaveBeenCalledWith(expect.objectContaining({
    shopUserId: 7, sessionId: sid, requestId: expect.any(String), startedAt: expect.any(Number),
  }), expect.any(Function));
  expect(saveRegisteredAdminCompletedReference.mock.invocationCallOrder[0])
    .toBeLessThan(clearRegisteredAdminChatReference.mock.invocationCallOrder[0]);
  expect(clearRegisteredAdminChatReference).toHaveBeenCalledTimes(1);
});

test('restored unresolved reference performs only exact GET and never another POST', async () => {
  const saved = { shopUserId: 7, sessionId: sid,
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
  readRegisteredAdminChatReference.mockReturnValue(saved);
  const transport = jest.fn(async url => {
    if (url.endsWith(`/chat/requests/${sid}/${saved.requestId}`)) return json({
      sessionId: sid, requestId: saved.requestId, status: 'unconfirmed',
    });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => expect(await current.recover()).toBe(false));
  expect(current.pending).toEqual(saved);
  expect(transport.mock.calls.map(([url]) => url)).toEqual([
    `/api/secureshop/agents/admin/chat/requests/${sid}/${saved.requestId}`,
  ]);
  expect(await current.send('Try again')).toBe(false);
});

test('failed parent ACK after saving exposes exact GET-only recovery without POST', async () => {
  const calls = [];
  const transport = jest.fn(async url => {
    calls.push(url);
    if (url.endsWith('/session')) return json({ sessionId: sid });
    throw Error(`Unexpected ${url}`);
  });
  saveRegisteredAdminChatReference.mockImplementation(async reference => {
    readRegisteredAdminChatReference.mockReturnValue(reference);
    throw Error('Parent ACK unavailable');
  });
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => expect(await current.send('Ask all registered tools')).toBe(false));
  expect(current.pending).toMatchObject({ shopUserId: 7, sessionId: sid,
    requestId: expect.any(String) });
  expect(current.status).toBe('unresolved');
  expect(calls).toEqual(['/api/secureshop/agents/admin/session']);
});

test('malformed saved results retain the UUID and never invent a completed reply', async () => {
  const saved = { shopUserId: 7, sessionId: sid,
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
  readRegisteredAdminChatReference.mockReturnValue(saved);
  let answer = { sessionId: sid, requestId: saved.requestId, status: 'unconfirmed', extra: true };
  const transport = jest.fn(async () => json(answer));
  await act(async () => root.render(<Probe transport={transport} />));
  await act(async () => expect(await current.recover()).toBe(false));
  expect(current.pending).toEqual(saved);
  answer = { sessionId: sid, requestId: saved.requestId, status: 'completed', replayed: true,
    result: { sessionId: sid, text: 'Wrong policy mode', stopReason: 'end_turn',
      hops: [], steps: 1, modeCapability: { ...mode, policyVersion: 'forged' } } };
  await act(async () => expect(await current.recover()).toBe(false));
  answer = { ...answer, result: { ...answer.result, modeCapability: mode, hops: [null] } };
  await act(async () => expect(await current.recover()).toBe(false));
  expect(current.turns[0].reply).toBe('');
  expect(clearRegisteredAdminChatReference).not.toHaveBeenCalled();
});

test('late protected GET cannot project a reply after credential renewal', async () => {
  const saved = { shopUserId: 7, sessionId: sid,
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
  readRegisteredAdminChatReference.mockReturnValue(saved);
  let finish;
  const transport = jest.fn(() => new Promise(resolve => { finish = resolve; }));
  await act(async () => root.render(<Probe transport={transport} />));
  let recovering;
  await act(async () => { recovering = current.recover(); });
  await act(async () => root.render(<Probe transport={transport} authorityKey="renewed" />));
  await act(async () => finish(json({ sessionId: sid, requestId: saved.requestId,
    status: 'completed', replayed: true, result: { sessionId: sid,
      text: 'Old credential reply', stopReason: 'end_turn', hops: [], steps: 1,
      modeCapability: mode } })));
  await act(async () => expect(await recovering).toBe(false));
  expect(current.turns[0].reply).toBe('');
  expect(clearRegisteredAdminChatReference).not.toHaveBeenCalled();
});

test('ordinary completed reload hydrates only the exact protected GET; pending takes precedence', async () => {
  const saved = { shopUserId: 7, sessionId: sid,
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
  readRegisteredAdminCompletedReference.mockReturnValue(saved);
  const transport = jest.fn(async url => {
    if (url.endsWith(`/chat/requests/${sid}/${saved.requestId}`)) return json({
      sessionId: sid, requestId: saved.requestId, status: 'completed', replayed: true,
      result: { sessionId: sid, text: 'Saved registered answer', stopReason: 'end_turn',
        hops: [], steps: 1, modeCapability: mode },
    });
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  expect(current.turns).toMatchObject([{ requestId: saved.requestId,
    reply: 'Saved registered answer', status: 'done' }]);
  expect(transport.mock.calls.map(([url]) => url)).toEqual([
    `/api/secureshop/agents/admin/chat/requests/${sid}/${saved.requestId}`,
  ]);
  await act(async () => root.unmount());
  root = createRoot(node);
  readRegisteredAdminChatReference.mockReturnValue(saved);
  transport.mockClear();
  await act(async () => root.render(<Probe transport={transport} />));
  expect(current.pending).toEqual(saved);
  expect(transport).not.toHaveBeenCalled();
});

test('description assessment reads and submits only the original verified saved turn', async () => {
  const saved = { shopUserId: 7, sessionId: sid,
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
  readRegisteredAdminCompletedReference.mockReturnValue(saved);
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith(`/chat/requests/${sid}/${saved.requestId}`)) return json({
      sessionId: sid, requestId: saved.requestId, status: 'completed', replayed: true,
      result: { sessionId: sid, text: 'Saved answer', stopReason: 'end_turn',
        hops: [], steps: 1, modeCapability: mode },
    });
    if (url.endsWith(`/chat/description-assessment/${sid}/${saved.requestId}`)) return json({
      completed: false, status: 'unconfirmed', modelEvaluated: false,
    });
    if (url.endsWith('/chat/description-assessment')) {
      expect(JSON.parse(options.body)).toEqual({ sessionId: sid, requestId: saved.requestId });
      return json({ completed: false, judgment: { verdict: 'fail',
        evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: false }, replayed: false });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  let result;
  await act(async () => { result = await current.readDescriptionAssessment({ sessionId: sid,
    requestId: saved.requestId }); });
  expect(result.kind).toBe('unconfirmed');
  await act(async () => { result = await current.submitDescriptionAssessment({ sessionId: sid,
    requestId: saved.requestId }); });
  expect(result).toMatchObject({ kind: 'judgment', completed: false,
    judgment: { verdict: 'fail' } });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/chat/description-assessment'))).toHaveLength(1);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/chat/assessment-retry'))).toHaveLength(0);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(0);
});

test('saved registered assessment reads and retries only the original completed turn', async () => {
  const saved = { shopUserId: 7, sessionId: sid,
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
  readRegisteredAdminCompletedReference.mockReturnValue(saved);
  const transport = jest.fn(async (url, options) => {
    if (url.endsWith(`/chat/requests/${sid}/${saved.requestId}`)) return json({
      sessionId: sid, requestId: saved.requestId, status: 'completed', replayed: true,
      result: { sessionId: sid, text: 'Saved answer', stopReason: 'end_turn',
        hops: [], steps: 1, modeCapability: mode },
    });
    if (url.endsWith(`/chat/assessment/${sid}/${saved.requestId}`)) return json({
      completed: false, status: 'unconfirmed', modelEvaluated: false,
    });
    if (url.endsWith('/chat/assessment-retry')) {
      expect(JSON.parse(options.body)).toEqual({ sessionId: sid, requestId: saved.requestId });
      return json({ completed: false, judgment: { verdict: 'unavailable',
        evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: true }, replayed: false });
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<Probe transport={transport} />));
  let result;
  await act(async () => { result = await current.readAssessment({ sessionId: sid, requestId: saved.requestId }); });
  expect(result.kind).toBe('unconfirmed');
  await act(async () => { result = await current.retryAssessment({ sessionId: sid, requestId: saved.requestId }); });
  expect(result).toMatchObject({ kind: 'judgment', completed: false,
    judgment: { verdict: 'unavailable' } });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/chat'))).toHaveLength(0);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/chat/assessment-retry'))).toHaveLength(1);
});
