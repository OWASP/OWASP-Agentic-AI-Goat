import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { useBoundRoleAssistant } from './useBoundRoleAssistant.js';
import { readRoleAssistantReference, saveRoleAssistantReference,
  clearRoleAssistantReference } from '../utils/roleAssistantReferences.mjs';
import { readRoleAssistantCompletedReference, saveRoleAssistantCompletedReference } from
  '../utils/roleAssistantCompletedReferences.mjs';

jest.mock('../utils/roleAssistantReferences.mjs', () => ({
  readRoleAssistantReference: jest.fn(), saveRoleAssistantReference: jest.fn(),
  clearRoleAssistantReference: jest.fn(),
}));
jest.mock('../utils/roleAssistantCompletedReferences.mjs', () => ({
  readRoleAssistantCompletedReference: jest.fn(),
  saveRoleAssistantCompletedReference: jest.fn(),
  clearRoleAssistantCompletedReference: jest.fn(),
  sameRoleAssistantReference: (a, b) => !!a && !!b && a.role === b.role
    && a.shopUserId === b.shopUserId && a.sessionId === b.sessionId
    && a.requestId === b.requestId && a.startedAt === b.startedAt,
}));

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const modes = {
  merchant: { version: 1, featureId: 'merchant_assistant', effectiveMode: 'vuln',
    policyVersion: 'owned-merchant-read-and-confirmation-v1',
    scope: { kind: 'launch_feature', id: 'merchant_assistant' } },
  admin: { version: 1, featureId: 'admin_assistant', effectiveMode: 'fixed',
    policyVersion: 'owned-admin-read-and-confirmation-v1',
    scope: { kind: 'launch_feature', id: 'admin_assistant' } },
};
const json = value => ({ ok: true, headers: { get: () => 'application/json' },
  json: async () => value });
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
let root, host, assistant;
function Probe({ role, transport }) {
  assistant = useBoundRoleAssistant({ role, shopUserId: 7,
    authorityKey: 'original-persona-token', transport });
  return <span>{assistant.status}</span>;
}

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  host = document.createElement('div'); document.body.append(host); root = createRoot(host);
  let saved = null;
  readRoleAssistantReference.mockImplementation(() => saved);
  saveRoleAssistantReference.mockImplementation(async value => { saved = value; });
  clearRoleAssistantReference.mockImplementation(async value => {
    if (saved?.requestId === value.requestId) saved = null;
  });
  readRoleAssistantCompletedReference.mockReturnValue(null);
  saveRoleAssistantCompletedReference.mockResolvedValue();
});
afterEach(async () => {
  await act(async () => root.unmount()); host.remove(); jest.clearAllMocks();
});

test.each(['merchant', 'admin'])(
  '%s stops only local observation after saved ACK and recovers the exact request by GET',
  async role => {
    let releaseRead, cancelled = 0, chatSignal, acknowledge, stored = null;
    readRoleAssistantReference.mockImplementation(() => stored);
    saveRoleAssistantReference.mockImplementation(value => new Promise(resolve => {
      acknowledge = () => { stored = value; resolve(); };
    }));
    const calls = [];
    const transport = jest.fn(async (url, options = {}) => {
      calls.push({ url, options });
      if (url.endsWith('/session')) return json({ sessionId });
      if (url.endsWith('/chat')) {
        chatSignal = options.signal;
        return { ok: true, headers: { get: () => 'text/event-stream; charset=utf-8' },
          body: { getReader: () => ({
            read: () => new Promise(resolve => { releaseRead = resolve; }),
            cancel: async () => { cancelled += 1; },
          }) } };
      }
      if (url.includes('/operations/')) {
        const saved = saveRoleAssistantReference.mock.calls[0][0];
        expect(url).toBe(`/api/secureshop/agents/${role}/assistant/operations/${saved.sessionId}/${saved.requestId}`);
        return json({ sessionId: saved.sessionId, requestId: saved.requestId,
          status: 'completed', replayed: true, text: 'Saved answer',
          stopReason: 'end_turn', hops: [], cards: [], modeCapability: modes[role] });
      }
      throw new Error(`Unexpected ${url}`);
    });
    await act(async () => root.render(<Probe role={role} transport={transport} />));
    let sending;
    await act(async () => { sending = assistant.send('Show my saved information'); await tick(); });
    expect(saveRoleAssistantReference).toHaveBeenCalledTimes(1);
    expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(0);
    expect(assistant.canStopWatching).toBe(false);
    expect(await assistant.stopWatching()).toBe(false);
    await act(async () => { acknowledge(); await tick(); });
    const reference = saveRoleAssistantReference.mock.calls[0]?.[0];
    expect(reference).toMatchObject({ role, shopUserId: 7, sessionId,
      requestId: expect.any(String) });
    expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(1);
    expect(assistant.canStopWatching).toBe(true);

    await act(async () => { expect(await assistant.stopWatching()).toBe(true); });
    expect(chatSignal.aborted).toBe(true);
    expect(assistant.status).toBe('unresolved');
    expect(assistant.pending).toEqual(reference);
    expect(readRoleAssistantReference()).toEqual(reference);
    expect(clearRoleAssistantReference).not.toHaveBeenCalled();
    expect(calls.some(call => call.url.includes('/operations/'))).toBe(false);

    const lateDone = `event: done\ndata: ${JSON.stringify({ sessionId,
      requestId: reference.requestId, stopReason: 'end_turn',
      modeCapability: modes[role] })}\n\n`;
    await act(async () => {
      releaseRead({ done: false, value: new TextEncoder().encode(lateDone) });
      expect(await sending).toBe(false);
    });
    expect(cancelled).toBeGreaterThanOrEqual(1);
    expect(assistant.turns.at(-1).status).not.toBe('done');
    expect(saveRoleAssistantCompletedReference).not.toHaveBeenCalled();
    expect(calls.some(call => call.url.includes('/operations/'))).toBe(false);

    await act(async () => { expect(await assistant.send('Do not send twice')).toBe(false); });
    expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(1);
    await act(async () => { expect(await assistant.recover()).toBe(true); });
    expect(calls.filter(call => call.url.includes('/operations/'))).toHaveLength(1);
    expect(calls.filter(call => call.url.endsWith('/chat'))).toHaveLength(1);
    expect(assistant.turns.at(-1)).toMatchObject({ requestId: reference.requestId,
      reply: 'Saved answer', status: 'done' });
    expect(clearRoleAssistantReference).toHaveBeenCalledTimes(1);
    expect(assistant.pending).toBeNull();
  },
);
