import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useSearchEchoAssessment } from './useSearchEchoAssessment.js';
import { createSearchEchoAssessmentStore } from '../utils/customerSearchEchoAssessmentReference.mjs';

const source = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', step: 2 };
const pending = { completed: false, status: 'unconfirmed', modelEvaluated: false };
const response = value => ({ ok: true, status: 200, headers: { get: () => 'application/json' },
  json: async () => value });

test('source IDs persist before one POST; remount and explicit recovery use GET only', async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const entries = new Map(), calls = [];
  const store = createSearchEchoAssessmentStore({ storage: {
    getItem: key => entries.get(key) ?? null,
    setItem: (key, value) => entries.set(key, value), removeItem: key => entries.delete(key),
  }, flush: async () => {} });
  const transport = async (url, init) => {
    calls.push([url, init.method, entries.size]); return response(pending);
  };
  let hook;
  const View = ({ authorityKey }) => { hook = useSearchEchoAssessment({ shopUserId: 7,
    authorityKey, transport, referenceStore: store }); return null; };
  const node = document.createElement('div'); document.body.append(node);
  const root = createRoot(node);
  await act(async () => root.render(<View authorityKey="launch-1" />));
  await act(async () => { expect(await hook.start(source)).toBe(true); });
  expect(calls.map(row => row[1])).toEqual(['POST', 'GET']);
  expect(calls[0][2]).toBe(1);
  expect(JSON.parse([...entries.values()][0])).toMatchObject({ ...source, shopUserId: 7 });
  await act(async () => root.render(<View authorityKey="launch-2" />));
  expect(calls.map(row => row[1])).toEqual(['POST', 'GET', 'GET']);
  await act(async () => { expect(await hook.check()).toBe(true); });
  expect(calls.map(row => row[1])).toEqual(['POST', 'GET', 'GET', 'GET']);
  expect(await hook.start({ ...source, step: 3 })).toBe(false);
  await act(async () => root.unmount()); node.remove();
});

test('response projection closes private fields and unknown verdicts', () => {
  const { decodeSearchEchoAssessment } = require('./useSearchEchoAssessment.js');
  expect(decodeSearchEchoAssessment(pending)).toEqual(pending);
  expect(() => decodeSearchEchoAssessment({ ...pending, echoHtml: '<img>' })).toThrow();
  expect(() => decodeSearchEchoAssessment({ completed: true, replayed: true,
    judgment: { evaluationId: source.sessionId, verdict: 'unknown', canRetry: false } })).toThrow();
});

test('explicit retry rechecks the same unconfirmed saved source before one same-ID POST', async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const entries = new Map(), calls = [];
  const store = createSearchEchoAssessmentStore({ storage: {
    getItem: key => entries.get(key) ?? null,
    setItem: (key, value) => entries.set(key, value), removeItem: key => entries.delete(key),
  }, flush: async () => {} });
  const transport = async (url, init) => {
    calls.push([url, init.method, init.body]);
    if (init.method === 'POST' && calls.filter(row => row[1] === 'POST').length === 1)
      throw Error('Original ACK unavailable');
    return response(pending);
  };
  let hook;
  const View = () => { hook = useSearchEchoAssessment({ shopUserId: 7,
    authorityKey: 'launch-1', transport, referenceStore: store }); return null; };
  const node = document.createElement('div'); document.body.append(node); const root = createRoot(node);
  await act(async () => root.render(<View />));
  await act(async () => { expect(await hook.start(source)).toBe(true); });
  expect(hook.outcome).toEqual(pending);
  expect(calls.map(row => row[1])).toEqual(['POST', 'GET']);
  await act(async () => { expect(await hook.retryUnconfirmed()).toBe(true); });
  expect(calls.map(row => row[1])).toEqual(['POST', 'GET', 'GET', 'POST', 'GET']);
  expect(JSON.parse(calls[0][2])).toEqual(source);
  expect(calls[3][2]).toBe(calls[0][2]);
  expect(entries.size).toBe(1);
  await act(async () => root.unmount()); node.remove();
});
