/* eslint-disable testing-library/no-unnecessary-act */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import useWorkshopResetController from './useWorkshopResetController';

beforeEach(() => { sessionStorage.clear(); globalThis.IS_REACT_ACT_ENVIRONMENT = true; });
function mount(options) {
  let controller;
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  function Harness() { controller = useWorkshopResetController({
    owner: { attendeeId: '7', workshopKey: 'ipi', scenarioId: 'document' },
    operationStorageKey: 'owasp-ai-goat:test:7:document', ...options,
  }); return null; }
  act(() => root.render(<Harness />));
  return { get controller() { return controller; }, close() { act(() => root.unmount()); node.remove(); } };
}

test('failed reset keeps its operation through cancellation and page remount, then clears after success', async () => {
  const attempts = [];
  const first = mount({ mutation: async ({ operationId }) => { attempts.push(operationId); throw Error('interrupted'); } });
  await act(async () => { await first.controller.confirmReset(); });
  const operation = attempts[0]; expect(operation).toMatch(/^[a-f0-9-]{36}$/);
  act(() => first.controller.cancelReset()); first.close();
  expect(sessionStorage.getItem('owasp-ai-goat:test:7:document')).toBe(operation);
  const next = mount({ mutation: async ({ operationId }) => { attempts.push(operationId); } });
  await act(async () => { await next.controller.confirmReset(); });
  expect(attempts).toEqual([operation, operation]);
  expect(sessionStorage.getItem('owasp-ai-goat:test:7:document')).toBe(null);
  await act(async () => { await next.controller.confirmReset(); });
  expect(attempts[2]).not.toBe(operation);
  next.close();
});

test('retry operation storage is scoped to the authenticated owner and scenario', async () => {
  sessionStorage.setItem('owasp-ai-goat:test:7:document', '11111111-1111-4111-8111-111111111111');
  let received;
  const f = mount({ operationStorageKey: 'owasp-ai-goat:test:8:document', mutation: async ({ operationId }) => { received = operationId; } });
  await act(async () => { await f.controller.confirmReset(); });
  expect(received).not.toBe('11111111-1111-4111-8111-111111111111');
  expect(sessionStorage.getItem('owasp-ai-goat:test:7:document')).toBe('11111111-1111-4111-8111-111111111111');
  f.close();
});

test('client reconciliation failure retains operation so retry cannot erase newer data', async () => {
  const ids = []; let fail = true;
  const f = mount({ mutation: async ({ operationId }) => { ids.push(operationId); }, onCommit: async () => { if (fail) { fail = false; throw Error('refresh interrupted'); } } });
  await act(async () => { await f.controller.confirmReset(); });
  await act(async () => { await f.controller.confirmReset(); });
  expect(ids[0]).toBe(ids[1]);
  expect(sessionStorage.getItem('owasp-ai-goat:test:7:document')).toBe(null);
  f.close();
});

test('late invalidated reset cannot unlock another in-flight reset', async () => {
  const releases = []; let calls = 0;
  const f = mount({ mutation: () => { calls++; return new Promise(resolve => releases.push(resolve)); } });
  let first, second;
  act(() => { first = f.controller.confirmReset(); });
  act(() => f.controller.invalidate());
  act(() => { second = f.controller.confirmReset(); });
  await act(async () => { releases[0](); await first; });
  await act(async () => { expect(await f.controller.confirmReset()).toBe(false); });
  expect(calls).toBe(2);
  await act(async () => { releases[1](); await second; });
  f.close();
});

test('unmounted reset cannot reconcile stale UI or clear a recoverable operation', async () => {
  let release; const commit = jest.fn();
  const f = mount({ mutation: () => new Promise(resolve => { release = resolve; }), onCommit: commit });
  let pending; act(() => { pending = f.controller.confirmReset(); });
  const operation = sessionStorage.getItem('owasp-ai-goat:test:7:document');
  f.close();
  await act(async () => { release(); await pending; });
  expect(commit).not.toHaveBeenCalled();
  expect(sessionStorage.getItem('owasp-ai-goat:test:7:document')).toBe(operation);
});
