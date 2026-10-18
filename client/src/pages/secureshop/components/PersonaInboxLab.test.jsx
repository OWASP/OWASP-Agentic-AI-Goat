import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import PersonaInboxLab from './PersonaInboxLab.jsx';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const response = (body, ok = true) => Promise.resolve({ ok, json: async () => body });
let root; let container; let calls;
beforeEach(() => {
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
  calls = [];
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { randomUUID: jest.fn(() => '10000000-0000-4000-8000-000000000009') } });
  global.fetch = jest.fn((url, options = {}) => { calls.push([url, options]);
    return response({ ready: true, acl: { version: 1, mode: 'advisory' }, capabilities: { enforceAcl: true },
      messages: [{ messageId: 3, ownerShopUserId: 13, ownerShopRole: 'admin', subject: 'Support' }] });
  });
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });
const render = async key => act(async () => root.render(<PersonaInboxLab personaKey={key} />));

test('default-off readiness preserves the existing inbox without rendering controls', async () => {
  global.fetch.mockImplementation(() => response({ ready: false }));
  await render('12:merchant');
  expect(container.textContent).toBe('');
  expect(global.fetch).toHaveBeenCalledTimes(1);
});

test('trusted customer readiness does not offer the merchant ACL control', async () => {
  global.fetch.mockImplementation(() => response({ ready: true,
    acl: { version: 1, mode: 'advisory' }, capabilities: { enforceAcl: false }, messages: [] }));
  await render('11:customer');
  expect(container.textContent).toContain('Persona inbox access');
  expect(container.textContent).not.toContain('Enforce ACL');
});

test('retries the exact failed request ID and clears it only after success', async () => {
  let reads = 0;
  global.fetch.mockImplementation((url, options = {}) => {
    calls.push([url, options]);
    if (url.endsWith('/read')) {
      reads += 1;
      return reads === 1 ? response({ error: 'temporary' }, false)
        : response({ ok: true, stopReason: 'end_turn', accesses: [] });
    }
    return response({ ready: true, acl: { version: 1, mode: 'advisory' }, capabilities: { enforceAcl: true },
      messages: [{ messageId: 3, ownerShopUserId: 13, ownerShopRole: 'admin', subject: 'Support' }] });
  });
  await render('12:merchant');
  const read = () => [...container.querySelectorAll('button')].find(button => button.textContent.includes('Ask agent'));
  await act(async () => read().click());
  expect(container.querySelector('[role="alert"]').textContent).toContain('temporary');
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent.includes('Refresh')).click());
  await act(async () => read().click());
  const bodies = calls.filter(call => call[0].endsWith('/read')).map(call => JSON.parse(call[1].body));
  expect(bodies).toEqual([{ request_id: '10000000-0000-4000-8000-000000000009', message_id: 3 },
    { request_id: '10000000-0000-4000-8000-000000000009', message_id: 3 }]);
  expect(container.textContent).toContain('end_turn');
});

test('persona transition aborts old work and ignores its late completion', async () => {
  let resolveRead;
  global.fetch.mockImplementation((url, options = {}) => {
    calls.push([url, options]);
    if (url.endsWith('/read')) return new Promise(resolve => { resolveRead = resolve; });
    return response({ ready: true, acl: { version: 1, mode: 'advisory' }, capabilities: { enforceAcl: true },
      messages: [{ messageId: 3, ownerShopUserId: 13, ownerShopRole: 'admin', subject: 'Support' }] });
  });
  await render('12:merchant');
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent.includes('Ask agent')).click());
  const oldSignal = calls.find(call => call[0].endsWith('/read'))[1].signal;
  await render('13:admin');
  expect(oldSignal.aborted).toBe(true);
  await act(async () => resolveRead({ ok: true, json: async () => ({ ok: true, stopReason: 'late' }) }));
  expect(container.textContent).not.toContain('late');
});

test('enforced transition uses an empty server-authorized body and refreshes ACL state', async () => {
  let enforced = false;
  global.fetch.mockImplementation((url, options = {}) => {
    calls.push([url, options]);
    if (url.endsWith('/enforce')) { enforced = true; return response({ ok: true, acl: { version: 2, mode: 'enforced' } }); }
    return response({ ready: true, acl: { version: enforced ? 2 : 1, mode: enforced ? 'enforced' : 'advisory' }, capabilities: { enforceAcl: true },
      messages: [{ messageId: 3, ownerShopUserId: 13, ownerShopRole: 'admin', subject: 'Support' }] });
  });
  await render('12:merchant');
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent.includes('Enforce ACL')).click());
  const call = calls.find(row => row[0].endsWith('/enforce'));
  expect(call[1].body).toBe('{}');
  expect(container.querySelector('[data-testid="persona-inbox-acl"]').textContent).toContain('v2: enforced');
});

test('failed refresh preserves known content, disables effects and offers recovery', async () => {
  let loads = 0;
  global.fetch.mockImplementation(url => {
    loads += 1;
    if (loads === 2) return response({ error: 'temporarily unavailable' }, false);
    return response({ ready: true, acl: { version: 1, mode: 'advisory' },
      capabilities: { enforceAcl: true },
      messages: [{ messageId: 3, ownerShopUserId: 13, ownerShopRole: 'admin', subject: 'Support' }] });
  });
  await render('12:merchant');
  const refresh = () => [...container.querySelectorAll('button')].find(button => button.textContent.includes('Refresh'));
  await act(async () => refresh().click());
  expect(container.textContent).toContain('Support');
  expect(container.querySelector('[role="alert"]').textContent).toContain('Use Refresh to retry');
  expect([...container.querySelectorAll('button')].find(button => button.textContent.includes('Ask agent')).disabled).toBe(true);
  await act(async () => refresh().click());
  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect([...container.querySelectorAll('button')].find(button => button.textContent.includes('Ask agent')).disabled).toBe(false);
});
