import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { useManualListings } from './useManualListings';
import { attachShopStorage, SHOP_LISTINGS_KEY } from '../../utils/shopStorage.mjs';

jest.mock('../../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => ({ frame: true }) }));
const server = require('../../../../../../server/services/secureshopManualListingContract');
const scopeKey = 'a'.repeat(64), createScopeKey = 'b'.repeat(64), editScopeKey = 'c'.repeat(64);
const listing = { name: 'Exact title', description: 'Literal <b>raw</b>', price: 12.34,
  category: 'Books', images: ['https://images.test/a.png'], templateSource: '{{ title }}' };
const preview = server.makeManualListingPreview({ version: 1, origin: 'manual', kind: 'create', listing,
  currency: 'USD', initialStock: 0, status: 'active', scopeKey: createScopeKey });
const response = (value, status = 200) => ({ ok: status < 400, status, json: async () => value });
const readiness = response({ ready: true, scopeKey, createScopeKey, editScopeKey });
const unknown = operationId => response({ origin: 'manual', kind: 'create', operationId,
  status: 'not_found', scopeKey: createScopeKey });

let root, container, manual, transport, release, values, flush;
function Probe({ token = 'owner-a' }) { manual = useManualListings(token, 12, transport); return null; }
const render = (token = 'owner-a') => act(async () => root.render(<Probe token={token} />));
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  values = new Map(); flush = async () => {};
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => flush() });
  transport = jest.fn(async url => url.endsWith('/readiness') ? readiness : response(preview));
  container = document.createElement('div'); root = createRoot(container);
});
afterEach(async () => { if (root) await act(async () => root.unmount()); release?.(); });

test('preview is read-only, and host flush ACK precedes the one confirm POST', async () => {
  await render(); expect(manual.ready).toBe(true);
  const draft = { ...listing, images: [...listing.images] };
  let reviewed;
  await act(async () => { reviewed = await manual.preview('create', draft); });
  draft.images[0] = 'https://changed.test/';
  expect(reviewed.listing.images).toEqual(listing.images);
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/confirm'))).toHaveLength(0);
  let acknowledge;
  flush = () => new Promise(resolve => { acknowledge = resolve; });
  transport.mockImplementation(async url => {
    if (url.endsWith('/readiness')) return readiness;
    if (url.endsWith('/confirm')) throw Error('response lost');
    return response(preview);
  });
  let result;
  await act(async () => { result = manual.confirm('create', reviewed).catch(error => error); await new Promise(resolve => setTimeout(resolve, 5)); });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/confirm'))).toHaveLength(0);
  const savedRaw = values.get(SHOP_LISTINGS_KEY);
  expect(savedRaw).toContain('manualCreate');
  expect(savedRaw).not.toContain('Exact title');
  expect(savedRaw).not.toContain('https://images.test/a.png');
  await act(async () => { acknowledge(); expect((await result).message).toContain('response lost'); });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/confirm'))).toHaveLength(1);
  expect(manual.references.manualCreate.operationId).toBeTruthy();
});

test('persistence refusal prevents confirm POST and leaves no acknowledged reference', async () => {
  await render();
  let reviewed; await act(async () => { reviewed = await manual.preview('create', listing); });
  flush = async () => { throw Error('Host refused persistence'); };
  await act(async () => { await expect(manual.confirm('create', reviewed)).rejects.toThrow('Host refused persistence'); });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/confirm'))).toHaveLength(0);
  expect(manual.references.manualCreate).toBeUndefined();
});

test('lost response remains hash-only across remount; not_found recovery never repeats POST or clears unknown', async () => {
  await render();
  let reviewed; await act(async () => { reviewed = await manual.preview('create', listing); });
  transport.mockImplementation(async url => {
    if (url.endsWith('/readiness')) return readiness;
    if (url.endsWith('/confirm')) throw Error('response lost');
    if (url.includes('/operations/')) return unknown(url.split('/').pop());
    return response(preview);
  });
  await act(async () => { await expect(manual.confirm('create', reviewed)).rejects.toThrow('response lost'); });
  const saved = JSON.parse(values.get(SHOP_LISTINGS_KEY));
  expect(Object.keys(saved.manualCreate).sort()).toEqual(['digest', 'manualScopeKey', 'operationId', 'requestSha256', 'scopeKey']);
  await act(async () => root.unmount()); root = createRoot(container);
  await render();
  await act(async () => { expect((await manual.recover('create')).status).toBe('not_found'); });
  await act(async () => { await expect(manual.clearCompleted('create')).rejects.toThrow('Check the saved'); });
  await act(async () => { await expect(manual.preview('create', listing)).rejects.toThrow('Check the saved'); });
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/confirm'))).toHaveLength(1);
  expect(transport.mock.calls.filter(([url]) => url.includes('/operations/'))).toHaveLength(1);
});

test('context A→B→A cannot revive an old held preview response', async () => {
  let finish;
  transport = jest.fn(url => url.endsWith('/readiness') ? Promise.resolve(readiness)
    : new Promise(resolve => { finish = resolve; }));
  await render();
  let result;
  await act(async () => { result = manual.preview('create', listing).catch(error => error); await Promise.resolve(); });
  await render('owner-b'); await render('owner-a');
  await act(async () => { finish(response(preview)); expect((await result).message).toContain('session changed'); });
});

test('completed GET recovery enables explicit clear; wrong-origin receipt never clears or resends', async () => {
  await render();
  let reviewed; await act(async () => { reviewed = await manual.preview('create', listing); });
  transport.mockImplementation(async url => {
    if (url.endsWith('/readiness')) return readiness;
    if (url.endsWith('/confirm')) throw Error('response lost');
    return response(preview);
  });
  await act(async () => { await expect(manual.confirm('create', reviewed)).rejects.toThrow('response lost'); });
  const ref = manual.references.manualCreate;
  const completed = { version: 1, operationId: ref.operationId, productId: 19,
    status: 'completed', scopeKey: createScopeKey, requestSha256: ref.requestSha256,
    sourceSha256: 'd'.repeat(64), receiptSha256: 'e'.repeat(64), replayed: true,
    origin: 'manual', kind: 'create' };
  transport.mockImplementation(async url => {
    if (url.endsWith('/readiness')) return readiness;
    if (url.includes('/operations/')) return response({ ...completed, origin: 'assistant' });
    throw Error('unexpected write');
  });
  await act(async () => { await expect(manual.recover('create')).rejects.toThrow('Invalid saved listing receipt'); });
  expect(manual.references.manualCreate).toEqual(ref);
  await act(async () => { await expect(manual.clearCompleted('create')).rejects.toThrow('Check the saved'); });
  transport.mockImplementation(async url => {
    if (url.endsWith('/readiness')) return readiness;
    if (url.includes('/operations/')) return response(completed);
    throw Error('unexpected write');
  });
  await act(async () => { expect((await manual.recover('create')).productId).toBe(19); });
  expect(manual.terminal.manualCreate.status).toBe('completed');
  await act(async () => manual.clearCompleted('create'));
  expect(manual.references.manualCreate).toBeUndefined();
  expect(values.get(SHOP_LISTINGS_KEY)).not.toContain('manualCreate');
  expect(transport.mock.calls.filter(([url]) => url.endsWith('/confirm'))).toHaveLength(1);
});

test.each([
  [response({ error: 'unavailable' }, 503), 'HTTP 503'],
  [response({ ready: true, scopeKey, createScopeKey: 'bad', editScopeKey }), 'could not be verified'],
])('readiness failure is visible and retry remains GET-only', async (failed, message) => {
  let bad = true;
  transport = jest.fn(async url => url.endsWith('/readiness')
    ? bad ? failed : readiness : response(preview));
  await render();
  expect(manual.ready).toBe(false);
  expect(manual.checking).toBe(false);
  expect(manual.error).toContain(message);
  await act(async () => { await expect(manual.preview('create', listing)).rejects.toThrow('unavailable'); });
  bad = false;
  await act(async () => manual.retryReadiness());
  expect(manual.ready).toBe(true);
  expect(manual.error).toBeNull();
  expect(transport.mock.calls.every(([url]) => url.endsWith('/readiness'))).toBe(true);
});
