import React, { StrictMode } from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import UploadZone from './UploadZone.jsx';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { SHOP_PRODUCT_MANUAL_KEY, SHOP_TOKEN_KEY, shopStorage, attachShopStorage } from '../utils/shopStorage.mjs';
import { createHash, webcrypto } from 'node:crypto';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: jest.fn() }));

const response = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  text: async () => JSON.stringify(body),
  json: async () => body,
});

const operationId = '123e4567-e89b-42d3-a456-426614174000';
const recoveryScopeKey = 'a'.repeat(64);
const sha256 = createHash('sha256').update('body').digest('hex');
const descriptor = { productId: '7', sha256, sizeBytes: '4', filename: 'manual.md',
  mime: 'text/markdown', public: 'true' };
const receipt = { productId: 7, sha256, sizeBytes: 4, filename: 'manual.md',
  mime: 'text/markdown', isPublic: true, chunkCount: 1, chunkIds: ['manual:1:0'],
  completedAt: '2026-10-19T00:00:00.000Z' };
const lookup = state => ({ version: 1, kind: 'product_manual', operationId,
  recoveryScopeKey, state, receipt: state === 'indexed' ? receipt : null });

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
};
const settleFileRead = async () => act(async () => {
  await new Promise(resolve => setTimeout(resolve, 15));
});
const fileBytes = file => new Promise((resolve, reject) => {
  const reader = new FileReader();
  reader.onerror = () => reject(reader.error);
  reader.onload = () => resolve(new Uint8Array(reader.result));
  reader.readAsArrayBuffer(file);
});

describe('UploadZone request lifecycle', () => {
  let container;
  let root;

  beforeEach(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    global.fetch = jest.fn();
    getBridgeFetchMetadata.mockReturnValue(null);
    localStorage.clear();
    Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    jest.restoreAllMocks();
  });

  const render = async (props = {}) => {
    await act(async () => root.render(<UploadZone kind="product_manual" {...props} />));
  };

  const choose = async (name = 'manual.md') => {
    const input = container.querySelector('input[type="file"]');
    const file = new File(['body'], name, { type: 'text/markdown' });
    Object.defineProperty(input, 'files', { configurable: true, value: [file] });
    await act(async () => input.dispatchEvent(new Event('change', { bubbles: true })));
  };

  const bound = async (props = {}) => {
    localStorage.setItem(SHOP_TOKEN_KEY, 'merchant-token');
    getBridgeFetchMetadata.mockImplementation(fetcher => fetcher === global.fetch ? { boundReviews: true } : null);
    await render({ scopeId: 7, authToken: 'merchant-token', merchantId: 12, transport: global.fetch, ...props });
  };

  test('manual consequence and product scope are visible before one explicit upload', async () => {
    await render({ scopeId: 7 });
    const notice = container.querySelector('[aria-label="Product manual upload consequence"]');
    expect(notice?.textContent).toContain('stores and indexes this file for product #7');
    expect(notice?.textContent).toContain('may influence later product answers and recommendations');
    expect(notice?.textContent).toContain('not a confidentiality guarantee');
    expect(notice?.textContent).not.toContain('will remain private');
    expect(global.fetch).not.toHaveBeenCalled();
    await choose('lesson.md');
    const publicChoice = container.querySelector('input[type="checkbox"]');
    await act(async () => publicChoice.click());
    expect(publicChoice.checked).toBe(false);
    expect(global.fetch).not.toHaveBeenCalled();
    global.fetch.mockResolvedValueOnce(response({ ok: true, kind: 'product_manual', scope_id: 7 }));
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [path, request] = global.fetch.mock.calls[0];
    expect(path).toBe('/api/secureshop/uploads');
    expect(request.method).toBe('POST');
    expect(request.body.get('kind')).toBe('product_manual');
    expect(request.body.get('scope_id')).toBe('7');
    expect(request.body.get('mime')).toBe('text/markdown');
    expect(request.body.get('public')).toBe('false');
    expect(request.body.get('file').name).toBe('lesson.md');
  });

  test('only calls onUploaded for HTTP success with ok true', async () => {
    const onUploaded = jest.fn();
    await render({ onUploaded });
    await choose();
    global.fetch.mockResolvedValueOnce(response({ ok: false, error: 'unavailable' }, 503));
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    expect(onUploaded).not.toHaveBeenCalled();
    expect(container.querySelector('pre').textContent).toContain('unavailable');
    global.fetch.mockResolvedValueOnce(response({ ok: true, id: 'upload-1' }));
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    expect(onUploaded).toHaveBeenCalledWith({ ok: true, id: 'upload-1' });
  });

  test('aborts and fences a stale request when scope changes', async () => {
    const pending = deferred();
    const onUploaded = jest.fn();
    global.fetch.mockImplementationOnce((url, options) => {
      expect(url).toBe('/api/secureshop/uploads');
      return pending.promise.then(() => response({ ok: true, id: 'stale' }));
    });
    await render({ scopeId: 7, onUploaded });
    await choose();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    const signal = global.fetch.mock.calls[0][1].signal;
    await render({ scopeId: 8, onUploaded });
    expect(signal.aborted).toBe(true);
    await act(async () => pending.resolve());
    expect(onUploaded).not.toHaveBeenCalled();
  });

  test('does not dispatch duplicate submits while one request is pending', async () => {
    const pending = deferred();
    global.fetch.mockReturnValueOnce(pending.promise);
    await render();
    await choose();
    const uploadButton = container.querySelector('button.ss-btn:not(.ss-btn--ghost)');
    await act(async () => { uploadButton.click(); uploadButton.click(); });
    expect(global.fetch).toHaveBeenCalledTimes(1);
    await act(async () => pending.resolve(response({ ok: true })));
  });

  test('aborts an in-flight request when unmounted', async () => {
    const pending = deferred();
    const onUploaded = jest.fn();
    global.fetch.mockImplementationOnce((url, options) => {
      expect(url).toBe('/api/secureshop/uploads');
      return pending.promise.then(() => response({ ok: true, id: 'unmounted' }));
    });
    await render({ onUploaded });
    await choose();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    const signal = global.fetch.mock.calls[0][1].signal;
    await act(async () => root.unmount());
    expect(signal.aborted).toBe(true);
    await act(async () => pending.resolve());
    expect(onUploaded).not.toHaveBeenCalled();
  });

  test('keeps successful uploads working through StrictMode effect replay', async () => {
    const onUploaded = jest.fn();
    global.fetch.mockResolvedValueOnce(response({ ok: true, id: 'strict' }));
    await act(async () => root.render(<StrictMode><UploadZone onUploaded={onUploaded} /></StrictMode>));
    await choose();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    expect(onUploaded).toHaveBeenCalledWith({ ok: true, id: 'strict' });
  });

  test('clears selected state and stale result when kind or scope changes', async () => {
    global.fetch.mockResolvedValueOnce(response({ ok: true, id: 'old' }));
    await render({ kind: 'avatar', scopeId: 7 });
    expect(container.querySelector('[aria-label="Product manual upload consequence"]')).toBeNull();
    await choose('old.txt');
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    expect(container.querySelector('pre').textContent).toContain('old');
    await render({ kind: 'product_manual', scopeId: 8 });
    expect(container.querySelector('[aria-label="Product manual upload consequence"]')?.textContent)
      .toContain('product #8');
    expect(container.querySelector('pre')).toBeNull();
    expect(container.querySelector('input[type="file"]').value).toBe('');
    expect(container.querySelector('button.ss-btn').textContent).toContain('Choose file');
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
  });

  test('bound upload preflights, persists a key before one POST, and accepts only indexed readback', async () => {
    const onUploaded = jest.fn();
    const seen = [];
    global.fetch.mockImplementation((url, options) => {
      seen.push([url, options]);
      if (options.method === 'GET') return Promise.resolve(response(lookup(seen.length === 1 ? 'not_found' : 'indexed')));
      expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
      expect(options.body.get('recoveryScopeKey')).toBe(recoveryScopeKey);
      return Promise.resolve(response({ ok: true, kind: 'product_manual', operationId }));
    });
    await bound({ onUploaded });
    expect(getBridgeFetchMetadata(global.fetch)).not.toBeNull();
    expect(shopStorage.getItem(SHOP_TOKEN_KEY)).toBe('merchant-token');
    await choose();
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(false);
    expect(global.fetch).not.toHaveBeenCalled();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    await settleFileRead();
    expect(container.querySelector('[role="alert"]')?.textContent).toBeFalsy();
    expect(seen.map(([, options]) => options.method)).toEqual(['GET', 'POST', 'GET']);
    const query = new URL(seen[0][0], window.location.origin).searchParams;
    expect(Object.fromEntries(query)).toEqual(descriptor);
    const posted = seen[1][1].body;
    expect(posted.get('file').name).toBe('manual.md');
    expect([...await fileBytes(posted.get('file'))]).toEqual([...new TextEncoder().encode('body')]);
    expect(Object.fromEntries([...posted.entries()].filter(([key]) => key !== 'file'))).toEqual({
      kind: 'product_manual', scope_id: '7', mime: 'text/markdown', public: 'true', recoveryScopeKey,
    });
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).toBeNull();
    expect(onUploaded).toHaveBeenCalledWith(receipt);
  });

  test('an already indexed initial GET skips POST and an uncertain POST reload recovers with GET only', async () => {
    const onUploaded = jest.fn();
    global.fetch.mockResolvedValueOnce(response(lookup('indexed')));
    await bound({ onUploaded });
    await choose();
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(false);
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    await settleFileRead();
    expect(container.querySelector('[role="alert"]')?.textContent).toBeFalsy();
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(onUploaded).toHaveBeenCalledWith(receipt);
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).toBeNull();

    onUploaded.mockClear();
    global.fetch.mockClear();
    global.fetch.mockResolvedValueOnce(response(lookup('not_found')))
      .mockRejectedValueOnce(new Error('lost response'));
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    await settleFileRead();
    expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'POST']);
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);

    await act(async () => root.unmount());
    root = createRoot(container);
    global.fetch.mockClear();
    await bound({ onUploaded });
    expect(container.textContent).toContain('Check saved upload');
    await choose('other.md');
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
    expect(container.textContent).not.toContain('manual.md');
    global.fetch.mockResolvedValueOnce(response(lookup('not_found')))
      .mockResolvedValueOnce(response(lookup('indexed')));
    const check = () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Check saved upload');
    await act(async () => check().click());
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
    expect(onUploaded).not.toHaveBeenCalled();
    await act(async () => check().click());
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).toBeNull();
    expect(onUploaded).toHaveBeenCalledWith(receipt);
    expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'GET']);
  });

  test('malformed initial indexed receipt never calls back or posts', async () => {
    const onUploaded = jest.fn();
    global.fetch.mockResolvedValueOnce(response({ ...lookup('indexed'),
      receipt: { ...receipt, sha256: 'b'.repeat(64) } }));
    await bound({ onUploaded });
    await choose();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    await settleFileRead();
    expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET']);
    expect(onUploaded).not.toHaveBeenCalled();
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).toBeNull();
    expect(container.querySelector('[role="alert"]')?.textContent).toBeTruthy();
  });

  test('malformed POST success leaves the saved reference for explicit GET-only recovery', async () => {
    const onUploaded = jest.fn();
    global.fetch.mockResolvedValueOnce(response(lookup('not_found')))
      .mockResolvedValueOnce(response({ ok: true, kind: 'product_manual', operationId: 'wrong' }))
      .mockResolvedValueOnce(response(lookup('indexed')));
    await bound({ onUploaded });
    await choose();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    await settleFileRead();
    expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'POST']);
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
    expect(onUploaded).not.toHaveBeenCalled();
    const check = [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Check saved upload');
    await act(async () => check.click());
    expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'POST', 'GET']);
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).toBeNull();
    expect(onUploaded).toHaveBeenCalledWith(receipt);
  });

  test('bound StrictMode replay never starts a request until the explicit click', async () => {
    localStorage.setItem(SHOP_TOKEN_KEY, 'merchant-token');
    getBridgeFetchMetadata.mockImplementation(fetcher => fetcher === global.fetch ? { boundReviews: true } : null);
    const onUploaded = jest.fn();
    global.fetch.mockResolvedValueOnce(response(lookup('indexed')));
    await act(async () => root.render(<StrictMode><UploadZone kind="product_manual" scopeId={7}
      merchantId={12} authToken="merchant-token" transport={global.fetch} onUploaded={onUploaded} /></StrictMode>));
    expect(global.fetch).not.toHaveBeenCalled();
    await choose();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    await settleFileRead();
    expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET']);
    expect(onUploaded).toHaveBeenCalledWith(receipt);
  });

  test('only an actual registered bridge transport activates the bound receipt path', async () => {
    const previousStreams = { ReadableStream: global.ReadableStream, WritableStream: global.WritableStream,
      TransformStream: global.TransformStream, MessagePort: global.MessagePort };
    Object.assign(global, require('node:stream/web'));
    global.MessagePort = require('node:worker_threads').MessagePort;
    const web = require('undici');
    const previous = { Request: global.Request, Response: global.Response, Headers: global.Headers };
    Object.assign(global, { Request: web.Request, Response: web.Response, Headers: web.Headers });
    try {
    const bridgeModule = jest.requireActual('../bridge/fetchAdapter.mjs');
    const bridge = { request: jest.fn(async name => {
      expect(name).toBe('uploads.productManual.receipt');
      return new Response(JSON.stringify(lookup('indexed')),
        { status: 200, headers: { 'content-type': 'application/json' } });
    }) };
    const transport = bridgeModule.createBridgeFetch({ bridge, origin: window.location.origin,
      getToken: () => 'merchant-token', boundReviews: true });
    getBridgeFetchMetadata.mockImplementation(bridgeModule.getBridgeFetchMetadata);
    expect(getBridgeFetchMetadata(transport)).not.toBeNull();
    localStorage.setItem(SHOP_TOKEN_KEY, 'merchant-token');
    const onUploaded = jest.fn();
    await render({ scopeId: 7, authToken: 'merchant-token', merchantId: 12,
      transport, onUploaded });
    await choose();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    await settleFileRead();
    expect(container.querySelector('[role="alert"]')?.textContent).toBeFalsy();
    expect(bridge.request).toHaveBeenCalledTimes(1);
    expect(global.fetch).not.toHaveBeenCalled();
    expect(onUploaded).toHaveBeenCalledWith(receipt);
    } finally { Object.assign(global, previous, previousStreams); }
  });

  test('double click during digest and GET cannot dispatch two POSTs', async () => {
    const waiting = deferred();
    global.fetch.mockReturnValueOnce(waiting.promise)
      .mockResolvedValueOnce(response({ ok: true, kind: 'product_manual', operationId }))
      .mockResolvedValueOnce(response(lookup('not_found')));
    await bound();
    await choose();
    const upload = container.querySelector('button.ss-btn:not(.ss-btn--ghost)');
    await act(async () => { upload.click(); upload.click(); });
    await settleFileRead();
    expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET']);
    await act(async () => waiting.resolve(response(lookup('not_found'))));
    expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'POST', 'GET']);
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
  });

  test('A→B→A on the same registered transport cannot complete an old preflight', async () => {
    const old = deferred();
    const onUploaded = jest.fn();
    global.fetch.mockReturnValueOnce(old.promise);
    await bound({ onUploaded });
    await choose();
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    await settleFileRead();
    expect(global.fetch).toHaveBeenCalledTimes(1);
    const oldSignal = global.fetch.mock.calls[0][1].signal;
    localStorage.setItem(SHOP_TOKEN_KEY, 'second-token');
    await render({ scopeId: 8, authToken: 'second-token', merchantId: 13,
      transport: global.fetch, onUploaded });
    expect(oldSignal.aborted).toBe(true);
    localStorage.setItem(SHOP_TOKEN_KEY, 'merchant-token');
    await render({ scopeId: 7, authToken: 'merchant-token', merchantId: 12,
      transport: global.fetch, onUploaded });
    await act(async () => old.resolve(response(lookup('indexed'))));
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).toBeNull();
    expect(onUploaded).not.toHaveBeenCalled();
    expect(container.querySelector('pre')).toBeNull();
  });

  test('transport switch and stale saved indexed recovery cannot clear the pending reference', async () => {
    const waiting = deferred();
    const onUploaded = jest.fn();
    localStorage.setItem(SHOP_PRODUCT_MANUAL_KEY, JSON.stringify({ version: 1,
      descriptor, operationId, recoveryScopeKey }));
    global.fetch.mockReturnValueOnce(waiting.promise);
    await bound({ onUploaded });
    const check = [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Check saved upload');
    await act(async () => check.click());
    expect(global.fetch).toHaveBeenCalledTimes(1);
    const oldSignal = global.fetch.mock.calls[0][1].signal;
    const nextTransport = jest.fn();
    getBridgeFetchMetadata.mockImplementation(fetcher =>
      [global.fetch, nextTransport].includes(fetcher) ? { boundReviews: true } : null);
    await render({ scopeId: 8, authToken: 'merchant-token', merchantId: 12,
      transport: nextTransport, onUploaded });
    expect(oldSignal.aborted).toBe(true);
    await act(async () => waiting.resolve(response(lookup('indexed'))));
    expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
    expect(onUploaded).not.toHaveBeenCalled();
    expect(container.querySelector('pre')).toBeNull();
    expect(nextTransport).not.toHaveBeenCalled();
  });

  test('authority change during acknowledged reserve leaves a pending reference and sends no POST', async () => {
    const flushing = deferred();
    const adapter = { getItem: key => localStorage.getItem(key),
      setItem: (key, value) => localStorage.setItem(key, value),
      removeItem: key => localStorage.removeItem(key), flush: () => flushing.promise };
    const release = attachShopStorage(adapter);
    try {
      global.fetch.mockResolvedValueOnce(response(lookup('not_found')));
      await bound();
      await choose();
      await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
      await settleFileRead();
      expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET']);
      expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
      localStorage.setItem(SHOP_TOKEN_KEY, 'second-token');
      await render({ scopeId: 8, authToken: 'second-token', merchantId: 13, transport: global.fetch });
      await act(async () => flushing.resolve());
      expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET']);
      expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
    } finally { release(); }
  });

  test('failed storage flush cannot authorize POST even when a reference was written', async () => {
    const adapter = { getItem: key => localStorage.getItem(key),
      setItem: (key, value) => localStorage.setItem(key, value),
      removeItem: key => localStorage.removeItem(key),
      flush: () => Promise.reject(new Error('parent storage unavailable')) };
    const release = attachShopStorage(adapter);
    try {
      global.fetch.mockResolvedValueOnce(response(lookup('not_found')));
      await bound();
      await choose();
      await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
      await settleFileRead();
      expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET']);
      expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
      expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
    } finally { release(); }
  });

  test('storage disconnection during receipt read cannot clear or call back', async () => {
    const waiting = deferred();
    const onUploaded = jest.fn();
    let disconnected = false;
    const adapter = { getItem: key => {
      if (disconnected) throw new Error('parent storage disconnected');
      return localStorage.getItem(key);
    }, setItem: (key, value) => localStorage.setItem(key, value),
    removeItem: key => localStorage.removeItem(key), flush: async () => {} };
    const release = attachShopStorage(adapter);
    try {
      localStorage.setItem(SHOP_PRODUCT_MANUAL_KEY, JSON.stringify({ version: 1,
        descriptor, operationId, recoveryScopeKey }));
      global.fetch.mockReturnValueOnce(waiting.promise);
      await bound({ onUploaded });
      const check = [...container.querySelectorAll('button')]
        .find(button => button.textContent === 'Check saved upload');
      await act(async () => check.click());
      expect(global.fetch.mock.calls.map(([, options]) => options.method)).toEqual(['GET']);
      disconnected = true;
      await act(async () => waiting.resolve(response(lookup('indexed'))));
      expect(localStorage.getItem(SHOP_PRODUCT_MANUAL_KEY)).not.toBeNull();
      expect(onUploaded).not.toHaveBeenCalled();
    } finally { release(); }
  });
});
