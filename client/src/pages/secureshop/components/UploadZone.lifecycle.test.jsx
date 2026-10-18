import React, { StrictMode } from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import UploadZone from './UploadZone.jsx';

const response = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  text: async () => JSON.stringify(body),
});

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
};

describe('UploadZone request lifecycle', () => {
  let container;
  let root;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    global.fetch = jest.fn();
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
    await choose('old.txt');
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    expect(container.querySelector('pre').textContent).toContain('old');
    await render({ kind: 'product_manual', scopeId: 8 });
    expect(container.querySelector('pre')).toBeNull();
    expect(container.querySelector('input[type="file"]').value).toBe('');
    expect(container.querySelector('button.ss-btn').textContent).toContain('Choose file');
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
  });
});
