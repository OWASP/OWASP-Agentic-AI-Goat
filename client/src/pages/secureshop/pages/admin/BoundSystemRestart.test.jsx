import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import BoundSystemRestart from './BoundSystemRestart.jsx';
import { SHOP_SYSTEM_RESTART_KEY } from '../../utils/shopStorage.mjs';
import { restartHash, restartResult, verifiedRestartResult, restartAdministration } from './systemRestartOperation.mjs';
import { validateShopSnapshot } from '../../bridge/stateStore.mjs';
const { webcrypto } = require('node:crypto');
const targetId = '00000000-0000-4000-8000-000000000011';
const before = '00000000-0000-4000-8000-000000000012', after = '00000000-0000-4000-8000-000000000013';
const response = (value, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => value });
const admin = () => response({ ok: true, administration: { restartCapability: 'secureshop-owned-system-restart.v1', targetId } });
const completed = async request => ({ ok: true, state: 'completed', operationId: request.operationId, targetId, requestSha256: await restartHash(request), receipt: {
  beforeInstanceId: before, afterInstanceId: after, beforeGeneration: 1, afterGeneration: 2, effectSha256: 'a'.repeat(64), outputSha256: 'b'.repeat(64), outputBytes: 0,
} });
let root, container;
beforeEach(() => {
  Object.defineProperty(global.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: webcrypto.randomUUID.bind(webcrypto) });
  localStorage.clear(); global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); jest.restoreAllMocks(); });
const pause = () => new Promise(resolve => setTimeout(resolve, 30));
const mount = async (token = 'admin') => { await act(async () => { root.render(<BoundSystemRestart authToken={token} transport={global.fetch} />); await pause(); }); await act(pause); };
const click = async text => act(async () => { [...container.querySelectorAll('button')].find(button => button.textContent === text).click(); await pause(); });

test('persists acknowledged opaque reference before POST and validates completed instance change', async () => {
  let persisted;
  global.fetch = jest.fn(async (_, options = {}) => {
    if (!options.method) return admin();
    persisted = JSON.parse(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY));
    return response(await completed(JSON.parse(options.body)));
  });
  await mount(); await click('restart');
  expect(persisted.references).toHaveLength(1);
  expect(Object.keys(persisted.references[0]).sort()).toEqual(['operationId', 'scopeKey', 'state']);
  expect(container.textContent).toContain('Owned service restarted. Receipt verified.');
  expect(JSON.parse(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY)).references[0]).toMatchObject({ state: 'completed' });
});

test('completed restart receipt survives remount and readback performs only GET', async () => {
  let request, posts = 0, reads = 0;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (options.method === 'POST') { posts++; request = JSON.parse(options.body); return response(await completed(request)); }
    if (url.includes('/restart-operations/')) { reads++; return response(await completed(request)); }
    if (!options.method) return admin();
    throw new Error(`Unexpected request ${url}`);
  });
  await mount(); await click('restart');
  const saved = JSON.parse(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY));
  const reference = saved.references[0];
  expect(reference).toMatchObject({ operationId: request.operationId, state: 'completed' });
  expect(Object.keys(reference).sort()).toEqual(['operationId', 'scopeKey', 'state']);
  expect(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY)).not.toContain('nginx');

  await act(async () => root.unmount()); root = createRoot(container);
  global.fetch.mockClear();
  await mount();
  expect(container.textContent).toContain(`Saved restart ${request.operationId} · completed`);
  await click('check restart outcome');
  expect(global.fetch.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(0);
  expect(global.fetch.mock.calls.filter(([url]) => url.includes(`/restart-operations/${request.operationId}`))).toHaveLength(1);
  expect(container.textContent).toContain('Receipt verified');
  expect(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY)).toBeNull();
});

test('lost response survives remount and recovery performs only GET', async () => {
  let request, posts = 0;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (options.method) { posts++; request = JSON.parse(options.body); throw new Error('Response lost'); }
    if (url.includes('restart-operations')) return response(await completed(request));
    return admin();
  });
  await mount(); await click('restart');
  const raw = localStorage.getItem(SHOP_SYSTEM_RESTART_KEY);
  expect(JSON.parse(raw).references[0].state).toBe('unknown');
  expect(raw).not.toContain('nginx');
  expect(() => validateShopSnapshot({ secureshop_v2_token: null, ss_guest_cart: null, [SHOP_SYSTEM_RESTART_KEY]: raw })).not.toThrow();
  await act(async () => root.unmount()); root = createRoot(container);
  await mount(); await click('check restart outcome');
  expect(posts).toBe(1); expect(container.textContent).toContain('Receipt verified');
  expect(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY)).toBeNull();
});

test('failed persistence prevents POST', async () => {
  const write = Storage.prototype.setItem;
  jest.spyOn(Storage.prototype, 'setItem').mockImplementation(function (key, value) { if (key === SHOP_SYSTEM_RESTART_KEY) throw new Error('Storage full'); return write.call(this, key, value); });
  global.fetch = jest.fn(async () => admin());
  await mount(); await click('restart');
  expect(global.fetch.mock.calls.some(([, options]) => options.method === 'POST')).toBe(false);
  expect(container.textContent).toContain('Storage full');
});

test('stale transport response cannot overwrite current authority or remove recovery reference', async () => {
  let resolve, request;
  global.fetch = jest.fn(async (_, options = {}) => {
    if (!options.method) return admin();
    request = JSON.parse(options.body); return new Promise(done => { resolve = done; });
  });
  await mount(); await click('restart');
  global.fetch = jest.fn(async () => admin()); await mount('new-admin');
  await act(async () => { resolve(response(await completed(request))); await pause(); });
  expect(container.textContent).not.toContain('Receipt verified');
  expect(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY)).not.toBeNull();
});

test('mismatched target, request digest, unchanged instance, or generation jumps cannot render success', async () => {
  const request = { version: 1, operationId: before, name: 'nginx' }, value = await completed(request);
  for (const changed of [{ ...value, receipt: { ...value.receipt, outputBytes: 65537 } }, { ...value, targetId: after }, { ...value, requestSha256: 'c'.repeat(64) }, { ...value, receipt: { ...value.receipt, afterInstanceId: before } }, { ...value, receipt: { ...value.receipt, afterGeneration: 3 } }]) {
    expect(() => restartResult(changed, request, targetId, value.requestSha256)).toThrow('Invalid restart response');
  }
});

test('unavailable capability does not enable legacy or bound POST', async () => {
  global.fetch = jest.fn(async () => response({ ok: false }, 503));
  await mount(); expect(container.querySelector('button[type="submit"]').disabled).toBe(true);
  expect(global.fetch.mock.calls).toHaveLength(1);
});

test('pending and uncertain operations retain references and disable a second restart', async () => {
  let request, uncertain = false;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (options.method) { request = JSON.parse(options.body); return response({ ok: false, state: 'running', operationId: request.operationId, automaticRetry: false }, 202); }
    if (url.includes('restart-operations')) return response({ ok: false, state: 'failed', operationId: request.operationId, failureCode: uncertain ? 'OUTCOME_UNCERTAIN' : 'EXECUTION_FAILED', automaticRetry: false });
    return admin();
  });
  await mount(); await click('restart');
  expect(container.querySelector('button[type="submit"]').disabled).toBe(true);
  uncertain = true; await click('check restart outcome');
  expect(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY)).not.toBeNull();
  expect(container.textContent).not.toContain('Receipt verified');
  uncertain = false; await click('check restart outcome');
  expect(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY)).toBeNull();
  expect(global.fetch.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(1);
});

test('corrupt recovery metadata leaves capability disabled without deleting the record', async () => {
  localStorage.setItem(SHOP_SYSTEM_RESTART_KEY, '{bad');
  global.fetch = jest.fn(async () => admin());
  await mount();
  expect(container.querySelector('button[type="submit"]').disabled).toBe(true);
  expect(localStorage.getItem(SHOP_SYSTEM_RESTART_KEY)).toBe('{bad');
});

test('v2 owned output verifies exact UTF-8 bytes and hash without treating output as HTML', async () => {
 const request={version:1,operationId:before,name:'nginx; whoami'};
 const value=await completed(request); const text='<script>lab</script>\nowned-user';
 value.receipt.outputText=text;value.receipt.outputBytes=new TextEncoder().encode(text).length;
 value.receipt.outputSha256=require('node:crypto').createHash('sha256').update(text).digest('hex');
 expect((await verifiedRestartResult(value,request,targetId)).receipt.outputText).toBe(text);
 expect(restartAdministration({ok:true,administration:{restartCapability:'secureshop-owned-system-restart.v2',targetId}}).targetId).toBe(targetId);
 await expect(verifiedRestartResult({...value,receipt:{...value.receipt,outputText:'tampered'}},request,targetId)).rejects.toThrow('Invalid restart response');
 await expect(verifiedRestartResult({...value,receipt:{...value.receipt,outputSha256:'0'.repeat(64)}},request,targetId)).rejects.toThrow('Invalid restart response');
 await expect(verifiedRestartResult({...value,receipt:{...value.receipt,outputText:'x'.repeat(16385),outputBytes:16385}},request,targetId)).rejects.toThrow('Invalid restart response');
 expect((await verifiedRestartResult(await completed(request),request,targetId)).receipt.outputText).toBeUndefined();
});
