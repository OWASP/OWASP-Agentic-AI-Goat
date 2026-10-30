import { assertSaved, clearPending, readOperation, readPending, savePending,
  requestReauthenticationForUnresolvedSelfChange } from './userAdminOperation.js';
import { SHOP_USER_ADMIN_KEY } from '../../utils/shopStorage.mjs';

const first = { scopeKey: 'owned-admin-scope', targetId: 7, action: 'set_role', role: 'merchant',
  operationId: '55555555-5555-5555-8555-555555555555', expectedVersion: '4' };
const replacement = { ...first, operationId: '66666666-6666-5666-8666-666666666666' };
function memory() {
  const values = new Map();
  return { getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
}
const deferred = () => { let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

test('foreign or unresolved saved user change blocks another save', async () => {
  const storage = memory();
  await savePending(first, storage);
  expect(() => readPending('other-admin-scope', storage)).toThrow('another administrator scope');
  await expect(savePending(replacement, storage)).rejects.toThrow('Check the saved user change');
  expect(assertSaved(first, storage)).toEqual(first);
});

test('parent ACK cannot admit a replaced saved request', async () => {
  const storage = memory(), ack = deferred();
  const saving = savePending(first, storage, () => ack.promise);
  storage.setItem(SHOP_USER_ADMIN_KEY, JSON.stringify(replacement));
  ack.resolve();
  await expect(saving).rejects.toThrow('differs from the confirmed request');
  expect(assertSaved(replacement, storage)).toEqual(replacement);
});

test('failed removal ACK restores only an absent exact reference', async () => {
  const storage = memory();
  await savePending(first, storage);
  await expect(clearPending(first, storage, async () => { throw Error('ACK lost'); })).rejects.toThrow('ACK lost');
  expect(assertSaved(first, storage)).toEqual(first);
  await expect(clearPending(first, storage, async () => {
    storage.setItem(SHOP_USER_ADMIN_KEY, JSON.stringify(replacement));
    throw Error('ACK lost');
  })).rejects.toThrow('ACK lost');
  expect(assertSaved(replacement, storage)).toEqual(replacement);
});

test('retired authority cannot restore an old reference after delayed failed ACK', async () => {
  const storage = memory(), ack = deferred();
  await savePending(first, storage);
  let current = true;
  const clearing = clearPending(first, storage, () => ack.promise, () => current);
  current = false;
  ack.reject(Error('ACK lost'));
  await expect(clearing).rejects.toThrow('ACK lost');
  expect(storage.getItem(SHOP_USER_ADMIN_KEY)).toBeNull();
});

test('only exact saved self-change can request sign-in after protected authority loss, without clearing it', async () => {
  const storage = memory();
  const nonce = 'a'.repeat(64);
  const scopeKey = JSON.stringify(['launch', 1, 2, 3, 7, 'actor-session']);
  const self = { ...first, scopeKey, targetId: 7, role: 'merchant' };
  await savePending(self, storage);
  const postMessage = jest.fn();
  const frame = { location: { hash: `#${nonce}` }, document: { baseURI: 'https://shop.example/standalone' },
    parent: { postMessage } };
  const before = storage.getItem(SHOP_USER_ADMIN_KEY);
  requestReauthenticationForUnresolvedSelfChange(self, 7, () => true, frame, storage);
  expect(postMessage).toHaveBeenCalledWith({ channel: 'owasp-ai-goat-secureshop-standalone-session-v1',
    type: 'auth-required', nonce }, 'https://shop.example');
  expect(storage.getItem(SHOP_USER_ADMIN_KEY)).toBe(before);
  postMessage.mockClear();
  for (const [row, actor, active, hash] of [
    [self, 8, true, `#${nonce}`], [self, 7, false, `#${nonce}`],
    [self, 7, true, '#bad'], [{ ...self, operationId: replacement.operationId }, 7, true, `#${nonce}`],
  ]) {
    frame.location.hash = hash;
    expect(() => requestReauthenticationForUnresolvedSelfChange(row, actor, () => active, frame, storage)).toThrow();
    expect(storage.getItem(SHOP_USER_ADMIN_KEY)).toBe(before);
  }
  expect(postMessage).not.toHaveBeenCalled();
});

test('operation GET distinguishes auth loss from 404 and network uncertainty without treating either as success', async () => {
  for (const status of [401, 403]) {
    await expect(readOperation(first, async () => ({ ok: false, status })))
      .rejects.toMatchObject({ code: 'ADMIN_AUTH_CHANGED', status });
  }
  await expect(readOperation(first, async () => ({ ok: false, status: 404 })))
    .rejects.toMatchObject({ code: 'OPERATION_NOT_OBSERVED' });
  await expect(readOperation(first, async () => { throw Error('network unknown'); }))
    .rejects.toThrow('network unknown');
});
