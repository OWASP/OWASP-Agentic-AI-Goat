import { createAdminSystemDiagnosticReferenceStore,
  decodeAdminSystemDiagnosticReference } from './adminSystemDiagnosticReference.mjs';
import { SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY, SHOP_TOKEN_KEY, SHOP_CART_KEY } from './shopStorage.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';

const reference = { shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  scopeKey: 'd'.repeat(64), proposalSha256: 'e'.repeat(64), startedAt: 123 };

test('opaque role diagnostic reference flushes before effect and survives closed frame storage', async () => {
  const values = new Map(); let flushes = 0;
  const store = createAdminSystemDiagnosticReferenceStore({ storage: {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  }, flush: async () => { flushes++; } });
  const saved = await store.save(reference);
  expect(flushes).toBe(1);
  expect(store.read(7)).toEqual(saved);
  expect(store.read(8)).toBeNull();
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY]: JSON.stringify(saved) })).not.toThrow();
  await expect(store.save(reference)).rejects.toThrow();
  await store.clear(saved);
  expect(store.read(7)).toBeNull();
});

test('diagnostic reference rejects command text and malformed identities', () => {
  for (const value of [
    { ...reference, version: 1, cmd_template: 'echo' },
    { ...reference, version: 1, proposalId: 'invalid' },
    { ...reference, version: 1, proposalSha256: 'x'.repeat(64) },
  ]) expect(() => decodeAdminSystemDiagnosticReference(JSON.stringify(value))).toThrow();
});
