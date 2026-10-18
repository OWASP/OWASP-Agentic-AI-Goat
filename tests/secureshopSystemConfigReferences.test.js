'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const load = () => import('../client/src/pages/secureshop/pages/admin/systemConfigOperation.mjs');
const ref = () => ({ scopeKey: 'a'.repeat(64), operationId: randomUUID(), state: 'pending' });

test('System recovery codec accepts only bounded nonsecret identity metadata', async () => {
  const { encodeSystemConfigReferences: encode, decodeSystemConfigReferences: decode } = await load();
  const row = ref(); assert.deepEqual(decode(encode([row])), [row]); assert.deepEqual(decode(null), []);
  for (const key of ['path','content','token','requestSha256','error']) assert.throws(() => encode([{ ...row, [key]: 'private' }]));
  for (const raw of ['', '{}', 'null', 'x'.repeat(4097)]) assert.throws(() => decode(raw));
  assert.throws(() => encode([row, row])); assert.throws(() => encode(Array(2)));
});

test('unknown references are never silently evicted or downgraded', async () => {
  const { rememberSystemConfigReference: remember } = await load();
  const rows = Array.from({ length: 8 }, ref), snapshot = structuredClone(rows);
  assert.throws(() => remember(rows, ref()), /earlier System operation/);
  const changed = remember(rows, { ...rows[0], state: 'unknown' });
  assert.equal(changed.length, 8); assert.deepEqual(rows, snapshot);
  assert.throws(() => remember(changed, rows[0]), /changed/);
});

test('forgetting requires exact reference state and preserves sibling scopes', async () => {
  const { forgetSystemConfigReference: forget } = await load();
  const first = ref(), sibling = { ...first, scopeKey: 'b'.repeat(64) };
  assert.deepEqual(forget([first, sibling], first), [sibling]);
  assert.throws(() => forget([first], { ...first, state: 'unknown' }), /changed/);
  assert.throws(() => forget([sibling], first), /changed/);
});

test('parent persistence boundary rejects payload fields even when direct child storage bypasses wrapper', async () => {
  const { validateShopSnapshot } = await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
  const { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_SYSTEM_CONFIG_KEY } = await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
  const { encodeSystemConfigReferences } = await load();
  const base = { [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null };
  assert.equal(validateShopSnapshot(base)[SHOP_TOKEN_KEY], null);
  const good = encodeSystemConfigReferences([ref()]);
  assert.equal(validateShopSnapshot({ ...base, [SHOP_SYSTEM_CONFIG_KEY]: good })[SHOP_SYSTEM_CONFIG_KEY], good);
  const bad = JSON.stringify({ version: 1, references: [{ ...ref(), content: 'private payload' }] });
  assert.throws(() => validateShopSnapshot({ ...base, [SHOP_SYSTEM_CONFIG_KEY]: bad }));
});

test('System recovery persistence never hides storage or acknowledgement failures', async () => {
  const { createShopStorage, createShopStorageBinding, SHOP_SYSTEM_CONFIG_KEY } = await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
  const failure = new Error('storage unavailable');
  const storage = createShopStorage({ getStorage: () => ({
    getItem() { throw failure; }, setItem() { throw failure; }, removeItem() { throw failure; },
  }) });
  assert.throws(() => storage.getItem(SHOP_SYSTEM_CONFIG_KEY), error => error === failure);
  assert.throws(() => storage.setItem(SHOP_SYSTEM_CONFIG_KEY, '{}'), error => error === failure);
  assert.throws(() => storage.removeItem(SHOP_SYSTEM_CONFIG_KEY), error => error === failure);
  const binding = createShopStorageBinding({ local: storage });
  const release = binding.attach({ getItem: () => null, setItem() {}, removeItem() {}, async flush() { throw failure; } });
  await assert.rejects(binding.flush(), error => error === failure);
  release();
  assert.throws(() => binding.storage.getItem(SHOP_SYSTEM_CONFIG_KEY), { name: 'AbortError' });
  await assert.rejects(binding.flush(), { name: 'AbortError' });
});
