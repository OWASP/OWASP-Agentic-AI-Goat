'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { MessageChannel } = require('node:worker_threads');

const scenarioId = '11111111-1111-4111-8111-111111111111';
const reference = { shopUserId: 5, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1780000000000 };

test('customer chat reference crosses parent ACK and reload, then removes the empty key', async () => {
  const { createScopedShopStateStore, validateShopSnapshot } = await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
  const { createHostShopStateChannel, connectFrameShopState } = await import('../client/src/pages/secureshop/bridge/stateChannel.mjs');
  const { attachShopStorage, SHOP_CUSTOMER_CHAT_KEY } = await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
  const { readCustomerChatReference, saveCustomerChatReference, clearCustomerChatReference } = await import('../client/src/pages/secureshop/utils/customerChatReferences.mjs');
  const values = new Map();
  const storage = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key) };
  const open = async () => {
    const ports = new MessageChannel();
    const store = createScopedShopStateStore({ storage, scenarioId, generation: 1, isCurrent: () => true });
    const host = createHostShopStateChannel({ port: ports.port1, store });
    const frame = await connectFrameShopState({ port: ports.port2, timeoutMs: 1000 });
    return { host, frame, release: attachShopStorage(frame) };
  };
  let first;
  let second;
  try {
    first = await open();
    assert.equal(readCustomerChatReference(reference.shopUserId), null);
    await saveCustomerChatReference(reference);
    assert.deepEqual(readCustomerChatReference(reference.shopUserId), reference);
    assert.equal(JSON.stringify([...values.values()]).includes('Show my cart'), false);
    first.release(); first.frame.close(); first.host.close();
    second = await open();
    assert.deepEqual(readCustomerChatReference(reference.shopUserId), reference);
    await clearCustomerChatReference(reference);
    assert.equal(readCustomerChatReference(reference.shopUserId), null);
    const saved = JSON.parse([...values.values()][0]);
    assert.equal(Object.hasOwn(saved, SHOP_CUSTOMER_CHAT_KEY), false);

    const raw = JSON.stringify({ version: 1, references: [reference] });
    assert.equal(validateShopSnapshot({ secureshop_v2_token: null, ss_guest_cart: null,
      [SHOP_CUSTOMER_CHAT_KEY]: raw })[SHOP_CUSTOMER_CHAT_KEY], raw);
    for (const invalid of [
      '{}',
      JSON.stringify({ version: 1, references: [{ ...reference, message: 'raw prompt' }] }),
      JSON.stringify({ version: 1, references: [reference, { ...reference, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }] }),
    ]) assert.throws(() => validateShopSnapshot({ secureshop_v2_token: null,
      ss_guest_cart: null, [SHOP_CUSTOMER_CHAT_KEY]: invalid }));
  } finally {
    first?.release(); first?.frame.close(); first?.host.close();
    second?.release(); second?.frame.close(); second?.host.close();
  }
});
