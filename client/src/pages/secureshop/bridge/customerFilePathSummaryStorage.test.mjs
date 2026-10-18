import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { validateShopSnapshot } from './stateStore.mjs';
import { createShopStorage, SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY,
  SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY, SHOP_CUSTOMER_FILE_SUMMARY_KEY } from '../utils/shopStorage.mjs';
import { createCustomerFilePathSummaryStore, createCustomerFilePathSummaryAssessmentStore,
  CUSTOMER_FILE_PATH_SUMMARY_KEY, CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY } from '../utils/customerFilePathSummaryReference.mjs';
const entry = { version: 1, shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 100 };
const keys = [SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY];
const snapshot = values => ({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null, ...values });

test('fresh V44 frame reads absent references and acknowledges save and clear through a real MessageChannel', () => {
  // Native MessagePort cloning targets Node's realm; Jest modules use a VM
  // realm. Run the unmodified channel and strict prototype validator together
  // in Node instead of loosening production validation for the test runner.
  const moduleUrl = name => pathToFileURL(require.resolve(name)).href;
  const script = `
    import assert from 'node:assert/strict';
    import { MessageChannel } from 'node:worker_threads';
    import { createHostShopStateChannel, connectFrameShopState } from ${JSON.stringify(moduleUrl('./stateChannel.mjs'))};
    import { createScopedShopStateStore } from ${JSON.stringify(moduleUrl('./stateStore.mjs'))};
    import { createShopStorage, SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY } from ${JSON.stringify(moduleUrl('../utils/shopStorage.mjs'))};
    import { createCustomerFilePathSummaryStore, createCustomerFilePathSummaryAssessmentStore } from ${JSON.stringify(moduleUrl('../utils/customerFilePathSummaryReference.mjs'))};
    const entry = ${JSON.stringify(entry)};
    const keys = [SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY];
  const rows = new Map(), ports = new MessageChannel();
  const store = createScopedShopStateStore({ storage: {
    getItem: key => rows.get(key) ?? null, setItem: (key, value) => rows.set(key, value),
  }, scenarioId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', generation: 1, isCurrent: () => true });
  const host = createHostShopStateChannel({ port: ports.port1, store });
  let frame;
  try {
    frame = await connectFrameShopState({ port: ports.port2, timeoutMs: 1000 });
    const storage = createShopStorage({ getStorage: () => frame });
    const stores = [createCustomerFilePathSummaryStore, createCustomerFilePathSummaryAssessmentStore]
      .map(create => create({ storage, flush: () => frame.flush() }));
    for (let i = 0; i < keys.length; i++) {
      assert.equal(frame.getItem(keys[i]), null);
      assert.equal(stores[i].read(7), null);
      assert.equal(Object.hasOwn(store.read(), keys[i]), false);
    }
    for (const reference of stores) await reference.submit(entry);
    for (let i = 0; i < keys.length; i++) {
      assert.deepEqual(stores[i].read(7), entry);
      assert.equal(stores[i].read(8), null);
      assert.deepEqual(JSON.parse(frame.getItem(keys[i])), entry);
      assert.deepEqual(JSON.parse(store.read()[keys[i]]), entry);
    }
    assert.throws(() => frame.getItem('secureshop.customer-file-path-summary.unknown'), /Unsupported shop key/);
    assert.throws(() => frame.setItem('secureshop.customer-file-path-summary.unknown', JSON.stringify(entry)));
    assert.throws(() => frame.removeItem('secureshop.customer-file-path-summary.unknown'));
    for (const key of keys) {
      assert.throws(() => frame.setItem(key, 'not JSON'));
      assert.throws(() => frame.setItem(key, JSON.stringify({ ...entry, path: '../etc/passwd' })));
      assert.deepEqual(JSON.parse(store.read()[key]), entry);
    }
    for (const reference of stores) await reference.clear(entry);
    for (let i = 0; i < keys.length; i++) {
      assert.equal(frame.getItem(keys[i]), null);
      assert.equal(stores[i].read(7), null);
      assert.equal(Object.hasOwn(store.read(), keys[i]), false);
    }
  } finally { frame?.close(); host.close(); }
  `;
  expect(() => execFileSync(process.execPath, ['--input-type=module', '-e', script], {
    timeout: 5000, encoding: 'utf8', stdio: 'pipe',
  })).not.toThrow();
});

test('both V44 ID references survive real shop storage and exact parent snapshot roundtrip', async () => {
  expect(keys).toEqual([CUSTOMER_FILE_PATH_SUMMARY_KEY, CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY]);
  const values = new Map(), storage = createShopStorage({ getStorage: () => ({ getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) }) });
  const stores = [createCustomerFilePathSummaryStore({ storage, flush: async () => {} }), createCustomerFilePathSummaryAssessmentStore({ storage, flush: async () => {} })];
  for (const store of stores) await store.submit(entry);
  const validated = validateShopSnapshot(snapshot(Object.fromEntries(keys.map(key => [key, storage.getItem(key)]))));
  for (let i = 0; i < keys.length; i++) { expect(JSON.parse(validated[keys[i]])).toEqual(entry); expect(stores[i].read(7)).toEqual(entry); expect(stores[i].read(8)).toBeNull(); }
  expect(storage.getItem(SHOP_CUSTOMER_FILE_SUMMARY_KEY)).toBeNull();
  for (const store of stores) await store.clear(entry);
  for (const key of keys) expect(storage.getItem(key)).toBeNull();
});

test.each(keys)('V44 snapshot key %s rejects credentials, bodies, unknown fields and invalid identity', key => {
  for (const patch of [{ authorityKey: 'jwt' }, { token: 'jwt' }, { launchCapability: 'secret' }, { path: '../etc/passwd' }, { text: 'private body' },
    { shopUserId: 0 }, { sessionId: entry.sessionId.toUpperCase() }, { requestId: 'other' }, { startedAt: 0 }, { version: 2 }]) {
    expect(() => validateShopSnapshot(snapshot({ [key]: JSON.stringify({ ...entry, ...patch }) }))).toThrow();
  }
  expect(() => validateShopSnapshot(snapshot({ [key]: 'not JSON' }))).toThrow();
  expect(() => validateShopSnapshot(snapshot({ [key]: JSON.stringify({ ...entry, extra: 'x'.repeat(512) }) }))).toThrow();
});

test.each(keys)('V44 storage key %s cannot fall back to memory after persistence failure', key => {
  const storage = createShopStorage({ getStorage: () => ({ getItem() { throw Error('offline'); }, setItem() { throw Error('offline'); }, removeItem() { throw Error('offline'); } }) });
  expect(() => storage.getItem(key)).toThrow('offline');
  expect(() => storage.setItem(key, JSON.stringify(entry))).toThrow('offline');
  expect(() => storage.removeItem(key)).toThrow('offline');
});


test('V27 ID-only reference crosses the real MessageChannel with fresh optional reads and acknowledged clear', () => {
  const moduleUrl = name => pathToFileURL(require.resolve(name)).href;
  const script = `
    import assert from 'node:assert/strict';
    import { MessageChannel } from 'node:worker_threads';
    import { createHostShopStateChannel, connectFrameShopState } from ${JSON.stringify(moduleUrl('./stateChannel.mjs'))};
    import { createScopedShopStateStore } from ${JSON.stringify(moduleUrl('./stateStore.mjs'))};
    import { createShopStorage, SHOP_POLICY_FINAL_HTML_KEY } from ${JSON.stringify(moduleUrl('../utils/shopStorage.mjs'))};
    import { createPolicyFinalHtmlReferenceStore } from ${JSON.stringify(moduleUrl('../utils/policyFinalHtmlReference.mjs'))};
    const rows = new Map(), ports = new MessageChannel();
    const store = createScopedShopStateStore({ storage: { getItem: k => rows.get(k) ?? null,
      setItem: (k,v) => rows.set(k,v) }, scenarioId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      generation: 1, isCurrent: () => true });
    const host = createHostShopStateChannel({ port: ports.port1, store }); let frame;
    try {
      frame = await connectFrameShopState({ port: ports.port2, timeoutMs: 1000 });
      const storage = createShopStorage({ getStorage: () => frame });
      const saved = createPolicyFinalHtmlReferenceStore({ storage, flush: () => frame.flush() });
      assert.equal(frame.getItem(SHOP_POLICY_FINAL_HTML_KEY), null);
      assert.equal(saved.read(7), null);
      const intent = { version:1, shopUserId:7, requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        sessionId:null,assessmentStarted:false,startedAt:100 };
      await saved.save(intent);
      assert.deepEqual(saved.read(7),intent);
      assert.throws(() => saved.read(8));
      assert.deepEqual(JSON.parse(store.read()[SHOP_POLICY_FINAL_HTML_KEY]),intent);
      for (const bad of ['not JSON', JSON.stringify({...intent,policy_html:'forbidden'}),
        JSON.stringify({...intent,assessmentStarted:true})])
        assert.throws(() => frame.setItem(SHOP_POLICY_FINAL_HTML_KEY,bad));
      const ack = {...intent,sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'};
      await saved.save(ack,intent);await saved.clear(ack);
      assert.equal(saved.read(7),null);assert.equal(frame.getItem(SHOP_POLICY_FINAL_HTML_KEY),null);
      assert.equal(Object.hasOwn(store.read(),SHOP_POLICY_FINAL_HTML_KEY),false);
    } finally { frame?.close();host.close(); }
  `;
  expect(() => execFileSync(process.execPath, ['--input-type=module', '-e', script],
    { timeout: 5000, encoding: 'utf8', stdio: 'pipe' })).not.toThrow();
});
