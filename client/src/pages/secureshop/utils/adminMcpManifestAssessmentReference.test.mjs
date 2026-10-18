import { createAdminMcpManifestAssessmentStore,
  decodeAdminMcpManifestAssessmentReference } from './adminMcpManifestAssessmentReference.mjs';
import { SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY, SHOP_TOKEN_KEY, SHOP_CART_KEY } from './shopStorage.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';

const ref = { shopUserId: 7, scopeKey: 'a'.repeat(64),
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  operationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  requestSha256: 'd'.repeat(64), stage: 'awaiting_import', startedAt: 123 };

test('IDs-only assessment reference advances before POST and is accepted by frame storage', async () => {
  const values = new Map();
  const store = createAdminMcpManifestAssessmentStore({ storage: {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  }, flush: async () => {} });
  const awaiting = await store.save(ref);
  expect(Object.keys(awaiting).sort()).toEqual([...Object.keys(ref), 'version'].sort());
  expect(store.read(8)).toBeNull();
  const ready = await store.advance(awaiting, 'ready');
  const submitted = await store.advance(ready, 'submitted');
  expect(store.read(7)).toEqual(submitted);
  expect(values.get(SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY)).toEqual(JSON.stringify(submitted));
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY]:
    values.get(SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY) })).not.toThrow();
  await expect(store.advance(submitted, 'ready')).rejects.toThrow();
  await store.clear(submitted);
  expect(store.read(7)).toBeNull();
});

test('malformed or private saved assessment fields fail closed', () => {
  for (const value of [
    { ...ref, version: 1, body: '<img>' },
    { ...ref, version: 1, proposalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' },
    { ...ref, version: 1, stage: 'awarded' },
  ]) expect(() => decodeAdminMcpManifestAssessmentReference(JSON.stringify(value))).toThrow();
});

test('discovery V2 uses the same acknowledged frame slot and preserves exact manifest V1 references', async () => {
  const values = new Map(), flush = jest.fn(async () => {});
  const store = createAdminMcpManifestAssessmentStore({ storage: {
    getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  }, flush });
  const saved = await store.save({ ...ref, version: 2, kind: 'discovery', stage: 'awaiting_registration' });
  expect(saved.version).toBe(2); expect(saved.kind).toBe('discovery');
  expect([...values.keys()]).toEqual([SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY]);
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY]: JSON.stringify(saved) })).not.toThrow();
  const submitted = await store.advance(await store.advance(saved, 'ready'), 'submitted');
  expect(store.read(7)).toEqual(submitted); expect(store.read(8)).toBeNull();
  await expect(store.advance(submitted, 'ready')).rejects.toThrow();
  await store.clear(submitted);
  expect(await store.save(ref)).toEqual({ version: 1, ...ref });
  expect(flush).toHaveBeenCalledTimes(5);
});

test('discovery references reject mixed historical shape, wrong kind and premature grading stage', () => {
  const v2 = { ...ref, version: 2, kind: 'discovery', stage: 'awaiting_registration' };
  for (const changed of [{ ...v2, version: 1 }, { ...v2, kind: 'manifest' },
    { ...v2, kind: undefined }, { ...v2, stage: 'awaiting_import' }, { ...v2, source: 'private' },
    { ...ref, version: 1, stage: 'awaiting_registration' }]) {
    expect(() => decodeAdminMcpManifestAssessmentReference(JSON.stringify(changed))).toThrow();
  }
});
