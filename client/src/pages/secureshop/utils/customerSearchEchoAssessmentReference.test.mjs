import { createSearchEchoAssessmentStore, decodeSearchEchoAssessmentReference } from './customerSearchEchoAssessmentReference.mjs';
import { SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY } from './shopStorage.mjs';

const value = { shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', step: 2, startedAt: 12345 };

test('persisted source contains only owner and exact source IDs with CAS', async () => {
  const rows = new Map();
  const storage = { getItem: key => rows.get(key) ?? null,
    setItem: (key, entry) => rows.set(key, entry), removeItem: key => rows.delete(key) };
  const store = createSearchEchoAssessmentStore({ storage, flush: async () => {} });
  const saved = await store.save(value);
  expect(saved).toEqual({ version: 1, ...value });
  expect(store.read(7)).toEqual(saved);
  expect(store.read(8)).toBeNull();
  await expect(store.save({ ...value, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' })).rejects.toThrow();
  await expect(store.clear({ ...saved, step: 3 })).rejects.toThrow();
  await store.clear(saved);
  expect(storage.getItem(SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY)).toBeNull();
});

test('decoder rejects unbounded or invented authority fields', () => {
  for (const bad of [{ ...value, step: 0 }, { ...value, step: 5 },
    { ...value, echoHtml: '<img>' }, { ...value, mode: 'vuln' },
    { ...value, sessionId: 'bad' }])
    expect(() => decodeSearchEchoAssessmentReference(JSON.stringify({ version: 1, ...bad }))).toThrow();
});
