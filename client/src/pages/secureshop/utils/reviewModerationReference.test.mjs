import { createReviewModerationReferenceStore, decodeReviewModerationReference,
  verifyReviewModerationHistory, verifyReviewModerationLookup } from './reviewModerationReference.mjs';
import { SHOP_REVIEW_MODERATION_KEY, SHOP_TOKEN_KEY, SHOP_CART_KEY,
  createShopStorage } from './shopStorage.mjs';
import { validateShopSnapshot } from '../bridge/stateStore.mjs';

const ids = ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  'cccccccc-cccc-4ccc-8ccc-cccccccccccc'];
const actionId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const key = 'e'.repeat(64);
const lookup = (requestId, requestedLimit, state = 'not_found', result = null) => ({
  version: 1, requestId, requestedLimit, recoveryScopeKey: key, state, result,
});
const batch = (requested, considered, continuationRequired = true, ok = true) => ({
  ok, processed: 0, decisions: [], stopReason: ok ? 'end_turn' : 'max_steps',
  batch: { requested, considered, complete: true, continuationRequired },
});
const done = (requestId, requestedLimit, considered, continuationRequired = true, ok = true) =>
  lookup(requestId, requestedLimit, 'completed',
    batch(requestedLimit, considered, continuationRequired, ok));

function fixture({ flush = async () => {} } = {}) {
  const values = new Map();
  const storage = { getItem: keyName => values.get(keyName) ?? null,
    setItem: (keyName, value) => values.set(keyName, value),
    removeItem: keyName => values.delete(keyName) };
  const store = createReviewModerationReferenceStore({ storage, flush });
  return { values, storage, store };
}

test('initial not_found preflight is persisted and acknowledged before one original POST', async () => {
  const { values, store } = fixture();
  const pending = await store.reserveInitialPost({ actionId, requestId: ids[0] },
    lookup(ids[0], 100), { assertCurrent: () => true });
  expect(pending).toEqual({ version: 1, actionId, recoveryScopeKey: key,
    completed: [], pending: { requestId: ids[0], requestedLimit: 100 } });
  const raw = values.get(SHOP_REVIEW_MODERATION_KEY);
  expect(raw).not.toMatch(/reviewBody|notes|decision|processed|considered|token/i);
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_REVIEW_MODERATION_KEY]: raw })[SHOP_REVIEW_MODERATION_KEY]).toBe(raw);
  await expect(store.reserveInitialPost({ actionId, requestId: ids[0] },
    lookup(ids[0], 100), { assertCurrent: () => true })).rejects.toThrow(/GET-only/);
  expect(store.observePending(lookup(ids[0], 100, 'uncertain')).state).toBe('uncertain');
  expect(store.observePending(lookup(ids[0], 100, 'not_found')).state).toBe('not_found');
  expect(store.read()).toEqual(pending);
});

test('matched completed GET records only source references; verified history gates remaining batch', async () => {
  const { values, store } = fixture();
  await store.reserveInitialPost({ actionId, requestId: ids[0] },
    lookup(ids[0], 100), { assertCurrent: () => true });
  const first = done(ids[0], 100, 5);
  const observed = await store.recordCompleted(first, [], { assertCurrent: () => true });
  expect(observed.result).toEqual(first.result);
  expect(observed.reference.completed).toEqual([[ids[0], 100]]);
  expect(observed.reference.pending).toBeNull();
  expect(values.get(SHOP_REVIEW_MODERATION_KEY)).not.toContain('max_steps');
  expect(verifyReviewModerationHistory(store.read(), [first])).toMatchObject({
    considered: 5, processed: 0, remaining: 95, canContinue: true,
  });
  await expect(store.reserveNextPost({ requestId: ids[1], requestedLimit: 95 },
    lookup(ids[1], 95), [lookup(ids[0], 100, 'not_found')],
    { assertCurrent: () => true })).rejects.toThrow();
  await expect(store.reserveNextPost({ requestId: ids[1], requestedLimit: 96 },
    lookup(ids[1], 96), [first], { assertCurrent: () => true })).rejects.toThrow();
  const second = await store.reserveNextPost({ requestId: ids[1], requestedLimit: 95 },
    lookup(ids[1], 95), [first], { assertCurrent: () => true });
  expect(second.pending).toEqual({ requestId: ids[1], requestedLimit: 95 });
  await expect(store.recordCompleted(lookup(ids[1], 95, 'started'), [first],
    { assertCurrent: () => true })).rejects.toThrow();
  expect(store.read().pending.requestId).toBe(ids[1]);
  const terminal = done(ids[1], 95, 1, false);
  await store.recordCompleted(terminal, [first], { assertCurrent: () => true });
  expect((await store.finish([first, terminal], { assertCurrent: () => true })).considered).toBe(6);
  expect(store.read()).toBeNull();
});

test('completed partial failure is observed without authorizing another batch', async () => {
  const { store } = fixture();
  await store.reserveInitialPost({ actionId, requestId: ids[0] },
    lookup(ids[0], 100), { assertCurrent: () => true });
  const failed = done(ids[0], 100, 3, true, false);
  await store.recordCompleted(failed, [], { assertCurrent: () => true });
  expect(verifyReviewModerationHistory(store.read(), [failed]).canContinue).toBe(false);
  await expect(store.reserveNextPost({ requestId: ids[1], requestedLimit: 97 },
    lookup(ids[1], 97), [failed], { assertCurrent: () => true })).rejects.toThrow();
  await store.finish([failed], { assertCurrent: () => true });
});

test('foreign, malformed and ambiguous lookup never grants a new POST or clears pending', async () => {
  const { values, store } = fixture();
  for (const bad of [lookup(ids[0], 100, 'started'),
    lookup(ids[0], 100, 'uncertain'), done(ids[0], 100, 1)])
    await expect(store.reserveInitialPost({ actionId, requestId: ids[0] }, bad,
      { assertCurrent: () => true })).rejects.toThrow();
  await store.reserveInitialPost({ actionId, requestId: ids[0] },
    lookup(ids[0], 100), { assertCurrent: () => true });
  const raw = values.get(SHOP_REVIEW_MODERATION_KEY);
  for (const bad of [{ ...lookup(ids[0], 100), recoveryScopeKey: 'f'.repeat(64) },
    { ...lookup(ids[0], 100), requestedLimit: 99 },
    { ...done(ids[0], 100, 1), result: { ...batch(100, 1), decisions: [{ body: 'forged' }] } },
    { ...done(ids[0], 100, 1), result: { ...batch(100, 1), batch: { ...batch(100, 1).batch, considered: 101 } } },
    { ...lookup(ids[0], 100), result: {} },
    { ...lookup(ids[0], 100), ownerId: 7 }])
    await expect(store.recordCompleted(bad, [], { assertCurrent: () => true })).rejects.toThrow();
  expect(values.get(SHOP_REVIEW_MODERATION_KEY)).toBe(raw);
  expect(() => decodeReviewModerationReference(JSON.stringify({ ...store.read(), bytes: 'private' }))).toThrow();
  expect(() => verifyReviewModerationLookup(done(ids[0], 100, 1), {
    requestId: ids[0], requestedLimit: 100, recoveryScopeKey: 'f'.repeat(64),
  })).toThrow();
});

test('failed flush, changed storage and stale authority retain unresolved reference and deny permission', async () => {
  const { storage, values } = fixture();
  let release;
  const wait = new Promise(resolve => { release = resolve; });
  const store = createReviewModerationReferenceStore({ storage, flush: () => wait });
  let current = true;
  const pending = store.reserveInitialPost({ actionId, requestId: ids[0] },
    lookup(ids[0], 100), { assertCurrent: () => current });
  expect(values.has(SHOP_REVIEW_MODERATION_KEY)).toBe(true);
  current = false; release();
  await expect(pending).rejects.toThrow();
  expect(store.read()).not.toBeNull();
  await expect(store.reserveInitialPost({ actionId, requestId: ids[0] },
    lookup(ids[0], 100), { assertCurrent: () => true })).rejects.toThrow(/GET-only/);
  const failed = createReviewModerationReferenceStore({ storage: { ...storage, getItem: () => null },
    flush: async () => { throw Error('flush unavailable'); } });
  await expect(failed.reserveInitialPost({ actionId, requestId: ids[1] },
    lookup(ids[1], 100), { assertCurrent: () => true })).rejects.toThrow('flush unavailable');
  await expect(store.recordCompleted(done(ids[0], 100, 1), [],
    { assertCurrent: async () => true })).rejects.toThrow();
  const strict = createShopStorage({ getStorage: () => ({ getItem: () => { throw Error('offline'); },
    setItem: () => { throw Error('offline'); }, removeItem: () => { throw Error('offline'); } }) });
  expect(() => strict.getItem(SHOP_REVIEW_MODERATION_KEY)).toThrow('offline');
  expect(() => strict.setItem(SHOP_REVIEW_MODERATION_KEY, '{}')).toThrow('offline');
});

test('decoder bounds and ordered historical request IDs reject forged quota progress', () => {
  const value = { version: 1, actionId, recoveryScopeKey: key,
    completed: [[ids[0], 100]], pending: { requestId: ids[1], requestedLimit: 95 } };
  expect(() => decodeReviewModerationReference(JSON.stringify({ ...value,
    completed: [[ids[0], 100], [ids[0], 95]] }))).toThrow();
  expect(() => decodeReviewModerationReference(JSON.stringify({ ...value,
    pending: { requestId: ids[1], requestedLimit: 101 } }))).toThrow();
  expect(() => decodeReviewModerationReference('x'.repeat(8193))).toThrow();
  expect(() => verifyReviewModerationHistory(value, [done(ids[0], 100, 4)])).toThrow();
  expect(() => verifyReviewModerationHistory(value, [done(ids[0], 100, 5, false)])).toThrow();
  expect(() => verifyReviewModerationHistory(value, [lookup(ids[0], 100, 'started')])).toThrow();
});

test('100 one-review batches remain within the explicit action quota', () => {
  const completed = Array.from({ length: 100 }, (_, index) => [
    `10000000-0000-4000-8000-${(index + 1).toString(16).padStart(12, '0')}`, 100 - index,
  ]);
  const reference = { version: 1, actionId, recoveryScopeKey: key,
    completed, pending: null };
  const lookups = completed.map(([requestId, requestedLimit], index) =>
    done(requestId, requestedLimit, 1, index < 99));
  expect(verifyReviewModerationHistory(reference, lookups)).toEqual({
    considered: 100, processed: 0, canContinue: false, remaining: 0,
  });
  expect(JSON.stringify(reference).length).toBeLessThan(8192);
});

test('completed original projection accepts an applied effect and rejects fabricated result details', () => {
  const applied = { review_id: 41, product_id: 7, applied_decision: 'reject',
    notes: 'Unrelated promotion', applied: { ok: true, review_id: 41 } };
  const result = { ...batch(100, 1, false), processed: 1, decisions: [applied] };
  expect(verifyReviewModerationLookup(lookup(ids[0], 100, 'completed', result), {
    requestId: ids[0], requestedLimit: 100, recoveryScopeKey: key,
  }).result.decisions).toEqual([applied]);
  for (const bad of [{ ...applied, review_id: 42 }, { ...applied, notes: 'x'.repeat(16385) },
    { ...applied, rawReview: '<script>' }])
    expect(() => verifyReviewModerationLookup(lookup(ids[0], 100, 'completed', {
      ...result, decisions: [bad],
    }), { requestId: ids[0], requestedLimit: 100, recoveryScopeKey: key })).toThrow();
});
