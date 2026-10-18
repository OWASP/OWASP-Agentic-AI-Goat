import { createCustomerIdorLessonReferenceStore,
  decodeCustomerIdorLessonReference, CUSTOMER_IDOR_LESSON_REFERENCE_KEY } from './customerIdorLessonReference.mjs';

const reference = { shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 100 };

function store() {
  const values = new Map();
  const storage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  };
  const flush = jest.fn(async () => {});
  return { values, flush,
    refs: createCustomerIdorLessonReferenceStore({ storage, flush }) };
}

test('reference is exact, small and IDs-only', () => {
  expect(decodeCustomerIdorLessonReference(null)).toBeNull();
  expect(decodeCustomerIdorLessonReference(JSON.stringify({ version: 1, ...reference })))
    .toEqual({ version: 1, ...reference });
  for (const row of [
    { ...reference, modelAnswer: 'private' },
    { ...reference, sessionId: 'not-a-uuid' },
    { ...reference, shopUserId: 0 },
    { ...reference, startedAt: NaN },
  ]) expect(() => decodeCustomerIdorLessonReference(JSON.stringify({ version: 1, ...row }))).toThrow();
  expect(() => decodeCustomerIdorLessonReference('x'.repeat(513))).toThrow();
});

test('save flushes and reads back before the model POST can be admitted', async () => {
  const { refs, values, flush } = store();
  await refs.save(reference);
  expect(flush).toHaveBeenCalledTimes(1);
  expect(refs.read(7)).toEqual({ version: 1, ...reference });
  expect(refs.read(8)).toBeNull();
  expect(JSON.parse(values.get(CUSTOMER_IDOR_LESSON_REFERENCE_KEY)))
    .toEqual({ version: 1, ...reference });
  await expect(refs.save({ ...reference, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }))
    .rejects.toThrow(/Check the saved/);
  await refs.clear(reference);
  expect(refs.read(7)).toBeNull();
});

test('failed acknowledgement never silently discards a saved request', async () => {
  const values = new Map();
  let failRemove = false;
  const storage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => { values.delete(key); failRemove = true; },
  };
  const flush = jest.fn(async () => { if (failRemove) { failRemove = false; throw Error('lost ack'); } });
  const refs = createCustomerIdorLessonReferenceStore({ storage, flush });
  await refs.save(reference);
  await expect(refs.clear(reference)).rejects.toThrow('lost ack');
  expect(refs.read(7)).toEqual({ version: 1, ...reference });
  expect(flush).toHaveBeenCalledTimes(3);
});

test('authority and foreign stored references fail closed', async () => {
  const { refs } = store();
  await expect(refs.save(reference, () => false)).rejects.toThrow(/authority changed/);
  await refs.save(reference);
  await expect(refs.save({ ...reference, shopUserId: 8 })).rejects.toThrow(/Check the saved/);
  await expect(refs.clear({ ...reference, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }))
    .rejects.toThrow(/changed/);
  expect(refs.read(7)).toEqual({ version: 1, ...reference });
});
