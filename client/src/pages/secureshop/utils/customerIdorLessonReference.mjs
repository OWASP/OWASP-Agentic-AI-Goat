const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const KEYS = ['version', 'shopUserId', 'sessionId', 'requestId', 'startedAt'];
const MAX_BYTES = 512;
export const CUSTOMER_IDOR_LESSON_REFERENCE_KEY = 'secureshop.customer-idor.lesson.v1';

const exact = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...KEYS].sort().join(',');
const same = (left, right) => !!left && !!right
  && KEYS.every(key => left[key] === right[key]);
const invalid = () => { throw new Error('Invalid saved access-control lesson request'); };

export function decodeCustomerIdorLessonReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > MAX_BYTES) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value) || value.version !== 1
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || typeof value.sessionId !== 'string' || !UUID.test(value.sessionId)
    || typeof value.requestId !== 'string' || !UUID.test(value.requestId)
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze(value);
}

// The caller supplies the credential-scoped, acknowledged host storage adapter.
// Shared storage key admission is intentionally left to the later mount batch.
export function createCustomerIdorLessonReferenceStore({ storage, flush,
  key = CUSTOMER_IDOR_LESSON_REFERENCE_KEY } = {}) {
  if (typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function'
    || typeof storage?.removeItem !== 'function' || typeof flush !== 'function'
    || key !== CUSTOMER_IDOR_LESSON_REFERENCE_KEY) {
    throw new TypeError('Acknowledged access-control lesson storage required');
  }
  const read = () => decodeCustomerIdorLessonReference(storage.getItem(key));
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      const value = read();
      return value?.shopUserId === shopUserId ? value : null;
    },
    async save(reference, current = () => true) {
      const value = decodeCustomerIdorLessonReference(JSON.stringify({ version: 1, ...reference }));
      if (current() !== true) throw Error('Access-control lesson authority changed');
      if (read() !== null) throw Error('Check the saved access-control lesson request first');
      storage.setItem(key, JSON.stringify(value));
      await flush();
      if (current() !== true || !same(read(), value))
        throw Error('Saved access-control lesson request changed');
      return value;
    },
    async clear(reference, current = () => true) {
      const value = decodeCustomerIdorLessonReference(JSON.stringify({ version: 1, ...reference }));
      if (current() !== true || !same(read(), value))
        throw Error('Saved access-control lesson request changed');
      try {
        storage.removeItem(key);
        await flush();
        if (current() !== true || read() !== null)
          throw Error('Saved access-control lesson request changed');
      } catch (error) {
        // A missing remove acknowledgement cannot prove durable deletion.
        if (current() === true) try {
          if (read() === null) {
            storage.setItem(key, JSON.stringify(value));
            await flush();
          }
        } catch { /* The mounted hook also retains the unresolved reference. */ }
        throw error;
      }
    },
  });
}
