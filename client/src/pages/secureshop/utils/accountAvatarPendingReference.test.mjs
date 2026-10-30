import { webcrypto } from 'node:crypto';
import { accountAvatarSessionFingerprint, createAccountAvatarPendingStore,
  decodeAccountAvatarPending, verifyAccountAvatarReceipt } from './accountAvatarPendingReference.mjs';
import { SHOP_ACCOUNT_AVATAR_PENDING_KEY } from './shopStorage.mjs';

const requestId = '123e4567-e89b-42d3-a456-426614174000';
const operationId = '123e4567-e89b-42d3-a456-426614174001';
const fingerprint = 'a'.repeat(64);
const pending = Object.freeze({ version: 1, ownerId: '7', sessionFingerprint: fingerprint,
  requestId, filename: 'portrait.svg', mime: 'image/svg+xml', sizeBytes: 4, public: false });
const claims = Object.freeze({ role: 'customer', username: 'student_customer',
  ss_authority_version: '1', ss_launch_id: '10000000-0000-4000-8000-000000000082',
  ss_scenario_id: '20000000-0000-4000-8000-000000000082', ss_generation: 5,
  ss_owner_id: 82, ss_platform_session_id: 802, iat: 1000, exp: 2000,
  iss: 'owasp-ai-goat-secureshop-bound', aud: 'owasp-ai-goat-secureshop-bound-persona',
  sub: '7', jti: '30000000-0000-4000-8000-000000000082' });
const token = (payload = claims) => [
  Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
  Buffer.from(JSON.stringify(payload)).toString('base64url'), 'signature',
].join('.');
const receipt = (status = 'completed') => ({ ok: status === 'completed', kind: 'avatar', scope_id: '7',
  requestId, operationId: status === 'uncertain' ? null : operationId, status,
  filename: 'portrait.svg', mime: 'image/svg+xml', size_bytes: 4,
  is_traversal: false, replayed: false, public: false,
  ...(status === 'denied' ? { denialCode: 'AVATAR_DENIED' } : {}) });

test('account avatar reference reserves once and only a matched saved GET receipt retires it', async () => {
  const values = new Map(); let flushes = 0;
  const storage = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
  const store = createAccountAvatarPendingStore({ storage, flush: async () => { flushes++; } });
  expect(store.read()).toBeNull();
  expect(await store.reserve(pending, () => true)).toEqual(pending);
  expect(flushes).toBe(1);
  expect(values.get(SHOP_ACCOUNT_AVATAR_PENDING_KEY)).toBe(JSON.stringify(pending));
  await expect(store.reserve(pending, () => true)).rejects.toThrow();
  expect(await store.clear(pending, receipt('uncertain'), () => true)).toBe(false);
  expect(store.read()).toEqual(pending);
  const absent = { ...receipt('uncertain'), filename: '', mime: '', size_bytes: 0, public: false };
  expect(verifyAccountAvatarReceipt(pending, absent).status).toBe('uncertain');
  expect(await store.clear(pending, absent, () => true)).toBe(false);
  expect(store.read()).toEqual(pending);
  await expect(store.clear(pending, { ...receipt(), scope_id: '8' }, () => true)).rejects.toThrow();
  await expect(store.clear(pending, { ...receipt(), operationId: 'bad' }, () => true)).rejects.toThrow();
  expect(store.read()).toEqual(pending);
  expect(await store.clear(pending, receipt(), () => true)).toBe(true);
  expect(store.read()).toBeNull();
  expect(flushes).toBe(2);
});

test('failed acknowledgement and stale owner/session keep the reference unresolved', async () => {
  const values = new Map();
  const storage = { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
  const store = createAccountAvatarPendingStore({ storage, flush: async () => { throw Error('no acknowledgement'); } });
  await expect(store.reserve(pending, () => true)).rejects.toThrow('no acknowledgement');
  expect(store.read()).toEqual(pending);
  await expect(store.clear({ ...pending, ownerId: '8' }, receipt(), () => true)).rejects.toThrow();
  await expect(store.clear({ ...pending, sessionFingerprint: 'b'.repeat(64) }, receipt(), () => true)).rejects.toThrow();
  expect(store.read()).toEqual(pending);
});

test('reference and receipt decoder reject forged keys, malformed identities and incorrect types', () => {
  expect(() => decodeAccountAvatarPending(JSON.stringify({ ...pending, token: 'secret' }))).toThrow();
  expect(() => decodeAccountAvatarPending(JSON.stringify({ ...pending, ownerId: '1' }))).not.toThrow();
  expect(() => decodeAccountAvatarPending(JSON.stringify({ ...pending, ownerId: '01' }))).toThrow();
  expect(() => verifyAccountAvatarReceipt(pending, { ...receipt(), public: 0 })).toThrow();
  expect(() => verifyAccountAvatarReceipt(pending, { ...receipt(), status: 'completed', ok: false })).toThrow();
  expect(() => verifyAccountAvatarReceipt(pending, { ...receipt(), extra: true })).toThrow();
  expect(() => verifyAccountAvatarReceipt(pending, { ...receipt('denied'), denialCode: '' })).toThrow();
  expect(verifyAccountAvatarReceipt(pending, receipt('denied')).status).toBe('denied');
});

test('v2 fingerprint follows the scoped persona session across re-signing, not a new authority', async () => {
  const previous = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  try {
    const a = await accountAvatarSessionFingerprint(token());
    const reissued = token({ ...claims, iat: 1010, exp: 2000 });
    expect(reissued).not.toBe(token());
    expect(await accountAvatarSessionFingerprint(reissued)).toBe(a);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
    for (const changed of [
      { sub: '8' }, { role: 'merchant' }, { ss_launch_id: '40000000-0000-4000-8000-000000000082' },
      { ss_scenario_id: '50000000-0000-4000-8000-000000000082' },
      { ss_generation: 6 }, { ss_owner_id: 83 }, { ss_platform_session_id: 803 },
      { jti: '60000000-0000-4000-8000-000000000082' }, { ss_authority_version: '2' },
    ]) expect(await accountAvatarSessionFingerprint(token({ ...claims, ...changed }))).not.toBe(a);
    for (const changed of [
      { iss: 'other' }, { aud: 'other' }, { jti: 'bad' }, { ss_authority_version: '0' },
      { ss_authority_version: 1 }, { extra: true }, { exp: claims.iat },
    ]) await expect(accountAvatarSessionFingerprint(token({ ...claims, ...changed }))).rejects.toThrow();
    await expect(accountAvatarSessionFingerprint('not-a-jwt')).rejects.toThrow();
    expect(JSON.stringify({ ...pending, version: 2, sessionFingerprint: a })).not.toContain(token());
    // Historical v1 records still require their exact bearer and cannot be silently migrated.
    const legacy = await accountAvatarSessionFingerprint(token(), 1);
    expect(await accountAvatarSessionFingerprint(reissued, 1)).not.toBe(legacy);
    expect(decodeAccountAvatarPending(JSON.stringify({ ...pending, sessionFingerprint: legacy }))).toEqual({
      ...pending, sessionFingerprint: legacy });
    expect(decodeAccountAvatarPending(JSON.stringify({ ...pending, version: 2,
      sessionFingerprint: a })).version).toBe(2);
  } finally { Object.defineProperty(globalThis, 'crypto', { configurable: true, value: previous }); }
});
