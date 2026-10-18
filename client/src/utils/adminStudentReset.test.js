import { webcrypto, createHash } from 'crypto';
import { TextEncoder } from 'util';
import { runAdminStudentReset } from './adminStudentReset';
const ID = '12345678-1234-4234-8234-123456789012';
const NEXT = '12345678-1234-4234-8234-123456789013';
function fixture() {
  const values = new Map();
  return { api: { post: jest.fn().mockResolvedValue({ data: { success: true } }) }, studentId: 7,
    token: 'private-token', isCurrent: () => true, digest: async token => `digest-${token.length}`,
    createId: () => ID, storage: { getItem: k => values.get(k) || null, setItem: (k,v) => values.set(k,v), removeItem: k => values.delete(k) }, values };
}
test('lost success retains UUID across a new caller/remount; acknowledged success allows a new action', async () => {
  const f = fixture(); f.api.post.mockRejectedValueOnce(new Error('response lost'));
  await expect(runAdminStudentReset(f)).rejects.toThrow('response lost');
  expect(f.values.size).toBe(1);
  expect(JSON.stringify([...f.values])).not.toContain(f.token);
  const remounted = { ...f, createId: () => NEXT };
  await runAdminStudentReset(remounted);
  expect(f.api.post.mock.calls[1][2].headers['x-reset-operation-id']).toBe(ID);
  expect(f.values.size).toBe(0);
  await runAdminStudentReset(remounted);
  expect(f.api.post.mock.calls[2][2].headers['x-reset-operation-id']).toBe(NEXT);
});
test('different student/session never reuses pending identity', async () => {
  const f = fixture(); f.api.post.mockRejectedValueOnce(new Error('lost'));
  await expect(runAdminStudentReset(f)).rejects.toThrow();
  await runAdminStudentReset({ ...f, studentId: 8, createId: () => NEXT });
  await runAdminStudentReset({ ...f, token: 'different-session-token', createId: () => NEXT });
  expect(f.api.post.mock.calls.slice(1).every(c => c[2].headers['x-reset-operation-id'] === NEXT)).toBe(true);
  expect(f.values.size).toBe(1);
});
test('stale response cannot clear saved identity or newer replacement', async () => {
  const f = fixture(); let resolve, current = true;
  f.isCurrent = () => current;
  f.api.post.mockImplementation(() => new Promise(r => { resolve = r; }));
  const pending = runAdminStudentReset(f); await Promise.resolve(); await Promise.resolve();
  const key = [...f.values.keys()][0]; f.storage.setItem(key, NEXT); current = false;
  resolve({ data: { success: true } });
  await expect(pending).rejects.toThrow('changed');
  expect(f.storage.getItem(key)).toBe(NEXT);
});
test('storage failure and changed scope stop before POST; construction never submits', async () => {
  const f = fixture(); expect(f.api.post).not.toHaveBeenCalled();
  f.storage.setItem = () => { throw Error('blocked'); };
  await expect(runAdminStudentReset(f)).rejects.toThrow('blocked');
  await expect(runAdminStudentReset({ ...f, isCurrent: () => false })).rejects.toThrow('changed');
  expect(f.api.post).not.toHaveBeenCalled();
});

test('real WebCrypto SHA256 and random UUID persist no bearer', async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const encoder = globalThis.TextEncoder;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
  globalThis.TextEncoder = TextEncoder;
  try {
    const f = fixture(); delete f.digest; delete f.createId;
    f.api.post.mockRejectedValue(new Error('lost'));
    await expect(runAdminStudentReset(f)).rejects.toThrow('lost');
    const [[key, id]] = [...f.values];
    expect(key).toBe(`dvaia:admin-student-reset:${createHash('sha256').update(f.token).digest('hex')}:7:sensitive_info_disclosure`);
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(JSON.stringify([...f.values])).not.toContain(f.token);
  } finally {
    Object.defineProperty(globalThis, 'crypto', original);
    globalThis.TextEncoder = encoder;
  }
});
test('HTTP without subtle uses canonical session partition, retains retry and separates sessions', async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) } });
  try {
    const jwt = jti => `header.${btoa(JSON.stringify({ userId: 19, jti }))}.signature`;
    const f = fixture(); delete f.digest; delete f.createId; f.token = jwt(ID);
    f.api.post.mockRejectedValueOnce(new Error('lost'));
    await expect(runAdminStudentReset(f)).rejects.toThrow('lost');
    const [[key, id]] = [...f.values];
    expect(key).toContain(`session-19-${ID}:7:`);
    expect(JSON.stringify([...f.values])).not.toContain(f.token);
    await runAdminStudentReset(f);
    expect(f.api.post.mock.calls[1][2].headers['x-reset-operation-id']).toBe(id);
    f.token = jwt(NEXT);
    await runAdminStudentReset(f);
    expect(f.api.post.mock.calls[2][2].headers['x-reset-operation-id']).not.toBe(id);
    await expect(runAdminStudentReset({ ...f, token: 'malformed' })).rejects.toThrow('identity');
    expect(f.api.post).toHaveBeenCalledTimes(3);
  } finally { Object.defineProperty(globalThis, 'crypto', original); }
});
