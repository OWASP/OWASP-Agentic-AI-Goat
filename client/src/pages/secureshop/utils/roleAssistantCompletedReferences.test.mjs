import { attachShopStorage, SHOP_ROLE_ASSISTANT_KEY,
  SHOP_ROLE_ASSISTANT_COMPLETED_KEY } from './shopStorage.mjs';
import { readRoleAssistantCompletedReference, saveRoleAssistantCompletedReference,
  clearRoleAssistantCompletedReference, markRoleAssistantRestartAssessmentAttempted } from './roleAssistantCompletedReferences.mjs';

const row = { role: 'merchant', shopUserId: 7,
  sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 42 };
const raw = value => JSON.stringify({ version: 1, references: [value] });

test('completed role pointer saves only the acknowledged pending identity', async () => {
  const values = new Map([[SHOP_ROLE_ASSISTANT_KEY, raw(row)]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => {} });
  try {
    await expect(saveRoleAssistantCompletedReference(row)).resolves.toEqual(row);
    expect(readRoleAssistantCompletedReference('merchant', 7)).toEqual(row);
    expect(values.get(SHOP_ROLE_ASSISTANT_COMPLETED_KEY)).toBe(raw(row));
    expect(values.get(SHOP_ROLE_ASSISTANT_COMPLETED_KEY)).not.toMatch(/message|token|cards/i);
    values.set(SHOP_ROLE_ASSISTANT_KEY, raw({ ...row,
      requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }));
    await expect(saveRoleAssistantCompletedReference(row)).rejects.toThrow('changed');
    await expect(clearRoleAssistantCompletedReference(row)).resolves.toBe(true);
    expect(readRoleAssistantCompletedReference('merchant', 7)).toBeNull();
  } finally { release(); }
});

test('failed parent ACK cannot release the pending role request', async () => {
  const values = new Map([[SHOP_ROLE_ASSISTANT_KEY, raw(row)]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { throw new Error('Parent ACK unavailable'); } });
  try {
    await expect(saveRoleAssistantCompletedReference(row)).rejects.toThrow('Parent ACK unavailable');
    expect(values.get(SHOP_ROLE_ASSISTANT_KEY)).toBe(raw(row));
  } finally { release(); }
});

test('admin completed pointer records one acknowledged restart assessment attempt without disturbing sibling', async () => {
  const admin = { ...row, role: 'admin', shopUserId: 8,
    requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' };
  const values = new Map([[SHOP_ROLE_ASSISTANT_COMPLETED_KEY,
    JSON.stringify({ version: 1, references: [row, admin] })]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => {} });
  try {
    await expect(markRoleAssistantRestartAssessmentAttempted(admin)).resolves.toMatchObject({
      ...admin, restartAssessmentAttempted: true,
    });
    expect(readRoleAssistantCompletedReference('merchant', 7)).toEqual(row);
    expect(readRoleAssistantCompletedReference('admin', 8).restartAssessmentAttempted).toBe(true);
    await expect(markRoleAssistantRestartAssessmentAttempted(admin)).rejects.toThrow('already attempted');
    await expect(markRoleAssistantRestartAssessmentAttempted(row)).rejects.toThrow('source changed');
    expect(values.get(SHOP_ROLE_ASSISTANT_COMPLETED_KEY)).not.toMatch(/message|command|token|output/i);
  } finally { release(); }
});

test('failed parent ACK retains attempted marker so reload stays GET-only', async () => {
  const admin = { ...row, role: 'admin', shopUserId: 8 };
  const values = new Map([[SHOP_ROLE_ASSISTANT_COMPLETED_KEY, raw(admin)]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => { throw Error('Parent ACK unavailable'); } });
  try {
    await expect(markRoleAssistantRestartAssessmentAttempted(admin)).rejects.toThrow('Parent ACK unavailable');
    expect(readRoleAssistantCompletedReference('admin', 8).restartAssessmentAttempted).toBe(true);
  } finally { release(); }
});


test('saving the same acknowledged result preserves its attempted marker but a new result does not inherit it', async () => {
  const admin = { ...row, role: 'admin', shopUserId: 8 };
  const values = new Map([[SHOP_ROLE_ASSISTANT_KEY, raw(admin)],
    [SHOP_ROLE_ASSISTANT_COMPLETED_KEY, raw({ ...admin, restartAssessmentAttempted: true })]]);
  const release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: async () => {} });
  try {
    await expect(saveRoleAssistantCompletedReference(admin)).resolves.toMatchObject({ restartAssessmentAttempted: true });
    await expect(markRoleAssistantRestartAssessmentAttempted(admin)).rejects.toThrow('already attempted');
    const next = { ...admin, requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', startedAt: 43 };
    values.set(SHOP_ROLE_ASSISTANT_KEY, raw(next));
    await expect(saveRoleAssistantCompletedReference(next)).resolves.toEqual(next);
    expect(readRoleAssistantCompletedReference('admin', 8)).toEqual(next);
  } finally { release(); }
});
