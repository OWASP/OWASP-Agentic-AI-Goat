import {
  readSystemConfigReferences,
  saveSystemConfigReference,
  forgetSystemConfigReference,
} from './systemConfigRecovery.js';
import { SHOP_SYSTEM_CONFIG_KEY } from '../../utils/shopStorage.mjs';

const scopeKey = 'a'.repeat(64);
const operationId = '44444444-4444-4444-8444-444444444444';
const reference = { scopeKey, operationId, state: 'pending' };

beforeEach(() => { localStorage.clear(); });

test('persists only bounded opaque references and preserves siblings', async () => {
  await saveSystemConfigReference(reference);
  await saveSystemConfigReference({ ...reference, scopeKey: 'b'.repeat(64), operationId: '55555555-5555-4555-8555-555555555555', state: 'unknown' });
  expect(readSystemConfigReferences()).toHaveLength(2);
  expect(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).not.toContain('path');
  expect(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).not.toContain('content');
});

test('forget requires the exact stored state and removes only its reference', async () => {
  await saveSystemConfigReference(reference);
  const sibling = { ...reference, scopeKey: 'b'.repeat(64), operationId: '55555555-5555-4555-8555-555555555555' };
  await saveSystemConfigReference(sibling);
  await expect(forgetSystemConfigReference({ ...reference, state: 'unknown' })).rejects.toThrow('changed');
  await forgetSystemConfigReference(reference);
  expect(readSystemConfigReferences()).toEqual([sibling]);
});

test('completed operation references remain opaque and cannot regress to pending', async () => {
  const completed = { ...reference, state: 'completed' };
  await saveSystemConfigReference(completed);
  expect(readSystemConfigReferences()).toEqual([completed]);
  await expect(saveSystemConfigReference(reference)).rejects.toThrow('changed');
  await forgetSystemConfigReference(completed);
  expect(readSystemConfigReferences()).toEqual([]);
});

test('storage and codec validation failures are surfaced without eviction', async () => {
  await saveSystemConfigReference(reference);
  const before = localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY);
  localStorage.setItem(SHOP_SYSTEM_CONFIG_KEY, '{"version":1,"references":[{"scopeKey":"bad"}]}');
  expect(() => readSystemConfigReferences()).toThrow('Invalid saved System operation');
  localStorage.setItem(SHOP_SYSTEM_CONFIG_KEY, before);
  await expect(saveSystemConfigReference({ ...reference, state: 'invalid' })).rejects.toThrow('Invalid saved System operation');
  expect(localStorage.getItem(SHOP_SYSTEM_CONFIG_KEY)).toBe(before);
});
