import { registeredPasswordResetRecoveryState, REGISTERED_PASSWORD_RESET_KEY } from './registeredPasswordResetRecovery.mjs';

const principalId = '4a792aa0-026b-4e76-9520-17ee0252c9aa';

test('recognizes only an operation reference owned by the current administrator', () => {
  const storage = { getItem: jest.fn().mockReturnValue(JSON.stringify({ adminPrincipalId: principalId,
    operationId: 'opaque-operation-reference' })) };
  expect(registeredPasswordResetRecoveryState(storage, principalId)).toBe('pending');
  expect(storage.getItem).toHaveBeenCalledWith(REGISTERED_PASSWORD_RESET_KEY);
  expect(registeredPasswordResetRecoveryState(storage, 'another-admin')).toBe('none');
  expect(registeredPasswordResetRecoveryState({ getItem: () => null }, principalId)).toBe('none');
});

test('fails closed when recovery storage cannot be read', () => {
  expect(registeredPasswordResetRecoveryState({ getItem() { throw new Error('blocked'); } }, principalId)).toBe('unavailable');
  expect(registeredPasswordResetRecoveryState(null, principalId)).toBe('unavailable');
  expect(registeredPasswordResetRecoveryState({ getItem: () => '{broken' }, principalId)).toBe('unavailable');
});
