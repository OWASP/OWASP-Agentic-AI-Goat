export const REGISTERED_PASSWORD_RESET_KEY = 'dvaia.secureshop.admin-password-reset.v1';
export const REGISTERED_PASSWORD_RESET_RESOLVED_EVENT = 'dvaia-secureshop-registered-password-reset-resolved-v1';

// This deliberately reads only the opaque owner marker. The saved operation
// reference contains no temporary password or reset receipt content.
export function registeredPasswordResetRecoveryState(storage, principalId) {
  if (typeof principalId !== 'string' || !principalId) return 'unavailable';
  try {
    if (!storage || typeof storage.getItem !== 'function') throw new Error('Recovery storage unavailable');
    const raw = storage.getItem(REGISTERED_PASSWORD_RESET_KEY);
    if (!raw) return 'none';
    const value = JSON.parse(raw);
    if (typeof value?.adminPrincipalId !== 'string') return 'unavailable';
    return value.adminPrincipalId === principalId ? 'pending' : 'none';
  } catch {
    // If the browser cannot read the reference, don't silently rotate the
    // session that may be required to recover its exact-session operation.
    return 'unavailable';
  }
}

export function notifyRegisteredPasswordResetResolved(target = globalThis.window) {
  target?.dispatchEvent?.(new Event(REGISTERED_PASSWORD_RESET_RESOLVED_EVENT));
}
