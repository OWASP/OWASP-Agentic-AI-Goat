import { shopStorage, flushShopStorage, SHOP_USER_ADMIN_KEY } from '../../utils/shopStorage.mjs';
import { STANDALONE_SESSION_CHANNEL } from '../../bridge/standaloneIntents.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION = /^[1-9][0-9]{0,18}$/;
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const same = (left, right) => left && right && ['scopeKey', 'targetId', 'action', 'operationId',
  'expectedVersion', left.action === 'ban' ? 'reason' : 'role'].every(key => left[key] === right[key]);

export function operationKey() { return SHOP_USER_ADMIN_KEY; }

export function decodePending(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || encoder.encode(raw).byteLength > 8192) throw new Error('Pending user change could not be restored');
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error('Pending user change could not be restored'); }
  if (!value || !['set_role', 'ban'].includes(value.action)
    || !exact(value, value.action === 'ban'
      ? ['scopeKey', 'targetId', 'action', 'reason', 'operationId', 'expectedVersion']
      : ['scopeKey', 'targetId', 'action', 'role', 'operationId', 'expectedVersion'])
    || typeof value.scopeKey !== 'string' || !value.scopeKey
    || !Number.isSafeInteger(value.targetId) || value.targetId < 1
    || typeof value.operationId !== 'string' || !UUID.test(value.operationId)
    || value.operationId !== value.operationId.toLowerCase()
    || typeof value.expectedVersion !== 'string' || !VERSION.test(value.expectedVersion)
    || (value.action === 'set_role' && !['customer', 'merchant', 'admin'].includes(value.role))
    || (value.action === 'ban' && (typeof value.reason !== 'string' || !value.reason.trim()
      || !value.reason.isWellFormed() || encoder.encode(value.reason).byteLength > 1024))) {
    throw new Error('Pending user change could not be restored');
  }
  return value;
}

export function readPending(scopeKey, storage = shopStorage) {
  const saved = decodePending(storage.getItem(operationKey()));
  if (saved && saved.scopeKey !== scopeKey) throw new Error('A saved user change belongs to another administrator scope');
  return saved;
}

export function assertSaved(operation, storage = shopStorage) {
  const saved = readPending(operation.scopeKey, storage);
  if (!same(saved, operation)) throw new Error('Saved user change differs from the confirmed request');
  return saved;
}

export async function savePending(value, storage = shopStorage,
  acknowledge = storage === shopStorage ? flushShopStorage : async () => {}, current = () => true) {
  const row = decodePending(JSON.stringify(value));
  if (storage.getItem(operationKey()) !== null) {
    throw new Error('Check the saved user change before starting another');
  }
  storage.setItem(operationKey(), JSON.stringify(row));
  await acknowledge();
  if (!current()) throw new Error('Administrator authority changed during the saved user change');
  assertSaved(row, storage);
  return row;
}

export async function clearPending(operation, storage = shopStorage,
  acknowledge = storage === shopStorage ? flushShopStorage : async () => {}, current = () => true) {
  const row = assertSaved(operation, storage);
  if (!current()) throw new Error('Administrator authority changed during the saved user change');
  storage.removeItem(operationKey());
  try {
    await acknowledge();
    if (!current()) throw new Error('Administrator authority changed during the saved user change');
    if (storage.getItem(operationKey()) !== null) throw new Error('Saved user change was replaced during confirmation');
  } catch (error) {
    try {
      if (current() && storage.getItem(operationKey()) === null) {
        storage.setItem(operationKey(), JSON.stringify(row));
        await acknowledge();
      }
    } catch { /* The mounted caller retains the unresolved request. */ }
    throw error;
  }
}

export async function acknowledgeRegisteredSelfChange(operation, receipt, actorId,
  current = () => true, frameWindow = globalThis.window) {
  let scope;
  try { scope = JSON.parse(operation.scopeKey); }
  catch { throw new Error('Current administrator scope is unavailable'); }
  const nonce = frameWindow?.location?.hash?.slice(1) || '';
  if (!Number.isSafeInteger(actorId) || actorId !== operation.targetId
    || !Array.isArray(scope) || scope.length !== 6 || scope[4] !== actorId
    || typeof scope[5] !== 'string' || receipt.actorId !== actorId
    || receipt.originalActorSessionId !== scope[5]
    || !/^[a-f0-9]{64}$/i.test(nonce)) {
    throw new Error('User change acknowledgement could not be verified');
  }
  await clearPending(operation, undefined, undefined, current);
  if (!current()) return;
  frameWindow.parent.postMessage({ channel: STANDALONE_SESSION_CHANNEL, type: 'auth-required', nonce },
    new URL(frameWindow.document.baseURI).origin);
}
export function requestReauthenticationForUnresolvedSelfChange(operation, actorId,
  current = () => true, frameWindow = globalThis.window, storage = shopStorage) {
  const saved = assertSaved(operation, storage);
  let scope;
  try { scope = JSON.parse(saved.scopeKey); }
  catch { throw new Error('Current administrator scope is unavailable'); }
  const nonce = frameWindow?.location?.hash?.slice(1) || '';
  if (!current() || !Number.isSafeInteger(actorId) || saved.targetId !== actorId
    || (saved.action !== 'ban' && (saved.action !== 'set_role' || saved.role === 'admin'))
    || !Array.isArray(scope) || scope.length !== 6 || scope[4] !== actorId
    || typeof scope[5] !== 'string' || !scope[5]
    || !/^[a-f0-9]{64}$/i.test(nonce)) {
    throw new Error('Sign-in handoff is unavailable for this saved user change');
  }
  frameWindow.parent.postMessage({ channel: STANDALONE_SESSION_CHANNEL, type: 'auth-required', nonce },
    new URL(frameWindow.document.baseURI).origin);
}
export function assertReceipt(receipt, operation) {
  if (!receipt || receipt.operationId !== operation.operationId || receipt.targetId !== operation.targetId
    || receipt.action !== operation.action || typeof receipt.version !== 'string'
    || receipt.version !== String(BigInt(operation.expectedVersion) + 1n)
    || (operation.action === 'set_role' && receipt.role !== operation.role)
    || (operation.action === 'ban' && typeof receipt.bannedAt !== 'string')) {
    throw new Error('User change acknowledgement could not be verified');
  }
  return receipt;
}
export async function readOperation(operation, fetcher = fetch) {
  const response = await fetcher(`/api/secureshop/admin/users/operations/${operation.operationId}`);
  if (response.status === 404) throw Object.assign(new Error('Saved user change has no committed receipt yet. Check it again; no new change was sent.'), { code: 'OPERATION_NOT_OBSERVED' });
  if (!response.ok) throw Object.assign(new Error(response.status === 401 || response.status === 403
    ? 'Outcome unknown. Sign in again or ask another administrator to inspect current user state.'
    : 'Change outcome is unknown. Refresh current state before choosing another change.'),
    response.status === 401 || response.status === 403
      ? { code: 'ADMIN_AUTH_CHANGED', status: response.status } : {});
  const body = await response.json();
  if (body?.ok !== true) throw new Error('Change outcome is unknown');
  return assertReceipt(body.receipt, operation);
}
