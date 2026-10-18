import { shopStorage, flushShopStorage, SHOP_REGISTERED_ADMIN_COMPLETED_KEY } from './shopStorage.mjs';
import { decodeRegisteredAdminChatReference, readRegisteredAdminChatReference } from './registeredAdminChatReference.mjs';

const same = (left, right) => !!left && !!right
  && ['shopUserId', 'sessionId', 'requestId', 'startedAt'].every(key => left[key] === right[key]);

export const readRegisteredAdminCompletedReference = () =>
  decodeRegisteredAdminChatReference(shopStorage.getItem(SHOP_REGISTERED_ADMIN_COMPLETED_KEY));

export async function saveRegisteredAdminCompletedReference(reference, current = () => true) {
  const saved = decodeRegisteredAdminChatReference(JSON.stringify({ version: 1, ...reference }));
  if (!current() || !same(readRegisteredAdminChatReference(), saved)) {
    throw Error('Saved registered-tools request changed');
  }
  shopStorage.setItem(SHOP_REGISTERED_ADMIN_COMPLETED_KEY, JSON.stringify(saved));
  await flushShopStorage();
  if (!current() || !same(readRegisteredAdminCompletedReference(), saved)) {
    throw Error('Saved registered-tools page changed');
  }
  return saved;
}

export async function clearRegisteredAdminCompletedReference(reference, current = () => true) {
  if (!current()) return false;
  const saved = readRegisteredAdminCompletedReference();
  if (!same(saved, reference)) return false;
  shopStorage.removeItem(SHOP_REGISTERED_ADMIN_COMPLETED_KEY);
  await flushShopStorage();
  if (!current()) return false;
  if (same(readRegisteredAdminCompletedReference(), reference)) {
    throw Error('Saved registered-tools page changed');
  }
  return true;
}
