import { decodeMailReferences, updateMailReference } from '../bridge/mailReferences.mjs';
import { SHOP_MAIL_KEY, shopStorage, flushShopStorage } from './shopStorage.mjs';
import { merchantMailChatReference } from './merchantMailAction.mjs';

const SHA = /^[a-f0-9]{64}$/;
const invalid = () => { throw new Error('Saved mail operation changed. No confirmation was sent.'); };
export const sameMerchantMailReference = (a, b) => !!a && !!b
  && a.action === b.action && a.requestId === b.requestId && a.digest === b.digest
  && a.chatSource?.sessionId === b.chatSource?.sessionId
  && a.chatSource?.requestId === b.chatSource?.requestId;

export function readMerchantMailPending(scopeKey) {
  if (typeof scopeKey !== 'string' || !SHA.test(scopeKey)) invalid();
  return decodeMailReferences(shopStorage.getItem(SHOP_MAIL_KEY)).scopes[scopeKey]?.pending ?? null;
}

function write(scopeKey, reference) {
  const encoded = updateMailReference(shopStorage.getItem(SHOP_MAIL_KEY), scopeKey, 'pending', reference);
  if (encoded === null) shopStorage.removeItem(SHOP_MAIL_KEY);
  else shopStorage.setItem(SHOP_MAIL_KEY, encoded);
}

export async function saveMerchantMailPending(scopeKey, reference, isCurrent = () => true) {
  merchantMailChatReference(reference);
  if (!isCurrent() || readMerchantMailPending(scopeKey)) invalid();
  write(scopeKey, reference);
  await flushShopStorage();
  if (!isCurrent() || !sameMerchantMailReference(readMerchantMailPending(scopeKey), reference)) invalid();
  window.dispatchEvent(new CustomEvent('secureshop-mail-pending', { detail: scopeKey }));
}

export function assertMerchantMailPending(scopeKey, reference, isCurrent = () => true) {
  merchantMailChatReference(reference);
  if (!isCurrent() || !sameMerchantMailReference(readMerchantMailPending(scopeKey), reference)) invalid();
}

export async function clearMerchantMailPending(scopeKey, reference, isCurrent = () => true) {
  assertMerchantMailPending(scopeKey, reference, isCurrent);
  write(scopeKey, null);
  try {
    await flushShopStorage();
    if (!isCurrent() || readMerchantMailPending(scopeKey) !== null) invalid();
  } catch (error) {
    // A failed parent clear ACK can leave the slot absent. Restore only this
    // reference, never a replacement, so exact GET recovery stays available.
    if (isCurrent() && readMerchantMailPending(scopeKey) === null) {
      try { write(scopeKey, reference); await flushShopStorage(); } catch { /* Keep the uncertain cleanup visible to the caller. */ }
    }
    throw error;
  }
  window.dispatchEvent(new CustomEvent('secureshop-mail-pending', { detail: scopeKey }));
}
