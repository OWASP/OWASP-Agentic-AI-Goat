// Persist only an opaque original-scope reference, never question or result data.
import { shopStorage, flushShopStorage, SHOP_ANALYTICS_KEY } from '../../utils/shopStorage.mjs';
import { decodeSystemConfigReferences, encodeSystemConfigReferences,
  rememberSystemConfigReference, forgetSystemConfigReference } from '../admin/systemConfigOperation.mjs';

export function readAnalyticsReferences() {
  return decodeSystemConfigReferences(shopStorage.getItem(SHOP_ANALYTICS_KEY));
}
export async function saveAnalyticsReference(reference) {
  const rows = rememberSystemConfigReference(readAnalyticsReferences(), reference);
  shopStorage.setItem(SHOP_ANALYTICS_KEY, encodeSystemConfigReferences(rows));
  await flushShopStorage();
  return rows;
}
export async function forgetAnalyticsReference(reference) {
  const rows = forgetSystemConfigReference(readAnalyticsReferences(), reference);
  if (rows.length) shopStorage.setItem(SHOP_ANALYTICS_KEY, encodeSystemConfigReferences(rows));
  else shopStorage.removeItem(SHOP_ANALYTICS_KEY);
  await flushShopStorage();
  return rows;
}
