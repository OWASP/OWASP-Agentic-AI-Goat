// Uses the shared opaque System reference schema; commands and outputs are never persisted.
import { shopStorage, flushShopStorage, SHOP_SYSTEM_RESTART_KEY } from '../../utils/shopStorage.mjs';
import {
  decodeSystemConfigReferences,
  encodeSystemConfigReferences,
  rememberSystemConfigReference,
  forgetSystemConfigReference as forgetReference,
} from './systemConfigOperation.mjs';

const MAX_BYTES = 4096;
const bytes = value => new TextEncoder().encode(value).byteLength;

function read() {
  return decodeSystemConfigReferences(shopStorage.getItem(SHOP_SYSTEM_RESTART_KEY));
}

function encoded(values) {
  const value = encodeSystemConfigReferences(values);
  if (bytes(value) > MAX_BYTES) throw new Error('Saved System operation references exceed limit');
  return value;
}

export function readSystemRestartReferences() {
  return read();
}

export async function saveSystemRestartReference(reference) {
  const next = rememberSystemConfigReference(read(), reference);
  shopStorage.setItem(SHOP_SYSTEM_RESTART_KEY, encoded(next));
  await flushShopStorage();
  return next;
}

export async function forgetSystemRestartReference(reference) {
  const next = forgetReference(read(), reference);
  if (next.length) shopStorage.setItem(SHOP_SYSTEM_RESTART_KEY, encoded(next));
  else shopStorage.removeItem(SHOP_SYSTEM_RESTART_KEY);
  await flushShopStorage();
  return next;
}
