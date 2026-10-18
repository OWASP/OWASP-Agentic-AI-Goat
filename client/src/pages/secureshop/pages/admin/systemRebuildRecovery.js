// Uses the shared opaque System reference schema; source documents and vectors are never persisted.
import { shopStorage, flushShopStorage, SHOP_SYSTEM_REBUILD_KEY } from '../../utils/shopStorage.mjs';
import {
  decodeSystemConfigReferences,
  encodeSystemConfigReferences,
  rememberSystemConfigReference,
  forgetSystemConfigReference as forgetReference,
} from './systemConfigOperation.mjs';

const MAX_BYTES = 4096;
const bytes = value => new TextEncoder().encode(value).byteLength;

function read() {
  return decodeSystemConfigReferences(shopStorage.getItem(SHOP_SYSTEM_REBUILD_KEY));
}

function encoded(values) {
  const value = encodeSystemConfigReferences(values);
  if (bytes(value) > MAX_BYTES) throw new Error('Saved System operation references exceed limit');
  return value;
}

export function readSystemRebuildReferences() {
  return read();
}

export async function saveSystemRebuildReference(reference) {
  const next = rememberSystemConfigReference(read(), reference);
  shopStorage.setItem(SHOP_SYSTEM_REBUILD_KEY, encoded(next));
  await flushShopStorage();
  return next;
}

export async function forgetSystemRebuildReference(reference) {
  const next = forgetReference(read(), reference);
  if (next.length) shopStorage.setItem(SHOP_SYSTEM_REBUILD_KEY, encoded(next));
  else shopStorage.removeItem(SHOP_SYSTEM_REBUILD_KEY);
  await flushShopStorage();
  return next;
}
