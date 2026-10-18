import { GUEST_CART_STORAGE_KEY, parseStoredGuestCart, validGuestCartItems } from './bridge/guestCartProtocol.mjs';

const REQUEST_KEY = 'dvaia.secureshop.guest-cart-import.v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function readSavedGuestCart(storage) {
  if (!storage || typeof storage.getItem !== 'function') return null;
  const snapshot = parseStoredGuestCart(storage.getItem(GUEST_CART_STORAGE_KEY));
  return snapshot?.items.length ? snapshot : null;
}

export function prepareGuestCartImport(storage, snapshot, createId = () => globalThis.crypto.randomUUID()) {
  if (!snapshot || !validGuestCartItems(snapshot.items) || !snapshot.items.length
    || !Number.isSafeInteger(snapshot.revision) || snapshot.revision < 0
    || typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function') {
    throw new TypeError('Saved guest cart required');
  }
  const current = readSavedGuestCart(storage);
  if (!current || current.revision !== snapshot.revision
    || JSON.stringify(current.items) !== JSON.stringify(snapshot.items)) {
    throw new Error('Saved cart changed. Review it before importing.');
  }
  const fingerprint = JSON.stringify([snapshot.revision, snapshot.items]);
  let saved;
  try { saved = JSON.parse(storage.getItem(REQUEST_KEY) || 'null'); } catch { saved = null; }
  const requestId = (saved?.fingerprint === fingerprint && UUID.test(saved?.requestId || '')
    ? saved.requestId : createId()).toLowerCase();
  if (!UUID.test(requestId)) throw new Error('Cannot prepare a safe cart import.');
  storage.setItem(REQUEST_KEY, JSON.stringify({ fingerprint, requestId }));
  return Object.freeze({ requestId, items: snapshot.items.map(item => ({ ...item })),
    revision: snapshot.revision, fingerprint });
}

export function clearImportedGuestCart(storage, prepared) {
  if (!prepared || !UUID.test(prepared.requestId || '') || !Number.isSafeInteger(prepared.revision)) return false;
  const current = readSavedGuestCart(storage);
  if (!current || current.revision !== prepared.revision
    || JSON.stringify([current.revision, current.items]) !== prepared.fingerprint) return false;
  storage.removeItem(GUEST_CART_STORAGE_KEY);
  let saved;
  try { saved = JSON.parse(storage.getItem(REQUEST_KEY) || 'null'); } catch { saved = null; }
  if (saved?.fingerprint === prepared.fingerprint && saved.requestId?.toLowerCase() === prepared.requestId) {
    storage.removeItem(REQUEST_KEY);
  }
  return true;
}

export { REQUEST_KEY as GUEST_CART_IMPORT_REQUEST_KEY };
