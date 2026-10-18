import { GUEST_CART_STORAGE_KEY } from './bridge/guestCartProtocol.mjs';
import { GUEST_CART_IMPORT_REQUEST_KEY, readSavedGuestCart,
  prepareGuestCartImport, clearImportedGuestCart } from './guestCartImport.mjs';

const initial = { version: 1, revision: 4, items: [{ productId: 125, quantity: 2 }] };
const uppercaseId = '7F078C35-0BDA-4BB4-9C9F-819807AA2668';
function memoryStorage() {
  const values = new Map();
  return { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key) };
}

test('import request ID is stable and lowercase across retry and page recovery', () => {
  const storage = memoryStorage();
  storage.setItem(GUEST_CART_STORAGE_KEY, JSON.stringify(initial));
  const first = prepareGuestCartImport(storage, readSavedGuestCart(storage), () => uppercaseId);
  expect(first.requestId).toBe(uppercaseId.toLowerCase());
  expect(JSON.parse(storage.getItem(GUEST_CART_IMPORT_REQUEST_KEY)).requestId).toBe(uppercaseId.toLowerCase());
  const recovered = prepareGuestCartImport(storage, readSavedGuestCart(storage), () => { throw Error('should reuse'); });
  expect(recovered.requestId).toBe(first.requestId);
});

test('confirmed receipt clears only the exact saved revision and items', () => {
  const storage = memoryStorage();
  storage.setItem(GUEST_CART_STORAGE_KEY, JSON.stringify(initial));
  const prepared = prepareGuestCartImport(storage, readSavedGuestCart(storage), () => uppercaseId);
  storage.setItem(GUEST_CART_STORAGE_KEY, JSON.stringify({ ...initial, revision: 5 }));
  expect(clearImportedGuestCart(storage, prepared)).toBe(false);
  expect(readSavedGuestCart(storage)?.revision).toBe(5);
  storage.setItem(GUEST_CART_STORAGE_KEY, JSON.stringify(initial));
  expect(clearImportedGuestCart(storage, prepared)).toBe(true);
  expect(storage.getItem(GUEST_CART_STORAGE_KEY)).toBeNull();
  expect(storage.getItem(GUEST_CART_IMPORT_REQUEST_KEY)).toBeNull();
});
