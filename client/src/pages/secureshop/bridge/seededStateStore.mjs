import { createScopedShopStateStore, validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY } from '../utils/shopStorage.mjs';

// The bootstrap persona JWT crosses only the verified shop-state MessagePort.
// Recovery references may persist for the launch, but the JWT never enters
// parent localStorage or a window.postMessage payload.
export function createSeededShopStateStore({ personaToken, ...scope }) {
  if (typeof personaToken !== 'string' || !personaToken || personaToken.length > 8192) {
    throw new TypeError('Bootstrap persona token required');
  }
  const store = createScopedShopStateStore(scope);
  let token = personaToken;
  return Object.freeze({
    read() {
      const snapshot = store.read();
      return validateShopSnapshot({ ...snapshot, [SHOP_TOKEN_KEY]: token });
    },
    replace(snapshot) {
      const value = validateShopSnapshot(snapshot);
      store.replace({ ...value, [SHOP_TOKEN_KEY]: null });
      token = value[SHOP_TOKEN_KEY];
    },
    retire: () => store.retire(),
    close() { token = null; store.close(); },
  });
}
