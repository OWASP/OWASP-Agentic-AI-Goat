import { createSeededShopStateStore } from './seededStateStore.mjs';

test('bootstrap persona JWT reaches the frame snapshot but never parent persistence', () => {
  const persisted = new Map();
  const storage = { getItem: key => persisted.get(key) ?? null,
    setItem: (key, value) => persisted.set(key, value), removeItem: key => persisted.delete(key) };
  const store = createSeededShopStateStore({ storage,
    scenarioId: '7f078c35-0bda-4bb4-9c9f-819807aa2668', generation: 1,
    isCurrent: () => true, personaToken: 'bootstrap.persona.token' });
  expect(store.read().secureshop_v2_token).toBe('bootstrap.persona.token');
  store.replace({ ...store.read(), ss_guest_cart: null, secureshop_v2_token: 'rotated.persona.token' });
  expect(store.read().secureshop_v2_token).toBe('rotated.persona.token');
  expect([...persisted.values()].join(' ')).not.toMatch(/bootstrap\.persona\.token|rotated\.persona\.token/);
  store.close();
});
