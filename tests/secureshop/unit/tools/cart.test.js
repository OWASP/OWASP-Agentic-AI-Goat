'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

function methods() {
  return {
    async cart_add_1({ state }, userId, productId, quantity) {
      const item = { id: state.nextId++, user_id: userId, product_id: productId, quantity };
      state.cartItems.push(item);
      return { lastInsertRowid: item.id };
    },
    async cart_remove_2({ state }, cartItemId) {
      const before = state.cartItems.length;
      state.cartItems = state.cartItems.filter(item => item.id !== cartItemId);
      return { changes: before - state.cartItems.length };
    },
    async cart_view_3({ state }, userId) {
      return state.cartItems.filter(item => item.user_id === userId).map(item => ({
        ...item,
        name: state.products.find(product => product.id === item.product_id)?.name,
        price: state.products.find(product => product.id === item.product_id)?.price,
      }));
    },
  };
}

test('cart add/view passes owned values to the PostgreSQL repository', async () => {
  await withPostgresRepositoryDoubles({
    commerce: { state: { nextId: 1, cartItems: [], products: [{ id: 1, name: 'Widget', price: 9.99 }] }, methods: methods() },
  }, async scope => {
    const { add, view } = scope.loadFresh('agent-host/agents/cart/tools/index.js');
    assert.deepEqual(await add({ product_id: 1, qty: 2 }, { userId: 7 }),
      { ok: true, cart_item_id: 1, product_id: 1, qty: 2 });
    assert.deepEqual(await view({}, { userId: 7 }), {
      items: [{ id: 1, user_id: 7, product_id: 1, quantity: 2, name: 'Widget', price: 9.99 }],
      subtotal: 19.98,
    });
    assert.deepEqual(scope.calls.map(call => [call.method, call.args]), [
      ['cart_add_1', [7, 1, 2]],
      ['cart_view_3', [7]],
    ]);
  });
});

test('cart remove retains the intentional cross-owner IDOR', async () => {
  await withPostgresRepositoryDoubles({
    commerce: {
      state: { nextId: 2, cartItems: [{ id: 1, user_id: 2, product_id: 1, quantity: 1 }], products: [] },
      methods: methods(),
    },
  }, async scope => {
    const { remove } = scope.loadFresh('agent-host/agents/cart/tools/index.js');
    assert.deepEqual(await remove({ cart_item_id: 1 }, { userId: 1 }), { ok: true, deleted: 1 });
    assert.deepEqual(scope.commerceState.cartItems, []);
    assert.deepEqual(scope.calls[0].args, [1], 'repository receives no caller/owner constraint');
  });
});
