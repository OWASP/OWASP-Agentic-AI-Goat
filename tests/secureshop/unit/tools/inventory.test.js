'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

function fixture() {
  return {
    state: {
      products: [
        { id: 1, name: 'Alices Widget', stock_quantity: 3, retailer_id: 2, units_sold: 10 },
        { id: 2, name: 'Bobs Gadget', stock_quantity: 25, retailer_id: 3, units_sold: 0 },
      ],
    },
    methods: {
      async inventory_stock_levels_1({ state }) { return state.products.map(product => ({ ...product })); },
      async inventory_reorder_suggestion_2({ state }, productId) {
        const product = state.products.find(row => row.id === productId);
        return product ? { ...product } : null;
      },
      async inventory_set_stock_3({ state }, quantity, productId) {
        const product = state.products.find(row => row.id === productId);
        if (!product) return { changes: 0 };
        product.stock_quantity = quantity;
        return { changes: 1 };
      },
    },
  };
}

test('inventory stock and reorder calculations use PostgreSQL repository results', async () => {
  await withPostgresRepositoryDoubles({ commerce: fixture() }, async scope => {
    const { stock_levels, reorder_suggestion } = scope.loadFresh('agent-host/agents/inventory/tools/index.js');
    const levels = await stock_levels();
    assert.equal(levels.count, 2);
    assert.deepEqual(levels.low_stock.map(row => row.id), [1]);
    assert.deepEqual(await reorder_suggestion({ product_id: 1 }), {
      ok: true, product_id: 1, current: 3, units_sold: 10, suggested_reorder: 17,
    });
  });
});

test('inventory set_stock retains the intentional cross-tenant write', async () => {
  await withPostgresRepositoryDoubles({ commerce: fixture() }, async scope => {
    const { set_stock } = scope.loadFresh('agent-host/agents/inventory/tools/index.js');
    assert.deepEqual(await set_stock({ product_id: 2, qty: 999 }, { userId: 2 }),
      { ok: true, product_id: 2, new_qty: 999 });
    assert.deepEqual(scope.calls[0].args, [999, 2], 'repository receives no retailer ownership condition');
    const product = scope.commerceState.products.find(row => row.id === 2);
    assert.equal(product.stock_quantity, 999);
    assert.equal(product.retailer_id, 3);
  });
});
