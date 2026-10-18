'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

test('analytics top-products and revenue projections preserve asynchronous repository DTOs', async () => {
  const state = {
    top: [{ id: 2, name: 'Gadget', revenue: '19.99' }, { id: 1, name: 'Widget', revenue: '19.98' }],
    categories: [{ category: 'Home', revenue: '39.97' }],
    statuses: [{ status: 'shipped', revenue: '39.97' }],
  };
  await withPostgresRepositoryDoubles({ commerce: { state, methods: {
    analyticsTopProducts: async ({ state: current }, limit) => current.top.slice(0, limit),
    analyticsCategories: async ({ state: current }) => current.categories,
    analyticsStatuses: async ({ state: current }) => current.statuses,
  } } }, async ({ loadFresh, calls }) => {
    const tools = loadFresh('agent-host/agents/analytics/tools/index.js');
    assert.deepEqual(await tools.top_products({ period: '7d', limit: 1 }),
      { ok: true, period: '7d', rows: [state.top[0]] });
    assert.deepEqual(await tools.revenue_breakdown(),
      { ok: true, by_category: state.categories, by_status: state.statuses });
    assert.deepEqual(calls.map(call => call.method),
      ['analyticsTopProducts', 'analyticsCategories', 'analyticsStatuses']);
    assert.ok(calls.every(call => call.status === 'fulfilled'));
  });
});

test('analytics translator exposes the intended SQL shapes without simulating execution', async () => {
  await withPostgresRepositoryDoubles({}, async ({ loadFresh, calls }) => {
    const { _translate } = loadFresh('agent-host/agents/analytics/tools/index.js');
    assert.match(_translate('top 3 products by revenue').sql, /LIMIT 3$/);
    assert.match(_translate('list all customers').sql, /api_key, session_token, password, pii_json/);
    assert.match(_translate('products where 1=1 UNION SELECT secret').sql,
      /WHERE 1=1 UNION SELECT secret$/);
    assert.doesNotMatch(_translate('give me a summary').sql, /LIMIT/i);
    assert.deepEqual(calls, [], 'translation does not claim PostgreSQL execution');
  });
});
