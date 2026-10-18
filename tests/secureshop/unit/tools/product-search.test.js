'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

test('personalized_feed passes the user limit through to the PostgreSQL repository', async () => {
  const feed = [
    { id: 4, name: 'Trail Camera', price: '49.00' },
    { id: 7, name: 'Field Notebook', price: '8.50' },
  ];

  await withPostgresRepositoryDoubles({
    commerce: {
      state: { feed },
      methods: {
        product_search_personalizedFeed_1: async ({ state }, ...args) => {
          assert.deepEqual(args, []);
          return state.feed;
        },
      },
    },
  }, async (scope) => {
    const tool = scope.loadFresh('agent-host/agents/product-search/tools/personalized_feed.js');
    const result = await tool.personalizedFeed({ user_id: 42 });

    assert.equal(result.user_id, 42);
    assert.equal(result.count, 2);
    assert.deepEqual(result.feed, feed);
    assert.deepEqual(scope.calls.map((call) => call.method), [
      'product_search_personalizedFeed_1',
    ]);
  });
});
