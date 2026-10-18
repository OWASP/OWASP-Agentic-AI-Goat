'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

const products = [
  { id: 1, name: 'Widget', price: '9.99', category: 'Electronics' },
  { id: 2, name: 'Gadget', price: '19.99', category: 'Electronics' },
];

function repositories() {
  return { commerce: { state: { products }, methods: {
    price_advisor_priceHistory_1: async ({ state }, id) => state.products.find(row => row.id === id),
    price_advisor_findDeals_2: async ({ state }, category) =>
      state.products.filter(row => !category || row.category === category),
    price_advisor_compareCompetitor_3: async ({ state }, id) => state.products.find(row => row.id === id),
  } } };
}

test('price-advisor history and ungrounded deals preserve tool contracts', async () => {
  await withPostgresRepositoryDoubles(repositories(), async ({ loadFresh, calls }) => {
    const { priceHistory, findDeals } = loadFresh('agent-host/agents/price-advisor/tools/index.js');
    const history = await priceHistory({ product_id: 1 });
    assert.equal(history.product_id, 1);
    assert.equal(history.history.length, 31);
    assert.equal(history.grounded, false);
    const result = await findDeals({ category: 'Electronics' });
    assert.equal(result.deals.length, 2);
    assert.ok(result.deals.every(deal => Number.isFinite(deal.competitor_price)
      && deal.quote_source === null));
    assert.equal(result.grounded, false);
    assert.deepEqual(calls.map(call => call.method),
      ['price_advisor_priceHistory_1', 'price_advisor_findDeals_2']);
  });
});

test('price-advisor competitor comparison returns an owned loopback response verbatim', async t => {
  const server = http.createServer((_request, response) => response.end('METADATA_SECRET_XYZ'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const address = server.address();
  await withPostgresRepositoryDoubles(repositories(), async ({ loadFresh, calls }) => {
    const { compareCompetitor } = loadFresh('agent-host/agents/price-advisor/tools/index.js');
    const result = await compareCompetitor({ product_id: 1,
      competitor_url: `http://127.0.0.1:${address.port}/quote` });
    assert.equal(result.competitor_response, 'METADATA_SECRET_XYZ');
    assert.match(result.summary, /METADATA_SECRET_XYZ/);
    assert.deepEqual(calls.map(call => call.method), ['price_advisor_compareCompetitor_3']);
  });
});
