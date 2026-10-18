'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const express = require('express');

test('merchant order sparkline uses daily order counts, never a generated rising sequence', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.UTC(2026, 8, 20, 12) });
  const original = Module._load;
  const route = require.resolve('../server/routes/secureshop/postgres/merchant');
  Module._load = function(name, parent, main) {
    if (name.includes('merchantSupervisor') || name.includes('/streaming.js')) return {};
    if (name.includes('_agentSessionControl')) return { agentSessionControl: () => ({
      create(_req, _res, next) { next(); }, requireOwned(_req, _res, next) { next(); },
    }) };
    if (name.includes('_ssAuthMiddleware')) return { requireRole: () => (_req, _res, next) => next() };
    if (name.includes('secureshopPools')) return {
      getCommercePool() { throw new Error('Metrics projection must use the supplied repository'); },
      getAgentsPool() { throw new Error('Metrics projection must use the supplied repository'); },
    };
    return original.call(this, name, parent, main);
  };
  let build;
  try { delete require.cache[route]; build = require(route); }
  finally { Module._load = original; }
  const repository = { async overview() { return {
    current: { revenue: '90', orders: 9 }, previous: { revenue: '30', orders: 3 },
    days: [{ day: '2026-09-19', revenue: '70', orders: 7 }, { day: '2026-09-20', revenue: '20', orders: 2 }],
  }; } };
  const app = express(); app.use(build({ repository }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/merchant/overview/kpis?retailer_id=2`);
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.deepEqual(result.orders.spark, [...Array(28).fill(0), 7, 2]);
    assert.deepEqual(result.revenue.spark, [...Array(28).fill(0), 70, 20]);
    assert.equal(result.orders.value, 9);
    assert.equal(result.orders.delta_pct, 200);
  } finally { await new Promise(resolve => server.close(resolve)); delete require.cache[route]; }
});
