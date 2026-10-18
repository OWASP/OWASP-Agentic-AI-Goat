'use strict';

/**
 * @intentional-vulnerability sqli-coupon
 * @teaches OWASP-Web:A03
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const express = require('express');
const { seedShop } = require('../_fixture.js');
const { createSecureShopCustomerRepository } = require('../../../../server/database/postgres/secureshopCustomerRepository');

const REPO = path.resolve(__dirname, '../../../..');

function post(port, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, method: 'POST', path: '/api/secureshop/cart/apply-coupon', headers: { 'content-type': 'application/json' } }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data) }));
    });
    req.on('error', reject);
    req.write(JSON.stringify(body));
    req.end();
  });
}

test('sqli-coupon: injected predicate selects an active coupon without its code', async () => {
  const fixture = await seedShop();
  const routePath = path.join(REPO, 'server/routes/secureshop/customer.js');
  delete require.cache[require.resolve(routePath)];
  const app = express();
  app.use(express.json());
  const repository = createSecureShopCustomerRepository(fixture.runtimePool, fixture.runtimePool);
  app.use('/api/secureshop', require(routePath)({ pool: {}, manifest: {}, provider: {}, repository }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const result = await post(server.address().port, { user_id: 2, code: "' OR 1=1--" });
    assert.equal(result.status, 200);
    assert.equal(result.body.ok, true);
    assert.equal(result.body.code, 'SUMMER10');
  } finally {
    await new Promise(resolve => server.close(resolve));
    await fixture.close();
  }
});
