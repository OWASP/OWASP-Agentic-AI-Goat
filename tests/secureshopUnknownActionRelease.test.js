'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSecureShopBoundGateway } = require('../server/routes/secureshop/boundGateway');
const { createSecureShopBoundDispatch } = require('../server/middleware/secureshopBoundDispatch');

const launch = Object.freeze({
  launchId: '10000000-0000-4000-8000-000000000091',
  scenarioId: '20000000-0000-4000-8000-000000000091',
  generation: 4,
  platformOwnerId: 91,
  platformSessionId: 901,
});
const launchBearer = 'g'.repeat(43);

function methods(names) {
  return Object.fromEntries(names.map(name => [name, async () => ({})]));
}

async function fixture(t) {
  let legacyCalls = 0;
  const personaAuth = methods(['login', 'renew', 'logout', 'listSessions', 'revokeOwnedSession',
    'changePassword', 'listApiKey', 'rotateApiKey', 'authenticateApiKey']);
  const gateway = createSecureShopBoundGateway({
    launches: { async resolveCapability(value) { return value === launchBearer ? launch : null; } },
    authenticatePersona(req, _res, next) {
      req.ssUser = { id: 7, role: 'admin' };
      return next();
    },
    personaAuth,
    reviewsRouter: express.Router(),
    browserRouter: express.Router(),
    catalog: methods(['listProducts', 'getProduct', 'listMerchantProducts', 'createMerchantProduct',
      'updateMerchantProduct', 'archiveMerchantProduct', 'categories']),
    commerce: methods(['cart', 'add', 'update', 'remove', 'summary', 'checkout', 'orders', 'order']),
    account: methods(['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress',
      'deleteAddress']),
  });
  const app = express();
  app.use(express.json());
  // Exercise the supported standalone launch path: the dispatch middleware
  // owns launch-bearing requests before the legacy router can see them.
  app.use('/api/secureshop', createSecureShopBoundDispatch({ getGateway: () => gateway }));
  app.use('/api/secureshop', (_req, res) => {
    legacyCalls += 1;
    res.json({ legacy: true });
  });
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  return {
    base: `http://127.0.0.1:${server.address().port}/api/secureshop`,
    legacyCalls: () => legacyCalls,
  };
}

function headers() {
  return {
    authorization: 'Bearer admin-7',
    'x-dvaia-secureshop-launch': launchBearer,
  };
}

test('bound unknown GET and POST actions are 404 while known disabled adapters remain terminal 503', async t => {
  const f = await fixture(t);

  for (const [method, path] of [
    ['GET', '/release-probe/unknown'],
    ['POST', '/release-probe/unknown'],
  ]) {
    const response = await fetch(`${f.base}${path}`, {
      method,
      headers: { ...headers(), ...(method === 'POST' ? { 'content-type': 'application/json' } : {}) },
      ...(method === 'POST' ? { body: '{}' } : {}),
    });
    assert.equal(response.status, 404);
    assert.deepEqual(await response.json(), { error: 'Bound SecureShop route not found' });
  }

  const disabled = await fetch(`${f.base}/v2/mcp-trust/discover`, {
    method: 'POST',
    headers: { ...headers(), 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(disabled.status, 503);
  assert.deepEqual(await disabled.json(), { error: 'MCP trust exercise unavailable' });

  const listingsDisabled = await fetch(`${f.base}/merchant/listings/rewrite-save`, {
    method: 'POST',
    headers: { ...headers(), 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(listingsDisabled.status, 503);
  assert.deepEqual(await listingsDisabled.json(), { error: 'Bound SecureShop operation unavailable' });
  const rewriteReadDisabled = await fetch(`${f.base}/merchant/listings/rewrite-saves/11111111-1111-4111-8111-111111111111`, {
    headers: headers(),
  });
  assert.equal(rewriteReadDisabled.status, 503);
  assert.deepEqual(await rewriteReadDisabled.json(), { error: 'Bound SecureShop operation unavailable' });

  const assessmentDisabled = await fetch(`${f.base}/agents/merchant/assistant/listing-create/assess`, {
    method: 'POST',
    headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ operationId: '11111111-1111-4111-8111-111111111111' }),
  });
  assert.equal(assessmentDisabled.status, 503);
  assert.deepEqual(await assessmentDisabled.json(), { error: 'Bound SecureShop operation unavailable' });
  const assessmentReadDisabled = await fetch(`${f.base}/agents/merchant/assistant/listing-create/assessment/11111111-1111-4111-8111-111111111111`, {
    headers: headers(),
  });
  assert.equal(assessmentReadDisabled.status, 503);
  assert.deepEqual(await assessmentReadDisabled.json(), { error: 'Bound SecureShop operation unavailable' });
  const assessmentTypo = await fetch(`${f.base}/agents/merchant/assistant/listing-create/assesss`, {
    headers: headers(),
  });
  assert.equal(assessmentTypo.status, 404);
  assert.deepEqual(await assessmentTypo.json(), { error: 'Bound SecureShop route not found' });
  const forbiddenRetryRoute = await fetch(`${f.base}/agents/merchant/assistant/listing-create/assessment-check`, {
    method: 'POST',
    headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ operationId: '11111111-1111-4111-8111-111111111111', evaluationId: '22222222-2222-4222-8222-222222222222' }),
  });
  assert.equal(forbiddenRetryRoute.status, 404);
  assert.deepEqual(await forbiddenRetryRoute.json(), { error: 'Bound SecureShop route not found' });

  for (const method of ['GET', 'POST']) {
    const response = await fetch(`${f.base}/v2/mcp-trust/operation`, {
      method,
      headers: { ...headers(), ...(method === 'POST' ? { 'content-type': 'application/json' } : {}) },
      ...(method === 'POST' ? { body: '{}' } : {}),
    });
    assert.equal(response.status, 404);
    assert.deepEqual(await response.json(), { error: 'Bound SecureShop route not found' });
  }
  const listingTypo = await fetch(`${f.base}/merchant/listings/rewrite-sav`, { headers: headers() });
  assert.equal(listingTypo.status, 404);
  assert.deepEqual(await listingTypo.json(), { error: 'Bound SecureShop route not found' });

  assert.equal(f.legacyCalls(), 0);
});
