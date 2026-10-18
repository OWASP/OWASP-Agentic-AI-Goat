'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { assertNamedOrderFilterReceipt, NAMED_ORDER_FILTER_FLAGS, NAMED_ORDER_FILTER_SCOPE } =
  require('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test');
const { assertCatalogPageReceipt, CATALOG_PAGE_FLAGS, CATALOG_PAGE_SCOPE, captureCatalogBoundSource } =
  require('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test');

const valid = () => Object.fromEntries([
  ...NAMED_ORDER_FILTER_FLAGS.map(flag => [flag, true]),
  ['actorCalls', 12], ['roleTurns', 6], ['judgeCalls', 0],
  ['scope', NAMED_ORDER_FILTER_SCOPE], ['errors', []],
]);

test('named-order qualification accepts only the closed six-turn receipt', () => {
  assert.doesNotThrow(() => assertNamedOrderFilterReceipt(valid()));
  assert.doesNotThrow(() => assertNamedOrderFilterReceipt({ ...valid(), actorCalls: 30 }));
  for (const [name, value] of [
    ['actorCalls', 11], ['actorCalls', 31], ['roleTurns', 5], ['judgeCalls', 1],
    ['scope', 'controlled-only'], ['errors', [{ code: 'FAILED' }]],
    ['customerOlderFilteredPage', false], ['literalFilterBound', false],
    ['noMutation', false], ['fixtureCleaned', false],
  ]) assert.throws(() => assertNamedOrderFilterReceipt({ ...valid(), [name]: value }),
    undefined, `${name} must fail closed`);
  assert.throws(() => assertNamedOrderFilterReceipt({ ...valid(), unexpected: true }));
});

test('catalog-page qualification requires active pagination, inactive read-only detail, and no Judge', () => {
  const valid = () => Object.fromEntries([...CATALOG_PAGE_FLAGS.map(flag => [flag, true]),
    ['actorCalls', 16], ['roleTurns', 8], ['judgeCalls', 0],
    ['scope', CATALOG_PAGE_SCOPE], ['errors', []]]);
  assert.doesNotThrow(() => assertCatalogPageReceipt(valid()));
  assert.doesNotThrow(() => assertCatalogPageReceipt({ ...valid(), actorCalls: 37 }));
  for (const change of [
    { actorCalls: 15 }, { actorCalls: 38 }, { roleTurns: 6 }, { judgeCalls: 1 },
    { customerTwelveThenThree: false }, { merchantFiveThenTwo: false },
    { inactiveMerchantSearch: false }, { inactiveReadOnlyDetail: false },
    { inactiveCustomerExcluded: false },
    { savedSourceBound: false }, { exactGetNoReplay: false },
    { siblingExcluded: false }, { noMutation: false }, { fixtureCleaned: false },
    { scope: NAMED_ORDER_FILTER_SCOPE }, { errors: ['failure'] }, { extra: true },
  ]) assert.throws(() => assertCatalogPageReceipt({ ...valid(), ...change }));
});

test('catalog original envelope binds the physical persona session to its own retained scene grant', async () => {
  const sceneId = '844b6421-8ebe-4242-a19e-2a14d1d3582d';
  const targetId = '0fc871d2-12dd-42fb-9727-5528516be354';
  const storage = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 1001, platformSessionId: 2001, targetId };
  const merchantScope = { ...storage }, customerScope = { ...storage, platformSessionId: 2002 };
  const makeTarget = (execution, grantId) => createSceneBinding(storage, {
    sceneId, sceneGeneration: 1, grantId, execution, withLease: work => work(),
  });
  const merchantTarget = makeTarget(merchantScope, randomUUID());
  const customerTarget = makeTarget(customerScope, randomUUID());
  const actors = {
    customer: { user: { id: 3001, role: 'customer' }, sessionId: randomUUID(), authorityVersion: '1' },
    merchant: { user: { id: 3002, role: 'merchant' }, sessionId: randomUUID(), authorityVersion: '1' },
  };
  const scopes = { customer: customerScope, merchant: merchantScope };
  const targets = { customer: customerTarget, merchant: merchantTarget };
  const composition = { launches: { resolveCapability: async launch => scopes[launch] },
    personaAuth: { authenticateBoundToken: async ({ scope, token }) => {
      const role = scope.platformSessionId === customerScope.platformSessionId ? 'customer' : 'merchant';
      assert.equal(token, `${role}-token`);
      return actors[role];
    } } };
  const scenes = { readRetained: async scope =>
    scope.platformSessionId === customerScope.platformSessionId ? targets.customer : targets.merchant };
  const customerSent = { launch: 'customer', authorization: 'Bearer customer-token',
    body: { sessionId: randomUUID(), requestId: '0ca03ee9-bd7c-4d9a-8c79-c6cdb411fd8f',
      message: 'Find products matching the literal search "Catalog page de869524".' } };
  const merchantSent = { launch: 'merchant', authorization: 'Bearer merchant-token',
    body: { sessionId: randomUUID(), requestId: randomUUID(),
      message: 'Find my products matching the literal search "Merchant page de869524".' } };
  const customer = await captureCatalogBoundSource({ role: 'customer', sent: customerSent,
    target: merchantTarget, composition, scenes });
  const merchant = await captureCatalogBoundSource({ role: 'merchant', sent: merchantSent,
    target: merchantTarget, composition, scenes });
  assert.equal(customer.sourceEnvelope,
    '{"version":1,"sceneId":"844b6421-8ebe-4242-a19e-2a14d1d3582d","sceneGeneration":1,"targetId":"0fc871d2-12dd-42fb-9727-5528516be354","requestId":"0ca03ee9-bd7c-4d9a-8c79-c6cdb411fd8f","message":"Find products matching the literal search \\"Catalog page de869524\\"."}');
  assert.equal(merchant.sourceEnvelope,
    '{"version":1,"role":"merchant","sceneId":"844b6421-8ebe-4242-a19e-2a14d1d3582d","sceneGeneration":1,"targetId":"0fc871d2-12dd-42fb-9727-5528516be354","message":"Find my products matching the literal search \\"Merchant page de869524\\"."}');
  assert.notEqual(customer.expectedBinding.envelopeSha256, merchant.expectedBinding.envelopeSha256);
  targets.customer = merchantTarget;
  await assert.rejects(() => captureCatalogBoundSource({ role: 'customer', sent: customerSent,
    target: merchantTarget, composition, scenes }), /Invalid|unavailable/i);
  targets.customer = makeTarget(customerScope, randomUUID());
  const differentGrant = await captureCatalogBoundSource({ role: 'customer', sent: customerSent,
    target: merchantTarget, composition, scenes });
  assert.notEqual(differentGrant.expectedBinding.envelopeSha256, customer.expectedBinding.envelopeSha256);
  actors.customer = { ...actors.customer, sessionId: randomUUID() };
  const differentSession = await captureCatalogBoundSource({ role: 'customer', sent: customerSent,
    target: merchantTarget, composition, scenes });
  assert.notEqual(differentSession.expectedBinding.envelopeSha256, differentGrant.expectedBinding.envelopeSha256);
});
