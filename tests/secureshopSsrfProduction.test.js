'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { activationPolicy, assertSecureShopSsrfReadiness } = require('../server/services/secureshopSsrfProduction');
const { createSecureShopBoundReviewComposition } = require('../server/services/secureshopBoundReviewComposition');

test('SSRF activation is explicit and requires PostgreSQL stores', () => {
  assert.equal(activationPolicy({ PLATFORM_DATABASE_ENGINE: 'postgres' }).requested, false);
  assert.throws(() => activationPolicy({ SS_CONTROLLED_SSRF_READY: 'yes' }), { code: 'INVALID_CONFIGURATION' });
  assert.throws(() => activationPolicy({ SS_CONTROLLED_SSRF_READY: 'true', PLATFORM_DATABASE_ENGINE: 'postgres' }));
  assert.equal(activationPolicy({ SS_CONTROLLED_SSRF_READY: 'true', PLATFORM_DATABASE_ENGINE: 'postgres',
    WORKSHOP_DATABASE_ENGINE: 'postgres' }).requested, true);
});

test('structural readiness preserves hidden/disabled catalog state and rejects partial schemas', async () => {
  let missing = false;
  const agentsPool = { async query(_sql, [names]) { return { rows: names.map((value, index) => ({
    value, ready: !missing || index !== 0,
  })) }; } };
  const identityPool = { async query(sql, args) {
    if (sql.includes('pg_constraint')) return { rows: args[0].map(conname => ({ conname, ready: true })) };
    return { rows: [{ exercise_active: true, objective_active: true, is_visible: false, is_enabled: false }] };
  } };
  assert.equal(await assertSecureShopSsrfReadiness({ identityPool, agentsPool }), true);
  missing = true;
  await assert.rejects(assertSecureShopSsrfReadiness({ identityPool, agentsPool }), { code: 'BOUND_SSRF_UNAVAILABLE' });
});

test('enabled direct composition shares SSRF reset bundle and requires its real tool pool', () => {
  let effects = 0;
  const pool = { async query() { effects++; throw new Error('No construction queries'); },
    async connect() { effects++; throw new Error('No construction connections'); } };
  const common = { identityPool: pool, agentsPool: pool, reviewPool: pool, leasePool: pool,
    ssrfFeature: true, ssrfFixtureRoot: '/owned-ssrf-fixture', fixtures: [],
    authenticatePersona(_req, _res, next) { next(); },
    catalog: Object.fromEntries(['listProducts', 'getProduct', 'listMerchantProducts', 'hasProduct', 'prepareTarget',
      'createMerchantProduct', 'updateMerchantProduct', 'archiveMerchantProduct', 'categories']
      .map(name => [name, async () => { throw new Error('No catalog effects'); }])),
    account: Object.fromEntries(['profile','updateProfile','addresses','createAddress','updateAddress','deleteAddress'].map(name => [name, async () => { throw new Error('No account effects'); }])),
    agentRuntime: { provider: { async chat() { effects++; }, async finalResponse() { effects++; } }, pool: { async callTool() { effects++; } } },
    reviewCardRenderer: { sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), async renderReviewCard() {} },
    browserQualification: { async qualify() { effects++; }, async close() {} },
  };
  assert.throws(() => createSecureShopBoundReviewComposition({ ...common, ssrfFixtureRoot: undefined }), { code: 'BOUND_SSRF_UNAVAILABLE' });
  assert.throws(() => createSecureShopBoundReviewComposition({ ...common,
    agentRuntime: { provider: common.agentRuntime.provider } }), { code: 'BOUND_SSRF_UNAVAILABLE' });
  const composition = createSecureShopBoundReviewComposition(common);
  assert.equal(composition.ssrf.ready, true);
  assert.equal(typeof composition.ssrf.router, 'function');
  assert.equal(typeof composition.launchResetCoordinator.reset, 'function');
  assert.equal(effects, 0);
});
