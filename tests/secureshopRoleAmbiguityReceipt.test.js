'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { SCOPE, FLAGS, validateRoleAmbiguityReceipt } = require('./fixtures/secureshopRoleAmbiguityReceipt');
const { _internals } = require('./postgres/secureshopStandaloneRoleAmbiguityRendered.integration.test');

const valid = () => ({ ...Object.fromEntries(FLAGS.map(flag => [flag, true])), scope: SCOPE,
  roleTurns: 4, actorCalls: 10, judgeCalls: 0, errors: [] });

test('Q03 accepts only the exact four-turn rendered ambiguity receipt', () => {
  assert.equal(validateRoleAmbiguityReceipt(valid()).passed, true);
  for (const flag of FLAGS) assert.throws(() => validateRoleAmbiguityReceipt({ ...valid(), [flag]: false }),
    { code: 'ERR_ASSERTION' }, `${flag} cannot be omitted`);
});

test('Q03 rejects extra claims, missing choices, model budget violations and Judge calls', () => {
  for (const changed of [
    { extra: true }, { scope: `${SCOPE} controlled` }, { roleTurns: 3 },
    { actorCalls: 7 }, { actorCalls: 21 }, { actorCalls: 9.5 },
    { judgeCalls: 1 }, { errors: ['ignored'] },
  ]) assert.throws(() => validateRoleAmbiguityReceipt({ ...valid(), ...changed }),
    { code: 'ERR_ASSERTION' });
  const missing = valid(); delete missing.adminSelectedIdentityBound;
  assert.throws(() => validateRoleAmbiguityReceipt(missing), { code: 'ERR_ASSERTION' });
});

test('Q03 serves detached frame assets with explicit opaque-origin CORS', () => {
  const calls = [];
  _internals.opaqueFrameStatic().setHeaders({ set(name, value) { calls.push([name, value]); } });
  assert.deepEqual(calls, [['Access-Control-Allow-Origin', '*']]);
});

test('Q03 supplies the administrator reset-recovery prerequisite before bootstrap', () => {
  const values = { identityPool: {}, authService: {}, launches: {}, scenes: {},
    resetComposition: { launchResetCoordinator: {}, sceneResetPreflight: {} } };
  let received;
  const result = _internals.createProtectedReset(values, input => { received = input; return { ready: true }; });
  assert.deepEqual(result, { ready: true });
  assert.deepEqual(received, { identityPool: values.identityPool, authService: values.authService,
    launches: values.launches, scenes: values.scenes,
    resetCoordinator: values.resetComposition.launchResetCoordinator,
    preflight: values.resetComposition.sceneResetPreflight });
});

test('Q03 role composers use the current portaled submit controls', () => {
  assert.deepEqual(_internals.composerSelectors('merchant'), {
    input: 'textarea[id^="lane-merchant-assistant-"]',
    button: 'form:has(textarea[id^="lane-merchant-assistant-"]) button[type="submit"]',
  });
  assert.deepEqual(_internals.composerSelectors('admin'), {
    input: 'textarea[id^="lane-admin-assistant-"]',
    button: '[data-testid="admin-role-composer-slot"] button[type="submit"]',
  });
  assert.throws(() => _internals.composerSelectors('customer'), /Bound role required/);
});

test('Q03 physically selects the explicit read-only merchant product action', () => {
  const choiceId = '10000000-0000-4000-8000-000000000003';
  assert.deepEqual(_internals.merchantProductDetailsAction({ choiceId, title: 'Q03 lantern azure' }), {
    selector: '[data-testid="merchant-role-assistant"] button[aria-label="View details for Q03 lantern azure"]',
    message: 'Show my selected product details.',
    selection: { choiceId, intent: 'product_details' },
  });
});

test('Q03 failure diagnostics retain bounded tool arguments and card identity only', () => {
  assert.deepEqual(_internals.boundedToolArgs({ search: 'x'.repeat(200), page: 1,
    nested: { secret: 'not serialized' } }), { search: 'x'.repeat(160), page: 1,
    nested: '[complex]' });
  const summary = _internals.boundedTurnSummary({ status: 'completed', stopReason: 'end_turn',
    cards: [{ kind: 'merchant_product', title: 'Owned product', detail: 'USD 12.5' }],
    hops: [{ tool: 'merchant.catalog_search', params: { search: 'Q03 lantern' } }] });
  assert.deepEqual(summary.cards, [{ kind: 'merchant_product', title: 'Owned product', detail: 'USD 12.5' }]);
  assert.deepEqual(summary.hops, [{ tool: 'merchant.catalog_search', status: '', error: false,
    errorStatus: null,
    params: { search: 'Q03 lantern' } }]);
  assert.equal(summary.proposals.listingCreateProposal, false);
});

test('Q03 role login waits for the exact authenticated bootstrap before route readiness', async () => {
  for (const [bootstrapRole, accepted] of [['admin', true], ['merchant', false]]) {
    let acknowledge, submitted = false, routeWaited = false;
    const bootstrap = { url: () => 'http://127.0.0.1:12345/api/secureshop/auth/bootstrap',
      request: () => ({ method: () => 'POST' }), status: () => 200,
      json: async () => ({ persona: { user: { role: bootstrapRole } } }) };
    const page = {
      async goto(url) {
        assert.equal(url, 'http://127.0.0.1:12345/secureshop/login?next=%2Fsecureshop%2Fadmin');
        return { status: () => 200 };
      },
      async waitForSelector(selector) { assert.equal(selector, '#ss-login-user'); },
      async type(selector) { assert.ok(['#ss-login-user', '#ss-login-pw'].includes(selector)); },
      waitForResponse(predicate) {
        assert.equal(predicate(bootstrap), true);
        return new Promise(resolve => { acknowledge = () => resolve(bootstrap); });
      },
      async waitForFunction(predicate, _options, target) {
        assert.match(String(predicate), /location\.pathname === target/);
        assert.equal(target, '/secureshop/admin'); assert.equal(submitted, true); routeWaited = true;
      },
      async evaluate() { return { path: '/secureshop/admin', text: 'Administrator', iframe: false }; },
    };
    const submit = async (_page, selector) => {
      assert.equal(selector, 'button[type="submit"]'); submitted = true; acknowledge();
    };
    const promise = _internals.loginRolePage(page, { origin: 'http://127.0.0.1:12345',
      username: 'student_admin', password: 'student123', role: 'admin', next: 'admin' }, submit);
    if (accepted) {
      assert.equal((await promise).persona.user.role, 'admin'); assert.equal(routeWaited, true);
    } else {
      await assert.rejects(promise, /"bootstrapStatus":200.*"bootstrapRole":"merchant"/);
      assert.equal(routeWaited, false);
    }
  }
});

test('Q03 role login safely observes bootstrap rejection when physical submit fails first', async () => {
  const page = {
    async goto() { return { status: () => 200 }; },
    async waitForSelector() {}, async type() {},
    waitForResponse() { return Promise.reject(new Error('bootstrap unavailable')); },
    async evaluate() { return { path: '/secureshop/login', text: 'Sign in', iframe: false }; },
  };
  await assert.rejects(_internals.loginRolePage(page, {
    origin: 'http://127.0.0.1:12345', username: 'student_admin', password: 'student123',
    role: 'admin', next: 'admin',
  }, async () => { throw new Error('physical submit failed'); }),
  /admin authenticated parent bootstrap failed/);
});
