'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { DEFAULTS_SHA256 } = require('../server/database/postgres/secureshopStandaloneSeed');
const {
  DEFAULT_ACCOUNTS,
  assertFreshDefaults,
  readRenderedAccountIdentity,
  matchesRenderedAccountIdentity,
  waitForRenderedAccountIdentity,
  clickExactRegistrationRole,
  readRenderedRegistrationRoles,
  assertRenderedRegistrationRoles,
  waitForRenderedLogout,
  readAuthoritySnapshot,
  registrationCohort,
} = require('./fixtures/fullBackendRenderedStandaloneBootstrap');

function row(account, index) {
  const id = index + 1;
  return { principalId: `${id}`.repeat(8) + '-aaaa-4aaa-8aaa-' + `${id}`.repeat(12),
    ownerId: id, shopUserId: 1000000000 + id, username: account.username,
    email: account.email, role: account.role, credentialVersion: '1', authorityVersion: '1',
    isActive: true, passwordHash: `synthetic-hash-${index}` };
}

test('A22 snapshot reads only exact standalone and platform authority records', async () => {
  const calls = [];
  const pool = { query: async (sql, values = []) => {
    calls.push([sql, values]);
    if (sql.includes('FROM secureshop_auth.principals')) {
      return { rows: DEFAULT_ACCOUNTS.map(row) };
    }
    if (sql.includes('FROM identity.users')) return { rows: [] };
    if (sql.includes('FROM secureshop_auth.default_seed_state')) {
      return { rows: [{ defaultsSha256: DEFAULTS_SHA256 }] };
    }
    throw new Error('Unexpected query');
  } };
  const names = DEFAULT_ACCOUNTS.map(account => account.username);
  const snapshot = assertFreshDefaults(await readAuthoritySnapshot(pool, names));
  assert.equal(snapshot.principals.length, 3);
  assert.ok(snapshot.principals.every(account => !Object.hasOwn(account, 'passwordHash')));
  assert.ok(snapshot.principals.every(account => /^[a-f0-9]{64}$/.test(account.passwordHashSha256)));
  assert.deepEqual(calls.map(([, values]) => values), [[names], [names], []]);
});

test('A22 default assertion rejects workshop authority and seed drift', () => {
  const principals = DEFAULT_ACCOUNTS.map(row);
  const base = { principals: principals.map(account => ({ ...account,
    passwordHashSha256: 'a'.repeat(64) })), platformUsers: [],
  marker: [{ defaultsSha256: DEFAULTS_SHA256 }] };
  assert.doesNotThrow(() => assertFreshDefaults(base));
  assert.throws(() => assertFreshDefaults({ ...base,
    platformUsers: [{ username: 'student_admin', role: 'admin', adminLevel: 2 }] }),
  /must not create workshop/);
  assert.throws(() => assertFreshDefaults({ ...base,
    marker: [{ defaultsSha256: 'b'.repeat(64) }] }), /durable seed marker/);
});

test('A22 registration cohort contains only public customer and merchant roles', () => {
  const cohort = registrationCohort('abc12345');
  assert.deepEqual(cohort.map(row => row.role), ['customer', 'merchant']);
  assert.equal(new Set(cohort.map(row => row.username)).size, 2);
  assert.ok(cohort.every(row => row.password.length >= 8 && row.email.endsWith('@example.invalid')));
  assert.throws(() => registrationCohort('../unsafe'), /regular expression/);
});

test('A22 Account identity binds exact DOM text to its visible uppercase role badge', () => {
  const node = ({ textContent, innerText = textContent, children = {}, nextElementSibling = null }) => ({
    textContent, innerText, nextElementSibling,
    getClientRects: () => [{}],
    querySelector: selector => children[selector] || null,
  });
  const username = node({ textContent: 'student_customer' });
  const role = node({ textContent: 'customer', innerText: 'CUSTOMER' });
  const identity = node({
    textContent: 'Signed in as student_customer · role: customer',
    innerText: 'Signed in as student_customer · role: CUSTOMER',
    children: { strong: username, '.ss-badge': role },
  });
  const heading = node({ textContent: 'Account', nextElementSibling: identity });
  const documentRef = { querySelectorAll: selector => selector === 'h1' ? [heading] : [] };
  const styleFor = element => ({ display: 'block', visibility: 'visible', opacity: '1',
    textTransform: element === role ? 'uppercase' : 'none' });
  const snapshot = readRenderedAccountIdentity(documentRef, styleFor);
  assert.equal(matchesRenderedAccountIdentity(snapshot,
    { username: 'student_customer', role: 'customer' }), true);
  assert.equal(matchesRenderedAccountIdentity({ ...snapshot, role: 'CUSTOMER' },
    { username: 'student_customer', role: 'customer' }), false,
  'CSS capitalization must not replace the exact underlying role value');
});

test('A22 Account wait failure reports only bounded identity diagnostics', async () => {
  const frame = { evaluate: async () => ({ accountHeadings: 1, headingVisible: true,
    identityVisible: true, usernameVisible: true, roleVisible: true,
    username: 'student_customer', role: 'customer', renderedIdentity: 'Loading account',
    renderedRole: '', roleTransform: 'uppercase' }) };
  await assert.rejects(waitForRenderedAccountIdentity(frame,
    { username: 'student_customer', role: 'customer', password: 'must-not-appear' }, 1), error => {
    assert.match(error.message, /Rendered Account identity mismatch/);
    assert.doesNotMatch(error.message, /must-not-appear/);
    assert.ok(error.message.length < 1024);
    return true;
  });
});

test('A22 registration binds exact visible role label nodes and preserves descriptions', async () => {
  const { JSDOM } = require('../client/node_modules/jsdom');
  const dom = new JSDOM(`<form><label>Role</label><div>
    <button type="button" aria-pressed="true"><div>Customer</div><div>shop products, chat with the customer agent</div></button>
    <button type="button" aria-pressed="false"><div>Merchant</div><div>manage listings and reviews</div></button>
  </div></form>`);
  const original = global.document;
  global.document = dom.window.document;
  const elements = [...document.querySelectorAll('*')];
  for (const element of elements) {
    element.getClientRects = () => [{}];
    element.scrollIntoView = () => {};
    element.getBoundingClientRect = () => ({ x: 10, y: 10, width: 100, height: 30 });
  }
  const styleFor = () => ({ display: 'block', visibility: 'visible', opacity: '1' });
  let clicked = false;
  const page = {
    waitForFunction: async (fn, _options, value) => assert.equal(fn(value), true),
    click: async selector => {
      const target = document.querySelector(selector);
      assert.equal(target.children[0].textContent, 'Merchant');
      for (const button of document.querySelectorAll('button[aria-pressed]')) {
        button.setAttribute('aria-pressed', String(button === target));
      }
      clicked = true;
    },
    evaluate: async fn => fn(),
  };
  try {
    document.elementFromPoint = () => document.querySelectorAll('button')[1];
    const initial = readRenderedRegistrationRoles(document, styleFor);
    assert.doesNotThrow(() => assertRenderedRegistrationRoles(initial));
    await clickExactRegistrationRole(page, 'Merchant');
    assert.equal(clicked, true);
    const selected = readRenderedRegistrationRoles(document, styleFor);
    assert.doesNotThrow(() => assertRenderedRegistrationRoles(selected, 'merchant'));
    assert.deepEqual(selected.roles.map(role => role.description),
      ['shop products, chat with the customer agent', 'manage listings and reviews']);
    assert.throws(() => assertRenderedRegistrationRoles({ ...selected,
      roles: [...selected.roles, { ...selected.roles[1], label: 'Admin', description: 'manage all users' }] },
    'merchant'), /exactly the visible Customer and Merchant/);
  } finally {
    global.document = original;
    dom.window.close();
  }
});

test('A22 logout observes SPA pathname without animation-frame polling and projects bounded failure state', async () => {
  const main = {};
  const child = { $$eval: async () => ['frame1:Account'] };
  let urls = 0;
  const page = {
    url: () => `http://127.0.0.1${++urls < 2 ? '/secureshop/account' : '/secureshop'}`,
    $$eval: async () => ['page:SecureShop'],
    mainFrame: () => main,
    frames: () => [main, child],
  };
  const sessionReader = async () => ({ status: 200,
    body: { authenticated: false, user: null, privateToken: 'must-not-appear' } });
  const result = await waitForRenderedLogout(page, { timeoutMs: 20, intervalMs: 1, sessionReader });
  assert.equal(result.pathname, '/secureshop');
  assert.deepEqual(result.headings, ['page:SecureShop', 'frame1:Account']);
  assert.deepEqual(result.session, { status: 200, authenticated: false, role: null });
  assert.doesNotMatch(JSON.stringify(result), /must-not-appear/);

  const stuck = { ...page, url: () => 'http://127.0.0.1/secureshop/account' };
  await assert.rejects(waitForRenderedLogout(stuck,
    { timeoutMs: 1, intervalMs: 1, sessionReader }), error => {
    assert.match(error.message, /Rendered sign-out did not reach the public shop/);
    assert.equal(error.actual.pathname, '/secureshop/account');
    assert.deepEqual(error.actual.session, { status: 200, authenticated: false, role: null });
    assert.doesNotMatch(error.message, /must-not-appear/);
    assert.ok(error.message.length < 1024);
    return true;
  });
});
