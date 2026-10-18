'use strict';

const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const {
  DEFAULTS,
  DEFAULTS_SHA256,
  seedSecureShopStandaloneDefaults,
} = require('../../server/database/postgres/secureshopStandaloneSeed');

const DEFAULT_PASSWORD = 'student123';
const DEFAULT_ACCOUNTS = Object.freeze(DEFAULTS.map(row => Object.freeze({
  username: row.username,
  email: row.email,
  role: row.role,
})));

function normalizeRows(rows) {
  return rows.map(row => Object.freeze({
    principalId: row.principalId,
    ownerId: Number(row.ownerId),
    shopUserId: Number(row.shopUserId),
    username: row.username,
    email: row.email,
    role: row.role,
    credentialVersion: String(row.credentialVersion),
    authorityVersion: String(row.authorityVersion),
    isActive: row.isActive,
    passwordHashSha256: createHash('sha256').update(row.passwordHash).digest('hex'),
  }));
}

async function readAuthoritySnapshot(pool, usernames) {
  assert.equal(typeof pool?.query, 'function', 'Identity runtime pool required');
  assert.ok(Array.isArray(usernames) && usernames.length > 0);
  assert.equal(new Set(usernames).size, usernames.length);
  assert.ok(usernames.every(value => typeof value === 'string' && value.length > 0));
  const principals = normalizeRows((await pool.query(`SELECT
      principal_id::text AS "principalId",owner_id AS "ownerId",shop_user_id AS "shopUserId",
      username,email,role,credential_version::text AS "credentialVersion",
      authority_version::text AS "authorityVersion",is_active AS "isActive",
      password_hash AS "passwordHash"
    FROM secureshop_auth.principals WHERE username=ANY($1::text[]) ORDER BY username`,
  [usernames])).rows);
  const platformUsers = (await pool.query(`SELECT username,role,admin_level AS "adminLevel"
    FROM identity.users WHERE username=ANY($1::text[]) ORDER BY username`, [usernames])).rows;
  const marker = (await pool.query(`SELECT defaults_sha256 AS "defaultsSha256"
    FROM secureshop_auth.default_seed_state WHERE seed_key='fresh-install-v1'`)).rows;
  return Object.freeze({ principals, platformUsers, marker });
}

function assertFreshDefaults(snapshot) {
  assert.deepEqual(snapshot.marker, [{ defaultsSha256: DEFAULTS_SHA256 }],
    'Fresh standalone defaults need their durable seed marker');
  assert.deepEqual(snapshot.platformUsers, [],
    'Shop defaults must not create workshop/platform users');
  assert.deepEqual(snapshot.principals.map(row => ({
    username: row.username, email: row.email, role: row.role,
  })).sort((a, b) => a.username.localeCompare(b.username)),
  [...DEFAULT_ACCOUNTS].sort((a, b) => a.username.localeCompare(b.username)));
  for (const row of snapshot.principals) {
    assert.match(row.principalId, /^[0-9a-f-]{36}$/);
    assert.ok(Number.isSafeInteger(row.ownerId) && row.ownerId > 0);
    assert.ok(Number.isSafeInteger(row.shopUserId) && row.shopUserId >= 1000000000);
    assert.equal(row.credentialVersion, '1');
    assert.equal(row.authorityVersion, '1');
    assert.equal(row.isActive, true);
    assert.match(row.passwordHashSha256, /^[a-f0-9]{64}$/);
  }
  return snapshot;
}

function registrationCohort(suffix) {
  assert.match(suffix, /^[a-z0-9]{6,16}$/);
  return Object.freeze(['customer', 'merchant'].map(role => Object.freeze({
    username: `a22_${role}_${suffix}`,
    email: `a22-${role}-${suffix}@example.invalid`,
    password: `A22-${suffix}-Pass!`,
    role,
  })));
}

async function responseFor(page, pathname, method, trigger) {
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === pathname && response.request().method() === method;
  }, { timeout: 20000 });
  pending.catch(() => {});
  await trigger();
  return pending;
}

async function clickExactButton(frame, label) {
  await frame.waitForFunction(text => {
    const matches = [...document.querySelectorAll('button')].filter(button =>
      button.textContent.trim() === text && !button.disabled && button.getClientRects().length);
    if (matches.length !== 1) return false;
    const button = matches[0];
    button.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    const rect = button.getBoundingClientRect();
    const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
    if (hit !== button && !button.contains(hit)) return false;
    button.setAttribute('data-a22-control', 'selected');
    return true;
  }, {}, label);
  try { await frame.click('[data-a22-control="selected"]'); }
  finally {
    await frame.evaluate(() => document.querySelector('[data-a22-control="selected"]')
      ?.removeAttribute('data-a22-control')).catch(() => {});
  }
}

async function clickExactRegistrationRole(page, label) {
  await page.waitForFunction(text => {
    const matches = [...document.querySelectorAll('button[aria-pressed]')].filter(button => {
      const [name, description, ...extra] = [...button.children];
      return name?.textContent.trim() === text && Boolean(description?.textContent.trim())
        && extra.length === 0 && !button.disabled && button.getClientRects().length
        && name.getClientRects().length && description.getClientRects().length;
    });
    if (matches.length !== 1) return false;
    const button = matches[0];
    button.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    const rect = button.getBoundingClientRect();
    const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
    if (hit !== button && !button.contains(hit)) return false;
    button.setAttribute('data-a22-role-control', 'selected');
    return true;
  }, {}, label);
  try { await page.click('[data-a22-role-control="selected"]'); }
  finally {
    await page.evaluate(() => document.querySelector('[data-a22-role-control="selected"]')
      ?.removeAttribute('data-a22-role-control')).catch(() => {});
  }
}

async function boundShopFrame(page) {
  const handle = await page.waitForSelector('iframe[title="SecureShop"]', { visible: true });
  const frame = await handle.contentFrame();
  assert.ok(frame, 'Owned SecureShop frame must load');
  await frame.waitForSelector('button[aria-label="Account menu"]', { visible: true });
  return frame;
}

function readRenderedAccountIdentity(documentRef = document, styleFor = getComputedStyle) {
  const clean = value => String(value || '').replace(/\s+/g, ' ').trim().slice(0, 128);
  const visible = element => {
    if (!element || !element.getClientRects().length) return false;
    const style = styleFor(element);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
  };
  const headings = [...documentRef.querySelectorAll('h1')]
    .filter(element => clean(element.textContent) === 'Account');
  const heading = headings.length === 1 ? headings[0] : null;
  const identity = heading?.nextElementSibling || null;
  const username = identity?.querySelector('strong') || null;
  const role = identity?.querySelector('.ss-badge') || null;
  return Object.freeze({
    accountHeadings: headings.length,
    headingVisible: visible(heading),
    identityVisible: visible(identity),
    usernameVisible: visible(username),
    roleVisible: visible(role),
    username: clean(username?.textContent),
    role: clean(role?.textContent),
    renderedIdentity: clean(identity?.innerText),
    renderedRole: clean(role?.innerText),
    roleTransform: clean(role ? styleFor(role).textTransform : ''),
  });
}

function matchesRenderedAccountIdentity(actual, expected) {
  return actual?.accountHeadings === 1
    && actual.headingVisible === true && actual.identityVisible === true
    && actual.usernameVisible === true && actual.roleVisible === true
    && actual.username === expected.username && actual.role === expected.role
    && actual.roleTransform === 'uppercase'
    && actual.renderedRole === expected.role.toUpperCase()
    && actual.renderedIdentity === `Signed in as ${expected.username} · role: ${expected.role.toUpperCase()}`;
}

async function waitForRenderedAccountIdentity(frame, expected, timeoutMs = 20000) {
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 20000);
  const safeExpected = { username: expected.username, role: expected.role };
  const deadline = Date.now() + timeoutMs;
  let actual = null;
  do {
    actual = await frame.evaluate(readRenderedAccountIdentity);
    if (matchesRenderedAccountIdentity(actual, safeExpected)) return actual;
    await new Promise(resolve => setTimeout(resolve, 100));
  } while (Date.now() < deadline);
  throw new assert.AssertionError({
    message: `Rendered Account identity mismatch: ${JSON.stringify(actual)}`,
    actual,
    expected: { ...safeExpected, renderedRole: safeExpected.role.toUpperCase(), roleTransform: 'uppercase' },
    operator: 'matchesRenderedAccountIdentity',
  });
}

function readRenderedRegistrationRoles(documentRef = document, styleFor = getComputedStyle) {
  const clean = value => String(value || '').replace(/\s+/g, ' ').trim().slice(0, 128);
  const visible = element => {
    if (!element || !element.getClientRects().length) return false;
    const style = styleFor(element);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
  };
  const labels = [...documentRef.querySelectorAll('label')]
    .filter(element => clean(element.textContent) === 'Role');
  const label = labels.length === 1 ? labels[0] : null;
  const controls = label?.nextElementSibling || null;
  const buttons = controls ? [...controls.querySelectorAll('button[aria-pressed]')] : [];
  return Object.freeze({
    roleLabels: labels.length,
    roleLabelVisible: visible(label),
    controlsVisible: visible(controls),
    roles: buttons.map(button => {
      const [name, description, ...extra] = [...button.children];
      return Object.freeze({
        label: clean(name?.textContent),
        description: clean(description?.textContent),
        pressed: button.getAttribute('aria-pressed'),
        type: button.getAttribute('type'),
        visible: visible(button),
        labelVisible: visible(name),
        descriptionVisible: visible(description),
        extraChildren: extra.length,
      });
    }),
  });
}

function assertRenderedRegistrationRoles(actual, selectedRole = 'customer') {
  assert.ok(['customer', 'merchant'].includes(selectedRole));
  assert.deepEqual(actual, {
    roleLabels: 1,
    roleLabelVisible: true,
    controlsVisible: true,
    roles: [
      { label: 'Customer', description: 'shop products, chat with the customer agent',
        pressed: String(selectedRole === 'customer'), type: 'button', visible: true,
        labelVisible: true, descriptionVisible: true, extraChildren: 0 },
      { label: 'Merchant', description: 'manage listings and reviews',
        pressed: String(selectedRole === 'merchant'), type: 'button', visible: true,
        labelVisible: true, descriptionVisible: true, extraChildren: 0 },
    ],
  }, 'Rendered registration must expose exactly the visible Customer and Merchant role controls');
}

async function readShopSession(page) {
  return page.evaluate(async () => {
    const response = await fetch('/api/secureshop/auth/session', { cache: 'no-store' });
    return { status: response.status, body: await response.json() };
  });
}

async function readLogoutDiagnostic(page, sessionReader = readShopSession) {
  const collect = async (target, surface) => target.$$eval('h1,h2', (elements, prefix) => {
    const clean = value => String(value || '').replace(/\s+/g, ' ').trim().slice(0, 80);
    return elements.filter(element => {
      const style = getComputedStyle(element);
      return element.getClientRects().length && style.display !== 'none'
        && style.visibility !== 'hidden' && style.opacity !== '0';
    }).slice(0, 4).map(element => `${prefix}:${clean(element.innerText || element.textContent)}`);
  }, surface).catch(() => []);
  const headings = await collect(page, 'page');
  const mainFrame = page.mainFrame?.();
  const frames = typeof page.frames === 'function'
    ? page.frames().filter(frame => frame !== mainFrame).slice(0, 2) : [];
  for (let index = 0; index < frames.length && headings.length < 8; index += 1) {
    headings.push(...await collect(frames[index], `frame${index + 1}`));
  }
  let session;
  try {
    const result = await sessionReader(page);
    session = { status: result.status, authenticated: result.body?.authenticated,
      role: result.body?.user?.role || null };
  } catch {
    session = { status: null, authenticated: null, role: null };
  }
  return Object.freeze({ pathname: new URL(page.url()).pathname,
    headings: headings.slice(0, 8), frameCount: frames.length, session: Object.freeze(session) });
}

async function waitForRenderedLogout(page, { timeoutMs = 20000, intervalMs = 100,
  sessionReader = readShopSession } = {}) {
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 20000);
  assert.ok(Number.isSafeInteger(intervalMs) && intervalMs > 0 && intervalMs <= 250);
  const deadline = Date.now() + timeoutMs;
  do {
    if (new URL(page.url()).pathname === '/secureshop') {
      const projection = await readLogoutDiagnostic(page, sessionReader);
      assert.deepEqual(projection.session, { status: 200, authenticated: false, role: null },
        'Rendered sign-out route must agree with the canonical shop session');
      return projection;
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  } while (Date.now() < deadline);
  const actual = await readLogoutDiagnostic(page, sessionReader);
  throw new assert.AssertionError({
    message: `Rendered sign-out did not reach the public shop: ${JSON.stringify(actual)}`,
    actual,
    expected: { pathname: '/secureshop', session: { status: 200, authenticated: false, role: null } },
    operator: 'renderedLogoutTransition',
  });
}

async function renderedAccountReadback(page, origin, expected) {
  await page.goto(origin + '/secureshop/account', { waitUntil: 'domcontentloaded' });
  const frame = await boundShopFrame(page);
  await waitForRenderedAccountIdentity(frame, expected);
  const session = await readShopSession(page);
  assert.equal(session.status, 200);
  assert.equal(session.body.authenticated, true);
  assert.equal(session.body.user.username, expected.username);
  assert.equal(session.body.user.email, expected.email);
  assert.equal(session.body.user.role, expected.role);
  assert.deepEqual(Object.keys(session.body.user).sort(),
    ['email', 'id', 'principalId', 'role', 'username'].sort());
  const authority = await page.evaluate(async () => {
    const [status, admin] = await Promise.all([
      fetch('/api/auth/status', { cache: 'no-store' }),
      fetch('/api/admin/users', { cache: 'no-store' }),
    ]);
    return { status: { code: status.status, body: await status.json() }, admin: admin.status };
  });
  assert.equal(authority.status.code, 200);
  assert.equal(authority.status.body.authenticated, false,
    'Shop cookie must not create workshop authority');
  assert.equal(authority.admin, 401, 'Shop cookie must not create instructor authority');
}

async function renderedLogout(page) {
  const frame = await boundShopFrame(page);
  await frame.click('button[aria-label="Account menu"]');
  const response = await responseFor(page, '/api/secureshop/auth/logout', 'POST',
    () => clickExactButton(frame, 'Sign out'));
  assert.equal(response.status(), 200);
  await waitForRenderedLogout(page);
}

async function renderedLogin(page, origin, account) {
  await page.goto(origin + '/secureshop/login?next=%2Fsecureshop%2Faccount',
    { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#ss-login-user', { visible: true });
  await page.type('#ss-login-user', account.username);
  await page.type('#ss-login-pw', account.password);
  const response = await responseFor(page, '/api/secureshop/auth/login', 'POST',
    () => page.click('button[type="submit"]'));
  assert.equal(response.status(), 200, `Default ${account.role} must sign in`);
  const body = await response.json();
  assert.equal(body.authenticated, true);
  assert.equal(body.user.username, account.username);
  assert.equal(body.user.role, account.role);
  await renderedAccountReadback(page, origin, account);
  await renderedLogout(page);
}

async function renderedRegister(page, origin, account) {
  await page.goto(origin + '/secureshop/register?next=%2Fsecureshop%2Faccount',
    { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#reg-user', { visible: true });
  assertRenderedRegistrationRoles(await page.evaluate(readRenderedRegistrationRoles));
  await page.type('#reg-user', account.username);
  await page.type('#reg-email', account.email);
  await page.type('#reg-pw', account.password);
  await page.type('#reg-pw2', account.password);
  if (account.role === 'merchant') {
    await clickExactRegistrationRole(page, 'Merchant');
    assertRenderedRegistrationRoles(await page.evaluate(readRenderedRegistrationRoles), 'merchant');
  }
  const response = await responseFor(page, '/api/secureshop/auth/register', 'POST',
    () => page.click('button[type="submit"]'));
  assert.equal(response.status(), 200, `Rendered ${account.role} registration must succeed`);
  const body = await response.json();
  assert.equal(body.authenticated, true);
  assert.equal(body.user.username, account.username);
  assert.equal(body.user.email, account.email);
  assert.equal(body.user.role, account.role);
  await renderedAccountReadback(page, origin, account);
  await renderedLogout(page);
}

async function postRegistration(page, body) {
  return page.evaluate(async input => {
    const response = await fetch('/api/secureshop/auth/register', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input),
    });
    return { status: response.status, body: await response.json() };
  }, body);
}

async function qualifyStandaloneBootstrapOnPage({ page, origin, identityPool,
  signal, suffix = randomUUID().replaceAll('-', '').slice(0, 12) }) {
  signal?.throwIfAborted();
  const defaultNames = DEFAULT_ACCOUNTS.map(row => row.username);
  const before = assertFreshDefaults(await readAuthoritySnapshot(identityPool, defaultNames));
  assert.deepEqual(await seedSecureShopStandaloneDefaults(identityPool), { seeded: false },
    'A completed fresh seed must be a no-op');
  assert.deepEqual(assertFreshDefaults(await readAuthoritySnapshot(identityPool, defaultNames)), before,
    'Repeated seeds must preserve exact standalone default principals');

  for (const account of DEFAULT_ACCOUNTS) {
    signal?.throwIfAborted();
    await renderedLogin(page, origin, { ...account, password: DEFAULT_PASSWORD });
  }

  const registered = registrationCohort(suffix);
  for (const account of registered) {
    signal?.throwIfAborted();
    await renderedRegister(page, origin, account);
  }

  const denied = [
    { username: `a22_admin_${suffix}`, email: `a22-admin-${suffix}@example.invalid`,
      password: `A22-${suffix}-Pass!`, role: 'admin' },
    { username: `a22_owner_${suffix}`, email: `a22-owner-${suffix}@example.invalid`,
      password: `A22-${suffix}-Pass!`, role: 'customer', ownerId: 1 },
    { username: `a22_platform_${suffix}`, email: `a22-platform-${suffix}@example.invalid`,
      password: `A22-${suffix}-Pass!`, role: 'merchant', platformUserId: 1 },
    { username: `a22_authority_${suffix}`, email: `a22-authority-${suffix}@example.invalid`,
      password: `A22-${suffix}-Pass!`, role: 'customer', adminLevel: 2 },
  ];
  for (const attempt of denied) {
    signal?.throwIfAborted();
    const response = await postRegistration(page, attempt);
    assert.equal(response.status, 400, `Registration must reject ${attempt.username}`);
    assert.deepEqual(response.body, { error: 'Invalid shop request' });
  }

  const allNames = [...defaultNames, ...registered.map(row => row.username),
    ...denied.map(row => row.username)];
  const after = await readAuthoritySnapshot(identityPool, allNames);
  assert.deepEqual(after.platformUsers, [],
    'Defaults and registered shop accounts must remain outside workshop authority');
  assert.deepEqual(after.marker, [{ defaultsSha256: DEFAULTS_SHA256 }]);
  assert.deepEqual(after.principals.filter(row => defaultNames.includes(row.username)), before.principals,
    'Registration and denied authority attempts must preserve seeded defaults');
  assert.deepEqual(after.principals.filter(row => registered.some(account => account.username === row.username))
    .map(row => ({ username: row.username, email: row.email, role: row.role })),
  registered.map(({ username, email, role }) => ({ username, email, role }))
    .sort((a, b) => a.username.localeCompare(b.username)));
  assert.deepEqual(after.principals.filter(row => denied.some(attempt => attempt.username === row.username)), [],
    'Denied admin and authority-field requests must create no principal');

  return Object.freeze({ scope: 'rendered_standalone_bootstrap_and_registration', passed: true,
    modelCalls: 0, checks: Object.freeze({ documentedDefaults: true, repeatSeedPreserved: true,
      renderedDefaultReadback: true, customerRegistration: true, merchantRegistration: true,
      adminRegistrationDenied: true, authorityFieldsDenied: true, workshopAuthorityAbsent: true }) });
}

async function qualifyFullBackendRenderedStandaloneBootstrap({ browser, origin, identityPool,
  signal, beginBrowserTeardown }) {
  assert.equal(typeof beginBrowserTeardown, 'function');
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  const errors = [], blocked = [];
  page.setDefaultTimeout(20000);
  page.on('pageerror', error => errors.push(error.message));
  await page.setRequestInterception(true);
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.protocol === 'data:' || url.origin === origin) void request.continue();
    else { blocked.push(url.origin); void request.abort('blockedbyclient'); }
  });
  await page.setCacheEnabled(false);
  let primaryFailure;
  try {
    const result = await qualifyStandaloneBootstrapOnPage({ page, origin, identityPool, signal });
    assert.deepEqual(blocked, []);
    assert.deepEqual(errors, []);
    return result;
  } catch (error) {
    primaryFailure = error;
    throw error;
  } finally {
    let teardownFailure;
    try { beginBrowserTeardown(); } catch (error) { teardownFailure = error; }
    try { await context.close(); } catch (error) {
      teardownFailure = teardownFailure
        ? new AggregateError([teardownFailure, error], 'Browser context teardown failed') : error;
    }
    if (teardownFailure) throw primaryFailure
      ? new AggregateError([primaryFailure, teardownFailure], 'A22 qualification and teardown failed')
      : teardownFailure;
  }
}

module.exports = {
  DEFAULT_ACCOUNTS,
  assertFreshDefaults,
  readRenderedAccountIdentity,
  matchesRenderedAccountIdentity,
  waitForRenderedAccountIdentity,
  clickExactRegistrationRole,
  readRenderedRegistrationRoles,
  assertRenderedRegistrationRoles,
  readLogoutDiagnostic,
  waitForRenderedLogout,
  readAuthoritySnapshot,
  registrationCohort,
  qualifyStandaloneBootstrapOnPage,
  qualifyFullBackendRenderedStandaloneBootstrap,
};
