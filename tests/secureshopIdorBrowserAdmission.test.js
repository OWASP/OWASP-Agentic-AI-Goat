'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const { createHash } = require('node:crypto');
const ROOT = path.resolve(__dirname, '..');
test('V12 entire native fixture compiles without executing native imports or registration', () => {
  const filename = path.join(__dirname, 'postgres/secureshopStandaloneIdorLessonRendered.integration.test.js');
  const source = fs.readFileSync(filename, 'utf8');
  assert.doesNotThrow(() => vm.compileFunction(source,
    ['require', 'module', 'exports', '__filename', '__dirname'], { filename }));
});
function helper(overrides = {}, extra = {}) {
  const filename = path.join(__dirname, 'fixtures/secureshopIdorBrowserAdmission.js');
  const real = require('node:module').createRequire(filename), module = { exports: {} };
  vm.compileFunction(fs.readFileSync(filename, 'utf8'),
    ['require', 'module', 'process', 'Date'], { filename })(name =>
    Object.hasOwn(overrides, name) ? overrides[name] : real(name), module,
    { cwd: () => ROOT, getuid: () => process.getuid(), pid: 123 }, extra.Date || Date);
  return module.exports;
}
function inputs() {
  const run = path.join(ROOT, 'tasks/qualification/run-controlled'), tmp = path.join(run, 'runtime/tmp');
  return {
    options: { workspace: ROOT, evidencePath: path.join(run, 'customer-idor-lesson-browser.json'),
      profile: path.join(tmp, 'dvaia-customer-idor-browser-controlled'), origin: 'http://127.0.0.1:12345' },
    env: { SECURESHOP_IDOR_LESSON_TEST_NO_SANDBOX: '1',
      SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE: '1', PG_TEST_DISPOSABLE: 'yes',
      LIVE_OLLAMA_TEST: '1', NODE_ENV: 'test', DVAIA_CURRENT_MAIN_WORKSPACE: ROOT, TMPDIR: tmp,
      SECURESHOP_IDOR_LESSON_BROWSER_RECORD_PATH: path.join(run, 'idor-lesson-browser.json'),
      SECURESHOP_IDOR_LESSON_BROWSER_ACK_PATH: path.join(run, 'idor-lesson-browser-ack.json'),
      SECURESHOP_IDOR_LESSON_BROWSER_SHA256: 'a'.repeat(64),
      SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT: path.join(ROOT, 'tests/postgres/secureshop_darwin_browser_birth.py'),
      SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON: '/controlled/python',
      PUPPETEER_EXECUTABLE_PATH: '/controlled/chrome' },
  };
}
test('V12 exception admits only full original cohort, owned profile and exact loopback origin', () => {
  let mode = 0o700, uid = process.getuid(), link = false, canonical = true;
  const f = helper({ 'node:fs': {
    lstatSync: () => ({ isDirectory: () => true, isSymbolicLink: () => link, mode, uid }),
    realpathSync: value => canonical ? value : '/foreign',
  } });
  const { env, options } = inputs();
  assert.deepEqual(f.browserArgs({}, {}), []);
  const args = f.browserArgs(env, options);
  assert.ok(args.includes('--no-sandbox'));
  assert.ok(args.includes('--disable-background-networking'));
  assert.ok(args.includes('--proxy-server=http://blocked.invalid:9'));
  assert.ok(!args.some(value => /disable-web-security|ignore-certificate/.test(value)));
  for (const patch of [
    { SECURESHOP_IDOR_LESSON_TEST_NO_SANDBOX: 'true' },
    { SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY: '1' },
    { SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE: '0' },
    { PG_TEST_DISPOSABLE: 'no' }, { LIVE_OLLAMA_TEST: '0' }, { NODE_ENV: 'production' },
    { DVAIA_CURRENT_MAIN_WORKSPACE: '/foreign' }, { TMPDIR: '/foreign' },
    { SECURESHOP_IDOR_LESSON_BROWSER_ACK_PATH: '/foreign' },
    { SECURESHOP_IDOR_LESSON_BROWSER_RECORD_PATH: '/foreign' },
    { SECURESHOP_IDOR_LESSON_BROWSER_SHA256: 'bad' },
    { SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT: '/foreign' },
  ]) assert.throws(() => f.browserArgs({ ...env, ...patch }, options));
  for (const origin of ['http://example.com:12345', 'https://127.0.0.1:12345', 'http://127.0.0.1:12345/path'])
    assert.throws(() => f.browserArgs(env, { ...options, origin }));
  assert.throws(() => f.browserArgs(env, { ...options, profile: path.join(env.TMPDIR, 'dvaia-manual-rag-other') }));
  mode = 0o755; assert.throws(() => f.browserArgs(env, options));
  mode = 0o700; uid++; assert.throws(() => f.browserArgs(env, options));
  uid = process.getuid(); link = true; assert.throws(() => f.browserArgs(env, options));
  link = false; canonical = false; assert.throws(() => f.browserArgs(env, options));
});
test('V12 birth ACK binds exact journal, direct parent, browser and profile before navigation', async () => {
  const { env, options } = inputs(), files = new Map();
  const record = { pid: 456, parentPid: 123 }, raw = `${JSON.stringify(record)}\n`;
  let patch = {}, mode = 0o600;
  const f = helper({
    './secureshopDarwinBrowserBirth': { captureBrowserRecord: value => {
      assert.equal(value.kind, 'idor_lesson_browser');
      assert.equal(value.pid, 456);
      return record;
    } },
    'node:fs': { realpathSync: value => value, promises: {
      writeFile: async (name, value, config) => { assert.equal(config.flag, 'wx'); files.set(name, value); },
      rename: async (old, next) => { files.set(next, files.get(old)); files.delete(old); },
      readFile: async name => name === env.SECURESHOP_IDOR_LESSON_BROWSER_RECORD_PATH
        ? files.get(name) : JSON.stringify({ schemaVersion: 1,
          recordSha256: createHash('sha256').update(raw).digest('hex'),
          parentPid: 123, browserPid: 456, profile: options.profile, ...patch }),
      lstat: async () => ({ isFile: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode }),
    } },
  });
  const value = { ...options, browser: { process: () => ({ pid: 456 }) } };
  await f.acknowledgeBrowser(env, value);
  for (const candidate of [{ recordSha256: 'forged' }, { parentPid: 999 }, { browserPid: 999 }, { profile: '/foreign' }]) {
    patch = candidate;
    await assert.rejects(f.acknowledgeBrowser(env, value));
  }
  patch = {}; mode = 0o644;
  await assert.rejects(f.acknowledgeBrowser(env, value));
});
test('V12 fixture places ACK before page creation and retains full original semantics', () => {
  const source = fs.readFileSync(path.join(__dirname,
    'postgres/secureshopStandaloneIdorLessonRendered.integration.test.js'), 'utf8');
  assert.ok(source.indexOf('await acknowledgeBrowser(') < source.indexOf('page = await browser.newPage()'));
  assert.ok(source.indexOf('await page.setRequestInterception(true)') < source.indexOf('await page.goto('));
  assert.match(source, /request\.url\(\)\.startsWith\(`\$\{origin\}\/`\)/);
  assert.match(source, /fixed-first denials and two genuine reserved-ID effects/);
  assert.match(source, /order_status: 'ss_idor_order_status_disclosure'/);
});
test('V12 physically reselects IDOR after each mode remount before using lesson controls', async () => {
  const f = helper(), events = [];
  let task = 'product_question';
  const frame = {
    waitForSelector: async (selector, options) => {
      events.push(['wait', selector, options]);
      if (selector.startsWith('section')) assert.equal(task, 'idor');
      return {};
    },
    select: async (selector, value) => { events.push(['select', selector, value]); task = value; },
  };
  await f.selectIdorLesson(frame);
  assert.deepEqual(events, [
    ['wait', 'select[id^="agent-lane-task-customer-"]', { visible: true }],
    ['select', 'select[id^="agent-lane-task-customer-"]', 'idor'],
    ['wait', 'section[aria-label="Customer access control lesson"]', undefined],
  ]);
  const source = fs.readFileSync(path.join(__dirname,
    'postgres/secureshopStandaloneIdorLessonRendered.integration.test.js'), 'utf8');
  const fixed = source.slice(source.indexOf('const fixedPost ='), source.indexOf('const prepareRequestPromise ='));
  const vulnerable = source.slice(source.indexOf('const vulnPost ='), source.indexOf('const vulnerableCards ='));
  for (const block of [fixed, vulnerable]) {
    assert.match(block, /frame = await frameFor\(page\);[\s\S]*await selectIdorLesson\(frame\);/);
  }
});
test('V12 renewal requires server-authenticated unchanged owner, session and generation without leaking tokens', async () => {
  const f = helper(), calls = [];
  const scope = { launchId: '11111111-1111-4111-8111-111111111111',
    scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1,
    platformOwnerId: 3, platformSessionId: 4 };
  const actor = { user: { id: 5, role: 'customer' }, jti: 'original-jti',
    sessionId: 'original-session', authorityVersion: '1', expiresAt: 'old' };
  let currentScope = scope, currentActor = actor, rejected = false;
  const composition = {
    launches: { resolveCapability: async bearer => { calls.push(['launch', bearer]); return currentScope; } },
    personaAuth: { authenticateBoundToken: async value => {
      calls.push(['authenticate', value]);
      if (rejected) throw Error(`untrusted diagnostic ${value.token}`);
      return currentActor;
    } },
  };
  const headers = { authorization: 'Bearer original.signed.token', 'x-dvaia-secureshop-launch': 'x'.repeat(43) };
  const baseline = await f.authenticateOwnerHeaders(composition, headers);
  const renewed = { ...headers, authorization: 'Bearer renewed.signed.token' };
  currentActor = { ...actor, expiresAt: 'renewed' };
  const accepted = await f.authenticateOwnerHeaders(composition, renewed, baseline.identity);
  assert.deepEqual(accepted.identity, baseline.identity);
  assert.equal(accepted.headers.authorization, renewed.authorization);
  assert.equal(calls.at(-1)[1].token, 'renewed.signed.token');
  assert.equal(calls.at(-1)[1].scope, scope);
  const checkDenied = async () => assert.rejects(
    f.authenticateOwnerHeaders(composition, renewed, baseline.identity), error => {
      assert.equal(error.message, 'V12 server-authenticated owner authority changed or is invalid');
      assert.ok(!String(error.stack).includes('renewed.signed.token'));
      return true;
    });
  for (const patch of [{ platformOwnerId: 8 }, { platformSessionId: 9 }, { generation: 2 },
    { launchId: '33333333-3333-4333-8333-333333333333' },
    { scenarioId: '33333333-3333-4333-8333-333333333333' }]) {
    currentScope = { ...scope, ...patch };
    await checkDenied();
  }
  currentScope = scope;
  for (const patch of [{ user: { id: 6, role: 'customer' } }, { user: { id: 5, role: 'admin' } },
    { jti: 'other' }, { sessionId: 'other' }, { authorityVersion: '2' }]) {
    currentActor = { ...actor, ...patch };
    await checkDenied();
  }
  currentActor = actor; rejected = true;
  await checkDenied();
});
