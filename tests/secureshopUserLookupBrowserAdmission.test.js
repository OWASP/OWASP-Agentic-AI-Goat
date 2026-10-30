'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const ROOT = path.resolve(__dirname, '..');
function helper(overrides = {}) {
  const filename = path.join(__dirname, 'fixtures/secureshopUserLookupBrowserAdmission.js');
  const real = require('node:module').createRequire(filename), module = { exports: {} };
  vm.compileFunction(fs.readFileSync(filename, 'utf8'), ['require', 'module', 'process'], { filename })(
    name => Object.hasOwn(overrides, name) ? overrides[name] : real(name), module,
    { cwd: () => ROOT, getuid: () => process.getuid(), pid: 123 });
  return module.exports;
}
test('combined lookup admission keeps default and rejects foreign authority, profile and network', () => {
  let mode = 0o700, uid = process.getuid(), link = false, canonical = true;
  const f = helper({ 'node:fs': {
    lstatSync: () => ({ isDirectory: () => true, isSymbolicLink: () => link, mode, uid }),
    realpathSync: value => canonical ? value : '/foreign',
  } });
  const run = path.join(ROOT, 'tasks/qualification/run-controlled'), tmp = path.join(run, 'runtime/tmp');
  const options = { workspace: ROOT, evidencePath: path.join(run, 'user-lookup-disclosure-browser.json'),
    profile: path.join(tmp, 'owasp-ai-goat-user-lookup-browser-controlled'), origin: 'http://127.0.0.1:12345' };
  const env = { SECURESHOP_USER_LOOKUP_TEST_NO_SANDBOX: '1', SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE: '1',
    SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE: '1', PG_TEST_DISPOSABLE: 'yes', LIVE_OLLAMA_TEST: '1', NODE_ENV: 'test',
    OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: ROOT, TMPDIR: tmp,
    SECURESHOP_USER_LOOKUP_BROWSER_RECORD_PATH: path.join(run, 'user-lookup-browser.json'),
    SECURESHOP_USER_LOOKUP_BROWSER_ACK_PATH: path.join(run, 'user-lookup-browser-ack.json'),
    SECURESHOP_USER_LOOKUP_BROWSER_SHA256: 'a'.repeat(64),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT: path.join(ROOT, 'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON: '/controlled/python' };
  assert.deepEqual(f.userLookupBrowserArgs({}, {}), []);
  const args = f.userLookupBrowserArgs(env, options);
  const benignEnv = { ...env, SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE: '1' };
  const benignOptions = { ...options, evidencePath: path.join(run, 'user-lookup-benign-browser.json') };
  assert.deepEqual(f.userLookupBrowserArgs(benignEnv, benignOptions), args);
  assert.deepEqual(f.userLookupBrowserArgs({ ...env, SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE: '0' }, options), args);
  assert.throws(() => f.userLookupBrowserArgs(benignEnv, options));
  assert.throws(() => f.userLookupBrowserArgs(env, benignOptions));
  for (const value of ['true', 'benign', '', true, 1])
    assert.throws(() => f.userLookupBrowserArgs({ ...env, SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE: value }, benignOptions));
  assert.ok(args.includes('--no-sandbox') && args.includes('--disable-background-networking'));
  assert.ok(!args.some(value => /disable-web-security|ignore-certificate/.test(value)));
  for (const patch of [{ SECURESHOP_USER_LOOKUP_TEST_NO_SANDBOX: 'true' },
    { SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE: '0' }, { SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE: '0' },
    { PG_TEST_DISPOSABLE: 'no' }, { LIVE_OLLAMA_TEST: '0' }, { NODE_ENV: 'production' },
    { OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: '/foreign' }, { TMPDIR: '/foreign' },
    { SECURESHOP_USER_LOOKUP_BROWSER_RECORD_PATH: '/foreign' }, { SECURESHOP_USER_LOOKUP_BROWSER_ACK_PATH: '/foreign' },
    { SECURESHOP_USER_LOOKUP_BROWSER_SHA256: 'bad' }]) {
    assert.throws(() => f.userLookupBrowserArgs({ ...env, ...patch }, options));
    assert.throws(() => f.userLookupBrowserArgs({ ...benignEnv, ...patch }, benignOptions));
  }
  for (const origin of ['http://example.com:12345', 'https://127.0.0.1:12345', 'http://127.0.0.1:12345/path'])
    assert.throws(() => f.userLookupBrowserArgs(env, { ...options, origin }));
  assert.throws(() => f.userLookupBrowserArgs(env, { ...options, profile: path.join(tmp, 'owasp-ai-goat-v19-browser-other') }));
  for (const changed of [
    { evidencePath: `${run}/../run-controlled/user-lookup-benign-browser.json` },
    { evidencePath: path.join(ROOT, 'tasks/tmp/user-lookup-benign-browser.json') },
    { profile: path.join(tmp, 'owasp-ai-goat-v19-browser-other') },
    { origin: 'http://example.com:12345' },
  ]) assert.throws(() => f.userLookupBrowserArgs(benignEnv, { ...benignOptions, ...changed }));
  mode = 0o755; assert.throws(() => f.userLookupBrowserArgs(env, options));
  assert.throws(() => f.userLookupBrowserArgs(benignEnv, benignOptions));
  mode = 0o700; uid++; assert.throws(() => f.userLookupBrowserArgs(env, options));
  uid = process.getuid(); link = true; assert.throws(() => f.userLookupBrowserArgs(env, options));
  assert.throws(() => f.userLookupBrowserArgs(benignEnv, benignOptions));
  link = false; canonical = false; assert.throws(() => f.userLookupBrowserArgs(env, options));
});
test('whole shared RoleChoices fixture compiles without running imports', () => {
  const filename = path.join(__dirname, 'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js');
  assert.doesNotThrow(() => vm.compileFunction(fs.readFileSync(filename, 'utf8'),
    ['require', 'module', 'exports', '__filename', '__dirname'], { filename }));
});
test('lookup ACK binds independent journal, parent, browser and exact profile', async () => {
  const record = { pid: 456, parentPid: 123 }, raw = `${JSON.stringify(record)}\n`;
  const env = { PUPPETEER_EXECUTABLE_PATH: '/controlled/chrome',
    SECURESHOP_USER_LOOKUP_BROWSER_RECORD_PATH: 'record', SECURESHOP_USER_LOOKUP_BROWSER_ACK_PATH: 'ack',
    SECURESHOP_USER_LOOKUP_BROWSER_SHA256: 'a'.repeat(64) };
  let patch = {}, mode = 0o600;
  const f = helper({
    './secureshopDarwinBrowserBirth': { captureBrowserRecord: value => {
      assert.equal(value.kind, 'user_lookup_disclosure_browser'); assert.equal(value.pid, 456); return record;
    } },
    'node:fs': { realpathSync: value => value, promises: {
      writeFile: async (_name, value, options) => { assert.equal(value, raw); assert.equal(options.flag, 'wx'); },
      rename: async () => {},
      readFile: async name => name === 'record' ? raw : JSON.stringify({
        schemaVersion: 1, recordSha256: require('node:crypto').createHash('sha256').update(raw).digest('hex'),
        parentPid: 123, browserPid: 456, profile: 'owned', ...patch }),
      lstat: async () => ({ isFile: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode }),
    } },
  });
  const options = { workspace: ROOT, profile: 'owned', browser: { process: () => ({ pid: 456 }) } };
  await f.acknowledgeUserLookupBrowser(env, options);
  for (const value of [{ recordSha256: 'forged' }, { parentPid: 999 }, { browserPid: 999 }, { profile: 'foreign' }]) {
    patch = value; await assert.rejects(f.acknowledgeUserLookupBrowser(env, options));
  }
  patch = {}; mode = 0o644; await assert.rejects(f.acknowledgeUserLookupBrowser(env, options));
});
