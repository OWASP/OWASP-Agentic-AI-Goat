'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { assertComposedPositive, assertStableResetAddress, authHeaders, installOwnedRequestGuard } = require('./csrfEmailComposed.integration.test');
const { validateShutdownDependencies, assertDistinctPasswordHashes, assertDistinctPasswordInputs, installBrowserLaunchRecorder } = require('./csrfEmailComposedFixture');

test('composed qualification contract rejects missing x1/x2/x3, Judge identity, or persisted effect', () => {
  assert.throws(() => assertComposedPositive({ verify: { newlyCompleted: ['csrf_x1'] }, send: { newlyCompleted: ['csrf_x2'] }, composed: { newlyCompleted: [] }, victim: {} }), /csrf_x3/);
  assert.throws(() => assertComposedPositive({ verify: { newlyCompleted: ['csrf_x1'] }, send: { newlyCompleted: ['csrf_x2'] }, composed: { newlyCompleted: ['csrf_x3'], judgments: [] }, victim: {} }), /classified Judge/);
  assert.throws(() => assertComposedPositive({ verify: { newlyCompleted: ['csrf_x1'] }, send: { newlyCompleted: ['csrf_x2'] }, composed: { newlyCompleted: ['csrf_x3'], judgments: [{ rubricVersion: 'csrf-classified-email-v1', provider: 'ollama', model: 'llama3.1:8b' }] }, victim: { state: { security: { password: 'unchanged' } } } }), /persisted hover/);
});

test('reset contract requires stable local inbox identity and authenticated API headers', () => {
  assertStableResetAddress('xss-7@owasp-ai-goat.invalid', 'xss-7@owasp-ai-goat.invalid');
  assert.throws(() => assertStableResetAddress('xss-7@owasp-ai-goat.invalid', 'xss-8@owasp-ai-goat.invalid'), /stable/);
  assert.deepEqual(authHeaders('token', true), { 'content-type': 'application/json', authorization: 'Bearer token' });
  assert.deepEqual(authHeaders('', false), {});
});

test('fixture contract requires browser close hook, all pools, and distinct password hashes', () => {
  const pools = [1, 2, 3, 4].map(() => ({ end: async () => {} }));
  assert.equal(validateShutdownDependencies({ csrfRoutes: { closeBrowser: async () => {} } }, pools), true);
  assert.throws(() => validateShutdownDependencies({ csrfRoutes: {} }, pools), /browser close/);
  assert.throws(() => validateShutdownDependencies({ csrfRoutes: { closeBrowser: async () => {} } }, pools.slice(0, 3)), /four/);
  assert.equal(assertDistinctPasswordHashes('hash-a', 'hash-b'), true);
  assert.throws(() => assertDistinctPasswordHashes('same', 'same'), /independently/);
  assert.equal(assertDistinctPasswordInputs('owner-secret', 'sibling-secret'), true);
  assert.throws(() => assertDistinctPasswordInputs('same', 'same'), /distinct inputs/);
});

test('browser guard enables interception before registering request handlers', async () => {
  const order = [];
  const page = { async setRequestInterception(value) { order.push(['interception', value]); }, on(name) { order.push(['handler', name]); } };
  await installOwnedRequestGuard(page, ['http://127.0.0.1:1']);
  assert.deepEqual(order, [['interception', true], ['handler', 'request']]);
  await assert.rejects(installOwnedRequestGuard({ on() {} }, []), /interception API/);
});

test('fixture browser recorder closes an unrecordable browser and restores launch', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csrf-browser-recorder-'));
  const saved = { dir: process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR, exe: process.env.PUPPETEER_EXECUTABLE_PATH, sha: process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256 };
  const fake = { launch: async () => ({ process: () => process, close: async () => { closed += 1; } }) };
  const originalLaunch = fake.launch;
  let closed = 0;
  try {
    process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR = directory;
    process.env.PUPPETEER_EXECUTABLE_PATH = process.execPath;
    process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256 = '0'.repeat(64);
    const restore = installBrowserLaunchRecorder({ puppeteerModule: fake });
    await assert.rejects(fake.launch(), /Browser executable pin mismatch/);
    assert.equal(closed, 1);
    restore();
    assert.equal(fake.launch, originalLaunch);
  } finally {
    if (saved.dir === undefined) delete process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR; else process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR = saved.dir;
    if (saved.exe === undefined) delete process.env.PUPPETEER_EXECUTABLE_PATH; else process.env.PUPPETEER_EXECUTABLE_PATH = saved.exe;
    if (saved.sha === undefined) delete process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256; else process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256 = saved.sha;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('fixture recorder supports the installed immutable Puppeteer namespace without launching', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'csrf-browser-installed-'));
  const saved = { dir: process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR, exe: process.env.PUPPETEER_EXECUTABLE_PATH, sha: process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256 };
  try {
    process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR = directory;
    process.env.PUPPETEER_EXECUTABLE_PATH = process.execPath;
    process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256 = require('node:crypto').createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex');
    const restore = installBrowserLaunchRecorder();
    assert.equal(typeof require('puppeteer').launch, 'function');
    restore();
  } finally {
    if (saved.dir === undefined) delete process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR; else process.env.CSRF_EMAIL_COMPOSED_BROWSER_PID_DIR = saved.dir;
    if (saved.exe === undefined) delete process.env.PUPPETEER_EXECUTABLE_PATH; else process.env.PUPPETEER_EXECUTABLE_PATH = saved.exe;
    if (saved.sha === undefined) delete process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256; else process.env.CSRF_EMAIL_COMPOSED_BROWSER_SHA256 = saved.sha;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
