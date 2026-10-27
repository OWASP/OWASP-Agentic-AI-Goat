'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const Module = require('node:module');
const { randomBytes } = require('node:crypto');
const { admitInventoryEvidence, launchInventoryBrowser,
  publishInventoryReceipt } = require('./fixtures/secureshopInventoryCurrentHostAdmission');

const ROOT = path.resolve(__dirname, '..');
const FIXTURE = path.join(ROOT, 'tests/postgres/secureshopStandaloneInventoryRendered.integration.test.js');
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const SOCKET = path.join(ROOT, '.qualification/goat-q/docker.sock');

async function withOwnedRun(body) {
  const run = path.join(ROOT, 'tasks/qualification', `run-q08inventory${randomBytes(8).toString('hex')}`);
  await fsp.mkdir(run, { mode: 0o700 });
  const names = ['DOCKER_HOST', 'DVAIA_CURRENT_MAIN_WORKSPACE', 'TMPDIR',
    'MAC_CHROMIUM_TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME',
    'PUPPETEER_EXECUTABLE_PATH', 'SECURESHOP_STANDALONE_INVENTORY_NATIVE',
    'SECURESHOP_STANDALONE_INVENTORY_RETRY_NATIVE'];
  const before = Object.fromEntries(names.map(key => [key, process.env[key]]));
  try {
    for (const name of ['runtime', 'runtime/tmp', 'runtime/home'])
      await fsp.mkdir(path.join(run, name), { mode: 0o700 });
    const profile = await fsp.mkdtemp(path.join(run, 'runtime/tmp', 'dvaia-standalone-inventory-'));
    const receiptPath = path.join(run, 'standalone-inventory-browser.json');
    Object.assign(process.env, {
      DOCKER_HOST: `unix://${SOCKET}`, DVAIA_CURRENT_MAIN_WORKSPACE: ROOT,
      TMPDIR: path.join(run, 'runtime/tmp'), MAC_CHROMIUM_TMPDIR: path.join(run, 'runtime/tmp'),
      XDG_CACHE_HOME: path.join(run, 'runtime/home/.cache'),
      XDG_CONFIG_HOME: path.join(run, 'runtime/home/.config'),
      PUPPETEER_EXECUTABLE_PATH: CHROME,
      SECURESHOP_STANDALONE_INVENTORY_NATIVE: '1',
      SECURESHOP_STANDALONE_INVENTORY_RETRY_NATIVE: '0',
    });
    await body({ profile, receiptPath });
  } finally {
    for (const [key, value] of Object.entries(before)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await fsp.rm(run, { recursive: true, force: true });
  }
}

test('actual inventory fixture calls owned admission, browser, and receipt without changing rubric', () => {
  const source = fs.readFileSync(FIXTURE, 'utf8');
  for (const text of [
    'admitInventoryEvidence(workspace, receiptPath);',
    'browser = await launchInventoryBrowser({ root: workspace, receiptPath, profile,',
    'await publishInventoryReceipt(workspace, receiptPath, written);',
    'timeout: 300000', 'status.fixedDenied = true',
  ]) assert.equal(source.split(text).length, 2, `exact fixture seam: ${text}`);
  assert.equal(source.split('assert.equal(judgeCalls, 1)').length, 3,
    'both original one-Judge branches remain');
});

test('current-host browser policy is scoped to original selector and owned loopback', async () => {
  await withOwnedRun(async ({ profile, receiptPath }) => {
    const original = Module._load;
    const launches = [];
    Module._load = function (id, parent, isMain) {
      if (id === 'puppeteer') return { launch: async options => {
        launches.push(options); return { admitted: true };
      } };
      return original.call(this, id, parent, isMain);
    };
    try {
      const input = { root: ROOT, receiptPath, profile, executablePath: CHROME,
        origin: 'http://127.0.0.1:43123' };
      assert.equal(admitInventoryEvidence(ROOT, receiptPath), true);
      assert.deepEqual(await launchInventoryBrowser(input), { admitted: true });
      assert.equal(launches.length, 1);
      assert.ok(launches[0].args.includes('--no-sandbox'));
      assert.ok(launches[0].args.includes('--proxy-server=http://blocked.invalid:9'));
      await assert.rejects(launchInventoryBrowser({ ...input, origin: 'http://example.com:43123' }));
      process.env.SECURESHOP_STANDALONE_INVENTORY_RETRY_NATIVE = '1';
      await assert.rejects(launchInventoryBrowser(input));
      process.env.SECURESHOP_STANDALONE_INVENTORY_RETRY_NATIVE = '0';
      process.env.SECURESHOP_STANDALONE_INVENTORY_NATIVE = '0';
      await assert.rejects(launchInventoryBrowser(input));
      assert.equal(launches.length, 1);
    } finally { Module._load = original; }
  });
});

test('external-host browser retains historical options', async () => {
  const prior = process.env.DOCKER_HOST;
  const original = Module._load;
  let options;
  process.env.DOCKER_HOST = 'unix:///outside/approved-docker.sock';
  Module._load = function (id, parent, isMain) {
    if (id === 'puppeteer') return { launch: async value => { options = value; return { historical: true }; } };
    return original.call(this, id, parent, isMain);
  };
  try {
    const receiptPath = '/outside/standalone-inventory-browser.json';
    assert.equal(admitInventoryEvidence(ROOT, receiptPath), false);
    assert.deepEqual(await launchInventoryBrowser({ root: ROOT, receiptPath,
      profile: '/outside/profile', executablePath: CHROME,
      origin: 'http://127.0.0.1:43123' }), { historical: true });
    assert.deepEqual(options, { headless: true, userDataDir: '/outside/profile',
      executablePath: CHROME });
  } finally {
    Module._load = original;
    if (prior === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = prior;
  }
});

test('private inventory receipt is exclusive, mode 0600, and close fault denies success', async () => {
  await withOwnedRun(async ({ receiptPath }) => {
    const packet = { passed: false, scope: 'inventory-only' };
    await publishInventoryReceipt(ROOT, receiptPath, packet);
    assert.equal((await fsp.lstat(receiptPath)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await fsp.readFile(receiptPath)), packet);
    await assert.rejects(publishInventoryReceipt(ROOT, receiptPath, packet));
    await fsp.unlink(receiptPath);
    const original = fsp.open;
    fsp.open = async (...args) => {
      const handle = await original(...args);
      return { stat: () => handle.stat(), writeFile: value => handle.writeFile(value),
        sync: () => handle.sync(), close: async () => {
          await handle.close(); throw Object.assign(Error('close-fault'), { code: 'EIO' });
        } };
    };
    try { await assert.rejects(publishInventoryReceipt(ROOT, receiptPath, packet), { code: 'EIO' }); }
    finally { fsp.open = original; }
  });
});
