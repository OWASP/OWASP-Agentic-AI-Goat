'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const Module = require('node:module');
const {
  APPLICATION_NODE_RANGE,
  assertSupportedApplicationNodeVersion,
  isSupportedApplicationNodeVersion,
} = require('../scripts/application-node-runtime');
const { setup } = require('../scripts/setup-application');
const { main: startApplication } = require('../scripts/start-application');

const ROOT = path.resolve(__dirname, '..');

test('application runtime guard exactly matches the declared Node compatibility lanes', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(APPLICATION_NODE_RANGE, manifest.engines.node);

  for (const version of ['26.10.0', '26.10.1', '27.0.0']) {
    assert.equal(isSupportedApplicationNodeVersion(version), true, version);
    assert.doesNotThrow(() => assertSupportedApplicationNodeVersion(version));
  }
  for (const version of ['20.19.0', '24.15.0', '26.0.0', '26.9.99', '25.0.0', '24.15.0-rc.1', 'v24.15.0',
    '026.0.0', '999999999999999999999.0.0', 'invalid']) {
    assert.equal(isSupportedApplicationNodeVersion(version), false, version);
    assert.throws(() => assertSupportedApplicationNodeVersion(version), { code: 'UNSUPPORTED_NODE_RUNTIME' });
  }
});

test('setup rejects an unsupported runtime before filesystem or subprocess mutation', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-node-runtime-setup-'));
  const root = path.join(directory, 'workspace');
  const homeDirectory = path.join(directory, 'home');
  fs.mkdirSync(root, { mode: 0o700 });
  fs.mkdirSync(homeDirectory, { mode: 0o700 });
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let subprocessCalls = 0;

  await assert.rejects(setup({
    root,
    homeDirectory,
    nodeVersion: '22.12.0',
    execute: async () => { subprocessCalls += 1; },
    runCommand: async () => { subprocessCalls += 1; },
  }), { code: 'UNSUPPORTED_NODE_RUNTIME' });

  assert.equal(subprocessCalls, 0);
  assert.equal(fs.existsSync(path.join(homeDirectory, '.dvaia')), false);
  assert.deepEqual(fs.readdirSync(root), []);
});

test('application launcher rejects an unsupported runtime before loading configuration', async () => {
  const originalLoad = Module._load;
  const originalDataRoot = process.env.DVAIA_APP_DATA_ROOT;
  let dotenvLoaded = false;
  Module._load = function guardedLoad(request, parent, isMain) {
    if (request === 'dotenv') dotenvLoaded = true;
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    await assert.rejects(startApplication([], { nodeVersion: '22.12.0' }), {
      code: 'UNSUPPORTED_NODE_RUNTIME',
    });
  } finally {
    Module._load = originalLoad;
    if (originalDataRoot === undefined) delete process.env.DVAIA_APP_DATA_ROOT;
    else process.env.DVAIA_APP_DATA_ROOT = originalDataRoot;
  }
  assert.equal(dotenvLoaded, false);
  assert.equal(process.env.DVAIA_APP_DATA_ROOT, originalDataRoot);
});

test('server entry rejects an unsupported runtime before loading configuration or stores', () => {
  const script = `
    const Module = require('node:module');
    const originalLoad = Module._load;
    const loaded = [];
    Object.defineProperty(process.versions, 'node', { value: '22.12.0' });
    Module._load = function(request, parent, isMain) {
      loaded.push(request);
      return originalLoad.call(this, request, parent, isMain);
    };
    try {
      require('./server/index');
      process.exit(2);
    } catch (error) {
      if (error.code !== 'UNSUPPORTED_NODE_RUNTIME') throw error;
      if (loaded.includes('dotenv') || loaded.some(request => request.includes('database'))) process.exit(3);
      process.stdout.write(error.code);
    }
  `;
  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'UNSUPPORTED_NODE_RUNTIME');
});

test('Unix runtime resolver returns a clear failure when no supported Node is available', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-node-runtime-path-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const bin = path.join(directory, 'bin');
  fs.mkdirSync(bin);
  const node = path.join(bin, 'node');
  fs.writeFileSync(node, '#!/bin/sh\nexit 1\n', { mode: 0o700 });

  const original = fs.readFileSync(path.join(ROOT, 'scripts/install/runtime-path.sh'), 'utf8');
  // Feed the resolver in memory; only the deliberately failing Node executable
  // is synthetic on disk. Keep its runtime guard pointed at the main module.
  const shellQuote = value => "'" + value.replace(/'/g, "'\"'\"'") + "'";
  assert.equal((original.match(/^dvaia_runtime_guard=.*$/gm)||[]).length,1);
  assert.equal(original.split('/opt/homebrew/bin /usr/local/bin').length-1,1);
  const isolated = original.replace(/^dvaia_runtime_guard=.*$/m,
    `dvaia_runtime_guard=${shellQuote(path.join(ROOT, 'scripts/application-node-runtime.js'))}`)
    .replace('/opt/homebrew/bin /usr/local/bin',
      `${shellQuote(path.join(directory, 'missing-one'))} ${shellQuote(path.join(directory, 'missing-two'))}`);
  const result = spawnSync('/bin/bash', ['-c', 'eval "$1"', 'controlled-runtime-resolver', isolated], {
    encoding: 'utf8',
    env: { PATH: `${bin}:/usr/bin:/bin`, HOME: directory, TMPDIR: directory },
    timeout: 5000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unsupported Node\.js runtime.*26\.10\.0 or newer/);
});
