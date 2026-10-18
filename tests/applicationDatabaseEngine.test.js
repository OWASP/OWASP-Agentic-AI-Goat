'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '..');
const helperPath = path.join(repoRoot, 'server', 'services', 'applicationDatabaseEngine.js');
const indexPath = path.join(repoRoot, 'server', 'index.js');

test('application engine requires PostgreSQL for both stores', () => {
  const { resolveApplicationDatabaseEngine } = require(helperPath);
  assert.equal(resolveApplicationDatabaseEngine({ env: { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' }, cwd: repoRoot }), 'postgres');

  for (const env of [
    {},
    { PLATFORM_DATABASE_ENGINE: 'sqlite' },
    { PLATFORM_DATABASE_ENGINE: 'mysql' },
    { PLATFORM_DATABASE_ENGINE: 'postgres' },
    { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'sqlite' },
  ]) {
    assert.throws(
      () => resolveApplicationDatabaseEngine({ env, cwd: repoRoot }),
      error => error.code === 'ERR_POSTGRES_REQUIRED' && /PostgreSQL is required/.test(error.message)
    );
  }
});

test('even a realpath-matched test workspace cannot select legacy SQLite', () => {
  const { resolveApplicationDatabaseEngine } = require(helperPath);
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-engine-test-'));
  const env = { NODE_ENV: 'test', DVAIA_ISOLATED_TEST_WORKSPACE: workspace, PLATFORM_DATABASE_ENGINE: 'sqlite' };
  try {
    assert.throws(() => resolveApplicationDatabaseEngine({ env, cwd: workspace }), /PostgreSQL is required/);
    assert.throws(() => resolveApplicationDatabaseEngine({ env: { ...env, PLATFORM_DATABASE_ENGINE: undefined }, cwd: workspace }), /PostgreSQL is required/);
    assert.throws(
      () => resolveApplicationDatabaseEngine({ env, cwd: repoRoot }),
      /PostgreSQL is required/
    );
    assert.throws(
      () => resolveApplicationDatabaseEngine({ env: { ...env, NODE_ENV: 'development' }, cwd: workspace }),
      /PostgreSQL is required/
    );
    assert.throws(
      () => resolveApplicationDatabaseEngine({ env: { ...env, PLATFORM_DATABASE_ENGINE: 'mysql' }, cwd: workspace }),
      /PostgreSQL is required/
    );
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test('main entrypoint fails before database or provider imports when PostgreSQL is not configured', () => {
  const isolatedCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-entrypoint-test-'));
  const script = `
    const Module = require('node:module');
    const originalLoad = Module._load;
    const blocked = [];
    Module._load = function guardedLoad(request, parent, isMain) {
      const name = String(request);
      // The entry gate exports a pure startup validator and loads only crypto.
      // Keep guarding its transitive imports, including any future framework or store.
      const startupGateValidator = name === './middleware/eventGate' && parent?.filename === ${JSON.stringify(indexPath)};
      if (!startupGateValidator && /database|sqlite|mysql|provider|ollama|agent-runtime|routes|middleware|express|compression|cors|session/.test(name)) {
        blocked.push(name);
        throw new Error('unexpected application import: ' + name);
      }
      return originalLoad.apply(this, arguments);
    };
    try {
      require(${JSON.stringify(indexPath)});
    } catch (error) {
      if (error.code !== 'ERR_POSTGRES_REQUIRED' || !error.message.includes('PostgreSQL is required')) {
        console.error(error.stack || error.message);
        process.exit(2);
      }
      if (blocked.length) {
        console.error(JSON.stringify(blocked));
        process.exit(3);
      }
      process.stdout.write('engine guard passed\\n');
    } finally {
      Module._load = originalLoad;
    }
  `;
  try {
    for (const engineEnv of [{}, { PLATFORM_DATABASE_ENGINE: 'postgres' }, { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'sqlite' }]) {
    const result = spawnSync(process.execPath, ['-e', script], {
      cwd: isolatedCwd,
      encoding: 'utf8',
      env: { PATH: process.env.PATH, NODE_ENV: 'development', ...engineEnv },
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /engine guard passed/);
    }
  } finally {
    fs.rmSync(isolatedCwd, { recursive: true, force: true });
  }
});
