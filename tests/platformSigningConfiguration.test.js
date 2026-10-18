'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '..');
const helper = require('../server/services/platformSigningConfiguration');

test('platform signing configuration accepts only a configured private secret', () => {
  const value = crypto.randomBytes(48).toString('hex');
  assert.deepEqual(helper.assertPlatformSigningConfiguration({ JWT_SECRET: value }), { jwtSecret: value });
  for (const env of [
    {},
    { JWT_SECRET: '' },
    { JWT_SECRET: ' '.repeat(32) },
    { JWT_SECRET: 'too-short' },
    { JWT_SECRET: 'dvaia-secret-key-2024' },
    { JWT_SECRET: 'change_me_to_a_long_random_string' },
  ]) {
    assert.throws(() => helper.assertPlatformSigningConfiguration(env), error =>
      error.code === 'INVALID_CONFIGURATION' && !String(error.message).includes(env.JWT_SECRET || '__absent__'));
  }
});

test('supported entrypoint rejects missing signing configuration before application imports', () => {
  const indexPath = path.join(repoRoot, 'server', 'index.js');
  const isolatedCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-signing-entrypoint-'));
  const script = `
    const Module = require('node:module');
    const originalLoad = Module._load;
    const blocked = [];
    Module._load = function guardedLoad(request, parent) {
      const name = String(request);
      // Permit only the pure early gate validator; guard its transitive imports.
      const startupGateValidator = name === './middleware/eventGate' && parent?.filename === ${JSON.stringify(indexPath)};
      if (!startupGateValidator && /database|sqlite|mysql|provider|ollama|agent-runtime|routes|middleware|express|compression|cors|session/.test(name)) {
        blocked.push(name); throw new Error('unexpected application import: ' + name);
      }
      return originalLoad.apply(this, arguments);
    };
    try { require(${JSON.stringify(indexPath)}); }
    catch (error) {
      if (error.code !== 'INVALID_CONFIGURATION' || !error.message.includes('JWT_SECRET')) process.exit(2);
      if (blocked.length) process.exit(3);
      process.stdout.write('signing guard passed\\n');
    } finally { Module._load = originalLoad; }
  `;
  try {
    for (const maintenance of [undefined, 'false']) {
      const env = { PATH: process.env.PATH, HOME: isolatedCwd, TMPDIR: isolatedCwd, NODE_ENV: 'development', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' };
      if (maintenance !== undefined) {
        env.LEGACY_PLATFORM_LIFECYCLE_ENABLED = maintenance;
        env.SENSITIVE_INFO_AGGREGATE_RESET_ENABLED = maintenance;
        env.SECURESHOP_PERSONA_INBOX_ENABLED = maintenance;
      }
      const result = spawnSync(process.execPath, ['-e', script], { cwd: isolatedCwd, encoding: 'utf8', timeout: 5000, env });
      assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
      assert.match(result.stdout, /signing guard passed/);
    }
    const unsafeValue = 'private-looking-but-short';
    const uncaught = spawnSync(process.execPath, [indexPath], {
      cwd: isolatedCwd,
      encoding: 'utf8',
      timeout: 5000,
        env: { PATH: process.env.PATH, HOME: isolatedCwd, TMPDIR: isolatedCwd, NODE_ENV: 'development', PLATFORM_DATABASE_ENGINE: 'postgres',
        WORKSHOP_DATABASE_ENGINE: 'postgres', JWT_SECRET: unsafeValue },
    });
    assert.notEqual(uncaught.status, 0);
    assert.doesNotMatch(`${uncaught.stdout}\n${uncaught.stderr}`, new RegExp(unsafeValue));
  } finally {
    fs.rmSync(isolatedCwd, { recursive: true, force: true });
  }
});

test('every supported local launcher delegates to the same signing guard', () => {
  const indexSource = fs.readFileSync(path.join(repoRoot, 'server', 'index.js'), 'utf8');
  const preflightSource = fs.readFileSync(path.join(repoRoot, 'scripts', 'lib', 'preflight.sh'), 'utf8');
  const signingGuardIndex = indexSource.indexOf('assertPlatformSigningConfiguration(process.env)');
  const expressImportIndex = indexSource.indexOf("require('express')");
  assert.ok(signingGuardIndex >= 0);
  assert.ok(expressImportIndex >= 0);
  assert.ok(signingGuardIndex < expressImportIndex);
  assert.match(preflightSource, /platformSigningConfiguration[^\n]+assertPlatformSigningConfiguration/);

  const launcherPath = path.join(repoRoot, 'scripts', 'start-application.js');
  const launcherEnvRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-signing-launcher-'));
  try { for (const args of [[], ['--init-db']]) {
    const script = `
      const Module = require('node:module');
      const originalLoad = Module._load;
      let spawned = 0, initialized = 0;
      Module._load = function(request, parent) {
        if (parent?.filename === ${JSON.stringify(launcherPath)}) {
          if (request === 'dotenv') return { config() {} };
          // Isolate signing validation from optional private renderer configuration.
          // Starting any managed service is still forbidden by the spawn counters.
          if (request === '../server/services/secureshopPolicyRendererManagedEnvironment') return { load() { return {}; } };
          if (request === 'node:child_process') return {
            spawn() { spawned++; throw new Error('unexpected child process'); },
            // The launcher prepares a promisified execFile for optional local
            // service readiness. Loading it is safe; executing it before the
            // missing-signing guard must still fail this test.
            execFile() { spawned++; throw new Error('unexpected child process'); }
          };
          if (request === './application-data-root') return {
            ensureApplicationDataRoot() { return process.cwd(); }
          };
          if (request === '../db/postgres/initialize-application') return {
            configurationPlan() { return [{ configured: true }]; },
            async initializeApplication() { initialized++; throw new Error('unexpected database initialization'); }
          };
        }
        return originalLoad.apply(this, arguments);
      };
      require(${JSON.stringify(launcherPath)}).main(${JSON.stringify(args)}).then(
        () => { process.exitCode = 2; },
        error => {
          if (error.code !== 'INVALID_CONFIGURATION' || !error.message.includes('JWT_SECRET')) {
            const code = typeof error?.code === 'string' ? error.code : 'NO_CODE';
            const message = String(error?.message || 'no message').replace(/[^A-Za-z0-9 _:.-]/g, '?').slice(0, 160);
            process.stderr.write('unexpected startup guard: ' + code + ' ' + message + '\\n');
            process.exitCode = 3;
          }
          else if (spawned || initialized) process.exitCode = 4;
          else process.stdout.write('launcher signing guard passed\\n');
        }
      ).finally(() => { Module._load = originalLoad; });
    `;
    const result = spawnSync(process.execPath, ['-e', script], {
      cwd: repoRoot, encoding: 'utf8', timeout: 5000,
      env: { PATH: process.env.PATH, HOME: launcherEnvRoot, TMPDIR: launcherEnvRoot, NODE_ENV: 'test', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' },
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /launcher signing guard passed/);
  } } finally { fs.rmSync(launcherEnvRoot, { recursive: true, force: true }); }
});

test('canonical PostgreSQL identity adapter has no public signing fallback', () => {
  const adapterPath = path.join(repoRoot, 'server', 'services', 'postgresIdentityAdapter.js');
  const script = `
    delete process.env.JWT_SECRET;
    try { require(${JSON.stringify(adapterPath)}).getPostgresIdentityAdapter(); process.exit(2); }
    catch (error) {
      if (error.code !== 'INVALID_CONFIGURATION' || !error.message.includes('JWT_SECRET')) process.exit(3);
      process.stdout.write('adapter guard passed\\n');
    }
  `;
  const adapterEnvRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-signing-adapter-'));
  try {
    const result = spawnSync(process.execPath, ['-e', script], {
      cwd: repoRoot, encoding: 'utf8', timeout: 5000,
      env: { PATH: process.env.PATH, HOME: adapterEnvRoot, TMPDIR: adapterEnvRoot, NODE_ENV: 'test' },
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /adapter guard passed/);
  } finally { fs.rmSync(adapterEnvRoot, { recursive: true, force: true }); }
});
