'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const dotenv = require('dotenv');
const { provisionOwnedRunnerForSetup, admitOwnedRunnerForSetup } = require('../scripts/setup-application');
const { provisionFromEnvironment } = require('../scripts/install/mcp-owned-provision');
const { prepareOwnedManagedConfiguration } = require('../scripts/install/mcp-owned-local');
const capabilities = require('../server/services/mcp/ownedQualification');

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'fresh-runner-env-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return { root, homeDirectory: root, directory: path.join(root, 'private'),
    envPath: path.join(root, '.env'), managedPath: path.join(root, 'private/mcp-owned.env'),
    applicationEnvironment: { JWT_SECRET: 's'.repeat(48), CUSTOM_SETTING: 'original' } };
}
const readiness = { ready: true,
  protectedStateCapability: capabilities.PROTECTED_STATE_CAPABILITY,
  observedActionCapability: capabilities.OBSERVED_ACTION_CAPABILITY,
  ticketReadCapability: capabilities.TICKET_READ_CAPABILITY,
  packageInstallCapability: capabilities.PACKAGE_INSTALL_CAPABILITY };

test('fresh setup provisions and activates from a private snapshot without publishing .env', async t => {
  const f = await fixture(t);
  const result = await provisionOwnedRunnerForSetup({ ...f, platform: 'linux', environment: {},
    provisionFromEnvironment: options => provisionFromEnvironment({ ...options,
      targetClientFactory: () => ({ readiness: async () => readiness }),
      provision: async options => {
        await assert.rejects(fs.access(f.envPath), { code: 'ENOENT' });
        assert.equal(options.commandEnv.CUSTOM_SETTING, 'original');
        assert.equal(options.commandEnv.JWT_SECRET, f.applicationEnvironment.JWT_SECRET);
        assert.equal(dotenv.parse(await fs.readFile(f.managedPath)).MCP_OWNED_RESOURCES_ENABLED, 'false');
        f.applicationEnvironment.JWT_SECRET = 'changed-after-admission';
        await options.readiness();
        return { ok: true, profile: 'dvaia-mcp-sandbox' };
      },
    }),
  });
  assert.equal(result.available, true);
  assert.equal(result.activationEnabled, true);
  await assert.rejects(fs.access(f.envPath), { code: 'ENOENT' });
  const managed = dotenv.parse(await fs.readFile(f.managedPath));
  assert.equal(managed.MCP_OWNED_RESOURCES_ENABLED, 'true');
  assert.equal(managed.CODEBOT_OWNED_EXECUTION_ENABLED, 'true');
  assert.equal(managed.JWT_SECRET, undefined);
  assert.equal((await fs.stat(f.managedPath)).mode & 0o077, 0);
});

test('failed fresh provisioning leaves private managed activation disabled and .env absent', async t => {
  const f = await fixture(t);
  await assert.rejects(provisionFromEnvironment({ ...f, platform: 'linux', activateQualified: true,
    targetClientFactory: () => ({}), provision: async () => { throw Error('controlled readiness failure'); },
  }), /controlled readiness failure/);
  assert.equal(dotenv.parse(await fs.readFile(f.managedPath)).MCP_OWNED_RESOURCES_ENABLED, 'false');
  await assert.rejects(fs.access(f.envPath), { code: 'ENOENT' });
});

test('in-memory input retains signing validation and default CLI mode still requires a private file', async t => {
  const f = await fixture(t);
  for (const applicationEnvironment of [null, [], {}, { JWT_SECRET: 'short' }, { JWT_SECRET: 42 }]) {
    await assert.rejects(prepareOwnedManagedConfiguration({ ...f, applicationEnvironment }));
  }
  await assert.rejects(fs.access(f.managedPath), { code: 'ENOENT' });
  await assert.rejects(prepareOwnedManagedConfiguration({ ...f, applicationEnvironment: undefined }),
    { code: 'MCP_INSTALL_ENV_REQUIRED' });
  const original = `JWT_SECRET=${'s'.repeat(48)}\nCUSTOM_SETTING=preserved\n`;
  await fs.writeFile(f.envPath, original, { mode: 0o600 });
  const result = await provisionFromEnvironment({ ...f, applicationEnvironment: undefined,
    platform: 'linux', activateQualified: true, targetClientFactory: () => ({}),
    provision: async options => {
      assert.equal(options.commandEnv.CUSTOM_SETTING, 'preserved');
      return { ok: true, profile: 'dvaia-mcp-sandbox' };
    },
  });
  assert.equal(result.activationEnabled, true);
  assert.equal(await fs.readFile(f.envPath, 'utf8'), original);
});

test('required runner errors expose bounded diagnostic identifiers without arbitrary error text', () => {
  assert.throws(() => admitOwnedRunnerForSetup({ available: false, code: 'MCP_INSTALL_ENV_REQUIRED', stage: 'owned-readiness' }),
    error => error.code === 'MCP_INSTALL_REQUIRED_UNAVAILABLE' && /MCP_INSTALL_ENV_REQUIRED; stage: owned-readiness/.test(error.message));
  assert.throws(() => admitOwnedRunnerForSetup({ available: false, code: 'postgres://secret', stage: 'secret value' }),
    error => !error.message.includes('secret'));
});
