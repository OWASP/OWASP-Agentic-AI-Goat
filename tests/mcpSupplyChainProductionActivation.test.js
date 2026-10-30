'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  installMcpOwnedResourceProduction,
  _internals: production,
} = require('../server/services/mcp/ownedResourceProduction');
const {
  createOwnedQualification,
  createOwnedToolAuthorizer,
  isProductionQualification,
  PROTECTED_STATE_CAPABILITY,
  OBSERVED_ACTION_CAPABILITY,
  OBSERVED_ACTION_QUALIFICATION_VERSION,
  OBSERVED_ACTION_QUALIFIED_OBJECTIVES,
  OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION,
  OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES,
  PACKAGE_INSTALL_CAPABILITY,
  SUPPLY_CHAIN_QUALIFICATION_VERSION,
  SUPPLY_CHAIN_QUALIFIED_OBJECTIVES,
  SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
  SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES,
} = require('../server/services/mcp/ownedQualification');
const { prepareOwnedManagedConfiguration } = require('../scripts/install/mcp-owned-local');
const { loadOwnedManagedConfiguration } = require('../server/services/mcp/ownedManagedConfiguration');

function identityPool() {
  return { async query(sql, params = []) {
    if (sql.includes('to_regclass')) return { rows: [{ name: params[0] }] };
    if (sql.includes('has_table_privilege') && params.length) {
      return { rows: [{ can_select: true, can_insert: true }] };
    }
    if (sql.includes('has_column_privilege')) {
      return { rows: [{ response_update: true, text_update: true, turn_delete: true }] };
    }
    throw new Error(`unexpected identity query: ${sql}`);
  } };
}
function resourcePool() {
  return { async query(sql, params = []) {
    if (sql.includes('to_regclass')) return { rows: [{ name: params[0] }] };
    if (sql.includes('has_table_privilege')) {
      return { rows: [{ can_select: true, can_insert: true, can_update: true }] };
    }
    throw new Error(`unexpected MCP query: ${sql}`);
  } };
}
function runner(extra = {}) {
  return { async readiness() { return {
    ready: true, runnerReady: true, version: 'mcp-owned-target-http.v1',
    isolation: 'bwrap-seccomp-v1', supervisorProfile: 'owasp-ai-goat-mcp-sandbox (enforce)',
    endpoint: 'http://127.0.0.1:48123/', ...extra,
  }; } };
}
function fixture({ env = {}, targetExtra = {} } = {}) {
  let options = null;
  return {
    input: {
      env: { MCP_OWNED_RESOURCES_ENABLED: 'true', MCP_OBSERVED_ACTION_ENABLED: 'true',
        PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres', ...env },
      route: { installOwnedRuntime() {} },
      identityAdapter: { pool: identityPool(), async validateSession() {} },
      resourcePool: resourcePool(), targets: runner(targetExtra),
      mailReadiness: async () => ({ ready: true }),
      compositionFactory(value) {
        options = value;
        return { enabled: true, qualification: value.qualification };
      },
    },
    options: () => options,
  };
}

test('package capability remains unavailable until the explicit seventh-objective profile is selected', () => {
  const base = { protectedStateCapability: PROTECTED_STATE_CAPABILITY,
    observedActionCapability: OBSERVED_ACTION_CAPABILITY, enableObservedAction: true,
    packageInstallCapability: PACKAGE_INSTALL_CAPABILITY };
  const six = createOwnedQualification(true, base);
  assert.equal(six.version, OBSERVED_ACTION_QUALIFICATION_VERSION);
  assert.equal(six.qualifiedObjectives, OBSERVED_ACTION_QUALIFIED_OBJECTIVES);
  assert.equal(createOwnedToolAuthorizer(six)('install_plugin', {}), false);

  const seven = createOwnedQualification(true, { ...base, enableSupplyChain: true });
  assert.equal(seven.version, SUPPLY_CHAIN_QUALIFICATION_VERSION);
  assert.equal(seven.qualifiedObjectives, SUPPLY_CHAIN_QUALIFIED_OBJECTIVES);
  assert.deepEqual([...seven.qualifiedObjectives], [...OBSERVED_ACTION_QUALIFIED_OBJECTIVES, 'mcp_supply_chain']);
  assert.equal(createOwnedToolAuthorizer(seven)('install_plugin', {}), true);
  assert.equal(isProductionQualification(seven), true);

  const copied = { ...seven, qualifiedObjectives: [...seven.qualifiedObjectives] };
  assert.equal(isProductionQualification(copied), false, 'production profile requires the canonical immutable list');
  assert.equal(createOwnedQualification(true, { ...base, enableSupplyChain: 'true' }).version,
    OBSERVED_ACTION_QUALIFICATION_VERSION);
  assert.equal(createOwnedQualification(true, { ...base, enableSupplyChain: true,
    packageInstallCapability: 'wrong' }).version, OBSERVED_ACTION_QUALIFICATION_VERSION);
});

test('production installs supply-chain capability alongside recon only with the explicit flag and exact live capability', async () => {
  const targetExtra = { protectedStateCapability: PROTECTED_STATE_CAPABILITY,
    observedActionCapability: OBSERVED_ACTION_CAPABILITY, packageInstallCapability: PACKAGE_INSTALL_CAPABILITY };
  const six = fixture({ targetExtra });
  const sixResult = await installMcpOwnedResourceProduction(six.input);
  assert.equal(sixResult.qualification.version, OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION);
  assert.equal(sixResult.qualification.qualifiedObjectives, OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES);
  assert.equal(six.options().authorizeTool('install_plugin', {}), false);

  const seven = fixture({ env: { MCP_SUPPLY_CHAIN_ENABLED: 'true' }, targetExtra });
  const sevenResult = await installMcpOwnedResourceProduction(seven.input);
  assert.equal(sevenResult.qualification.version, SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION);
  assert.equal(sevenResult.qualification.qualifiedObjectives, SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES);
  assert.equal(seven.options().authorizeTool('install_plugin', {}), true);
  assert.equal(sevenResult.readiness.packageInstallCapability, PACKAGE_INSTALL_CAPABILITY);

  for (const changed of [
    { packageInstallCapability: undefined },
    { packageInstallCapability: 'wrong' },
    { observedActionCapability: undefined },
    { protectedStateCapability: undefined },
  ]) {
    const missing = fixture({ env: { MCP_SUPPLY_CHAIN_ENABLED: 'true' },
      targetExtra: { ...targetExtra, ...changed } });
    await assert.rejects(installMcpOwnedResourceProduction(missing.input),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
    assert.equal(missing.options(), null);
  }
});

test('supply-chain configuration is default-false, hierarchical and backwards compatible', async t => {
  assert.equal(production.supplyChainEnabled({}), false);
  assert.equal(production.supplyChainEnabled({ MCP_SUPPLY_CHAIN_ENABLED: 'true' }), true);
  assert.throws(() => production.supplyChainEnabled({ MCP_SUPPLY_CHAIN_ENABLED: 'yes' }),
    /must be true or false/);
  for (const env of [
    { MCP_SUPPLY_CHAIN_ENABLED: 'true' },
    { MCP_OWNED_RESOURCES_ENABLED: 'true', MCP_SUPPLY_CHAIN_ENABLED: 'true' },
  ]) await assert.rejects(installMcpOwnedResourceProduction({ env }),
    /requires MCP_OWNED_RESOURCES_ENABLED and MCP_OBSERVED_ACTION_ENABLED/);

  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-mcp-supply-activation-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const envPath = path.join(directory, '.env');
  const managedPath = path.join(directory, 'mcp-owned.env');
  await fs.writeFile(envPath, `JWT_SECRET=${'j'.repeat(48)}\nMCP_SUPPLY_CHAIN_ENABLED=false\n`, { mode: 0o600 });
  await prepareOwnedManagedConfiguration({ envPath, managedPath, activateQualified: true,
    activateObservedAction: true, randomToken: () => 't'.repeat(64) });
  let values = loadOwnedManagedConfiguration({ file: managedPath });
  assert.equal(values.MCP_OBSERVED_ACTION_ENABLED, 'true');
  assert.equal(values.MCP_SUPPLY_CHAIN_ENABLED, 'false');

  await assert.rejects(prepareOwnedManagedConfiguration({ envPath, managedPath,
    activateQualified: true, activateSupplyChain: true }), { code: 'MCP_INSTALL_ENV_INVALID' });
  await prepareOwnedManagedConfiguration({ envPath, managedPath, activateQualified: true,
    activateObservedAction: true, activateSupplyChain: true });
  values = loadOwnedManagedConfiguration({ file: managedPath });
  assert.equal(values.MCP_SUPPLY_CHAIN_ENABLED, 'true');
  assert.equal(values.MCP_OBSERVED_ACTION_ENABLED, 'true');

  const priorFormat = (await fs.readFile(managedPath, 'utf8')).split('\n')
    .filter(line => !line.startsWith('MCP_SUPPLY_CHAIN_ENABLED=')).join('\n');
  await fs.writeFile(managedPath, priorFormat, { mode: 0o600 });
  assert.equal(loadOwnedManagedConfiguration({ file: managedPath }).MCP_SUPPLY_CHAIN_ENABLED, 'false');
});
