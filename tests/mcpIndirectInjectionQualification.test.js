'use strict';

process.env.EXPORT_INTERNALS = '1';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');

const { createMcpOwnedResourceReadiness } = require('../server/services/mcp/ownedResourceComposition');
const { createMcpOwnedResourceApplication } = require('../server/services/mcp/ownedResourceApplication');
const production = require('../server/services/mcp/ownedResourceProduction');
const {
  createOwnedQualification, createOwnedToolAuthorizer, isProductionQualification,
  PROTECTED_STATE_CAPABILITY, PROTECTED_QUALIFICATION_VERSION,
  OBSERVED_ACTION_CAPABILITY, OBSERVED_ACTION_QUALIFICATION_VERSION,
  OBSERVED_ACTION_QUALIFIED_OBJECTIVES, TICKET_READ_CAPABILITY,
  INDIRECT_INJECTION_QUALIFICATION_VERSION, INDIRECT_INJECTION_QUALIFIED_OBJECTIVES,
  PACKAGE_INSTALL_CAPABILITY, CATALOG_OBSERVATION_CAPABILITY,
  INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION,
  INDIRECT_INJECTION_CATALOG_QUALIFIED_OBJECTIVES,
  INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION,
  INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES,
} = require('../server/services/mcp/ownedQualification');

function resourcePool() {
  return { async query(sql, params = []) {
    if (sql.includes('to_regclass')) return { rows: [{ name: params[0] }] };
    if (sql.includes('has_table_privilege')) {
      return { rows: [{ can_select: true, can_insert: true, can_update: true }] };
    }
    throw new Error(`unexpected resource query: ${sql}`);
  } };
}

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

function exactCapabilities(overrides = {}) {
  return { protectedStateCapability: PROTECTED_STATE_CAPABILITY,
    observedActionCapability: OBSERVED_ACTION_CAPABILITY,
    ticketReadCapability: TICKET_READ_CAPABILITY, ...overrides };
}

test('indirect candidate requires its explicit flag and all three exact capabilities', () => {
  const capabilities = exactCapabilities();
  const unchanged = createOwnedQualification(true, capabilities);
  assert.equal(unchanged.version, PROTECTED_QUALIFICATION_VERSION);
  assert.equal(unchanged.canGrade('mcp_indirect_injection'), false);

  const observed = createOwnedQualification(true, { ...capabilities, enableObservedAction: true });
  assert.equal(observed.version, OBSERVED_ACTION_QUALIFICATION_VERSION);
  assert.equal(observed.qualifiedObjectives, OBSERVED_ACTION_QUALIFIED_OBJECTIVES);

  const candidate = createOwnedQualification(true, { ...capabilities, enableIndirectInjection: true });
  assert.equal(candidate.version, INDIRECT_INJECTION_QUALIFICATION_VERSION);
  assert.equal(candidate.qualifiedObjectives, INDIRECT_INJECTION_QUALIFIED_OBJECTIVES);
  assert.deepEqual([...candidate.qualifiedObjectives], [...OBSERVED_ACTION_QUALIFIED_OBJECTIVES,
    'mcp_indirect_injection']);
  assert.equal(candidate.canGrade('mcp_indirect_injection'), true);
  assert.equal(isProductionQualification(candidate), true);

  for (const changed of [
    { protectedStateCapability: undefined }, { protectedStateCapability: 'wrong' },
    { observedActionCapability: undefined }, { observedActionCapability: 'wrong' },
    { ticketReadCapability: undefined }, { ticketReadCapability: 'wrong' },
  ]) {
    assert.notEqual(createOwnedQualification(true, { ...capabilities, ...changed,
      enableIndirectInjection: true }).version, INDIRECT_INJECTION_QUALIFICATION_VERSION);
  }
  assert.notEqual(createOwnedQualification(true, { ...capabilities,
    enableIndirectInjection: 'true' }).version, INDIRECT_INJECTION_QUALIFICATION_VERSION);
});

test('candidate identity authorizes only purpose-bound indirect tools and copies cannot widen access', () => {
  const candidate = createOwnedQualification(true, { ...exactCapabilities(), enableIndirectInjection: true });
  const authorize = createOwnedToolAuthorizer(candidate);
  assert.equal(authorize('read_ticket', { purpose: 'observation' }), true);
  assert.equal(authorize('read_ticket', {}), false);
  assert.equal(authorize('read_ticket', { purpose: 'indirect_injection' }), false);
  assert.equal(authorize('send_report', { purpose: 'indirect_injection' }), true);
  assert.equal(authorize('send_report', {}), true, 'existing confused-deputy send remains available');
  assert.equal(authorize('check_system_status', { purpose: 'observation' }), true);
  assert.equal(authorize('read_file', { purpose: 'tool_poisoning' }), true);
  assert.equal(authorize('install_plugin', {}), false);
  assert.equal(authorize('register_server', {}), false);

  const copied = Object.freeze({ ...candidate, qualifiedObjectives: [...candidate.qualifiedObjectives] });
  assert.equal(isProductionQualification(copied), false);
  const copiedAuthorize = createOwnedToolAuthorizer(copied);
  assert.equal(copiedAuthorize('read_ticket', { purpose: 'observation' }), false);
  assert.equal(copiedAuthorize('send_report', { purpose: 'indirect_injection' }), false);
});

test('public indirect profiles preserve catalog and optional supply-chain objectives and tools', () => {
  const input = { ...exactCapabilities(), enableObservedAction: true,
    enableIndirectInjection: true, enableCatalogRecon: true,
    catalogObservationCapability: CATALOG_OBSERVATION_CAPABILITY };
  const catalog = createOwnedQualification(true, input);
  assert.equal(catalog.version, INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION);
  assert.equal(catalog.qualifiedObjectives, INDIRECT_INJECTION_CATALOG_QUALIFIED_OBJECTIVES);
  assert.deepEqual([...catalog.qualifiedObjectives], [...OBSERVED_ACTION_QUALIFIED_OBJECTIVES,
    'mcp_indirect_injection', 'mcp_recon']);
  assert.equal(catalog.canGrade('mcp_indirect_injection'), true);
  assert.equal(catalog.canGrade('mcp_recon'), true);
  assert.equal(createOwnedToolAuthorizer(catalog)('read_ticket', { purpose: 'observation' }), true);
  assert.equal(createOwnedToolAuthorizer(catalog)('install_plugin', {}), false);
  assert.equal(isProductionQualification(catalog), true);

  const combined = createOwnedQualification(true, { ...input, enableSupplyChain: true,
    packageInstallCapability: PACKAGE_INSTALL_CAPABILITY });
  assert.equal(combined.version, INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION);
  assert.equal(combined.qualifiedObjectives, INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES);
  assert.deepEqual([...combined.qualifiedObjectives], [...OBSERVED_ACTION_QUALIFIED_OBJECTIVES,
    'mcp_indirect_injection', 'mcp_supply_chain', 'mcp_recon']);
  const authorize = createOwnedToolAuthorizer(combined);
  assert.equal(authorize('read_ticket', { purpose: 'observation' }), true);
  assert.equal(authorize('send_report', { purpose: 'indirect_injection' }), true);
  assert.equal(authorize('install_plugin', {}), true);
  assert.equal(isProductionQualification(combined), true);

  for (const trusted of [catalog, combined]) {
    const copied = Object.freeze({ ...trusted, qualifiedObjectives: [...trusted.qualifiedObjectives] });
    assert.equal(isProductionQualification(copied), false);
    assert.equal(createOwnedToolAuthorizer(copied)('read_ticket', { purpose: 'observation' }), false);
    assert.equal(createOwnedToolAuthorizer(copied)('install_plugin', {}), false);
  }
});

test('ticket readiness is projected without requiring package or catalog capabilities', async () => {
  const readiness = createMcpOwnedResourceReadiness({ resourcePool: resourcePool(), targets: {
    async readiness() { return { ready: true, runnerReady: true, version: 'mcp-owned-target-http.v1',
      isolation: 'bwrap-seccomp-v1', supervisorProfile: 'dvaia-mcp-sandbox (enforce)',
      endpoint: 'http://127.0.0.1:48123/', ...exactCapabilities() }; },
  } });
  const result = await readiness();
  assert.equal(result.ready, true);
  assert.equal(result.ticketReadCapability, TICKET_READ_CAPABILITY);
  assert.equal(result.packageInstallCapability, undefined);
});

function productionFixture(capabilities = exactCapabilities()) {
  let composition = null;
  const installed = [];
  return { options: {
    env: { MCP_OWNED_RESOURCES_ENABLED: 'true', PLATFORM_DATABASE_ENGINE: 'postgres',
      WORKSHOP_DATABASE_ENGINE: 'postgres' },
    route: { installOwnedRuntime(value) { installed.push(value); } },
    identityAdapter: { pool: identityPool(), async validateSession() {} },
    resourcePool: resourcePool(),
    targets: { async readiness() { return { ready: true, runnerReady: true,
      version: 'mcp-owned-target-http.v1', isolation: 'bwrap-seccomp-v1',
      supervisorProfile: 'dvaia-mcp-sandbox (enforce)', endpoint: 'http://127.0.0.1:48123/',
      ...capabilities }; } },
    mailReadiness: async () => ({ ready: true }),
    compositionFactory(value) { composition = value; return { enabled: true,
      qualification: value.qualification }; },
  }, installed, get composition() { return composition; } };
}

test('public indirect activation is strict, default-off and preserves catalog plus supply chain', async () => {
  assert.equal(production._internals.indirectInjectionEnabled({}), false);
  assert.equal(production._internals.indirectInjectionEnabled({ MCP_INDIRECT_INJECTION_ENABLED: 'true' }), true);
  assert.throws(() => production._internals.indirectInjectionEnabled({ MCP_INDIRECT_INJECTION_ENABLED: 'yes' }),
    /must be true or false/);
  for (const env of [
    { MCP_INDIRECT_INJECTION_ENABLED: 'true' },
    { MCP_OWNED_RESOURCES_ENABLED: 'true', MCP_INDIRECT_INJECTION_ENABLED: 'true' },
  ]) await assert.rejects(production.installMcpOwnedResourceProduction({ env }),
    /requires MCP_OWNED_RESOURCES_ENABLED and MCP_OBSERVED_ACTION_ENABLED/);

  const publicIndirect = productionFixture();
  Object.assign(publicIndirect.options.env, { MCP_OBSERVED_ACTION_ENABLED: 'true',
    MCP_INDIRECT_INJECTION_ENABLED: 'true' });
  publicIndirect.options.protocolManager = { catalogObservationCapability: CATALOG_OBSERVATION_CAPABILITY };
  const indirectResult = await production.installMcpOwnedResourceProduction(publicIndirect.options);
  assert.equal(indirectResult.qualification.version, INDIRECT_INJECTION_CATALOG_QUALIFICATION_VERSION);
  assert.equal(indirectResult.qualification.qualifiedObjectives, INDIRECT_INJECTION_CATALOG_QUALIFIED_OBJECTIVES);
  assert.equal(publicIndirect.composition.authorizeTool('read_ticket', { purpose: 'observation' }), true);
  assert.equal(publicIndirect.composition.authorizeTool('install_plugin', {}), false);

  const combined = productionFixture(exactCapabilities({ packageInstallCapability: PACKAGE_INSTALL_CAPABILITY }));
  Object.assign(combined.options.env, { MCP_OBSERVED_ACTION_ENABLED: 'true',
    MCP_INDIRECT_INJECTION_ENABLED: 'true', MCP_SUPPLY_CHAIN_ENABLED: 'true' });
  combined.options.protocolManager = { catalogObservationCapability: CATALOG_OBSERVATION_CAPABILITY };
  const combinedResult = await production.installMcpOwnedResourceProduction(combined.options);
  assert.equal(combinedResult.qualification.version, INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFICATION_VERSION);
  assert.equal(combinedResult.qualification.qualifiedObjectives,
    INDIRECT_SUPPLY_CHAIN_CATALOG_QUALIFIED_OBJECTIVES);
  assert.equal(combined.composition.authorizeTool('read_ticket', { purpose: 'observation' }), true);
  assert.equal(combined.composition.authorizeTool('install_plugin', {}), true);
});

test('public combined profile fails before mount unless every exact live capability is present', async () => {
  const capabilities = exactCapabilities({ packageInstallCapability: PACKAGE_INSTALL_CAPABILITY });
  for (const changed of [
    { protectedStateCapability: undefined }, { observedActionCapability: undefined },
    { ticketReadCapability: undefined }, { packageInstallCapability: undefined },
  ]) {
    const missing = productionFixture({ ...capabilities, ...changed });
    Object.assign(missing.options.env, { MCP_OBSERVED_ACTION_ENABLED: 'true',
      MCP_INDIRECT_INJECTION_ENABLED: 'true', MCP_SUPPLY_CHAIN_ENABLED: 'true' });
    missing.options.protocolManager = { catalogObservationCapability: CATALOG_OBSERVATION_CAPABILITY };
    await assert.rejects(production.installMcpOwnedResourceProduction(missing.options),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
    assert.equal(missing.composition, null);
    assert.equal(missing.installed.length, 0);
  }
  const missingCatalog = productionFixture(capabilities);
  Object.assign(missingCatalog.options.env, { MCP_OBSERVED_ACTION_ENABLED: 'true',
    MCP_INDIRECT_INJECTION_ENABLED: 'true', MCP_SUPPLY_CHAIN_ENABLED: 'true' });
  missingCatalog.options.protocolManager = { catalogObservationCapability: 'wrong' };
  await assert.rejects(production.installMcpOwnedResourceProduction(missingCatalog.options),
    { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  assert.equal(missingCatalog.composition, null);
  assert.equal(missingCatalog.installed.length, 0);
});

test('private installer selects only the non-catalog indirect candidate and rejects missing live capabilities', async () => {
  const fixture = productionFixture();
  const result = await production._internals.installIndirectInjectionCandidate(fixture.options);
  assert.equal(result.qualification.version, INDIRECT_INJECTION_QUALIFICATION_VERSION);
  assert.equal(result.qualification.qualifiedObjectives, INDIRECT_INJECTION_QUALIFIED_OBJECTIVES);
  assert.equal(result.readiness.ticketReadCapability, TICKET_READ_CAPABILITY);
  assert.equal(fixture.composition.authorizeTool('read_ticket', { purpose: 'observation' }), true);
  assert.equal(fixture.composition.authorizeTool('send_report', { purpose: 'indirect_injection' }), true);
  assert.equal(fixture.composition.authorizeTool('install_plugin', {}), false);
  assert.equal(fixture.installed.length, 1);

  for (const changed of [
    { protectedStateCapability: undefined }, { observedActionCapability: undefined },
    { ticketReadCapability: undefined }, { ticketReadCapability: 'wrong' },
  ]) {
    const missing = productionFixture(exactCapabilities(changed));
    await assert.rejects(production._internals.installIndirectInjectionCandidate(missing.options),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
    assert.equal(missing.composition, null);
    assert.equal(missing.installed.length, 0);
  }
});

test('private indirect installer is absent unless EXPORT_INTERNALS is enabled before module load', () => {
  const env = { ...process.env };
  delete env.EXPORT_INTERNALS;
  const result = spawnSync(process.execPath, ['-e',
    "const p=require('./server/services/mcp/ownedResourceProduction');process.stdout.write(String(typeof p._internals.installIndirectInjectionCandidate));"],
  { cwd: process.cwd(), env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'undefined');
});

test('candidate readiness is checked on every admission before another target allocation', async () => {
  const qualification = createOwnedQualification(true, { ...exactCapabilities(), enableIndirectInjection: true });
  let current = exactCapabilities(); let admissions = 0; let reserved = null;
  const application = createMcpOwnedResourceApplication({
    sessionResolver: { async resolveRequest() { return Object.freeze({ platformOwnerId: 7,
      platformSessionId: 71, async assertCurrent() {} }); } },
    readiness: async () => ({ ready: true, runnerReady: true, repositoryReady: true,
      runnerIsolation: 'bwrap-seccomp-v1', ...current }),
    repository: {
      async readActiveRunnerTarget() { return reserved; }, async listRunnerTargetsForOwner() { return []; },
      async reserveRunnerTarget(value) { reserved = { ...value }; },
    },
    mailResources: { async send() {}, async cleanup() {}, async project() {} },
    targets: { async admit({ scope }) { admissions += 1; return { scope,
      runner: { async exec() { return { ok: true }; } } }; }, async retire() {} },
    qualification, authorizeTool: createOwnedToolAuthorizer(qualification),
  });
  const execution = { ownerKey: JSON.stringify(['MCP', '7']), durableGeneration: 3,
    runId: '123e4567-e89b-42d3-a456-426614174099', async check() {}, async effect(_key, work) { return work(); } };
  await application.admitChat({}, execution);
  assert.equal(admissions, 1);
  current = exactCapabilities({ ticketReadCapability: 'wrong' });
  await assert.rejects(application.admitChat({}, execution), { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  assert.equal(admissions, 1);
});

test('public combined readiness rechecks ticket, protected, observed, catalog and package capabilities', async () => {
  const qualification = createOwnedQualification(true, { ...exactCapabilities(),
    packageInstallCapability: PACKAGE_INSTALL_CAPABILITY,
    catalogObservationCapability: CATALOG_OBSERVATION_CAPABILITY,
    enableObservedAction: true, enableIndirectInjection: true,
    enableSupplyChain: true, enableCatalogRecon: true });
  let current = { ...exactCapabilities(), packageInstallCapability: PACKAGE_INSTALL_CAPABILITY,
    catalogObservationCapability: CATALOG_OBSERVATION_CAPABILITY };
  let admissions = 0; let reserved = null;
  const application = createMcpOwnedResourceApplication({
    sessionResolver: { async resolveRequest() { return Object.freeze({ platformOwnerId: 7,
      platformSessionId: 71, async assertCurrent() {} }); } },
    readiness: async () => ({ ready: true, runnerReady: true, repositoryReady: true,
      runnerIsolation: 'bwrap-seccomp-v1', ...current }),
    repository: {
      async readActiveRunnerTarget() { return reserved; }, async listRunnerTargetsForOwner() { return []; },
      async reserveRunnerTarget(value) { reserved = { ...value }; },
    },
    mailResources: { async send() {}, async cleanup() {}, async project() {} },
    targets: { async admit({ scope }) { admissions += 1; return { scope,
      runner: { async exec() { return { ok: true }; } } }; }, async retire() {} },
    qualification, authorizeTool: createOwnedToolAuthorizer(qualification),
  });
  const execution = { ownerKey: JSON.stringify(['MCP', '7']), durableGeneration: 3,
    runId: '123e4567-e89b-42d3-a456-426614174099', async check() {}, async effect(_key, work) { return work(); } };
  await application.admitChat({}, execution);
  assert.equal(admissions, 1);
  for (const capability of ['protectedStateCapability', 'observedActionCapability', 'ticketReadCapability',
    'catalogObservationCapability', 'packageInstallCapability']) {
    const value = current[capability]; current = { ...current, [capability]: 'wrong' };
    await assert.rejects(application.admitChat({}, execution), { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
    assert.equal(admissions, 1, capability);
    current = { ...current, [capability]: value };
  }
});
