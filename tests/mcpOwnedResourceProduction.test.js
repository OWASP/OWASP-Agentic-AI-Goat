'use strict';

process.env.EXPORT_INTERNALS = '1';
const test = require('node:test');
const assert = require('node:assert/strict');
const { installMcpOwnedResourceProduction, conversationReadiness, _internals } = require('../server/services/mcp/ownedResourceProduction');
const { createOwnedQualification, QUALIFIED_OBJECTIVES, QUALIFICATION_VERSION,
  PROTECTED_STATE_CAPABILITY, PROTECTED_QUALIFICATION_VERSION, PROTECTED_QUALIFIED_OBJECTIVES,
  OBSERVED_ACTION_CAPABILITY, OBSERVED_ACTION_QUALIFICATION_VERSION, OBSERVED_ACTION_QUALIFIED_OBJECTIVES,
  CATALOG_QUALIFICATION_VERSION, CATALOG_QUALIFIED_OBJECTIVES,
  PROTECTED_CATALOG_QUALIFICATION_VERSION, PROTECTED_CATALOG_QUALIFIED_OBJECTIVES,
  OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION, OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES,
  canExecuteOwnedTool } = require('../server/services/mcp/ownedQualification');

function identityPool({ missing = null } = {}) {
  return { async query(sql, params = []) {
    if (sql.includes('to_regclass')) {
      const name = params[0];
      return { rows: [{ name: name === missing ? null : name }] };
    }
    if (sql.includes('has_table_privilege') && params.length) return { rows: [{ can_select: true, can_insert: true }] };
    if (sql.includes('has_column_privilege')) return { rows: [{ response_update: true, text_update: true, turn_delete: true }] };
    throw new Error(`unexpected identity readiness query: ${sql}`);
  } };
}
function resourcePool({ missing = null, relations = [] } = {}) {
  return { async query(sql, params = []) {
    if (sql.includes('to_regclass')) {
      const literal = sql.match(/to_regclass\('([^']+)'\)/)?.[1];
      const name = params[0] || literal;
      if (literal && !params[0] && !relations.includes(literal)) return { rows: [{ name: null }] };
      return { rows: [{ name: name === missing ? null : name }] };
    }
    if (sql.includes('has_table_privilege')) return { rows: [{ can_select: true, can_insert: true, can_update: true }] };
    throw new Error(`unexpected resource readiness query: ${sql}`);
  } };
}
function fixture(overrides = {}) {
  const installed = [];
  let application = null;
  return {
    env: { MCP_OWNED_RESOURCES_ENABLED: 'true', MCP_OWNED_HTTP_ENABLED: 'false', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' },
    route: { installOwnedRuntime(value) { installed.push(value); } },
    identityAdapter: { pool: identityPool(), validateSession: async () => null },
    resourcePool: resourcePool(), ownedShadow: null,
    targets: { readiness: async () => ({ ready: true, runnerReady: true, version: 'mcp-owned-target-http.v1',
      isolation: 'bwrap-seccomp-v1', supervisorProfile: 'dvaia-mcp-sandbox (enforce)',
      endpoint: 'http://127.0.0.1:48123/' }) },
    mailReadiness: async () => ({ ready: true }),
    compositionFactory(options) { application = { enabled: true, qualification: options.qualification,
      admitChat() {}, readOnly() {}, reset() {}, state() {} }; return application; },
    installed, get application() { return application; }, ...overrides,
  };
}

test('owned runtime activation defaults off without touching dependencies', async () => {
  assert.deepEqual(await installMcpOwnedResourceProduction({ env: {}, route: null }), { enabled: false, installed: false });
  assert.equal(_internals.enabled({ MCP_OWNED_RESOURCES_ENABLED: 'false' }), false);
  assert.throws(() => _internals.enabled({ MCP_OWNED_RESOURCES_ENABLED: 'yes' }), /must be true or false/);
  assert.equal(_internals.observedActionEnabled({}), false);
  assert.equal(_internals.observedActionEnabled({ MCP_OBSERVED_ACTION_ENABLED: 'true' }), true);
  assert.throws(() => _internals.observedActionEnabled({ MCP_OBSERVED_ACTION_ENABLED: 'yes' }), /must be true or false/);
});

test('owned runtime publishes application and persistence together only after every readiness gate', async () => {
  const f = fixture();
  const result = await installMcpOwnedResourceProduction(f);
  assert.equal(result.installed, true); assert.equal(result.readiness.conversationsReady, true);
  assert.equal(result.readiness.mailReady, true); assert.equal(f.installed.length, 1);
  assert.equal(result.qualification.version, CATALOG_QUALIFICATION_VERSION);
  assert.equal(result.qualification.qualifiedObjectives, CATALOG_QUALIFIED_OBJECTIVES);
  assert.equal(f.installed[0].application, f.application);
  assert.equal(typeof f.installed[0].requests.admit, 'function');
  assert.equal(typeof f.installed[0].conversations.list, 'function');
});

test('catalog recon is promoted in normal production and the candidate installer stays compatible', async () => {
  const production = fixture({ compositionFactory(options) { return { enabled: true,
    qualification: options.qualification, admitChat() {}, readOnly() {}, readiness() {}, reset() {}, state() {} }; } });
  const normal = await installMcpOwnedResourceProduction(production);
  assert.equal(normal.qualification.version, CATALOG_QUALIFICATION_VERSION);
  assert.equal(normal.qualification.canGrade('mcp_recon'), true);

  const candidate = fixture({ compositionFactory(options) { return { enabled: true,
    qualification: options.qualification, admitChat() {}, readOnly() {}, readiness() {}, reset() {}, state() {} }; } });
  const result = await _internals.installCatalogReconCandidate(candidate);
  assert.equal(result.qualification.version, CATALOG_QUALIFICATION_VERSION);
  assert.equal(result.qualification.qualifiedObjectives, CATALOG_QUALIFIED_OBJECTIVES);
  assert.equal(result.qualification.canGrade('mcp_recon'), true);
});

test('normal production fails closed without the exact local catalog capability', async () => {
  for (const catalogObservationCapability of [undefined, null, 'wrong']) {
    const f = fixture({ protocolManager: { catalogObservationCapability } });
    await assert.rejects(installMcpOwnedResourceProduction(f),
      { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
    assert.equal(f.installed.length, 0);
  }
});

test('partial resource, conversation, mail or runner readiness never publishes activation', async () => {
  for (const changed of [
    { resourcePool: resourcePool({ missing: 'mcp.mail_intents' }) },
    { identityAdapter: { pool: identityPool({ missing: 'workshop_conversations.requests' }), validateSession: async () => null } },
    { mailReadiness: async () => ({ ready: false }) },
    { targets: { readiness: async () => ({ ready: false }) } },
    { resourcePool: { async query() { throw new Error('relation unavailable'); } } },
  ]) {
    const f = fixture(changed);
    await assert.rejects(installMcpOwnedResourceProduction(f), { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
    assert.equal(f.installed.length, 0);
  }
});

test('a runner outage after startup is rechecked and blocks before target allocation', async () => {
  let runnerReady = true; let allocations = 0; let liveReadiness;
  const f = fixture({
    targets: { async readiness() { return runnerReady
      ? { ready: true, runnerReady: true, version: 'mcp-owned-target-http.v1', isolation: 'bwrap-seccomp-v1',
        supervisorProfile: 'dvaia-mcp-sandbox (enforce)', endpoint: 'http://127.0.0.1:48123/' }
        : { ready: false, runnerReady: false }; } },
    compositionFactory(options) {
      liveReadiness = options.readiness;
      return { enabled: true, qualification: options.qualification,
        async admitChat() { const receipt = await options.readiness(); if (!receipt.ready) {
          throw Object.assign(new Error('unavailable'), { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
        } allocations += 1; }, readOnly() {}, reset() {}, state() {} };
    },
  });
  await installMcpOwnedResourceProduction(f); assert.equal((await liveReadiness()).ready, true);
  runnerReady = false;
  await assert.rejects(f.installed[0].application.admitChat(), { code: 'MCP_OWNED_RESOURCES_UNAVAILABLE' });
  assert.equal(allocations, 0);
});

test('conversation readiness requires exact relations and least-privilege operations', async () => {
  assert.equal(await conversationReadiness(identityPool()), true);
  assert.equal(await conversationReadiness(identityPool({ missing: 'workshop_conversations.turns' })), false);
});

test('owned qualification admits exactly the two native-qualified objectives', () => {
  const value = createOwnedQualification(true);
  assert.equal(value.version, QUALIFICATION_VERSION);
  assert.deepEqual(value.qualifiedObjectives, QUALIFIED_OBJECTIVES);
  assert.equal(value.canGrade('mcp_cmd_injection'), true);
  assert.equal(value.canGrade('mcp_confused_deputy'), true);
  for (const objective of ['mcp_recon','mcp_ssrf','mcp_tool_poisoning','mcp_indirect_injection','mcp_broken_authz',
    'mcp_secret_exposure','mcp_supply_chain','mcp_audit_gap','mcp_shadow_server']) assert.equal(value.canGrade(objective), false);
});

test('exact protected-state capability expands only the three qualified tools and objectives', async () => {
  let composition;
  const f = fixture({
    targets: { readiness: async () => ({ ready: true, runnerReady: true, version: 'mcp-owned-target-http.v1',
      isolation: 'bwrap-seccomp-v1', supervisorProfile: 'dvaia-mcp-sandbox (enforce)',
      protectedStateCapability: PROTECTED_STATE_CAPABILITY, endpoint: 'http://127.0.0.1:48123/' }) },
    compositionFactory(options) {
      composition = options;
      return { enabled: true, qualification: options.qualification,
        admitChat() {}, readOnly() {}, readiness() {}, reset() {}, state() {} };
    },
  });
  const result = await installMcpOwnedResourceProduction(f);
  assert.equal(result.qualification.version, PROTECTED_CATALOG_QUALIFICATION_VERSION);
  assert.equal(result.qualification.qualifiedObjectives, PROTECTED_CATALOG_QUALIFIED_OBJECTIVES);
  for (const tool of ['run_command','send_report','admin_rotate_keys','get_config','set_audit_logging']) {
    assert.equal(composition.authorizeTool(tool, {}), true, tool);
  }
  for (const tool of ['read_file','fetch_url','check_system_status','read_ticket','install_plugin','register_server']) {
    assert.equal(composition.authorizeTool(tool, {}), false, tool);
  }
  assert.equal(composition.authorizeTool('send_report', { purpose: 'indirect_injection' }), false);
});

test('capable rebuilt runner retains the protected profile plus promoted recon until observed action is released', async () => {
  let composition;
  const f = fixture({
    targets: { readiness: async () => ({ ready: true, runnerReady: true, version: 'mcp-owned-target-http.v1',
      isolation: 'bwrap-seccomp-v1', supervisorProfile: 'dvaia-mcp-sandbox (enforce)',
      protectedStateCapability: PROTECTED_STATE_CAPABILITY, observedActionCapability: OBSERVED_ACTION_CAPABILITY,
      endpoint: 'http://127.0.0.1:48123/' }) },
    compositionFactory(options) { composition = options; return { enabled: true, qualification: options.qualification,
      admitChat() {}, readOnly() {}, readiness() {}, reset() {}, state() {} }; },
  });
  const result = await installMcpOwnedResourceProduction(f);
  assert.equal(result.qualification.version, PROTECTED_CATALOG_QUALIFICATION_VERSION);
  assert.equal(result.qualification.qualifiedObjectives, PROTECTED_CATALOG_QUALIFIED_OBJECTIVES);
  assert.equal(composition.authorizeTool('check_system_status', { purpose: 'observation' }), false);
  assert.equal(composition.authorizeTool('read_file', { purpose: 'tool_poisoning' }), false);
  for (const [tool, context] of [['check_system_status', {}], ['read_file', {}],
    ['read_file', { purpose: 'observation' }], ['fetch_url', {}]]) {
    assert.equal(composition.authorizeTool(tool, context), false, `${tool}:${context.purpose || 'direct'}`);
  }
});

test('explicit production release selects six only with both exact runner capabilities', async () => {
  let composition;
  const f = fixture({
    env: { MCP_OWNED_RESOURCES_ENABLED: 'true', MCP_OWNED_HTTP_ENABLED: 'false', MCP_OBSERVED_ACTION_ENABLED: 'true',
      PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' },
    targets: { readiness: async () => ({ ready: true, runnerReady: true, version: 'mcp-owned-target-http.v1',
      isolation: 'bwrap-seccomp-v1', supervisorProfile: 'dvaia-mcp-sandbox (enforce)',
      protectedStateCapability: PROTECTED_STATE_CAPABILITY, observedActionCapability: OBSERVED_ACTION_CAPABILITY,
      endpoint: 'http://127.0.0.1:48123/' }) },
    compositionFactory(options) { composition = options; return { enabled: true, qualification: options.qualification,
      admitChat() {}, readOnly() {}, readiness() {}, reset() {}, state() {} }; },
  });
  const result = await installMcpOwnedResourceProduction(f);
  assert.equal(result.qualification.version, OBSERVED_ACTION_CATALOG_QUALIFICATION_VERSION);
  assert.equal(result.qualification.qualifiedObjectives, OBSERVED_ACTION_CATALOG_QUALIFIED_OBJECTIVES);
  assert.equal(composition.authorizeTool('check_system_status', { purpose: 'observation' }), true);
  assert.equal(composition.authorizeTool('read_file', { purpose: 'tool_poisoning' }), true);
  for (const [tool, context] of [['check_system_status', {}], ['read_file', {}],
    ['check_system_status', { purpose: 'tool_poisoning' }], ['read_file', { purpose: 'observation' }]]) {
    assert.equal(composition.authorizeTool(tool, context), false, `${tool}:${context.purpose || 'direct'}`);
  }
});

test('owned subset blocks unqualified external-effect tools before global target or runner calls', async () => {
  const targets = require('../server/services/mcp/targets');
  const original = { fetchViaSsrfTarget: targets.fetchViaSsrfTarget,
    postToTarget: targets.postToTarget, discoverRogueServer: targets.discoverRogueServer };
  let globalCalls = 0; let runnerCalls = 0;
  targets.fetchViaSsrfTarget = targets.postToTarget = targets.discoverRogueServer = async () => { globalCalls += 1; throw new Error('must not run'); };
  const factory = require('../server/services/mcp/sandboxShell').createSandboxFactory({
    createRunner: () => ({ async exec() { runnerCalls += 1; throw new Error('must not run'); } }),
    createMailDelivery: () => async () => { throw new Error('must not run'); }, authorizeTool: canExecuteOwnedTool,
  });
  const sandbox = factory.getOrCreate('scope', {}, 'mcp_1');
  const registry = require('../server/services/mcp/toolRegistry');
  try {
    const cases = [
      ['read_file', { path: '/var/secrets/master_key.txt' }, {}],
      ['fetch_url', { url: 'http://127.0.0.1/admin' }, {}],
      ['install_plugin', { source: 'https://example.invalid/package.tgz' }, {}],
      ['register_server', { url: 'http://rogue.invalid/mcp', name: 'rogue' }, {}],
      ['read_ticket', { id: '4295' }, {}],
      ['check_system_status', {}, {}],
      ['admin_rotate_keys', {}, {}],
      ['get_config', {}, {}],
      ['set_audit_logging', { action: 'disable' }, {}],
      ['send_report', { to: 'outside@example.invalid', body: 'ticket data' }, { purpose: 'indirect_injection' }],
      ['read_file', { path: '/var/secrets/master_key.txt' }, { purpose: 'tool_poisoning' }],
    ];
    for (const [name, args, context] of cases) {
      const result = await registry.performTool(sandbox, name, args, context);
      assert.equal(result.errorCode, 'MCP_OBJECTIVE_RUNTIME_UNQUALIFIED'); assert.equal(result.real, false);
    }
    assert.equal(globalCalls, 0); assert.equal(runnerCalls, 0);
  } finally { Object.assign(targets, original); }
});

 test('observed-action candidate requires explicit release and both exact capabilities', () => {
  const capabilities = { protectedStateCapability: PROTECTED_STATE_CAPABILITY,
    observedActionCapability: OBSERVED_ACTION_CAPABILITY };
  for (const enableObservedAction of [undefined, false, 'true']) {
    assert.equal(createOwnedQualification(true, { ...capabilities, enableObservedAction }).version,
      PROTECTED_QUALIFICATION_VERSION);
  }
  assert.equal(createOwnedQualification(true, { ...capabilities, enableObservedAction: true }).version,
    OBSERVED_ACTION_QUALIFICATION_VERSION);
  for (const observedActionCapability of [null, 'invalid']) {
    assert.equal(createOwnedQualification(true, { ...capabilities, enableObservedAction: true,
      observedActionCapability }).version, PROTECTED_QUALIFICATION_VERSION);
  }
  assert.equal(createOwnedQualification(true, { ...capabilities, enableObservedAction: true,
    protectedStateCapability: null }).version, QUALIFICATION_VERSION);
});
test('production releases HTTP only after enabled service manifest and both schema ACL gates',async()=>{
 const {MANIFEST_SHA256}=require('../server/services/mcp/ownedHttpCapability');
 const f=fixture();const baseResources=f.resourcePool,baseIdentity=f.identityAdapter.pool;
 let available=true;
 f.resourcePool={query:async(sql,params)=>sql.includes("to_regclass('mcp.http_target_leases')")?{rows:[{name:'mcp.http_target_leases'}]}:sql.includes("'mcp.http_target_leases'")?{rows:[{read:true,insert:true,publish:true,delete:false}]}:baseResources.query(sql,params)};
 f.identityAdapter.pool={query:async(sql,params)=>sql.includes("to_regclass('workshop_conversations.mcp_http_operations')")?{rows:[{name:'workshop_conversations.mcp_http_operations'}]}:sql.includes("'workshop_conversations.mcp_http_operations'")?{rows:[{read:true,insert:true,publish:true,delete:false}]}:baseIdentity.query(sql,params)};
 f.targets={...f.targets,admit:async()=>{},retire:async()=>{}};
 f.ownedHttp={enabled:true,client:{readiness:async()=>({ready:available,manifestSha256:MANIFEST_SHA256})},readMode:async()=>'vuln'};
 let options;f.compositionFactory=value=>{options=value;return{qualification:value.qualification};};
 const installed=await installMcpOwnedResourceProduction(f);assert.equal(installed.qualification.canGrade('mcp_ssrf'),true);assert.equal(options.authorizeTool('fetch_url'),true);assert.equal(options.authorizeTool('install_plugin'),false);
 available=false;assert.equal((await options.readiness()).ready,false);
 await assert.rejects(installMcpOwnedResourceProduction(f),{code:'MCP_OWNED_RESOURCES_UNAVAILABLE'});
});

test('protected production attaches metadata service and closes managed pools if publication fails',async()=>{
 const pg=require('../server/database/postgres');const before=pg.getPoolBudgetSnapshot().reserved;
 const f=fixture();f.env={...f.env,MCP_PROTECTED_RECOVERY_ENABLED:'true',IDENTITY_DATABASE_URL:'postgresql://fixture@localhost/identity',MCP_WORKSHOP_DATABASE_URL:'postgresql://fixture@localhost/mcp'};
 const original=f.identityAdapter.pool.query;f.identityAdapter.pool.query=async(sql,args=[])=>sql.includes('mcp_protected_current')?{rows:[{admit:true,append:true,internal:false}]}:String(args[0]).includes('mcp_protected_')?{rows:[{read:true,write:false}]}:original(sql,args);
 const old=f.targets.readiness;f.targets={...f.targets,readProtectedOperationReceipt:async()=>{},readiness:async()=>({...await old(),protectedJournalCapability:'mcp-owned-protected-operation-journal.v1',protectedReadbackCapability:'mcp-owned-protected-readback.v1'})};
 const result=await installMcpOwnedResourceProduction(f);assert.equal(result.protectedRecoveryReady,true);assert.equal(typeof f.installed[0].protectedRecovery.reconcile,'function');assert.equal(pg.getPoolBudgetSnapshot().reserved,before+4);await result.close();assert.equal(pg.getPoolBudgetSnapshot().reserved,before);
 f.route={installOwnedRuntime(){throw Error('controlled publication failure');}};await assert.rejects(installMcpOwnedResourceProduction(f),/controlled publication failure/);assert.equal(pg.getPoolBudgetSnapshot().reserved,before);
});
