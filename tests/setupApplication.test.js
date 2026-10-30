'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const {
  setup: actualSetup, localPostgres, encodeEnv, verifyInstalledComponents, ensureOllamaModel,
  verifyBrowserRuntime, ensurePuppeteerBrowserInstalled, ownedRunnerOptions, provisionOwnedRunnerForSetup,
  admitOwnedRunnerForSetup, REQUIRED_INSTALLED_COMPONENTS,
  OLLAMA_SETUP_GENERATE_URL, OLLAMA_SETUP_INFERENCE_TIMEOUT_MS, shouldBindLocalSidecarDocker,
} = require('../scripts/setup-application');
const { provisioningPlan } = require('../db/postgres/provision-application');
const { inspectUpgradeState } = require('../scripts/application-upgrade');
const { initializeAdditions } = require('../scripts/initialize-application-additions');
const { writeLocalDockerAuthority } = require('../scripts/local-docker-authority');
const CONTROLLED_UPLOAD_ASSETS={SS_BOUND_UPLOAD_ASSETS_ENABLED:'true',SS_UPLOAD_ASSET_HOST:'::1',SS_UPLOAD_ASSET_PORT:'49160',SS_UPLOAD_ASSET_PUBLIC_ORIGIN:'http://[::1]:49160',SS_UPLOAD_ASSET_CAPABILITY_SECRET:'controlled-private-upload-asset-secret'};
// Controlled dispatch exercises the actual phase body with a real branded scope;
// no PostgreSQL/socket/process setup occurs in this unit suite.
async function setup(options = {}) {
  const authority=require('../scripts/install/ctf-authority-setup'),originalAuthority=authority.prepareCtfAuthority;
  authority.prepareCtfAuthority=async ({maintenanceScope,environment})=>{options.observeControlledCtf?.();if(options.controlledCtfFailure)throw Object.assign(Error('controlled CTF unavailable'),{code:'CTF_SETUP_NOT_PREPARED'});require('../scripts/lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope,environment);return {state:'active',trafficStarted:false};};
  try { return await actualSetup({ ...options, runDatabasePhase: async (request, dependencies) => {
    const before = { ...process.env };
    const env = require('../scripts/install/setup-database-phase').validateRequest(request);
    Object.assign(process.env, env);
    let publish;
    try {
      return await require('../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({ environment: env,
        acquire: async () => ({ assertHeld() {}, async beginMaintenance(){return Object.freeze({epoch:"1"});}, async finishMaintenance(){}, async close() {} }), drain: async () => {}, afterDrain: async () => publish(),
      }, scope => require('../scripts/setup-application').executeSetupDatabasePhase(request, scope, { ...dependencies, runCommand: options.runCommand, initializeApplication: options.initializeApplication || (async () => request.kind === 'fresh' ? options.runCommand?.(process.execPath, ['controlled-scoped-initializer'], request.context.root, {...process.env}) : undefined), deferPublication: callback => { publish = callback; },
        prepareUploadAssetEnvironment: options.prepareUploadAssetEnvironment || (async request => {
          options.observeUploadAssetPreparation?.(request);
          if (request.environment.SS_BOUND_UPLOAD_ASSETS_ENABLED === 'false') {
            const configuration={SS_BOUND_UPLOAD_ASSETS_ENABLED:'false'};
            return {state:'preserved-disabled',configuration,additions:{},probed:false};
          }
          if (request.environment.SS_BOUND_UPLOAD_ASSETS_ENABLED === 'true') {
            const keys=['SS_BOUND_UPLOAD_ASSETS_ENABLED','SS_UPLOAD_ASSET_HOST','SS_UPLOAD_ASSET_PORT','SS_UPLOAD_ASSET_PUBLIC_ORIGIN','SS_UPLOAD_ASSET_CAPABILITY_SECRET'];
            const configuration=Object.fromEntries(keys.map(key=>[key,request.environment[key]]));
            return {state:'preserved',configuration,additions:{},probed:false};
          }
          const configuration={...CONTROLLED_UPLOAD_ASSETS};
          return {state:'created',configuration,additions:configuration,probed:true};
        }) }));
    } finally { for (const key of Object.keys(process.env)) if (!(key in before)) delete process.env[key]; Object.assign(process.env, before); }
  }}); } finally { authority.prepareCtfAuthority=originalAuthority; }
}
async function temporary(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-setup-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}
async function writeInstalledComponentFixture(root) {
  const dependencies = Object.fromEntries(REQUIRED_INSTALLED_COMPONENTS.map((name, index) => [name, `1.2.${index}`]));
  await fs.writeFile(path.join(root, 'package.json'), JSON.stringify({ dependencies }));
  for (const [name, version] of Object.entries(dependencies)) {
    const directory = path.join(root, 'node_modules', ...name.split('/'));
    await fs.mkdir(directory, { recursive: true });
    await fs.writeFile(path.join(directory, 'package.json'), JSON.stringify({ name, version, main: 'index.js' }));
    const entry = name === '@modelcontextprotocol/sdk' ? path.join(directory, 'server', 'index.js') : path.join(directory, 'index.js');
    await fs.mkdir(path.dirname(entry), { recursive: true });
    await fs.writeFile(entry, 'module.exports = {}\n');
  }
  return dependencies;
}
test('fresh setup refuses existing configuration before installing or provisioning', async t => {
  const root = await temporary(t);
  await fs.writeFile(path.join(root, '.env'), 'EXISTING=value\n');
  await assert.rejects(setup({ root }), /will not overwrite/);
  assert.equal(await fs.readFile(path.join(root, '.env'), 'utf8'), 'EXISTING=value\n');
  assert.deepEqual(await fs.readdir(root), ['.env']);
});
test('generated environment round trips without allowing extra lines', () => {
  const config = { DATABASE_URL: 'postgresql://user:password@localhost/db', VALUE: 'value # preserved' };
  assert.deepEqual(require('dotenv').parse(encodeEnv(config)), config);
  assert.throws(() => encodeEnv({ VALUE: 'value\nOTHER=secret' }), /Invalid/);
});
test('owned runner setup selects the local Linux path and an explicit macOS Colima profile', () => {
  assert.deepEqual(ownedRunnerOptions({ platform: 'linux' }), { platform: 'linux', colimaProfile: undefined });
  assert.deepEqual(ownedRunnerOptions({ platform: 'darwin' }), { platform: 'darwin', colimaProfile: 'colima-default' });
  assert.deepEqual(ownedRunnerOptions({ platform: 'darwin', environment: { DVAIA_MCP_OWNED_COLIMA_PROFILE: 'colima-dvaia-lab' } }),
    { platform: 'darwin', colimaProfile: 'colima-dvaia-lab' });
});
test('local sidecar Docker binding is skipped only for disabled or externally managed sidecars', () => {
  assert.equal(shouldBindLocalSidecarDocker({}), true);
  assert.equal(shouldBindLocalSidecarDocker({ MCP_SIDECARS_AUTOSTART: 'false' }), false);
  assert.equal(shouldBindLocalSidecarDocker({ TEAM_ID: 'task' }), false);
  assert.equal(shouldBindLocalSidecarDocker({ ECS_CONTAINER_METADATA_URI_V4: 'http://metadata' }), false);
  assert.equal(shouldBindLocalSidecarDocker({ SANDBOX_RUNNER_URL: 'http://mcp-sandbox:8090' }), false);
  assert.equal(shouldBindLocalSidecarDocker({ SANDBOX_RUNNER_URL: 'https://remote.invalid/localhost/status' }), false);
  assert.equal(shouldBindLocalSidecarDocker({ SANDBOX_RUNNER_URL: 'http://localhost:8090' }), true);
  assert.equal(shouldBindLocalSidecarDocker({ SANDBOX_RUNNER_URL: 'http://[::1]:8090' }), true);
});
test('owned runner setup reports disabled availability honestly when provisioning fails', async t => {
  const root = await temporary(t), homeDirectory = await temporary(t), directory = path.join(homeDirectory, '.dvaia', 'workspace');
  await fs.mkdir(directory, { recursive: true });
  const unavailable = await provisionOwnedRunnerForSetup({ root, directory, homeDirectory, environment: {}, platform: 'darwin',
    provisionFromEnvironment: async options => {
      assert.equal(options.colimaProfile, 'colima-default');
      assert.equal(options.activateQualified, true);
      assert.equal(options.activateObservedAction, true);
      assert.equal(options.activateIndirectInjection, true);
      assert.equal(options.activateSupplyChain, true);
      throw Object.assign(new Error('profile unavailable'), { code: 'MCP_INSTALL_READINESS_FAILED', stage: 'owned-readiness' });
    } });
  assert.deepEqual(unavailable, {
    available: false, activationEnabled: false, profile: null,
    managedPath: path.join(directory, 'mcp-owned.env'), code: 'MCP_INSTALL_READINESS_FAILED', stage: 'owned-readiness',
  });
});
test('owned runner setup reports activation only when the strict provisioner confirms it', async t => {
  const root = await temporary(t), homeDirectory = await temporary(t), directory = path.join(homeDirectory, '.dvaia', 'workspace');
  await fs.mkdir(directory, { recursive: true });
  const result = await provisionOwnedRunnerForSetup({ root, directory, homeDirectory, environment: {}, platform: 'linux',
    provisionFromEnvironment: async options => {
      assert.equal(options.activateQualified, true);
      assert.equal(options.activateObservedAction, true);
      assert.equal(options.activateIndirectInjection, true);
      assert.equal(options.activateSupplyChain, true);
      assert.equal(options.colimaProfile, undefined);
      return { ok: true, profile: 'dvaia-mcp-sandbox', managedPath: options.managedPath, activationEnabled: true };
    } });
  assert.deepEqual(result, {
    available: true, activationEnabled: true, profile: 'dvaia-mcp-sandbox',
    managedPath: path.join(directory, 'mcp-owned.env'), code: null, stage: null,
  });
});
test('owned runner setup rejects incomplete, failed and foreign-path provisioning results', async t => {
  const root = await temporary(t), homeDirectory = await temporary(t);
  const directory = path.join(homeDirectory, '.dvaia', 'workspace');
  const managedPath = path.join(directory, 'mcp-owned.env');
  const valid = { ok: true, profile: 'dvaia-mcp-sandbox', managedPath, activationEnabled: false };
  for (const result of [null, {}, { available: false }, { ...valid, ok: false },
    { ...valid, available: false }, { ...valid, managedPath: '/foreign/mcp-owned.env' },
    { ...valid, profile: '' }, { ...valid, activationEnabled: 'true' }]) {
    const actual = await provisionOwnedRunnerForSetup({ root, directory, homeDirectory, environment: {},
      provisionFromEnvironment: async () => result });
    assert.deepEqual(actual, { available: false, activationEnabled: false, profile: null,
      managedPath, code: 'MCP_INSTALL_INVALID_RESULT', stage: 'owned-readiness' });
  }
  const prepared = await provisionOwnedRunnerForSetup({ root, directory, homeDirectory, environment: {},
    provisionFromEnvironment: async () => valid });
  assert.equal(prepared.available, true);
  assert.equal(prepared.activationEnabled, false);
});
test('required owned runner admission fails closed while optional status remains reportable', () => {
  const unavailable = Object.freeze({ available: false, activationEnabled: false, profile: null,
    managedPath: '/private/managed.env', code: 'MCP_INSTALL_READINESS_FAILED', stage: 'owned-readiness' });
  assert.equal(admitOwnedRunnerForSetup(unavailable, { required: false }), unavailable);
  assert.throws(() => admitOwnedRunnerForSetup(unavailable), { code: 'MCP_INSTALL_REQUIRED_UNAVAILABLE' });
  const prepared = Object.freeze({ ...unavailable, available: true, code: null, activationEnabled: false });
  assert.throws(() => admitOwnedRunnerForSetup(prepared), { code: 'MCP_INSTALL_REQUIRED_NOT_ACTIVATED' });
  const activated = Object.freeze({ ...prepared, activationEnabled: true });
  assert.equal(admitOwnedRunnerForSetup(activated), activated);
});
function configurationFor(plan) {
  return Object.fromEntries(plan.flatMap(row => [
    [row.runtimeVariable, `postgresql://${row.runtimeRole}:runtime@127.0.0.1:5432/${row.database}`],
    [row.migrationVariable, `postgresql://${row.migrationRole}:migration@127.0.0.1:5432/${row.database}`],
  ]));
}
async function upgradeFixture(t, manifestPlan = provisioningPlan().slice(0, -1)) {
  const root = await fs.realpath(await temporary(t)), homeDirectory = await temporary(t);
  const directory = path.join(homeDirectory, '.dvaia', require('../scripts/setup-application').workspaceId(root));
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const configuration = configurationFor(manifestPlan);
  const manifestPath = path.join(directory, 'provisioning.json');
  await fs.writeFile(manifestPath, JSON.stringify({ version: 1, status: 'complete', plan: manifestPlan,
    configuration, created: [] }), { mode: 0o600 });
  const original = Buffer.from(`# operator formatting stays byte-exact\nJWT_SECRET='unchanged secret'\n${encodeEnv(configuration)}`);
  await fs.writeFile(path.join(root, '.env'), original, { mode: 0o600 });
  return { root, homeDirectory, directory, manifestPath, configuration, original };
}
async function existingDockerAuthority() {
  return { authority: { version: 1, workspaceId: 'fixture', host: 'unix:///tmp/docker-fixture.sock',
    daemonId: 'daemon-fixture', source: 'active-context' }, persisted: true };
}
test('repair requires an existing installation and rejects invalid upgrade state before package work', async t => {
  const root = await temporary(t), homeDirectory = await temporary(t);
  await assert.rejects(actualSetup({ root, homeDirectory, repair: true, runCommand: async () => assert.fail('no package work') }),
    /requires an existing installation/);
  const value = await upgradeFixture(t);
  await fs.writeFile(path.join(value.root, '.env.upgrade'), 'ambiguous', { mode: 0o600 });
  await assert.rejects(actualSetup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true, repair: true,
    runCommand: async () => assert.fail('invalid upgrade state must not run packages'),
    runDatabasePhase: async () => assert.fail('invalid upgrade state must not reach database phase') }),
  { code: 'UPGRADE_ENV_RECOVERY_REQUIRED' });
  assert.deepEqual(await fs.readFile(path.join(value.root, '.env')), value.original);
});
test('repair prepares the installed runtime before additive phase and retains private environment bytes', async t => {
  const value = await upgradeFixture(t);
  await writeInstalledComponentFixture(value.root);
  const commands = [];
  let phase = null;
  await actualSetup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true, repair: true,
    install: false, ensureModel: false, processEnvironment: {},
    adminUrl: 'postgresql://admin:synthetic@127.0.0.1/postgres',
    runCommand: async (_command, args, cwd) => { commands.push({ args, cwd }); },
    loadPuppeteer: () => ({ launch: async options => {
      assert.equal(options.args, undefined, 'repair must not disable the browser sandbox');
      return { close: async () => {} };
    } }),
    loadRenderer: () => ({ sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
      renderReviewCard: async ({ body }) => `<article>${body}</article>` }),
    loadTicketRenderer: () => ({ component: { id: 'SecureShop.AdminTicketBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadSearchEchoRenderer: () => ({ component: { id: 'SecureShop.SearchEcho', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadPolicyOutputRenderer: () => ({ component: { id: 'SecureShop.PolicyFinalResponse', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), renderProductDescription: async product => `<div>${product.description_html}</div>` }), loadMailRenderer: () => ({ component: { id: 'SecureShop.MailMessageBody',
      sourceSha256: 'c'.repeat(64), artifactSha256: 'd'.repeat(64) } }),
    ensureDockerAuthority: existingDockerAuthority,
    runDatabasePhase: async request => { phase = request; return { upgradedSchemas: [] }; },
  });
  assert.deepEqual(commands.map(row => row.args), [['run', 'build:review-renderer'], ['run', 'build:mail-renderer'], ['run', 'build:product-description-renderer'], ['run', 'build:ticket-renderer'], ['run', 'build:search-echo-renderer'], ['run', 'build:policy-output-renderer']]);
  assert.equal(phase.kind, 'upgrade');
  assert.deepEqual(await fs.readFile(path.join(value.root, '.env')), value.original);
  await assert.rejects(fs.lstat(path.join(value.directory, 'administrator.json')), { code: 'ENOENT' });
});
test('repair invokes both locked dependency installs before any database phase', async t => {
  const value = await upgradeFixture(t);
  const cli = path.join(value.root, 'npm-cli.js');
  await fs.writeFile(cli, '/* controlled npm CLI identity */\n');
  const calls = [], stop = new Error('controlled stop after client install');
  await assert.rejects(actualSetup({ root: value.root, homeDirectory: value.homeDirectory,
    upgrade: true, repair: true, processEnvironment: { npm_execpath: cli },
    execute: async () => ({ stdout: '12.1.0' }),
    runCommand: async (command, args, cwd) => {
      calls.push({ command, args, cwd });
      if (calls.length === 2) throw stop;
    },
    runDatabasePhase: async () => assert.fail('repair must finish dependencies before database phase'),
  }), error => error === stop);
  assert.deepEqual(calls.map(row => row.args), Array(2).fill(null).map(() => [cli, 'ci', '--strict-peer-deps', '--strict-allow-scripts']));
  assert.deepEqual(calls.map(row => row.cwd), [value.root, path.join(value.root, 'client')]);
  assert.deepEqual(await fs.readFile(path.join(value.root, '.env')), value.original);
});
test('Analytics opt-in upgrade preserves existing credentials and disabled preference on repeat and readiness failure',async t=>{
 const plan=provisioningPlan(),value=await upgradeFixture(t,plan),envPath=path.join(value.root,'.env');
 await fs.appendFile(envPath,encodeEnv({SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'}));
 let calls=0;const options={root:value.root,homeDirectory:value.homeDirectory,upgrade:true,ownedAnalytics:true,processEnvironment:{},
  adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:existingDockerAuthority,
  provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision:async()=>({status:'existing',plan,configuration:value.configuration}),
  provisionAuditSql:async()=>({activationEnabled:false,preserved:true}),
  runCommand:async()=>assert.fail('no unrelated initializer or package changes'),
  setupOwnedAnalytics:async args=>{calls++;assert.equal(args.requested,true);assert.equal(args.applicationEnvironment.JWT_SECRET,'unchanged secret');assert.equal(args.applicationEnvironment.SECURESHOP_AGENTS_DATABASE_URL,value.configuration.SECURESHOP_AGENTS_DATABASE_URL);return{requested:true,activationEnabled:false,changed:false};}};
 const first=await setup(options);assert.equal(first.analytics.activationEnabled,false);
 const bytes=await fs.readFile(envPath),reset=await fs.readFile(path.join(value.directory,'secureshop-reset-key.json'));
 await setup({...options,ownedAnalytics:false,enableOwnedAnalytics:true,setupOwnedAnalytics:async args=>{assert.equal(args.requested,true);assert.equal(args.explicitActivation,true);return{requested:true,activationEnabled:true,changed:true};}});
 await setup(options);assert.equal(calls,2);assert.deepEqual(await fs.readFile(envPath),bytes);assert.deepEqual(await fs.readFile(path.join(value.directory,'secureshop-reset-key.json')),reset);
 await assert.rejects(setup({...options,setupOwnedAnalytics:async()=>{throw Object.assign(Error('schema unavailable'),{code:'ANALYTICS_NOT_READY'});}}),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(c=>c.code==='ANALYTICS_NOT_READY'));
 assert.deepEqual(await fs.readFile(envPath),bytes);assert.deepEqual(await fs.readFile(path.join(value.directory,'secureshop-reset-key.json')),reset);
});
test('Analytics opt-in prerequisites fail before provisioning or fresh setup writes',async t=>{
 const root=await temporary(t),homeDirectory=await temporary(t);let touched=false;
 await assert.rejects(setup({root,homeDirectory,ownedAnalytics:true,processEnvironment:{},provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision:async()=>{touched=true;},runCommand:async()=>{touched=true;}}),{code:'ANALYTICS_SETUP_PREREQUISITES'});
 assert.equal(touched,false);assert.deepEqual(await fs.readdir(root),[]);
});
test('additive setup preserves the old environment and initializes all stores including missing suffix stores', async t => {
  const value = await upgradeFixture(t), plan = provisioningPlan();
  const complete = { ...value.configuration, ...configurationFor(plan.slice(-1)) };
  const calls = [];
  const result = await setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin:secret@127.0.0.1:5432/postgres', install: true, ensureModel: true,
    ensureDockerAuthority: existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async options => { calls.push(['provision', options]);return { status: 'upgraded', plan, configuration: complete }; },
    initializeApplication: async ({maintenanceScope}) => { maintenanceScope.assertHeld(); calls.push(['initialize', provisioningPlan().map(row => row.schema), {...process.env}]); },
    runCommand: async () => assert.fail('upgrade must not install packages or run the fresh initializer'),
    loadPuppeteer: () => assert.fail('upgrade must not verify a browser'),
  });
  assert.deepEqual(result.upgradedSchemas, ['secureshop_review']);
  assert.equal(calls[0][0], 'provision');
  assert.equal(calls[0][1].upgrade, true);
  assert.deepEqual(calls[1][1], plan.map(row => row.schema));
  assert.equal(calls[1][2].JWT_SECRET, 'unchanged secret');
  const upgraded = await fs.readFile(path.join(value.root, '.env'));
  assert.equal(upgraded.subarray(0, value.original.length).equals(value.original), true);
  assert.deepEqual(require('dotenv').parse(upgraded), { JWT_SECRET: 'unchanged secret', ...complete, CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf', ...CONTROLLED_UPLOAD_ASSETS,
    SS_PASSWORD_RESET_KEY_PATH: path.join(value.directory, 'secureshop-reset-key.json') });
  assert.equal((await fs.stat(path.join(value.root, '.env'))).mode & 0o777, 0o600);
  await assert.rejects(fs.lstat(path.join(value.directory, 'administrator.json')), { code: 'ENOENT' });
});
test('local SecureShop upgrade activates owned audit and defaults summary only when unset', async t => {
  for (const {preference,activated} of [
    {preference:null,activated:true},
    {preference:'false',activated:true},
    {preference:null,activated:false},
  ]) {
    const plan = provisioningPlan(), value = await upgradeFixture(t, plan);
    const envPath = path.join(value.root, '.env');
    const original = Buffer.concat([value.original, Buffer.from(`SS_ENABLE="true"\n${preference === null ? '' : `SS_AUDIT_SUMMARY_ENABLED="${preference}"\n`}`)]);
    await fs.writeFile(envPath, original, {mode:0o600});
    let provisioned = 0;
    const result = await setup({root:value.root,homeDirectory:value.homeDirectory,upgrade:true,processEnvironment:{},
      adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',
      ensureDockerAuthority:existingDockerAuthority,
      provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),
      provision:async()=>({status:'existing',plan,configuration:value.configuration}),
      initializeApplication:async({maintenanceScope})=>maintenanceScope.assertHeld(),
      provisionAuditSql:async options=>{provisioned++;assert.equal(options.applicationEnvironment.SS_ENABLE,'true');return{provisioned:true,activationEnabled:activated};},
      runCommand:async()=>assert.fail('upgrade must not run fresh setup commands')});
    assert.equal(provisioned,1);
    assert.equal(result.auditSql.activationEnabled,activated);
    const upgraded = await fs.readFile(envPath);
    assert.equal(upgraded.subarray(0,original.length).equals(original),true);
    assert.equal(require('dotenv').parse(upgraded).SS_AUDIT_SUMMARY_ENABLED,
      preference ?? (activated ? 'true' : undefined));
  }
});
test('additive setup preserves a fourteen-store environment while initializing both reviewed suffix stores', async t => {
  const plan = provisioningPlan(), value = await upgradeFixture(t, plan.slice(0, -2));
  const suffix = plan.slice(-2), complete = { ...value.configuration, ...configurationFor(suffix) };
  const calls = [];
  const result = await setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin:secret@127.0.0.1:5432/postgres',
    ensureDockerAuthority: existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async options => { calls.push(['provision', options]);return { status: 'upgraded', plan, configuration: complete }; },
    initializeApplication: async ({maintenanceScope}) => { maintenanceScope.assertHeld(); calls.push(['initialize', provisioningPlan().map(row => row.schema), {...process.env}]); },
  });
  assert.deepEqual(result.upgradedSchemas, ['session_disclosure', 'secureshop_review']);
  assert.deepEqual(calls[1][1], plan.map(row => row.schema));
  assert.equal(calls[1][2].JWT_SECRET, 'unchanged secret');
  const upgraded = await fs.readFile(path.join(value.root, '.env'));
  assert.equal(upgraded.subarray(0, value.original.length).equals(value.original), true);
  assert.deepEqual(require('dotenv').parse(upgraded), { JWT_SECRET: 'unchanged secret', ...complete, CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf', ...CONTROLLED_UPLOAD_ASSETS,
    SS_PASSWORD_RESET_KEY_PATH: path.join(value.directory, 'secureshop-reset-key.json') });
});
test('completed manifest plus old environment safely retries the additive initialization', async t => {
  const plan = provisioningPlan(), value = await upgradeFixture(t, plan);
  const last = plan.at(-1), source = require('dotenv').parse(value.original);
  delete source[last.runtimeVariable];delete source[last.migrationVariable];
  const oldBytes = Buffer.from(`# retained\n${encodeEnv(source)}`);
  await fs.writeFile(path.join(value.root, '.env'), oldBytes, { mode: 0o600 });
  const state = await inspectUpgradeState({ envPath: path.join(value.root, '.env'), manifestPath: value.manifestPath, currentPlan: plan });
  assert.equal(state.envBytes.equals(oldBytes), true);
  let initialized = 0;
  await setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin:secret@127.0.0.1:5432/postgres',
    ensureDockerAuthority: existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => ({ status: 'existing', plan, configuration: value.configuration }),
    initializeApplication: async ({maintenanceScope}) => { initialized += 1; maintenanceScope.assertHeld(); },
  });
  assert.equal(initialized, 1);
  assert.deepEqual(require('dotenv').parse(await fs.readFile(path.join(value.root, '.env'))),
    { JWT_SECRET: 'unchanged secret', ...value.configuration, CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf', ...CONTROLLED_UPLOAD_ASSETS,
      SS_PASSWORD_RESET_KEY_PATH: path.join(value.directory, 'secureshop-reset-key.json') });
});
test('additive setup rejects environment conflicts and ambiguous staging before provisioning', async t => {
  const value = await upgradeFixture(t), plan = provisioningPlan(), last = plan.at(-1);
  await fs.appendFile(path.join(value.root, '.env'), `${last.runtimeVariable}=postgresql://attacker.invalid/db\n`);
  let provisioned = false;
  await assert.rejects(setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin@127.0.0.1/postgres', ensureDockerAuthority: existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => { provisioned = true; } }),
  error => error.code === 'UPGRADE_ENV_CONFLICT');
  assert.equal(provisioned, false);
  await fs.writeFile(path.join(value.root, '.env'), value.original, { mode: 0o600 });
  await fs.writeFile(path.join(value.root, '.env.upgrade'), 'ambiguous', { mode: 0o600 });
  await assert.rejects(setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin@127.0.0.1/postgres', ensureDockerAuthority: existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => { provisioned = true; } }),
  error => error.code === 'UPGRADE_ENV_RECOVERY_REQUIRED');
  assert.equal(provisioned, false);
});
test('initial upgrade refuses a missing credential pair from the prior manifest', async t => {
  const value = await upgradeFixture(t), priorLast = provisioningPlan().at(-2);
  const parsed = require('dotenv').parse(value.original);
  delete parsed[priorLast.runtimeVariable];delete parsed[priorLast.migrationVariable];
  await fs.writeFile(path.join(value.root, '.env'), encodeEnv(parsed), { mode: 0o600 });
  let provisioned = false;
  await assert.rejects(setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin@127.0.0.1/postgres', ensureDockerAuthority: existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => { provisioned = true; } }),
  error => error.code === 'UPGRADE_ENV_MANIFEST_MISMATCH');
  assert.equal(provisioned, false);
});
test('failed additive initialization leaves the original environment retryable', async t => {
  const value = await upgradeFixture(t), plan = provisioningPlan();
  const complete = { ...value.configuration, ...configurationFor(plan.slice(-1)) };
  await assert.rejects(setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin@127.0.0.1/postgres',
    ensureDockerAuthority: existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => ({ status: 'upgraded', plan, configuration: complete }),
    initializeApplication: async () => { throw new Error('fixture migration failure'); },
  }), {code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});
  assert.equal((await fs.readFile(path.join(value.root, '.env'))).equals(value.original), true);
  await assert.rejects(fs.lstat(path.join(value.root, '.env.upgrade')), { code: 'ENOENT' });
});
test('external PostgreSQL upgrade records the selected local sidecar daemon before provisioning', async t => {
  const plan = provisioningPlan(), value = await upgradeFixture(t, plan);
  const calls = [];
  await setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin@127.0.0.1/postgres',
    processEnvironment: { DOCKER_HOST: 'unix:///tmp/docker-desktop-fixture.sock' },
    execute: async (_command, args, options) => {
      calls.push({ args, env: options.env });
      return { stdout: '"daemon-desktop"' };
    },
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => ({ status: 'existing', plan, configuration: value.configuration }),
  });
  const statePath = path.join(value.directory, 'local-docker.json');
  const state = JSON.parse(await fs.readFile(statePath, 'utf8'));
  assert.deepEqual(state, { version: 1, workspaceId: require('../scripts/setup-application').workspaceId(value.root),
    host: 'unix:///tmp/docker-desktop-fixture.sock', daemonId: 'daemon-desktop', source: 'environment-host' });
  assert.equal((await fs.stat(statePath)).mode & 0o777, 0o600);
  assert.deepEqual(calls.map(call => call.args.slice(0, 3)), [
    ['--host', 'unix:///tmp/docker-desktop-fixture.sock', 'info'],
  ]);
  assert.equal(calls[0].env.DOCKER_HOST, undefined);
});
test('externally managed AWS upgrade does not inspect or record local Docker authority', async t => {
  const plan = provisioningPlan(), value = await upgradeFixture(t, plan);
  await setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
    adminUrl: 'postgresql://admin@postgres.internal/postgres', processEnvironment: { TEAM_ID: 'fixture' },
    ensureDockerAuthority: async () => assert.fail('externally managed setup must not bind a local daemon'),
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => ({ status: 'existing', plan, configuration: value.configuration }),
  });
  await assert.rejects(fs.lstat(path.join(value.directory, 'local-docker.json')), { code: 'ENOENT' });
});
test('upgrade honors existing environment sidecar ownership before requiring local Docker', async t => {
  for (const setting of [
    'MCP_SIDECARS_AUTOSTART=false',
    'SANDBOX_RUNNER_URL=https://remote.invalid/localhost/status',
  ]) {
    const plan = provisioningPlan(), value = await upgradeFixture(t, plan);
    await fs.appendFile(path.join(value.root, '.env'), `${setting}\n`);
    await setup({ root: value.root, homeDirectory: value.homeDirectory, upgrade: true,
      adminUrl: 'postgresql://admin@postgres.internal/postgres', processEnvironment: {},
      ensureDockerAuthority: async () => assert.fail('effective existing environment manages sidecars without local Docker'),
      provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => ({ status: 'existing', plan, configuration: value.configuration }),
    });
    await assert.rejects(fs.lstat(path.join(value.directory, 'local-docker.json')), { code: 'ENOENT' });
  }
});
test('additive initializer invokes only explicitly selected configured repositories', async () => {
  const calls = [], row = provisioningPlan().at(-1);
  const before={...process.env};
  const environment={...process.env,IDENTITY_DATABASE_URL:'postgres://runtime@localhost/id',IDENTITY_MIGRATION_DATABASE_URL:'postgres://migration@localhost/id',[row.runtimeVariable]:'runtime',[row.migrationVariable]:'migration'};
  Object.assign(process.env,environment);
  try { await require('../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment,
    acquire:async()=>({assertHeld(){},async beginMaintenance(){return Object.freeze({epoch:"1"});},async finishMaintenance(){},async close(){}}),drain:async()=>{}}, maintenanceScope=>initializeAdditions([row.schema], {environment,maintenanceScope,load:request=>({initializeSecureShopReviewDb:async()=>calls.push(request)})})); }
  finally{for(const key of Object.keys(process.env))if(!(key in before))delete process.env[key];Object.assign(process.env,before);}
  assert.deepEqual(calls, ['../server/database/postgres/secureshopReviewDb']);
  await assert.rejects(initializeAdditions(['identity'], { environment: {} }), { code: 'INVALID_ADDITIVE_SCHEMA' });
});
test('local setup refuses an unowned existing container', async t => {
  const directory = await temporary(t);
  const calls = [];
  await assert.rejects(localPostgres({ directory, id: 'fixture', execute: async (_cmd, args) => {
    calls.push(args);
    if (args[2] === 'info') return { stdout: '"daemon-fixture"' };
    if (args[2] === 'inspect') return { stdout: JSON.stringify([{ Config: { Labels: {} } }]) };
    throw Object.assign(new Error('missing'), { code: 1 });
  }, environment: { DOCKER_HOST: 'unix:///tmp/docker-fixture.sock' } }), /without matching setup ownership/);
  assert.deepEqual(calls.map(args => args[2]), ['info', 'inspect', 'volume']);
  await assert.rejects(fs.lstat(path.join(directory, 'local-docker.json')), { code: 'ENOENT' });
});
test('local setup never mounts an existing volume it does not own', async t => {
  const directory = await temporary(t);
  const calls = [];
  await assert.rejects(localPostgres({ directory, id: 'fixture', execute: async (_cmd, args) => {
    calls.push(args);
    if (args[2] === 'info') return { stdout: '"daemon-fixture"' };
    if (args[2] === 'inspect') throw Object.assign(new Error('missing'), { code: 1 });
    if (args[2] === 'volume') return { stdout: JSON.stringify([{ Labels: {} }]) };
    return { stdout: '' };
  }, environment: { DOCKER_HOST: 'unix:///tmp/docker-fixture.sock' } }), /unowned PostgreSQL volume/);
  assert.equal(calls.some(args => args[2] === 'run'), false);
  await assert.rejects(fs.lstat(path.join(directory, 'local-docker.json')), { code: 'ENOENT' });
});
test('fresh local PostgreSQL retry reuses an existing matching Docker authority', async t => {
  const directory = await temporary(t), id = 'fixture', host = 'unix:///tmp/docker-fixture.sock';
  await writeLocalDockerAuthority({ directory, authority: { version: 1, workspaceId: id, host,
    daemonId: 'daemon-fixture', source: 'environment-host', platform: process.platform } });
  let containerCreated = false;
  const container = {
    Config: { Labels: { 'org.dvaia.workspace': id } }, State: { Running: true },
    Mounts: [{ Type: 'volume', Name: `dvaia-postgres-${id}`, Destination: '/var/lib/postgresql' }],
    HostConfig: { PortBindings: { '5432/tcp': [] } },
    NetworkSettings: { Ports: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: null }] } },
  };
  const result = await localPostgres({ directory, id, environment: { DOCKER_HOST: 'tcp://ignored.invalid:2375' },
    execute: async (_command, args) => {
      if (args[2] === 'info') return { stdout: '"daemon-fixture"' };
      if (args[2] === 'volume' && args[3] === 'inspect') throw Object.assign(new Error('missing'), { code: 1 });
      if (args[2] === 'inspect') {
        if (!containerCreated) throw Object.assign(new Error('missing'), { code: 1 });
        const state = JSON.parse(await fs.readFile(path.join(directory, 'local-postgres.json'), 'utf8'));
        container.HostConfig.PortBindings['5432/tcp'] = [{ HostIp: '127.0.0.1', HostPort: String(state.port) }];
        container.NetworkSettings.Ports['5432/tcp'][0].HostPort = String(state.port);
        return { stdout: JSON.stringify([container]) };
      }
      if (args[2] === 'volume' && args[3] === 'create') return { stdout: `dvaia-postgres-${id}` };
      if (args[2] === 'run') { containerCreated = true;return { stdout: `dvaia-postgres-${id}` }; }
      if (args[2] === 'exec') return { stdout: 'accepting connections' };
      assert.fail(`unexpected Docker call: ${args.join(' ')}`);
    } });
  assert.match(result, /^postgresql:\/\/postgres:[a-f0-9]{64}@127\.0\.0\.1:\d+\/postgres$/);
  assert.equal(JSON.parse(await fs.readFile(path.join(directory, 'local-docker.json'), 'utf8')).daemonId, 'daemon-fixture');
  assert.equal(JSON.parse(await fs.readFile(path.join(directory, 'local-postgres.json'), 'utf8')).version, 2);
});
test('additive local PostgreSQL lookup never creates missing setup state', async t => {
  const directory = await temporary(t);let called = false;
  await assert.rejects(localPostgres({ directory, id: 'fixture', existingOnly: true,
    execute: async () => { called = true; } }), /existing owned PostgreSQL state/);
  assert.equal(called, false);
  assert.deepEqual(await fs.readdir(directory), []);
});
test('legacy local PostgreSQL state adopts an exact owned container and volume before reuse', async t => {
  const directory = await temporary(t), id = 'fixture', name = `dvaia-postgres-${id}`;
  const legacy = { version: 1, id, name, port: 55432, password: 'a'.repeat(64) };
  await fs.writeFile(path.join(directory, 'local-postgres.json'), JSON.stringify(legacy), { mode: 0o600 });
  const container = {
    Config: { Labels: { 'org.dvaia.workspace': id } },
    State: { Running: true },
    Mounts: [{ Type: 'volume', Name: name, Destination: '/var/lib/postgresql' }],
    HostConfig: { PortBindings: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: '55432' }] } },
    NetworkSettings: { Ports: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: '55432' }] } },
  };
  const calls = [];
  const result = await localPostgres({ directory, id, environment: { DOCKER_HOST: 'unix:///tmp/docker-fixture.sock' },
    execute: async (_command, args, options) => {
      calls.push({ args, env: options.env });
      if (args[2] === 'info') return { stdout: '"daemon-fixture"' };
      if (args[2] === 'volume') return { stdout: JSON.stringify([{ Labels: { 'org.dvaia.workspace': id } }]) };
      if (args[2] === 'inspect') return { stdout: JSON.stringify([container]) };
      if (args[2] === 'exec') return { stdout: 'accepting connections' };
      assert.fail(`unexpected Docker call: ${args.join(' ')}`);
    } });
  assert.equal(result, `postgresql://postgres:${legacy.password}@127.0.0.1:55432/postgres`);
  const upgraded = JSON.parse(await fs.readFile(path.join(directory, 'local-postgres.json'), 'utf8'));
  const authority = JSON.parse(await fs.readFile(path.join(directory, 'local-docker.json'), 'utf8'));
  assert.equal(upgraded.version, 2);
  assert.match(upgraded.dockerAuthorityDigest, /^[a-f0-9]{64}$/);
  assert.equal(authority.daemonId, 'daemon-fixture');
  assert.equal(calls.some(call => ['start', 'run', 'create'].includes(call.args[2])), false);
  assert.ok(calls.every(call => call.args[0] === '--host' && call.args[1] === authority.host));
  assert.ok(calls.every(call => call.env.DOCKER_HOST === undefined && call.env.DOCKER_CONTEXT === undefined));
});
test('legacy local PostgreSQL state preserves an owned volume when recreating its missing container', async t => {
  const directory = await temporary(t), id = 'fixture', name = `dvaia-postgres-${id}`;
  const legacy = { version: 1, id, name, port: 55432, password: 'd'.repeat(64) };
  await fs.writeFile(path.join(directory, 'local-postgres.json'), JSON.stringify(legacy), { mode: 0o600 });
  let containerCreated = false;
  const calls = [];
  const container = {
    Config: { Labels: { 'org.dvaia.workspace': id } }, State: { Running: true },
    Mounts: [{ Type: 'volume', Name: name, Destination: '/var/lib/postgresql' }],
    HostConfig: { PortBindings: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: '55432' }] } },
    NetworkSettings: { Ports: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: '55432' }] } },
  };
  await localPostgres({ directory, id, existingOnly: true,
    environment: { DOCKER_HOST: 'unix:///tmp/docker-fixture.sock' },
    execute: async (_command, args) => {
      calls.push(args);
      if (args[2] === 'info') return { stdout: '"daemon-fixture"' };
      if (args[2] === 'volume') return { stdout: JSON.stringify([{ Labels: { 'org.dvaia.workspace': id } }]) };
      if (args[2] === 'inspect') {
        if (!containerCreated) throw Object.assign(new Error('missing'), { code: 1 });
        return { stdout: JSON.stringify([container]) };
      }
      if (args[2] === 'run') { containerCreated = true;return { stdout: name }; }
      if (args[2] === 'exec') return { stdout: 'accepting connections' };
      assert.fail(`unexpected Docker call: ${args.join(' ')}`);
    } });
  assert.equal(containerCreated, true);
  assert.equal(calls.some(args => args[2] === 'volume' && args[3] === 'create'), false);
  assert.equal(JSON.parse(await fs.readFile(path.join(directory, 'local-postgres.json'), 'utf8')).version, 2);
});
test('legacy local PostgreSQL state without an owned volume is not adopted or mutated', async t => {
  const directory = await temporary(t), id = 'fixture', name = `dvaia-postgres-${id}`;
  const legacyBytes = Buffer.from(JSON.stringify({ version: 1, id, name, port: 55432, password: 'b'.repeat(64) }));
  await fs.writeFile(path.join(directory, 'local-postgres.json'), legacyBytes, { mode: 0o600 });
  const calls = [];
  await assert.rejects(localPostgres({ directory, id, environment: { DOCKER_HOST: 'unix:///tmp/docker-fixture.sock' },
    execute: async (_command, args) => {
      calls.push(args);
      if (args[2] === 'info') return { stdout: '"daemon-fixture"' };
      throw Object.assign(new Error('missing'), { code: 1 });
    } }), /no owned persistent volume/);
  assert.equal((await fs.readFile(path.join(directory, 'local-postgres.json'))).equals(legacyBytes), true);
  await assert.rejects(fs.lstat(path.join(directory, 'local-docker.json')), { code: 'ENOENT' });
  assert.equal(calls.some(args => ['start', 'run', 'create'].includes(args[2])), false);
});
test('legacy authority adoption rejects an owned container with a mismatched mount', async t => {
  const directory = await temporary(t), id = 'fixture', name = `dvaia-postgres-${id}`;
  const legacyBytes = Buffer.from(JSON.stringify({ version: 1, id, name, port: 55432, password: 'c'.repeat(64) }));
  await fs.writeFile(path.join(directory, 'local-postgres.json'), legacyBytes, { mode: 0o600 });
  const container = {
    Config: { Labels: { 'org.dvaia.workspace': id } }, State: { Running: false },
    Mounts: [{ Type: 'volume', Name: 'another-volume', Destination: '/var/lib/postgresql' }],
    HostConfig: { PortBindings: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: '55432' }] } },
  };
  await assert.rejects(localPostgres({ directory, id, environment: { DOCKER_HOST: 'unix:///tmp/docker-fixture.sock' },
    execute: async (_command, args) => {
      if (args[2] === 'info') return { stdout: '"daemon-fixture"' };
      if (args[2] === 'inspect') return { stdout: JSON.stringify([container]) };
      if (args[2] === 'volume') return { stdout: JSON.stringify([{ Labels: { 'org.dvaia.workspace': id } }]) };
      assert.fail('no mutating Docker command is allowed');
    } }), /does not match the owned PostgreSQL state/);
  assert.equal((await fs.readFile(path.join(directory, 'local-postgres.json'))).equals(legacyBytes), true);
  await assert.rejects(fs.lstat(path.join(directory, 'local-docker.json')), { code: 'ENOENT' });
});
test('required framework, agent-host, LangChain, LangGraph, and PostgreSQL versions resolve from the application install', async t => {
  const root = await temporary(t);
  assert.equal(REQUIRED_INSTALLED_COMPONENTS.includes('@langchain/ollama'), true,
    'setup readiness must include the local Ollama LangChain adapter');
  assert.equal(REQUIRED_INSTALLED_COMPONENTS.includes('express'), true);
  assert.equal(REQUIRED_INSTALLED_COMPONENTS.includes('jsonwebtoken'), true);
  assert.equal(REQUIRED_INSTALLED_COMPONENTS.includes('@modelcontextprotocol/sdk'), true);
  assert.equal(REQUIRED_INSTALLED_COMPONENTS.includes('multer'), true);
  assert.equal(REQUIRED_INSTALLED_COMPONENTS.includes('xml2js'), true);
  assert.equal(REQUIRED_INSTALLED_COMPONENTS.includes('sax'), true);
  assert.equal(REQUIRED_INSTALLED_COMPONENTS.includes('zod'), true);
  const dependencies = await writeInstalledComponentFixture(root);
  assert.deepEqual(await verifyInstalledComponents(root), dependencies);
  const ollamaAdapter = path.join(root, 'node_modules', '@langchain', 'ollama');
  await fs.rm(ollamaAdapter, { recursive: true });
  await assert.rejects(verifyInstalledComponents(root), /Required component @langchain\/ollama@.* is not installed/);
  await fs.mkdir(ollamaAdapter, { recursive: true });
  await fs.writeFile(path.join(ollamaAdapter, 'package.json'), JSON.stringify({
    name: '@langchain/ollama', version: dependencies['@langchain/ollama'], main: 'index.js',
  }));
  await fs.writeFile(path.join(ollamaAdapter, 'index.js'), 'module.exports = {}\n');
  const mismatch = path.join(root, 'node_modules', 'langchain', 'package.json');
  await fs.writeFile(mismatch, JSON.stringify({ name: 'langchain', version: '9.9.9', main: 'index.js' }));
  await assert.rejects(verifyInstalledComponents(root), /expected 1\.2\.0/);
});
test('detached SecureShop authentication dependencies resolve and load from the application install', async () => {
  const root = path.resolve(__dirname, '..');
  const manifest = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  const installed = await verifyInstalledComponents(root);
  assert.equal(installed.bcryptjs, manifest.dependencies.bcryptjs);
  assert.equal(installed['express-rate-limit'], manifest.dependencies['express-rate-limit']);
  assert.equal(installed.express, manifest.dependencies.express);
  assert.equal(installed.jsonwebtoken, manifest.dependencies.jsonwebtoken);
  assert.equal(installed['@modelcontextprotocol/sdk'], manifest.dependencies['@modelcontextprotocol/sdk']);
  assert.equal(installed.zod, manifest.dependencies.zod);
  assert.equal(typeof require('bcryptjs').hash, 'function');
  assert.equal(typeof require('express-rate-limit').rateLimit, 'function');
  assert.equal(typeof require('express'), 'function');
  assert.equal(typeof require('jsonwebtoken').verify, 'function');
  assert.equal(typeof require('@modelcontextprotocol/sdk/server/index.js').Server, 'function');
  assert.equal(typeof require('zod').object, 'function');
});
test('Ollama setup leaves an installed 8B model unchanged', async () => {
  const calls = [];let request;
  const result = await ensureOllamaModel({
    execute: async (command, args) => { calls.push([command, ...args]); },
    runCommand: async () => assert.fail('pull must not run'),
    requestGeneration: async options => { request = options;return { model: options.model, response: 'READY', done: true }; },
  });
  assert.deepEqual(result, { model: 'llama3.1:8b', alreadyInstalled: true, pulled: false });
  assert.deepEqual(calls, [['ollama', 'show', 'llama3.1:8b']]);
  assert.deepEqual(request, { model: 'llama3.1:8b', endpoint: OLLAMA_SETUP_GENERATE_URL,
    timeoutMs: OLLAMA_SETUP_INFERENCE_TIMEOUT_MS });
});
test('Ollama setup pulls and re-verifies the exact 8B model when missing', async () => {
  const calls = [];let shows = 0;
  const result = await ensureOllamaModel({
    env: { OLLAMA_HOST: 'https://remote.invalid' },
    execute: async (command, args, options) => { calls.push([command, ...args, options.env.OLLAMA_HOST, options.timeout]);if(shows++ === 0)throw Object.assign(new Error('missing model'),{code:1}); },
    runCommand: async (command, args, _root, env, options) => { calls.push([command, ...args, env.OLLAMA_HOST, options.timeoutMs]); },
    requestGeneration: async options => { calls.push(['generate', options.endpoint, options.model, options.timeoutMs]);return { model: options.model, response: 'READY', done: true }; },
  });
  assert.deepEqual(result, { model: 'llama3.1:8b', alreadyInstalled: false, pulled: true });
  assert.deepEqual(calls, [
    ['ollama', 'show', 'llama3.1:8b', 'http://127.0.0.1:11434', 15_000],
    ['ollama', 'pull', 'llama3.1:8b', 'http://127.0.0.1:11434', 60 * 60 * 1000],
    ['ollama', 'show', 'llama3.1:8b', 'http://127.0.0.1:11434', 15_000],
    ['generate', OLLAMA_SETUP_GENERATE_URL, 'llama3.1:8b', OLLAMA_SETUP_INFERENCE_TIMEOUT_MS],
  ]);
});
test('Ollama setup reports missing binary and service failures without attempting another model', async () => {
  let pulled = false;
  await assert.rejects(ensureOllamaModel({
    execute: async () => { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); },
    runCommand: async () => { pulled = true; },
  }), /Ollama is required/);
  assert.equal(pulled, false);
  await assert.rejects(ensureOllamaModel({
    execute: async () => { throw Object.assign(new Error('not ready'), { code: 1 }); },
    runCommand: async () => { throw new Error('daemon unavailable'); },
  }), /service is running/);
  await assert.rejects(ensureOllamaModel({ model: 'another-model' }), /requires the qualified llama3\.1:8b/);
});
test('Ollama setup distinguishes unavailable, timed-out, and invalid inference', async () => {
  const fixture = requestGeneration => ensureOllamaModel({
    execute: async () => {},
    runCommand: async () => assert.fail('an installed model must not be downloaded again'),
    requestGeneration,
  });
  await assert.rejects(fixture(async () => { throw Object.assign(new Error('late'), { code: 'ETIMEDOUT' }); }),
    /inference timed out.*enough memory/);
  await assert.rejects(fixture(async () => { throw Object.assign(new Error('offline'), { code: 'ECONNREFUSED' }); }),
    /became unavailable.*Restart the local Ollama service/);
  await assert.rejects(fixture(async () => { throw Object.assign(new Error('bad status'), { code: 'OLLAMA_HTTP_ERROR' }); }),
    /inference failed.*service logs/);
  await assert.rejects(fixture(async () => ({ model: 'llama3.1:8b', response: '   ', done: true })),
    /no completed output.*available memory/);
  await assert.rejects(fixture(async () => ({ model: 'another-model', response: 'READY', done: true })),
    /wrong model identity; expected llama3\.1:8b/);
});
test('failed real-model readiness stops fresh setup before database provisioning', async t => {
  const root = await temporary(t), homeDirectory = await temporary(t);
  await writeInstalledComponentFixture(root);
  let provisioned = false;
  await assert.rejects(setup({
    root,
    homeDirectory,
    install: false,
    adminUrl: 'postgresql://unused.invalid/postgres',
    processEnvironment: {},
    execute: async (command, args) => {
      assert.deepEqual([command, ...args], ['ollama', 'show', 'llama3.1:8b']);
    },
    runCommand: async (command, args) => {
      assert.equal(command,'npm');assert.equal(args[0],'run');assert(['build:review-renderer','build:mail-renderer','build:product-description-renderer','build:ticket-renderer','build:search-echo-renderer','build:policy-output-renderer'].includes(args[1]));
    },
    loadTicketRenderer: () => ({ component: { id: 'SecureShop.AdminTicketBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadSearchEchoRenderer: () => ({ component: { id: 'SecureShop.SearchEcho', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadPolicyOutputRenderer: () => ({ component: { id: 'SecureShop.PolicyFinalResponse', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), renderProductDescription: async product => `<div>${product.description_html}</div>` }), loadMailRenderer: () => ({ component: { id: 'SecureShop.MailMessageBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadRenderer: () => ({ sourceSha256: 'source', artifactSha256: 'artifact',
      renderReviewCard: async ({ body }) => `<article>${body}</article>` }),
    requestGeneration: async options => {
      assert.equal(options.endpoint, 'http://127.0.0.1:11434/api/generate');
      throw Object.assign(new Error('fixture timeout'), { code: 'ETIMEDOUT' });
    },
    loadPuppeteer: () => assert.fail('browser verification must follow model readiness'),
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => { provisioned = true;assert.fail('database provisioning must not run'); },
  }), /inference timed out/);
  assert.equal(provisioned, false);
});
test('browser readiness launches and closes with sandbox enabled and persists a supplied executable path', async t => {
  const root = await temporary(t), executablePath = process.execPath;
  const launches = [];let closed = 0;
  const result = await verifyBrowserRuntime({
    root, executablePath,
    loadPuppeteer: () => ({ launch: async options => { launches.push(options);return { close: async () => { closed += 1; } }; } }),
  });
  assert.deepEqual(launches, [{ headless: true, timeout: 30_000, executablePath }]);
  assert.equal(Object.hasOwn(launches[0], 'args'), false);
  assert.equal(closed, 1);
  assert.deepEqual(result, { ready: true, configuredExecutablePath: executablePath, sandboxDisabled: false });
});
test('browser readiness fails clearly and closes a malformed browser handle', async () => {
  await assert.rejects(verifyBrowserRuntime({
    loadPuppeteer: () => ({ launch: async () => { throw new Error('sandbox unavailable'); } }),
  }), /sandboxed browser/);
  await assert.rejects(verifyBrowserRuntime({ executablePath: 'relative/chromium', loadPuppeteer: () => ({}) }), /absolute executable path/);
});
test('supported setup provisions a missing Puppeteer browser through the installed CLI and system trust', async t => {
  const root = await temporary(t), modules = path.join(root, 'node_modules');
  const cli = path.join(modules, '.bin', 'puppeteer');
  const missingBrowser = path.join(root, 'cache', 'chrome');
  let installed = false;
  await fs.mkdir(path.dirname(cli), { recursive: true });
  await fs.writeFile(cli, '#!/usr/bin/env node\n', { mode: 0o700 });
  const calls = [];
  const result = await ensurePuppeteerBrowserInstalled({
    root, env: { PATH: process.env.PATH },
    loadPuppeteer: () => ({ executablePath: async () => installed ? process.execPath : missingBrowser }),
    runCommand: async (command, args, cwd, env, options) => {
      calls.push({ command, args, cwd, env, options });
      installed = true;
    },
  });
  assert.deepEqual(result, { ready: true, downloaded: true, configuredExecutablePath: null });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, process.execPath);
  assert.deepEqual(calls[0].args, ['--use-system-ca', await fs.realpath(cli), 'browsers', 'install', 'chrome']);
  assert.equal(calls[0].cwd, root);
  assert.equal(calls[0].options.timeoutMs, 600_000);
});
test('browser provisioning respects an explicit system browser and rejects an unbound skip-download setting', async t => {
  const root = await temporary(t), browser = path.join(root, 'chromium');
  const explicit = await ensurePuppeteerBrowserInstalled({
    root, env: { PUPPETEER_EXECUTABLE_PATH: browser },
    loadPuppeteer: () => assert.fail('explicit system browser must not load the bundled browser'),
    runCommand: async () => assert.fail('explicit system browser must not download'),
  });
  assert.deepEqual(explicit, { ready: true, downloaded: false, configuredExecutablePath: browser });
  await assert.rejects(ensurePuppeteerBrowserInstalled({
    root, env: { PUPPETEER_SKIP_DOWNLOAD: 'true' },
    loadPuppeteer: () => assert.fail('unbound skip must fail before loading Puppeteer'),
  }), /requires an explicit PUPPETEER_EXECUTABLE_PATH/);
});
test('fresh setup seeds generated files after databases and publishes an explicitly enabled owned policy renderer', async t => {
  const root = await temporary(t), homeDirectory = await temporary(t);
  const preservedAssets={...CONTROLLED_UPLOAD_ASSETS,SS_UPLOAD_ASSET_PORT:'49161',SS_UPLOAD_ASSET_PUBLIC_ORIGIN:'http://[::1]:49161'};
  await writeInstalledComponentFixture(root);
  const fixtureRoot = path.join(homeDirectory, 'teaching-files'), commands = [];
  const postgres = require('../server/database/postgres');
  const bootstrap = require('../db/postgres/bootstrap-admin');
  const originalPool = postgres.createPool, originalBootstrap = bootstrap.bootstrapAdmin;
  let closed = false;
  postgres.createPool = () => ({ end: async () => { closed = true; } });
  bootstrap.bootstrapAdmin = async ({pool, ...credentials}) => { assert.ok(pool);assert.deepEqual(credentials,{username:'admin',email:'admin@dvaia.local',password:'admin123',initialTrainingProfile:true});commands.push({ args: ['controlled-bootstrap'] }); };
  try {
    const result = await setup({ root, homeDirectory, install: false, ensureModel: false, ownedMcpRegistry:true,
      ownedPolicyRenderer:true,enableOwnedPolicyRenderer:true,
      provisionOwnedPolicyRenderer:async args=>{assert.deepEqual(Object.keys(args).sort(),['activate','architecture','environment','home','platform','root']);assert.equal(args.root,await fs.realpath(root));assert.equal(args.home,homeDirectory);assert.equal(args.platform,process.platform);assert.equal(args.architecture,process.arch);assert.equal(args.activate,true);assert.deepEqual(args.environment,{ LEGACY_SENSITIVE_FILES_ROOT: fixtureRoot, MCP_SIDECARS_AUTOSTART: 'false', MCP_WORKSHOP_AUTOSTART: 'false', IPI_EMAIL_PROVIDER: 'gmail', GMAIL_USER: 'installer@example.test', GMAIL_APP_PASSWORD: 'synthetic-app-password', ...preservedAssets });await assert.rejects(fs.stat(path.join(root,'.env')),{code:'ENOENT'});return{ready:true,enabled:true,baseUrl:'http://127.0.0.1:8098'};},
      setupOwnedMcpRegistry:async args=>{assert(commands.some(row=>row.args[0]==='controlled-scoped-initializer'));await assert.rejects(fs.stat(path.join(root,'.env')),{code:'ENOENT'});assert.equal(args.requested,true);assert.equal(args.explicitActivation,false);return{requested:true,activationEnabled:false};},
      preflightOwnedMcpRegistryArchitecture:async()=>({architecture:'arm64',dockerHost:'unix:///var/run/docker.sock'}),
      adminUrl: 'postgresql://controlled.invalid/postgres',
      processEnvironment: { LEGACY_SENSITIVE_FILES_ROOT: fixtureRoot, MCP_SIDECARS_AUTOSTART: 'false', MCP_WORKSHOP_AUTOSTART: 'false', IPI_EMAIL_PROVIDER: 'gmail', GMAIL_USER: 'installer@example.test', GMAIL_APP_PASSWORD: 'synthetic-app-password', ...preservedAssets },
      ensureDockerAuthority: async args => { assert.equal(args.persist,false);return{authority:{host:'unix:///var/run/docker.sock'}}; },
      loadTicketRenderer: () => ({ component: { id: 'SecureShop.AdminTicketBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadSearchEchoRenderer: () => ({ component: { id: 'SecureShop.SearchEcho', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadPolicyOutputRenderer: () => ({ component: { id: 'SecureShop.PolicyFinalResponse', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), renderProductDescription: async product => `<div>${product.description_html}</div>` }), loadMailRenderer: () => ({ component: { id: 'SecureShop.MailMessageBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadRenderer: () => ({ sourceSha256: 'source', artifactSha256: 'artifact', renderReviewCard: async ({ body }) => `<article>${body}</article>` }),
      loadPuppeteer: () => ({ launch: async () => ({ close: async () => {} }) }),
      provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => ({ configuration: { IDENTITY_DATABASE_URL: 'postgresql://controlled.invalid/identity', IDENTITY_MIGRATION_DATABASE_URL: 'postgresql://controlled.invalid/identity' } }),
      provisionOwnedRunner: async () => ({ available: false }),
      runCommand: async (_command, args, _cwd, env) => { commands.push({ args, env }); },
    });
    const database = commands.findIndex(row => row.args[0] === 'controlled-scoped-initializer');
    const echoBuild = commands.findIndex(row => row.args.includes('build:search-echo-renderer'));
    assert.ok(echoBuild >= 0 && echoBuild < database, 'search echo artifact precedes fresh database work');
    const ticketBuild = commands.findIndex(row => row.args.includes('build:ticket-renderer'));
    assert.ok(ticketBuild >= 0 && ticketBuild < database, 'ticket artifact must be prepared before fresh database work');
    const seed = commands.findIndex(row => row.args[0] === 'server/database/sensitiveInfoFiles.js');
    assert.ok(database >= 0 && seed > database);
    assert.deepEqual(commands[seed].args, ['server/database/sensitiveInfoFiles.js', '--initialize-missing']);
    assert.equal(commands[database].env.LEGACY_SENSITIVE_FILES_ROOT, fixtureRoot);
    assert.equal(commands[seed].env.LEGACY_SENSITIVE_FILES_ROOT, fixtureRoot);
    const persisted = require('dotenv').parse(await fs.readFile(path.join(root, '.env'), 'utf8'));
    assert.equal(persisted.LEGACY_SENSITIVE_FILES_ROOT, fixtureRoot);
    assert.equal(persisted.SS_BOUND_PROMPT_POLICIES_ENABLED,'true');
    assert.equal(persisted.SS_POLICY_RENDERER_BASE_URL,'http://127.0.0.1:8098');
    assert.equal(persisted.GMAIL_USER, 'installer@example.test');
    assert.equal(persisted.GMAIL_APP_PASSWORD, 'synthetic-app-password');
    for(const [key,value] of Object.entries(preservedAssets))assert.equal(persisted[key],value);
    assert.equal(closed, true);
    assert.deepEqual(result.policyRenderer,{requested:true,ready:true,enabled:true});
    assert.deepEqual(result.ownedRunner, { available: false, activationEnabled: false, profile: null,
      managedPath: path.join(homeDirectory, '.dvaia', require('../scripts/setup-application').workspaceId(await fs.realpath(root)), 'mcp-owned.env'),
      code: 'MCP_INSTALL_EXPLICITLY_DISABLED', stage: null });
  } finally { postgres.createPool = originalPool;bootstrap.bootstrapAdmin = originalBootstrap; }
});
test('fresh setup cannot succeed when its required owned runner is unavailable', async t => {
  const root = await temporary(t), homeDirectory = await temporary(t);
  await writeInstalledComponentFixture(root);
  const postgres = require('../server/database/postgres');
  const bootstrap = require('../db/postgres/bootstrap-admin');
  const originalPool = postgres.createPool, originalBootstrap = bootstrap.bootstrapAdmin;
  postgres.createPool = () => ({ end: async () => {} });
  bootstrap.bootstrapAdmin = async () => {};
  try {
    await assert.rejects(setup({
      root, homeDirectory, install: false, ensureModel: false,
      adminUrl: 'postgresql://controlled.invalid/postgres',
      processEnvironment: { IPI_EMAIL_PROVIDER: 'gmail', MCP_WORKSHOP_AUTOSTART: 'false' },
      ensureDockerAuthority: async () => ({ persisted: true }),
      loadTicketRenderer: () => ({ component: { id: 'SecureShop.AdminTicketBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadSearchEchoRenderer: () => ({ component: { id: 'SecureShop.SearchEcho', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadPolicyOutputRenderer: () => ({ component: { id: 'SecureShop.PolicyFinalResponse', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), renderProductDescription: async product => `<div>${product.description_html}</div>` }), loadMailRenderer: () => ({ component: { id: 'SecureShop.MailMessageBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadRenderer: () => ({ sourceSha256: 'source', artifactSha256: 'artifact',
        renderReviewCard: async ({ body }) => `<article>${body}</article>` }),
      loadPuppeteer: () => ({ launch: async () => ({ close: async () => {} }) }),
      provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => ({ configuration: {
        IDENTITY_DATABASE_URL: 'postgresql://controlled.invalid/identity',
        IDENTITY_MIGRATION_DATABASE_URL: 'postgresql://controlled.invalid/identity',
      } }),
      provisionOwnedRunner: async () => { throw Object.assign(new Error('controlled readiness failure'), {
        code: 'MCP_INSTALL_READINESS_FAILED', stage: 'owned-readiness',
      }); },
      runCommand: async () => {},
    }), error => error.code === 'APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&error.errors.some(c=>c.code==='MCP_INSTALL_REQUIRED_UNAVAILABLE'));
    const envPath = path.join(root, '.env');
    await assert.rejects(fs.stat(envPath), {code:'ENOENT'});
    assert.equal((await fs.stat(path.join(homeDirectory,'.dvaia',require('../scripts/setup-application').workspaceId(await fs.realpath(root)),'administrator.json'))).mode & 0o777, 0o600);
  } finally { postgres.createPool = originalPool;bootstrap.bootstrapAdmin = originalBootstrap; }
});
test('fresh supported setup requires HTTP after CLI and preserves configuration on HTTP failure', async t => {
  const postgres = require('../server/database/postgres');
  const bootstrap = require('../db/postgres/bootstrap-admin');
  const originalPool = postgres.createPool, originalBootstrap = bootstrap.bootstrapAdmin;
  postgres.createPool = () => ({ end: async () => {} }); bootstrap.bootstrapAdmin = async () => {};
  try {
    for (const failure of ['none', 'http', 'shadow', 'audit']) {
      const failHttp = failure === 'http';
      const root = await temporary(t), homeDirectory = await temporary(t), order = [];
      await writeInstalledComponentFixture(root);
      const options = { root, homeDirectory, install: false, ensureModel: false, platform: 'darwin',
        adminUrl: 'postgresql://controlled.invalid/postgres',
        processEnvironment: { IPI_EMAIL_PROVIDER: 'gmail', DVAIA_MCP_OWNED_COLIMA_PROFILE: 'colima-controlled', SS_BOUND_UPLOAD_ASSETS_ENABLED:'false' },
        ensureDockerAuthority: async () => ({}),
        loadTicketRenderer: () => ({ component: { id: 'SecureShop.AdminTicketBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
        loadSearchEchoRenderer: () => ({ component: { id: 'SecureShop.SearchEcho', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
        loadPolicyOutputRenderer: () => ({ component: { id: 'SecureShop.PolicyFinalResponse', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
    loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), renderProductDescription: async product => `<div>${product.description_html}</div>` }), loadMailRenderer: () => ({ component: { id: 'SecureShop.MailMessageBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadRenderer: () => ({ sourceSha256: 'source', artifactSha256: 'artifact', renderReviewCard: async ({ body }) => `<article>${body}</article>` }),
        loadPuppeteer: () => ({ launch: async () => ({ close: async () => {} }) }),
        provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision: async () => ({ configuration: { IDENTITY_DATABASE_URL: 'postgresql://controlled.invalid/identity', IDENTITY_MIGRATION_DATABASE_URL: 'postgresql://controlled.invalid/identity' } }),
        runCommand: async (_command, args) => { if (args[0] === 'controlled-scoped-initializer') order.push('schema'); },
        provisionOwnedRunner: async ({ managedPath }) => { order.push('cli'); return { ok: true, profile: 'dvaia-mcp-sandbox', activationEnabled: true, managedPath }; },
        provisionOwnedShadow: async () => { order.push('shadow'); if(failure==='shadow')throw Error('controlled shadow prerequisite failure');return {available:true,activationEnabled:true}; },
        provisionAuditSql: async () => { order.push('audit-sql'); if (failure === 'audit') throw Error('controlled audit prerequisite failure'); return { candidateOnly: true }; },
        provisionOwnedHttp: async ({ applicationEnvironment }) => { order.push('http'); assert.equal(applicationEnvironment.DVAIA_MCP_OWNED_COLIMA_PROFILE, 'colima-controlled');
          if (failHttp) throw Error('controlled service unavailable'); return { available: true, activationEnabled: true }; },
      };
      if (failHttp) await assert.rejects(setup(options), e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(c=>c.code==='MCP_HTTP_SETUP_REQUIRED'));
      else if (failure === 'shadow') await assert.rejects(setup(options), e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(c=>c.code==='MCP_SHADOW_SETUP_REQUIRED'));
      else if (failure === 'audit') await assert.rejects(setup(options), e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(c=>c.code==='AUDIT_SQL_SETUP_REQUIRED'));
      else { const configured = await setup(options); assert.equal(configured.ownedHttp.activationEnabled, true); assert.equal(configured.auditSql.activationEnabled, false); }
      assert.deepEqual(order, failHttp ? ['schema', 'cli', 'http'] : failure==='shadow'?['schema','cli','http','shadow']:['schema', 'cli', 'http', 'shadow', 'audit-sql']); if(failure==='none'){const saved=require('dotenv').parse(await fs.readFile(path.join(root, '.env')));assert.equal(saved.DVAIA_MCP_OWNED_COLIMA_PROFILE,'colima-controlled');assert.equal(saved.SS_BOUND_UPLOAD_ASSETS_ENABLED,'false');assert.equal(Object.hasOwn(saved,'SS_UPLOAD_ASSET_CAPABILITY_SECRET'),false);}else await assert.rejects(fs.stat(path.join(root,'.env')),{code:'ENOENT'});
    }
  } finally { postgres.createPool = originalPool; bootstrap.bootstrapAdmin = originalBootstrap; }
});
test('coupon opt-in setup automatically prepares Analytics before schema activation and preserves private environment',async t=>{
 const plan=provisioningPlan(),value=await upgradeFixture(t,plan),envPath=path.join(value.root,'.env');
 await fs.appendFile(envPath,encodeEnv({SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'}));
 const calls=[],options={root:value.root,homeDirectory:value.homeDirectory,upgrade:true,ownedCoupons:true,processEnvironment:{},adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:existingDockerAuthority,provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision:async()=>({status:'existing',plan,configuration:value.configuration}),provisionAuditSql:async()=>({activationEnabled:false,preserved:true}),runCommand:async()=>assert.fail('unrelated setup command'),setupOwnedAnalytics:async args=>{calls.push('analytics');assert.equal(args.explicitActivation,false);return{requested:true,activationEnabled:true};},setupOwnedCoupons:async args=>{calls.push('coupons');assert.equal(args.applicationEnvironment.SECURESHOP_REVIEW_MIGRATION_DATABASE_URL,value.configuration.SECURESHOP_REVIEW_MIGRATION_DATABASE_URL);return{requested:true,activationEnabled:true};}};
 const first=await setup(options);assert.equal(first.coupons.activationEnabled,true);assert.deepEqual(calls,['analytics','coupons']);const bytes=await fs.readFile(envPath);await setup(options);assert.deepEqual(await fs.readFile(envPath),bytes);
 await assert.rejects(setup({...options,setupOwnedCoupons:async()=>{throw Object.assign(Error('coupon unavailable'),{code:'COUPON_SCHEMA_UNAVAILABLE'});}}),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(c=>c.code==='COUPON_SCHEMA_UNAVAILABLE'));assert.deepEqual(await fs.readFile(envPath),bytes);
});
test('qualified SecureShop defaults coupons only when private preferences permit it',()=>{
 const select=require('../scripts/setup-application').selectOwnedCouponBundle;
 const base={upgrade:true,qualifiedSecureShop:false,boundReviewsEnabled:true,couponPreference:null,
  analyticsPreference:null,ownedCoupons:false,ownedAnalytics:false,enableOwnedAnalytics:false};
 assert.deepEqual(select(base),{ownedCoupons:true,ownedAnalytics:true});
 assert.deepEqual(select({...base,upgrade:false,qualifiedSecureShop:true,boundReviewsEnabled:false}),
  {ownedCoupons:true,ownedAnalytics:true});
 assert.deepEqual(select({...base,upgrade:false,qualifiedSecureShop:true,boundReviewsEnabled:false,
  couponPreference:false}),{ownedCoupons:false,ownedAnalytics:false});
 assert.deepEqual(select({...base,boundReviewsEnabled:false}),{ownedCoupons:false,ownedAnalytics:false});
 assert.deepEqual(select({...base,couponPreference:false}),{ownedCoupons:false,ownedAnalytics:false});
 assert.deepEqual(select({...base,analyticsPreference:false}),{ownedCoupons:false,ownedAnalytics:true});
 assert.deepEqual(select({...base,couponPreference:false,analyticsPreference:true}),
  {ownedCoupons:false,ownedAnalytics:true});
 assert.deepEqual(select({...base,analyticsPreference:false,ownedCoupons:true}),
  {ownedCoupons:true,ownedAnalytics:true});
});

test('explicit owned-runner autostart opt-out never invokes even an injected provisioner', async t => {
  const directory=await temporary(t); let calls=0;
  const value=await provisionOwnedRunnerForSetup({directory,environment:{MCP_SIDECARS_AUTOSTART:'false'},provisionFromEnvironment:async()=>{calls++;throw Error('must not run');}});
  assert.equal(calls,0);assert.equal(value.code,'MCP_INSTALL_EXPLICITLY_DISABLED');assert.equal(value.activationEnabled,false);
});
test('CTF delivery extension preserves existing private TLS policy on upgrade',async t=>{
 const plan=provisioningPlan(),value=await upgradeFixture(t,plan);
 await fs.appendFile(path.join(value.root,'.env'),'\nPG_TLS=require\n');
 let observed;
 await setup({root:value.root,homeDirectory:value.homeDirectory,upgrade:true,processEnvironment:{},adminUrl:'postgresql://admin:synthetic@remote.example/postgres',ensureDockerAuthority:existingDockerAuthority,
  provision:async()=>({status:'existing',plan,configuration:value.configuration}),
  provisionDelivery:async options=>{observed=options.env.PG_TLS;return{configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@remote.example/dvaia_ctf'}};},
  runCommand:async()=>assert.fail('no store initialization')});
 assert.equal(observed,'require');assert.equal(require('dotenv').parse(await fs.readFile(path.join(value.root,'.env'))).PG_TLS,'require');
});

test('CTF activation failure prevents additive private environment publication',async t=>{
 const plan=provisioningPlan(),value=await upgradeFixture(t,plan),before=await fs.readFile(path.join(value.root,'.env'));
 await assert.rejects(setup({root:value.root,homeDirectory:value.homeDirectory,upgrade:true,controlledCtfFailure:true,
  adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:existingDockerAuthority,
  provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),
  provision:async()=>({status:'existing',plan,configuration:value.configuration}),
 }));
 assert.equal((await fs.readFile(path.join(value.root,'.env'))).equals(before),true,'private original bytes must remain exact');
});

test('upgrade with every store configured still initializes before CTF and preserves private environment on failure', async t => {
  const plan=provisioningPlan(),value=await upgradeFixture(t,plan); let initialized=0,ctfCalls=0;
  const options={root:value.root,homeDirectory:value.homeDirectory,upgrade:true,processEnvironment:{},observeControlledCtf:()=>{ctfCalls++;assert.equal(initialized,2);},
    adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:existingDockerAuthority,
    provision:async()=>({status:'existing',plan,configuration:value.configuration}),
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),
    initializeApplication:async({maintenanceScope})=>{initialized++;maintenanceScope.assertHeld();for(const row of plan)assert.equal(process.env[row.runtimeVariable],value.configuration[row.runtimeVariable]);throw Object.assign(Error('controlled'),{code:'MIGRATION_FAILED'});}};
  await assert.rejects(setup(options),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(x=>x.code==='MIGRATION_FAILED'));
  assert.equal(initialized,1);assert.equal(ctfCalls,0);assert.deepEqual(await fs.readFile(path.join(value.root,'.env')),value.original);
  await assert.rejects(fs.lstat(path.join(value.root,'.env.upgrade')),{code:'ENOENT'});
  const result=await setup({...options,initializeApplication:async({maintenanceScope})=>{initialized++;maintenanceScope.assertHeld();}});
  assert.equal(initialized,2);assert.equal(ctfCalls,1);assert.deepEqual(result.upgradedSchemas,[]);
});

test('registry setup follows migrations, preserves disabled preference and fails before publication', async t => {
  const plan=provisioningPlan(), value=await upgradeFixture(t,plan), envPath=path.join(value.root,'.env');
  let initialized=false, calls=0;
  const options={root:value.root,homeDirectory:value.homeDirectory,upgrade:true,ownedMcpRegistry:true,processEnvironment:{},
    adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:existingDockerAuthority,
    preflightOwnedMcpRegistryArchitecture:async()=>({architecture:'arm64',dockerHost:'unix:///tmp/docker-fixture.sock'}),
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),
    provision:async()=>({status:'existing',plan,configuration:value.configuration}),initializeApplication:async()=>{initialized=true;},
    setupOwnedMcpRegistry:async args=>{calls++;assert.equal(initialized,true);assert.equal(args.requested,true);assert.equal(args.explicitActivation,false);assert.equal(args.root,value.root);assert.equal(args.homeDirectory,value.homeDirectory);assert.equal(args.applicationEnvironment.SECURESHOP_AGENTS_DATABASE_URL,value.configuration.SECURESHOP_AGENTS_DATABASE_URL);return{requested:true,activationEnabled:false};}};
  const first=await setup(options);assert.equal(first.ownedRegistry.activationEnabled,false);
  const saved=await fs.readFile(envPath);
  await setup(options);assert.equal(calls,2);assert.deepEqual(await fs.readFile(envPath),saved);
  const explicit=await setup({...options,ownedMcpRegistry:false,enableOwnedMcpRegistry:true,setupOwnedMcpRegistry:async args=>{assert.equal(args.explicitActivation,true);return{requested:true,activationEnabled:true};}});
  assert.equal(explicit.ownedRegistry.activationEnabled,true);
  await assert.rejects(setup({...options,setupOwnedMcpRegistry:async()=>{throw Object.assign(Error('controlled unavailable'),{code:'MCP_REGISTRY_NOT_READY'});}}),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(x=>x.code==='MCP_REGISTRY_NOT_READY'));
  assert.deepEqual(await fs.readFile(envPath),saved);
  const omitted=await setup({...options,ownedMcpRegistry:false,setupOwnedMcpRegistry:()=>assert.fail('unrequested registry')});
  assert.deepEqual(omitted.ownedRegistry,{requested:false,activationEnabled:false});
});

test('requested registry rejects unsupported selected daemon before local PostgreSQL, Mailpit or application provisioning', async t => {
  const root=await temporary(t),homeDirectory=await temporary(t),steps=[];
  const selected={host:'unix:///var/run/docker.sock'};
  await assert.rejects(actualSetup({root,homeDirectory,install:false,ensureModel:false,
    ownedMcpRegistry:true,processEnvironment:{IPI_EMAIL_PROVIDER:'gmail',MCP_SIDECARS_AUTOSTART:'false'},
    prepareRuntime:async()=>({}),
    ensureDockerAuthority:async args=>{steps.push('authority');assert.equal(args.persist,false);return{authority:selected};},
    preflightOwnedMcpRegistryArchitecture:async args=>{steps.push('architecture');assert.equal(args.dockerAuthority,selected);throw Object.assign(Error('unsupported selected daemon'),{code:'REGISTRY_BUILD_AMD64_UNQUALIFIED'});},
    setupLocalPostgres:async()=>assert.fail('no PostgreSQL container before registry architecture'),
    setupLocalMailpit:async()=>assert.fail('no Mailpit before registry architecture'),
    provision:async()=>assert.fail('no application database or role provisioning before registry architecture'),
    runDatabasePhase:async()=>assert.fail('no migrations before registry architecture'),
  }),{code:'REGISTRY_BUILD_AMD64_UNQUALIFIED'});
  assert.deepEqual(steps,['authority','architecture']);
});

test('unrequested registry never probes Docker architecture', async t => {
  const root=await temporary(t),homeDirectory=await temporary(t),steps=[];
  const result=await actualSetup({root,homeDirectory,install:false,ensureModel:false,
    adminUrl:'postgresql://controlled.invalid/postgres',
    processEnvironment:{IPI_EMAIL_PROVIDER:'gmail',MCP_SIDECARS_AUTOSTART:'false'},
    prepareRuntime:async()=>({}),
    ensureDockerAuthority:async()=>assert.fail('unrequested registry must not select Docker'),
    preflightOwnedMcpRegistryArchitecture:async()=>assert.fail('unrequested registry must not inspect architecture'),
    runDatabasePhase:async()=>{steps.push('database-phase');return'observed';},
    provision:async()=>{steps.push('provision');return{configuration:{}};},
  });
  assert.equal(result,'observed');
  assert.deepEqual(steps,['provision','database-phase']);
});

test('requested registry upgrade checks architecture before its database phase', async t => {
  const plan=provisioningPlan(),value=await upgradeFixture(t,plan),steps=[];
  await assert.rejects(actualSetup({root:value.root,homeDirectory:value.homeDirectory,
    upgrade:true,ownedMcpRegistry:true,processEnvironment:{},
    adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',
    ensureDockerAuthority:async args=>{steps.push('authority');assert.equal(args.persist,false);return{authority:{host:'unix:///var/run/docker.sock'}};},
    preflightOwnedMcpRegistryArchitecture:async()=>{steps.push('architecture');throw Object.assign(Error('unsupported selected daemon'),{code:'REGISTRY_BUILD_AMD64_UNQUALIFIED'});},
    runDatabasePhase:async()=>assert.fail('no upgrade database phase before registry architecture'),
    provision:async()=>assert.fail('no upgrade provision before registry architecture'),
  }),{code:'REGISTRY_BUILD_AMD64_UNQUALIFIED'});
  assert.deepEqual(steps,['authority','architecture']);
  assert.deepEqual(await fs.readFile(path.join(value.root,'.env')),value.original);
});

test('policy renderer setup preserves disabled state and publishes activation only after exact readiness',async t=>{
  const plan=provisioningPlan(),value=await upgradeFixture(t,plan),envPath=path.join(value.root,'.env');
  await fs.appendFile(envPath,'SS_BOUND_PROMPT_POLICIES_ENABLED="false"\nSS_POLICY_RENDERER_BASE_URL="http://127.0.0.1:8099"\n');
  let initialized=false,calls=0;
  const base={root:value.root,homeDirectory:value.homeDirectory,upgrade:true,ownedPolicyRenderer:true,processEnvironment:{},
    adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),
    provision:async()=>({status:'existing',plan,configuration:value.configuration}),initializeApplication:async()=>{initialized=true;}};
  const disabled=await setup({...base,provisionOwnedPolicyRenderer:async args=>{calls++;assert.equal(initialized,true);assert.deepEqual(Object.keys(args).sort(),['activate','architecture','environment','home','platform','root']);assert.equal(args.root,value.root);assert.equal(args.home,value.homeDirectory);assert.equal(args.platform,process.platform);assert.equal(args.architecture,process.arch);assert.deepEqual(args.environment,{});assert.equal(args.activate,false);return{ready:false,enabled:false,preservedDisabled:true};}});
  assert.deepEqual(disabled.policyRenderer,{requested:true,ready:false,enabled:false,preservedDisabled:true});
  assert.equal(require('dotenv').parse(await fs.readFile(envPath)).SS_BOUND_PROMPT_POLICIES_ENABLED,'false');
  const enabled=await setup({...base,enableOwnedPolicyRenderer:true,provisionOwnedPolicyRenderer:async args=>{calls++;assert.equal(args.activate,true);return{ready:true,enabled:true,baseUrl:'http://127.0.0.1:8098',containerId:'private',imageId:'private'};}});
  assert.deepEqual(enabled.policyRenderer,{requested:true,ready:true,enabled:true});
  const parsed=require('dotenv').parse(await fs.readFile(envPath));assert.equal(parsed.SS_BOUND_PROMPT_POLICIES_ENABLED,'true');assert.equal(parsed.SS_POLICY_RENDERER_BASE_URL,'http://127.0.0.1:8098');
  const published=await fs.readFile(envPath);
  await assert.rejects(setup({...base,enableOwnedPolicyRenderer:true,provisionOwnedPolicyRenderer:async()=>({ready:true,enabled:false,baseUrl:'http://127.0.0.1:8098'})}),e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(x=>x.code==='POLICY_RENDER_SETUP_INCOMPLETE'));
  assert.deepEqual(await fs.readFile(envPath),published);
  const omitted=await setup({...base,ownedPolicyRenderer:false,provisionOwnedPolicyRenderer:()=>assert.fail('unrequested renderer')});
  assert.deepEqual(omitted.policyRenderer,{requested:false,ready:false,enabled:false});assert.equal(calls,2);
});

test('policy renderer enablement rejects missing ownership before setup work',async()=>{
  await assert.rejects(actualSetup({root:'/controlled/missing',platform:'win32',enableOwnedPolicyRenderer:true,observeWindowsHost:()=>assert.fail('host preflight must not run')}),{code:'POLICY_RENDER_ENABLE_REQUIRES_OWNED'});
});

test('Listings template setup stages disabled and activates only after exact owned readiness',async t=>{
  const plan=provisioningPlan(),value=await upgradeFixture(t,plan),envPath=path.join(value.root,'.env');
  let initialized=false,calls=0;
  const base={root:value.root,homeDirectory:value.homeDirectory,upgrade:true,ownedListingTemplate:true,processEnvironment:{},
    adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:existingDockerAuthority,
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),
    provision:async()=>({status:'existing',plan,configuration:value.configuration}),initializeApplication:async()=>{initialized=true;}};
  const disabled=await setup({...base,provisionOwnedListingTemplate:async args=>{
    calls++;assert.equal(initialized,true);assert.deepEqual(Object.keys(args).sort(),['activate','architecture','environment','home','platform','root']);
    assert.equal(args.root,value.root);assert.equal(args.home,value.homeDirectory);assert.equal(args.platform,process.platform);
    assert.equal(args.architecture,process.arch);assert.deepEqual(args.environment,{});assert.equal(args.activate,false);
    return{ready:false,enabled:false,staged:true};
  }});
  assert.deepEqual(disabled.listingTemplate,{requested:true,ready:false,enabled:false,staged:true});
  const saved=await fs.readFile(envPath);
  const enabled=await setup({...base,enableOwnedListingTemplate:true,provisionOwnedListingTemplate:async args=>{
    calls++;assert.equal(args.activate,true);return{ready:true,enabled:true,baseUrl:'http://127.0.0.1:8109',containerId:'a'.repeat(64),imageId:'sha256:'+'b'.repeat(64)};
  }});
  assert.deepEqual(enabled.listingTemplate,{requested:true,ready:true,enabled:true});
  assert.deepEqual(await fs.readFile(envPath),saved);
  await assert.rejects(setup({...base,enableOwnedListingTemplate:true,provisionOwnedListingTemplate:async()=>({ready:true,enabled:true,baseUrl:'http://127.0.0.1:8109',containerId:'wrong',imageId:'sha256:'+'b'.repeat(64)})}),
    e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&e.errors.some(x=>x.code==='LISTING_TEMPLATE_SETUP_INCOMPLETE'));
  assert.deepEqual(await fs.readFile(envPath),saved);
  const omitted=await setup({...base,ownedListingTemplate:false,provisionOwnedListingTemplate:()=>assert.fail('unrequested template')});
  assert.deepEqual(omitted.listingTemplate,{requested:false,ready:false,enabled:false});assert.equal(calls,2);
});

test('Listings template rejects unpaired enablement and unsupported Windows before setup work',async()=>{
  await assert.rejects(actualSetup({root:'/controlled/missing',platform:'win32',enableOwnedListingTemplate:true,observeWindowsHost:()=>assert.fail('host preflight must not run')}),{code:'LISTING_TEMPLATE_ENABLE_REQUIRES_OWNED'});
  await assert.rejects(actualSetup({root:'/controlled/missing',platform:'win32',ownedListingTemplate:true,observeWindowsHost:()=>assert.fail('host preflight must not run')}),{code:'LISTING_TEMPLATE_PLATFORM_UNQUALIFIED'});
});

test('combined SecureShop opt-in carries registry preparation to the validated database phase',async t=>{
  const plan=provisioningPlan(),value=await upgradeFixture(t,plan);
  const result=await actualSetup({root:value.root,homeDirectory:value.homeDirectory,upgrade:true,qualifiedSecureShop:true,ownedSystem:true,
    processEnvironment:{},adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:existingDockerAuthority,
    preflightOwnedMcpRegistryArchitecture:async()=>({architecture:'arm64',dockerHost:'unix:///tmp/docker-fixture.sock'}),
    preflightQualifiedSystem:async()=>{},setupOwnedMcpRegistry:async()=>{},
    runDatabasePhase:async(request,dependencies)=>{require('../scripts/install/setup-database-phase').validateRequest(request);assert.equal(request.context.ownedMcpRegistry,true);assert.equal(request.context.enableOwnedMcpRegistry,false);assert.equal(typeof dependencies.setupOwnedMcpRegistry,'function');return 'observed';}});
  assert.equal(result,'observed');
});

test('registry CLI plan is nonmutating and dispatches only the closed preparation flags',async()=>{
  const source=await fs.readFile(path.join(__dirname,'../scripts/setup-application.js'),'utf8');
  const cli=source.slice(source.indexOf('if (require.main === module) {'),source.indexOf('// Explicit candidate seam only;'));
  for(const flag of ['--owned-mcp-registry','--enable-owned-mcp-registry','--qualified-secureshop']){
    const owner={},messages=[],process={argv:['node','setup','--plan',flag]};
    require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,process,setupHostPlan:()=>null,console:{log:x=>messages.push(x),error:()=>assert.fail('CLI rejected supported flag')},setup:()=>assert.fail('plan must not call setup')});
    assert(messages.some(x=>x.includes('Linux AMD64 remains unqualified')));assert.equal(process.exitCode,undefined);
  }
  let options;const owner={};require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,process:{argv:['node','setup','--enable-owned-mcp-registry']},console,setup:x=>{options=x;return Promise.resolve();}});
  assert.equal(options.enableOwnedMcpRegistry,true);assert.equal(options.ownedMcpRegistry,false);
});

test('policy renderer CLI requires paired consent and keeps plan nonmutating',async()=>{
  const source=await fs.readFile(path.join(__dirname,'../scripts/setup-application.js'),'utf8');
  const cli=source.slice(source.indexOf('if (require.main === module) {'),source.indexOf('// Explicit candidate seam only;'));
  const owner={},messages=[],processForPlan={argv:['node','setup','--plan','--owned-policy-renderer','--enable-owned-policy-renderer']};
  require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,process:processForPlan,setupHostPlan:()=>null,console:{log:x=>messages.push(x),error:()=>assert.fail('paired policy renderer plan rejected')},setup:()=>assert.fail('plan must not call setup')});
  assert(messages.some(x=>x.includes('Owned strict policy renderer')));assert.equal(processForPlan.exitCode,undefined);
  const rejected={argv:['node','setup','--plan','--enable-owned-policy-renderer']},errors=[];
  require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,process:rejected,setupHostPlan:()=>assert.fail('invalid pair must fail before plan'),console:{log:()=>{},error:x=>errors.push(x)},setup:()=>assert.fail('invalid pair must fail before setup')});
  assert.equal(rejected.exitCode,1);assert(errors[0].includes('requires --owned-policy-renderer'));
  let options;require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,process:{argv:['node','setup','--owned-policy-renderer','--enable-owned-policy-renderer']},console,setup:x=>{options=x;return Promise.resolve();}});
  assert.equal(options.ownedPolicyRenderer,true);assert.equal(options.enableOwnedPolicyRenderer,true);
});

test('Listings template CLI requires paired consent and keeps plan nonmutating',async()=>{
  const source=await fs.readFile(path.join(__dirname,'../scripts/setup-application.js'),'utf8');
  const cli=source.slice(source.indexOf('if (require.main === module) {'),source.indexOf('// Explicit candidate seam only;'));
  const owner={},messages=[],processForPlan={argv:['node','setup','--plan','--owned-listing-template','--enable-owned-listing-template']};
  require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,process:processForPlan,setupHostPlan:()=>null,
    console:{log:x=>messages.push(x),error:()=>assert.fail('paired template plan rejected')},setup:()=>assert.fail('plan must not call setup')});
  assert(messages.some(x=>x.includes('Owned Listings template')&&x.includes('does not enable Listings')));assert.equal(processForPlan.exitCode,undefined);
  const rejected={argv:['node','setup','--plan','--enable-owned-listing-template']},errors=[];
  require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,process:rejected,setupHostPlan:()=>assert.fail('invalid pair must fail before plan'),
    console:{log:()=>{},error:x=>errors.push(x)},setup:()=>assert.fail('invalid pair must fail before setup')});
  assert.equal(rejected.exitCode,1);assert(errors[0].includes('requires --owned-listing-template'));
  let options;require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,
    process:{argv:['node','setup','--owned-listing-template','--enable-owned-listing-template']},console,
    setup:x=>{options=x;return Promise.resolve();}});
  assert.equal(options.ownedListingTemplate,true);assert.equal(options.enableOwnedListingTemplate,true);
});
