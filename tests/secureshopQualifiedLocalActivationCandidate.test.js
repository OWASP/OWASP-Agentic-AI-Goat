'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { execFileSync } = require('node:child_process');
const express = require('express');
const candidate = require('../docs/modernization/drafts/secureshopQualifiedActivationCandidate');
const config = require('../docs/modernization/drafts/secureshopQualifiedManagedConfiguration.candidate');
const provisioner = require('../docs/modernization/drafts/secureshopQualifiedLocalProvision.candidate');
const cli = require('../docs/modernization/drafts/secureshop-qualified-local.candidate');
const builder = require('../scripts/build-secureshop-qualified-activation');
const runtimeReadiness = require('../docs/modernization/drafts/secureshopRuntimeReadiness.candidate');
const activationQualifier = require('../scripts/qualify-secureshop-qualified-activation');

const ROOT = path.resolve(__dirname, '..');

test('installed curriculum retains all qualified objectives and the historical builder rejects drift', () => {
  const source = fs.readFileSync(path.join(ROOT, 'server/config/secureshopCurriculum.js'), 'utf8');
  assert.throws(() => candidate.buildCurriculum(source), /curriculum source changed/);
  const curriculum = require('../server/config/secureshopCurriculum');
  assert.deepEqual(curriculum.QUALIFIED_OBJECTIVE_IDS, curriculum.OBJECTIVES.filter(row=>row.qualification!=='pending').map(row => row.id));
  assert.deepEqual(curriculum.PENDING_OBJECTIVE_IDS, [
    'ss_file_upload_instruction_adoption',
    'ss_pricing_false_grounding',
    'ss_pricing_manual_injection',
    'ss_manual_rag_instruction_adoption',
    'ss_product_description_instruction_adoption',
    'ss_idor_order_status_disclosure',
    'ss_mcp_description_instruction_adoption',
    'ss_policy_final_html_execution',
    'ss_user_lookup_sensitive_disclosure',
  ]);
  assert.equal(curriculum.QUALIFIED_OBJECTIVE_IDS.length, 55);
  assert.equal(curriculum.OBJECTIVES.length, 64);
  assert.deepEqual(curriculum.PENDING_OBJECTIVE_IDS, curriculum.OBJECTIVES.filter(row=>row.qualification==='pending').map(row=>row.id));
  assert.deepEqual(curriculum.QUALIFIED_MECHANISMS, ['native-model', 'native-browser-judge']);
  assert.ok(curriculum.OBJECTIVES.every(row => (row.qualification==='pending'||curriculum.QUALIFIED_MECHANISMS.includes(row.qualification))
    && row.defaultEnabled === false));
  assert.equal(curriculum.OBJECTIVES.find(row => row.id === 'ss_stored_browser_execution').qualification,
    'native-browser-judge');
  assert.ok(curriculum.OBJECTIVES.filter(row => row.qualification !== 'native-browser-judge'&&row.qualification!=='pending')
    .every(row => row.qualification === 'native-model'));
  for (const id of ['ss_rogue_tool_selected', 'ss_rug_pull_invoked', 'ss_stored_browser_execution', 'ss_controlled_ssrf']) {
    assert.doesNotMatch(curriculum.HINTS[id].hints.join(' '), /not yet available/);
    assert.doesNotMatch(curriculum.SOLUTIONS[id].approach, /^Unavailable/);
    assert.notEqual(curriculum.SOLUTIONS[id].examples[0].action, 'Unavailable');
  }
  assert.equal(curriculum.CHALLENGE.defaultVisible, false);
});

test('installed catalog and managed configuration preserve startup ordering', () => {
  const seed = fs.readFileSync(path.join(ROOT, 'server/database/postgres/workshopPlatformSeed.js'), 'utf8');
  assert.throws(() => candidate.buildSeed(seed), /seed source changed/);
  // Other workshops can advance the shared audit version without changing
  // SecureShop activation. Verify version propagation, not a historical date.
  assert.match(seed, /CATALOG_VERSION='workshop-defaults-[^']+'/);
  assert.match(seed, /catalogVersion=CATALOG_VERSION/);
  const entry = fs.readFileSync(path.join(ROOT, 'server/index.js'), 'utf8');
  const index = fs.readFileSync(path.join(ROOT, 'server/applicationServer.js'), 'utf8');
  const owned = index.indexOf("ownedManagedConfiguration').loadOwnedManagedConfiguration()");
  const shop = index.indexOf("secureshopSystemManagedEnvironment').loadWithQualified()");
  const dotenv = entry.indexOf("require('dotenv').config()");
  const construction = entry.indexOf("require('./applicationServer')");
  const lease = entry.indexOf('lease=await');
  const engine = index.indexOf('assertApplicationDatabaseEngine()');
  assert.ok(dotenv >= 0 && lease > dotenv && construction > lease);
  assert.ok(owned >= 0 && shop > owned && engine > shop);
  const managedSource=fs.readFileSync(path.join(ROOT,'server/services/secureshopSystemManagedEnvironment.js'),'utf8');
  assert.match(managedSource,/const qualified=require\('\.\/secureshopQualifiedManagedConfiguration'\)\.load\(\{root,home\}\)/);
  assert.match(managedSource,/environment:\{\.\.\.environment,\.\.\.qualified\}/);
  assert.match(index, /secureshop-runtime-readiness/);
  assert.match(index, /createRouter\(\{ authenticateToken, requireAdminLevel,/);
  assert.match(index, /secureshopBoundReadiness = bound\.readiness/);
  const bound = fs.readFileSync(path.join(ROOT, 'server/services/secureshopBoundApplication.js'), 'utf8');
  assert.match(bound, /mountedReadiness\(composition\)/);
});

test('mounted readiness fails a missing panel and restricted endpoint reflects live startup and shutdown state', async t => {
  const complete = {
    catalog:{ listProducts() {} }, router() {}, browserRouter() {},
    personaInbox:{ ready:true, router() {} }, mcpTrust:{ ready:true, router() {} },
    ssrf:{ ready:true, router() {} },
  };
  assert.throws(() => runtimeReadiness.mountedReadiness({ ...complete, ssrf:{ ready:false } }),
    /panel readiness incomplete/);
  let current = null;
  const app = express();
  app.use('/ready', runtimeReadiness.createRouter({
    authenticateToken(req,res,next) {
      if (req.get('authorization') === 'Bearer admin') { req.user={ admin_level:1 }; return next(); }
      if (req.get('authorization') === 'Bearer student') { req.user={ admin_level:0 }; return next(); }
      return res.status(401).json({ error:'Authentication required' });
    },
    requireAdminLevel: level => (req,res,next) => req.user.admin_level >= level
      ? next() : res.status(403).json({ error:'Access denied' }),
    getReadiness: () => current,
  }));
  const server = http.createServer(app); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/ready`;
  assert.equal((await fetch(url)).status,401);
  assert.equal((await fetch(url,{headers:{authorization:'Bearer student'}})).status,403);
  assert.equal((await fetch(url,{headers:{authorization:'Bearer admin'}})).status,503);
  current=runtimeReadiness.mountedReadiness(complete);
  const ready=await fetch(url,{headers:{authorization:'Bearer admin'}});
  assert.equal(ready.status,200);assert.deepEqual(await ready.json(),current);
  current=null; // lifecycle shutdown clears app.locals.secureshopBoundReadiness.
  assert.equal((await fetch(url,{headers:{authorization:'Bearer admin'}})).status,503);
});

test('standalone qualifier applies validated managed flags and fixture roots before policies read process env', () => {
  const keys=['SS_ENABLE','PLATFORM_DATABASE_ENGINE','WORKSHOP_DATABASE_ENGINE','SS_PERSONA_INBOX_READY','SS_MCP_TRUST_READY',
    'SS_CONTROLLED_SSRF_READY','SS_MCP_TRUST_FIXTURE_ROOT','SS_CONTROLLED_SSRF_FIXTURE_ROOT',
    'SS_BOUND_REVIEWS_ENABLED'];
  const before=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  try {
    process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.WORKSHOP_DATABASE_ENGINE='postgres';
    const values={ SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',SS_PERSONA_INBOX_READY:'true',
      SS_MCP_TRUST_READY:'true',SS_CONTROLLED_SSRF_READY:'true',
      SS_MCP_TRUST_FIXTURE_ROOT:'/owned/mcp',SS_CONTROLLED_SSRF_FIXTURE_ROOT:'/owned/ssrf' };
    assert.deepEqual(activationQualifier.applyManagedConfiguration(()=>values),values);
    assert.equal(require('../server/services/secureshopPersonaInboxActivationPolicy').activationPolicy(process.env).requested,true);
    assert.equal(require('../server/services/secureshopMcpTrustActivationPolicy').activationPolicy(process.env).requested,true);
    assert.equal(require('../server/services/secureshopSsrfProduction').activationPolicy(process.env).requested,true);
    assert.equal(process.env.SS_MCP_TRUST_FIXTURE_ROOT,'/owned/mcp');
    assert.equal(process.env.SS_CONTROLLED_SSRF_FIXTURE_ROOT,'/owned/ssrf');
  } finally {
    for(const key of keys) before[key]===undefined ? delete process.env[key] : process.env[key]=before[key];
  }
});

test('private provisioner activates and disables all bound features atomically without touching application env', async t => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dvaia-ss-managed-'));
  const root = path.join(directory, 'workspace'), home = path.join(directory, 'home');
  await Promise.all([fsp.mkdir(root), fsp.mkdir(home)]);
  const applicationEnv = path.join(root, '.env'); const original = Buffer.from('JWT_SECRET=private-existing-value\n');
  await fsp.writeFile(applicationEnv, original, { mode: 0o600 });
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));

  const active = await provisioner.provision({ root, home, enabled: true });
  assert.equal(active.enabled, true);
  assert.deepEqual(config.load({ root, home }), {
    SS_ENABLE: 'true', SS_BOUND_REVIEWS_ENABLED: 'true', SS_PERSONA_INBOX_READY: 'true',
    SS_MCP_TRUST_READY: 'true', SS_CONTROLLED_SSRF_READY: 'true',
    ...config.expectedRoots(root, home),
  });
  assert.equal((await fsp.stat(active.file)).mode & 0o777, 0o600);
  for (const fixtureRoot of active.fixtureRoots) assert.equal((await fsp.stat(fixtureRoot)).mode & 0o777, 0o700);
  assert.deepEqual(await fsp.readFile(applicationEnv), original);

  const disabled = await provisioner.provision({ root, home, enabled: false });
  assert.equal(disabled.enabled, false);
  const values = config.load({ root, home });
  assert.equal(values.SS_ENABLE, 'true');
  for (const key of config.BOOLEAN_KEYS) assert.equal(values[key], 'false');
  assert.deepEqual(await fsp.readFile(applicationEnv), original);
  await provisioner.restore({ root, home, previous:disabled.previous });
  assert.equal(config.load({ root, home }).SS_BOUND_REVIEWS_ENABLED, 'true');
  await provisioner.restore({ root, home, previous:active.previous });
  await assert.rejects(fsp.stat(active.file), { code:'ENOENT' });
});

test('managed configuration rejects partial activation, path substitution and untrusted roots', async t => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dvaia-ss-managed-negative-'));
  const root = path.join(directory, 'workspace'), home = path.join(directory, 'home');
  await Promise.all([fsp.mkdir(root), fsp.mkdir(home)]); t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const roots = config.expectedRoots(root, home);
  const values = { SS_ENABLE:'true', ...Object.fromEntries(config.BOOLEAN_KEYS.map(key => [key, 'true'])), ...roots };
  const encode = item => Buffer.from(config.KEYS.map(key => `${key}=${item[key]}`).join('\n') + '\n');
  assert.throws(() => config.parse(encode({ ...values, SS_CONTROLLED_SSRF_READY:'false' }), { root, home }),
    { code:'SECURESHOP_MANAGED_CONFIGURATION_INVALID' });
  assert.throws(() => config.parse(encode({ ...values, SS_MCP_TRUST_FIXTURE_ROOT:'/tmp/substituted' }), { root, home }),
    { code:'SECURESHOP_MANAGED_CONFIGURATION_INVALID' });
  await provisioner.provision({ root, home, enabled:true });
  await fsp.chmod(roots.SS_MCP_TRUST_FIXTURE_ROOT, 0o755);
  assert.throws(() => config.load({ root, home }), { code:'SECURESHOP_FIXTURE_ROOT_UNTRUSTED' });
});

test('provisioner rejects a malformed existing managed file instead of overwriting it', async t => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dvaia-ss-managed-existing-'));
  const root = path.join(directory, 'workspace'), home = path.join(directory, 'home');
  await Promise.all([fsp.mkdir(root), fsp.mkdir(home)]); t.after(() => fsp.rm(directory, { recursive:true, force:true }));
  const file = config.managedPath(root, home); await fsp.mkdir(path.dirname(file), { recursive:true, mode:0o700 });
  const original = Buffer.from('SS_ENABLE=true\n'); await fsp.writeFile(file, original, { mode:0o600 });
  await assert.rejects(provisioner.provision({ root, home, enabled:true }), { code:'SECURESHOP_MANAGED_CONFIGURATION_INVALID' });
  assert.deepEqual(await fsp.readFile(file), original);
});

test('activation command plans without writes and maps explicit activation or maintenance disable', async () => {
  const calls = [], output = [], root = '/owned/workspace';
  const plan = await cli.main(['--plan'], { root, write: async value => calls.push(value), output: value => output.push(value) });
  assert.equal(plan.planned, true); assert.deepEqual(calls, []); assert.match(output[0], /applicationEnvChanged/);
  await cli.main(['--activate-qualified'], { root, write: async value => { calls.push(value); return { file:'/private/config', enabled:value.enabled }; }, output: value => output.push(value) });
  await cli.main(['--disable'], { root, write: async value => { calls.push(value); return { file:'/private/config', enabled:value.enabled }; }, output: value => output.push(value) });
  assert.deepEqual(calls.map(value => value.enabled), [true, false]);
  await assert.rejects(cli.main(['--activate-qualified', '--disable'], { root }), /Usage/);
});

// Compile main bytes under destination filenames without materializing source.
// Only the closed relocation set changes __dirname; other dependencies stay main.
function relocatedLoader(sourceRoot, destinationRoot, relatives) {
  const fs = require('node:fs'), path = require('node:path');
  const { Module, createRequire } = require('node:module');
  destinationRoot = fs.realpathSync(destinationRoot);
  const allowed = new Set(relatives.map(relative => path.resolve(sourceRoot, relative)));
  const cache = new Map();
  function load(filename) {
    if (!allowed.has(filename)) throw Error('Unregistered relocation module');
    if (cache.has(filename)) return cache.get(filename).exports;
    const virtual = path.join(destinationRoot, path.relative(sourceRoot, filename));
    const loaded = new Module(virtual);
    loaded.filename = virtual;
    const mainRequire = createRequire(filename);
    loaded.require = request => {
      const resolved = mainRequire.resolve(request);
      return allowed.has(resolved) ? load(resolved) : mainRequire(request);
    };
    cache.set(filename, loaded);
    try { loaded._compile(fs.readFileSync(filename, 'utf8'), virtual); }
    catch (error) { cache.delete(filename); throw error; }
    return loaded.exports;
  }
  return relative => load(path.resolve(sourceRoot, relative));
}

test('installed activation relocates to the current workspace and rejects historical rebuild', async t => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dvaia-ss-output-'));
  t.after(() => fsp.rm(directory, { recursive:true, force:true }));
  assert.throws(() => builder.build({sourceRoot:ROOT,destinationRoot:directory}), /activation input changed/);
  const manifest = require('../docs/modernization/drafts/secureshop-qualified-activation-manifest-2026-09-14.json');
  const relatives = [...Object.keys(manifest.productionOutputs), 'server/services/mcp/ownedManagedConfiguration.js'];
  const load = relocatedLoader(ROOT, directory, relatives);
  const relocated = load('server/services/secureshopQualifiedManagedConfiguration.js');
  const canonicalRoot = fs.realpathSync(directory);
  assert.equal(relocated.managedPath(), path.join(path.dirname(
    load('server/services/mcp/ownedManagedConfiguration.js').managedConfigurationPath({ root:canonicalRoot })),
  'secureshop-qualified.env'));
  const generatedCurriculum = load('server/config/secureshopCurriculum.js');
  assert.deepEqual(generatedCurriculum.QUALIFIED_OBJECTIVE_IDS,
    require('../server/config/secureshopCurriculum').QUALIFIED_OBJECTIVE_IDS);
  assert.notDeepEqual(generatedCurriculum.QUALIFIED_OBJECTIVE_IDS, manifest.qualifiedObjectiveIds,
    'The retained activation manifest remains historical and must not redefine the current qualified catalog');
  const childHome=path.join(directory,'home');await fsp.mkdir(childHome);
  const childProgram = `${relocatedLoader.toString()}\nconst load=relocatedLoader(${JSON.stringify(ROOT)},${JSON.stringify(directory)},${JSON.stringify(relatives)});\nload('scripts/install/secureshop-qualified-local.js').main(['--plan'],{output:()=>{}}).then(value=>process.stdout.write(JSON.stringify(value))).catch(error=>{console.error(error);process.exitCode=1;});`;
  const planned=JSON.parse(execFileSync(process.execPath,['-'],
    { input:childProgram,encoding:'utf8',env:{...process.env,HOME:childHome} }));
  assert.equal(planned.file,relocated.managedPath(canonicalRoot,childHome));
  const generatedProvisioner=load('scripts/install/secureshop-qualified-local-lib.js');
  const generatedProvision=await generatedProvisioner.provision({home:childHome,enabled:true});
  assert.equal(generatedProvision.file,relocated.managedPath(canonicalRoot,childHome));
  assert.equal(relocated.load({root:canonicalRoot,home:childHome}).SS_BOUND_REVIEWS_ENABLED,'true');
  await generatedProvisioner.restore({home:childHome,previous:generatedProvision.previous});
  await assert.rejects(fsp.stat(generatedProvision.file),{code:'ENOENT'});
  const qualifier = fs.readFileSync(path.join(ROOT, 'scripts/qualify-secureshop-qualified-activation.js'), 'utf8');
  assert.match(qualifier, /Object\.assign\(process\.env, managed\)/);
  assert.ok(qualifier.indexOf('Object.assign(process.env, managed)')
    < qualifier.indexOf("require('../server/services/secureshopBoundReviewComposition')"));
});
