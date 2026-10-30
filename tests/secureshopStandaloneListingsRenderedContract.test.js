'use strict';

// Controlled assembly contracts only. No store, browser, executor or model starts.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const filename = path.join(__dirname, 'postgres/secureshopStandaloneListingsRendered.integration.test.js');
const source = fs.readFileSync(filename, 'utf8');
const realRequire = createRequire(filename);

function load(env = {}, entry = false, controls = {}) {
  let allocations = 0;
  const registered = [];
  const module = { exports: {} };
  function require(name) {
    if (name === 'node:fs/promises' && controls.fs) return controls.fs;
    if (name === 'puppeteer' && controls.puppeteer) return controls.puppeteer;
    if (name === 'node:test') return (...args) => registered.push(args);
    if (name === 'pg') return { Pool: class { constructor() { allocations++; throw Error('Resource allocation forbidden'); } } };
    return realRequire(name);
  }
  require.main = entry ? module : {};
  vm.compileFunction(source+'\nObject.assign(module.exports,{managerConfiguration,assertStandaloneReceiptPath,publishStandaloneReceipt,launchStandaloneBrowser,observeAssessmentQualification,observeListingsBrowserAssessment,captureAssessmentFailure,recordReadiness,readinessShape,observeReadiness,renderedReadinessState});', ['require', 'module', 'process', '__dirname'], { filename })(
    require, module, { env, cwd: () => controls.cwd || '/', getuid: () => process.getuid() }, path.dirname(filename));
  return { ...module.exports, registered, allocations: () => allocations };
}

{
const h=load(),diagnostic=()=>({server:[],browser:[],errors:[],dom:null});
test('actual readiness readiness wrapper preserves invocation/result/error and bounds cause tokens',async()=>{
 const d=diagnostic(),receiver={},result={secret:'not retained'};let calls=0;
 const wrapped=h.observeReadiness(function(...args){calls++;assert.equal(this,receiver);assert.deepEqual(args,[1,2]);return result;},d);
 assert.equal(await wrapped.call(receiver,1,2),result);assert.equal(calls,1);
 for(const code of ['LISTINGS_MANAGER_TIMEOUT','LISTINGS_MANAGER_PROTOCOL','SECURESHOP_FEATURE_MODE_STALE']){
  const cause=Object.assign(new SyntaxError('secret'),{code:'secret'}),error=Object.assign(new Error('secret'),{code,cause});
  await assert.rejects(h.observeReadiness(()=>{throw error;},d)(),e=>e===error);
  assert.equal(d.errors.at(-2).code,code);assert.equal(d.errors.at(-1).name,'SyntaxError');
 }
 const circular=Object.assign(new Error('secret'),{code:'secret'});circular.cause=circular;
 for(let i=0;i<20;i++)await assert.rejects(h.observeReadiness(()=>{throw circular;},d)(),e=>e===circular);
 assert.equal(d.errors.length,16);assert.ok(!JSON.stringify(d).includes('secret'));
 const bad=Object.defineProperty({},'errors',{get(){throw Error('observer failed');}});
 await assert.rejects(h.observeReadiness(()=>{throw circular;},bad)(),e=>e===circular);
});
test('actual readiness response middleware observes exact cohort/path/method and preserves response',()=>{
 const start=source.indexOf("          if (standalonePrivateReceipt && req.method === 'GET'");
 const end=source.indexOf('          if (RECOVERY_ENABLED',start);
 assert.ok(start>0&&end>start);
 const run=vm.compileFunction(source.slice(start,end),['standalonePrivateReceipt','req','res','recordReadiness','readinessShape','readinessDiagnostic']);
 for(const [cohort,method,url,expected]of [[true,'GET','/merchant/listings/readiness',1],[false,'GET','/merchant/listings/readiness',0],[true,'POST','/merchant/listings/readiness',0],[true,'GET','/merchant/listings/template-readiness',0]]){
  const d=diagnostic(),body={ready:true,versionedListings:true,scopeKey:'a'.repeat(64),secret:'secret'},sentinel={};let calls=0;
  const res={statusCode:200,json(value){assert.equal(this,res);assert.equal(value,body);calls++;return sentinel;}};
  run(cohort,{method,path:url},res,h.recordReadiness,h.readinessShape,d);
  assert.equal(res.json(body),sentinel);assert.equal(calls,1);assert.equal(d.server.length,expected);assert.ok(!JSON.stringify(d).includes('secret'));
 }
 const body={},res={statusCode:503,json:value=>value};run(true,{method:'GET',path:'/merchant/listings/readiness'},res,()=>{throw Error('observer');},h.readinessShape,diagnostic());assert.equal(res.json(body),body);
 assert.deepEqual(h.readinessShape(200,{ready:false}),{status:200,object:true,ready:false,versionedListings:false,scopeKeyValid:false});
});
test('actual readiness browser listener is origin/path/method bound, capped and never consumes body',()=>{
 const start=source.indexOf("          if (standalonePrivateReceipt) try {\n            if (response.request().method() === 'GET'");
 const end=source.indexOf("          if (response.request().method() === 'POST'",start);
 const run=vm.compileFunction(source.slice(start,end),['standalonePrivateReceipt','response','app','recordReadiness','readinessDiagnostic']);
 const d=diagnostic(),origin='http://127.0.0.1:1234';
 const response=(url,method='GET')=>({url:()=>url,request:()=>({method:()=>method}),status:()=>503,json(){throw Error('body');},text(){throw Error('body');}});
 for(const [cohort,url,method]of [[false,origin+'/api/secureshop/merchant/listings/readiness','GET'],[true,'http://foreign/api/secureshop/merchant/listings/readiness','GET'],[true,origin+'/api/secureshop/merchant/listings/readiness','POST'],[true,origin+'/other','GET']])run(cohort,response(url,method),{origin},h.recordReadiness,d);
 assert.equal(d.browser.length,0);
 for(let i=0;i<30;i++)run(true,response(origin+'/api/secureshop/merchant/listings/readiness'),{origin},h.recordReadiness,d);
 assert.equal(d.browser.length,16);assert.deepEqual(d.browser[0],{status:503});
 run(true,response(origin+'/api/secureshop/merchant/listings/readiness'),{origin},()=>{throw Error('observer');},d);
});
test('actual readiness DOM callback returns only known categories and equality booleans',async()=>{
 const alerts=[{textContent:'secret'}, {textContent:'Listing actions could not be verified (HTTP 503). Retry readiness'}];
 const button={textContent:'Import',disabled:true},input={value:'synthetic'};
 const visible=x=>Object.assign(x,{getClientRects:()=>[{}]});alerts.forEach(visible);visible(button);
 const frame={async evaluate(fn,value){const context={document:{querySelectorAll:selector=>selector==='button'?[button]:alerts,querySelector:()=>input},getComputedStyle:()=>({visibility:'visible'}),value};return vm.runInNewContext('('+fn.toString()+')(value)',context);}};
 const row=await h.renderedReadinessState(frame,'synthetic');
 assert.equal(JSON.stringify(row),JSON.stringify({categories:['http'],importPresent:true,importDisabled:true,inputPresent:true,inputEqualsExpected:true}));
 assert.ok(!JSON.stringify(row).includes('secret'));
});
test('actual factory wrapper composes prior factory and restores original on production failure',async()=>{
 const start=source.indexOf('      if (standalonePrivateReceipt) {\n        const priorRouterFactory');
 const end=source.indexOf("      try { listings = await require",start);
 const setup=vm.compileFunction(source.slice(start,end),['standalonePrivateReceipt','listingsRouteModule','observeReadiness','readinessDiagnostic']);
 for(const cohort of [true,false]){
  const result={},original=options=>options,module={createBoundListingsRouter:original},d=diagnostic();setup(cohort,module,h.observeReadiness,d);
  const read=async()=>result,options=module.createBoundListingsRouter({readReadiness:read});assert.equal(await options.readReadiness(),result);
  if(!cohort)assert.equal(options.readReadiness,read);
  const cleanup="listingsRouteModule.createBoundListingsRouter = originalListingsRouter;";
  assert.ok(source.includes('finally { '+cleanup+' }'));
  const sentinel=new Error('construction failed');
  const restore=vm.compileFunction('try { throw sentinel; } finally { '+cleanup+' }',
   ['listingsRouteModule','originalListingsRouter','sentinel']);
  assert.throws(()=>restore(module,original,sentinel),e=>e===sentinel);
  assert.equal(module.createBoundListingsRouter,original);
 }
});
}

test('actual private manager configuration preserves original workspace validator and rejects aliases', () => {
  const root=path.resolve(__dirname,'..'),runId='a'.repeat(32);
  const workspaceId=require('../scripts/application-data-root').workspaceId(root);
  const profile='owasp-ai-goat-owned-listings-'+workspaceId;
  const qualified=require('../scripts/install/secureshop-owned-listings-qualified-candidate').qualifiedPackage({root,architecture:'arm64'});
  const hash=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
  const profileSha=hash(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-listings/profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',profile));
  const host=`unix:///var/tmp/owasp-ai-goat-v23-build-${runId}/fs/docker.sock`,daemonId='d'.repeat(36);
  const env={SECURESHOP_LISTINGS_TEST_MANAGER_RUNTIME_DIGEST:qualified.runtimeDigest,
    SECURESHOP_LISTINGS_TEST_MANAGER_SOURCE_SHA256:qualified.qualifiedSourceSha256,
    SECURESHOP_LISTINGS_TEST_MANAGER_IMAGE_ID:'sha256:'+'b'.repeat(64),
    SECURESHOP_LISTINGS_TEST_MANAGER_CONTAINER_ID:'c'.repeat(64),
    SECURESHOP_LISTINGS_TEST_DOCKER_HOST:host,SECURESHOP_LISTINGS_TEST_DOCKER_DAEMON_ID:daemonId,
    SECURESHOP_LISTINGS_TEST_DOCKER_AUTHORITY_SHA256:require('../scripts/local-docker-authority').authorityDigest({version:1,workspaceId,host,daemonId}),
    SECURESHOP_LISTINGS_TEST_MANAGER_ORIGIN:'http://127.0.0.1:1234',SECURESHOP_LISTINGS_TEST_MANAGER_TOKEN:'x'.repeat(48),
    SECURESHOP_LISTINGS_PRIVATE_MANAGER_RUN_ID:runId,SECURESHOP_LISTINGS_PRIVATE_MANAGER_PROFILE:profile,
    SECURESHOP_LISTINGS_PRIVATE_MANAGER_CONTAINER:profile,SECURESHOP_LISTINGS_PRIVATE_MANAGER_PROFILE_SHA256:profileSha};
  const record=load(env).managerConfiguration(root);
  assert.equal(record.workspaceId,workspaceId);assert.equal(record.profile.name,profile);
  for(const [key,value] of [['SECURESHOP_LISTINGS_PRIVATE_MANAGER_RUN_ID','b'.repeat(32)],
    ['SECURESHOP_LISTINGS_PRIVATE_MANAGER_PROFILE','owasp-ai-goat-owned-listings-'+runId.slice(0,12)],
    ['SECURESHOP_LISTINGS_PRIVATE_MANAGER_PROFILE_SHA256','0'.repeat(64)],
    ['SECURESHOP_LISTINGS_PRIVATE_MANAGER_CONTAINER','foreign'],
    ['SECURESHOP_LISTINGS_TEST_DOCKER_DAEMON_ID','e'.repeat(36)]])
    assert.throws(()=>load({...env,[key]:value}).managerConfiguration(root));
  const original={...env};for(const key of Object.keys(original))if(key.startsWith('SECURESHOP_LISTINGS_PRIVATE_'))delete original[key];
  assert.deepEqual(load(original).managerConfiguration(root),record);
});

test('importing the assembly registers no default test and allocates nothing', () => {
  const fixture = load();
  assert.equal(typeof fixture.runStandaloneListingsQualification, 'function');
  assert.deepEqual(fixture.registered, []);
  assert.equal(fixture.allocations(), 0);
});

test('actual original browser wrapper forwards exact bounded policy and rejects unowned inputs before launch', async () => {
  const root = path.resolve(__dirname, '..'), directory = path.join(root, 'tasks/qualification/run-browser123');
  const runtime = path.join(directory, 'runtime'), tmp = path.join(runtime, 'tmp'), home = path.join(runtime, 'home');
  const receiptPath = path.join(directory, 'standalone-listings-browser.json');
  const executablePath = '/controlled/canonical/chromium';
  const env = { OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: root, TMPDIR: tmp, MAC_CHROMIUM_TMPDIR: tmp,
    XDG_CACHE_HOME: path.join(home, '.cache'), XDG_CONFIG_HOME: path.join(home, '.config'),
    PUPPETEER_EXECUTABLE_PATH: executablePath };
  const base = { root, receiptPath, origin: 'http://127.0.0.1:1234',
    profile: path.join(tmp, 'owasp-ai-goat-listings-browser-owned'), executablePath };
  let launches = [], alteration = null;
  const io = { lstat: async value => {
    if (value === receiptPath) throw Object.assign(Error('absent'), { code: 'ENOENT' });
    const row = { isDirectory: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o700 };
    if (alteration?.path === value) Object.assign(row, alteration.fields);
    return row;
  }, realpath: async value => alteration?.alias === value ? value + '-alias' : value,
  access: async (value, mode) => { assert.equal(value, executablePath); assert.equal(mode, fs.constants.X_OK); } };
  const browser = { controlled: true };
  const fixture = values => load(values, false, { cwd: root, fs: io,
    puppeteer: { launch: async options => { launches.push(options); return browser; } } });
  const expectedArgs = ['--no-sandbox', '--disable-background-networking', '--disable-component-update',
    '--disable-domain-reliability', '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--proxy-server=http://blocked.invalid:9', '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]'];
  for (const role of ['vulnerable', 'fixed', 'customer']) {
    const input = { ...base, profile: path.join(tmp, 'owasp-ai-goat-listings-browser-' + role) };
    assert.equal(await fixture(env).launchStandaloneBrowser(input), browser);
    assert.deepEqual(launches.at(-1), { headless: true, userDataDir: input.profile, executablePath, args: expectedArgs });
  }
  await fixture({}).launchStandaloneBrowser({ ...base, receiptPath: null });
  assert.deepEqual(launches.at(-1), { headless: true, userDataDir: base.profile, executablePath });
  const assessment = { ...base, origin: undefined, assessment: true,
    launchOptions: { headless: true, timeout: 1234 } };
  assert.equal(await fixture(env).launchStandaloneBrowser(assessment), browser);
  assert.deepEqual(launches.at(-1), { headless: true, userDataDir: base.profile,
    executablePath, timeout: 1234, args: expectedArgs });
  const count = launches.length;
  const denied = async (input = base, values = env) => {
    await assert.rejects(fixture(values).launchStandaloneBrowser(input)); assert.equal(launches.length, count);
  };
  for (const origin of ['http://localhost:1234', 'https://127.0.0.1:1234', 'http://127.0.0.1:0',
    'http://127.0.0.1:65536', 'http://u:p@127.0.0.1:1234', 'http://127.0.0.1:1234/',
    'http://127.0.0.1:1234/x', 'http://127.0.0.1:1234?q=1', 'http://127.0.0.1:1234#x']) await denied({ ...base, origin });
  for (const [key, value] of [['root', root + '-other'], ['receiptPath', path.join(directory, 'foreign.json')],
    ['receiptPath', path.join(root, 'tasks/qualification/run-another123/standalone-listings-browser.json')],
    ['profile', path.join(tmp, 'foreign-profile')], ['profile', path.join(home, 'owasp-ai-goat-listings-browser-other')],
    ['executablePath', executablePath + '-changed']]) await denied({ ...base, [key]: value });
  for (const bad of [{ ...assessment, origin: base.origin },
    { ...assessment, receiptPath: null },
    { ...assessment, assessment: 1 },
    { ...assessment, assessment: 'true' },
    { ...assessment, assessment: null },
    { ...assessment, launchOptions: { headless: true, timeout: 499 } },
    { ...assessment, launchOptions: { headless: true, timeout: 30001 } },
    { ...assessment, launchOptions: { headless: true, timeout: 1234, args: ['--unrestricted'] } },
    { ...assessment, launchOptions: { headless: false, timeout: 1234 } }]) await denied(bad);
  for (const key of Object.keys(env)) await denied(base, { ...env, [key]: '/foreign' });
  for (const value of [directory, runtime, tmp, home, base.profile, env.XDG_CACHE_HOME, env.XDG_CONFIG_HOME]) {
    alteration = { path: value, fields: { uid: process.getuid() + 1 } }; await denied();
    alteration = { path: value, fields: { mode: 0o755 } }; await denied();
    alteration = { path: value, fields: { isSymbolicLink: () => true } }; await denied();
    alteration = { alias: value }; await denied();
  }
  alteration = { alias: executablePath }; await denied(); alteration = null;
});

test('actual qualifier facade preserves its result, launch failure, and fixture ownership', async () => {
  const { createXssBrowserQualification } = require('../server/services/xssBrowserQualification');
  const fixture = load(), diagnostic = { qualification: null, errors: [], active: true };
  let attempts = 0;
  const qualifier = createXssBrowserQualification({ puppeteer: { launch: async options => {
    attempts++;
    assert.deepEqual(options, { headless: true, timeout: 30000 });
    throw Error('controlled launch failure');
  } } });
  const facade = fixture.observeAssessmentQualification(qualifier, diagnostic);
  try {
    const result = await facade.qualify('<div>offline</div>');
    assert.equal(result.reason, 'qualification_error');
    assert.equal(result.executed, false);
    assert.equal(attempts, 1);
    assert.deepEqual(diagnostic.qualification, { reason: 'qualification_error', executed: false,
      targetEventExecuted: false, targetEffectObserved: false });
    assert.equal(await facade.qualify('<div>offline-again</div>').then(value => value.reason), 'qualification_error');
    assert.equal(attempts, 2);
    assert.equal(diagnostic.qualification.reason, 'qualification_error');
  } finally { await qualifier.close(); }
  let closes = 0;
  const raw = Object.freeze({ reason: 'browser_observed_effect', executed: true,
    targetEventExecuted: true, targetEffectObserved: true });
  const direct = fixture.observeAssessmentQualification({ qualify: async () => raw,
    qualifyDocument: async () => raw, qualifyClient: async () => raw,
    close: async () => { closes++; } }, { qualification: null, errors: [], active: true });
  assert.equal(await direct.qualify('source'), raw);
  await direct.close(); assert.equal(closes, 1);
  const opaque = Object.defineProperty({}, 'reason', { get() { throw Error('diagnostic getter'); } });
  const guarded = fixture.observeAssessmentQualification({ qualify: async () => opaque },
    { qualification: null, errors: [], active: true });
  assert.equal(await guarded.qualify('source'), opaque);
});

test('actual fixture composition forwards the owned qualifier only for its current-host receipt', async () => {
  const begin = source.indexOf('      let assessmentBrowserFacade;');
  const end = source.indexOf('      restoreRetrievalFactory?.();', begin);
  assert.ok(begin > 0 && end > begin);
  const run = vm.compileFunction('return (async()=>{ let composition,assessmentQualification; with(ctx) {'+
    source.slice(begin, end)+'} return {composition,assessmentQualification}; })();', ['ctx'], { filename });
  const root = path.resolve(__dirname, '..');
  const directory = path.join(root, 'tasks/qualification/run-controlled123');
  const tmp = path.join(directory, 'runtime/tmp');
  const profile = path.join(tmp, 'owasp-ai-goat-listings-browser-abc');
  const raw = { qualify: async () => ({ executed: false, reason: 'qualification_error' }),
    qualifyDocument: async () => ({}), qualifyClient: async () => ({}), close: async () => {} };
  for (const admitted of [true, false]) {
    let created = 0, captured, writes = 0;
    const ctx = { standalonePrivateReceipt: admitted, root,
      receiptPath: path.join(directory, 'standalone-listings-browser.json'),
      executablePath: '/controlled/chromium', assert, path,
      os: { tmpdir: () => tmp }, process: { env: { TMPDIR: tmp }, getuid: () => process.getuid() },
      fs: { mkdtemp: async prefix => { writes++; assert.equal(prefix, path.join(tmp, 'owasp-ai-goat-listings-browser-')); return profile; },
        lstat: async () => ({ isDirectory: () => true, isSymbolicLink: () => false,
          uid: process.getuid(), mode: 0o700 }), realpath: async value => value },
      assertStandaloneReceiptPath: async () => directory,
      profiles: [], assessmentDiagnostic: { qualification: null, errors: [], active: true },
      observeAssessmentQualification: load().observeAssessmentQualification,
      launchStandaloneBrowser: async () => { throw Error('must not launch'); },
      require: name => name.endsWith('xssBrowserQualification')
        ? { createXssBrowserQualification: () => { created++; return raw; } }
        : { createSecureShopBoundReviewComposition: options => {
          captured = options; return { browserQualification: options.browserQualification };
        } },
      identity: {}, agents: {}, review: {}, commerce: {}, reset: {}, grading: {}, scenes: {},
      modeAuthority: {}, SEARCH_ENABLED: false, CHAT_LISTINGS_ENABLED: false,
      objectiveIds: null, listingTemplateClient: null, OBJECTIVE: 'a', BROWSER_OBJECTIVE: 'b',
      TEMPLATE_OBJECTIVE: 'c', manualFiles: null, provider: {}, judge: () => {} };
    const result = await run(ctx);
    assert.equal(created, admitted ? 1 : 0);
    assert.equal(writes, admitted ? 1 : 0);
    assert.deepEqual(ctx.profiles, admitted ? [profile] : []);
    assert.equal(result.assessmentQualification, admitted ? raw : undefined);
    assert.equal(result.composition.browserQualification, captured.browserQualification);
    if (admitted) assert.equal((await captured.browserQualification.qualify('<div/>')).reason,
      'qualification_error');
    else assert.equal(Object.hasOwn(captured, 'browserQualification'), false);
    if (admitted) {
      ctx.os.tmpdir = () => '/outside-repository';
      await assert.rejects(run(ctx));
      assert.equal(writes, 1, 'bad TMPDIR rejected before any additional profile write');
    }
  }
});

test('assessment diagnostic captures only allowlisted bounded tokens', () => {
  const fixture = load(), diagnostic = { qualification: null, errors: [] };
  const secret = Object.assign(Error('secret request body'), { name: 'SecretName',
    code: 'SECRET_TOKEN', phase: 'secret_phase', cleanupErrorCode: 'SECRET_CLEANUP' });
  const outer = new AggregateError([secret, Object.assign(Error('retired'), {
    code: 'BROWSER_RETIREMENT_INCOMPLETE', phase: 'context_retirement' })], 'secret aggregate');
  outer.cause = Object.assign(Error('third'), { code: 'GRADE_STORE_NOT_READY' });
  fixture.captureAssessmentFailure(outer, diagnostic);
  assert.equal(diagnostic.errors.length, 3);
  assert.deepEqual(diagnostic.errors[0], { name: 'AggregateError', code: null,
    cleanupErrorCode: null, phase: null });
  assert.deepEqual(diagnostic.errors[2], { name: null, code: null,
    cleanupErrorCode: null, phase: null });
  fixture.captureAssessmentFailure(secret, diagnostic);
  assert.equal(diagnostic.errors.length, 3);
  assert.equal(JSON.stringify(diagnostic).includes('secret'), false);
});

test('actual browser assessment wrapper preserves result, original error, and retry method', async () => {
  const fixture = load(), diagnostic = { qualification: null, errors: [], active: false };
  const original = Object.assign(Error('secret body'), { code: 'GRADE_STORE_NOT_READY' });
  const result = Object.freeze({ completed: false, status: 'ineligible' });
  let inside = false, retryCalls = 0;
  const actual = { async runAttempt(input) {
    inside = diagnostic.active;
    if (input.fail) throw original;
    return result;
  }, async retryAttempt() { retryCalls++; return result; } };
  const observed = fixture.observeListingsBrowserAssessment(actual, diagnostic);
  assert.equal(await observed.runAttempt({ fail: false }), result);
  assert.equal(inside, true); assert.equal(diagnostic.active, false);
  await assert.rejects(observed.runAttempt({ fail: true }), error => error === original);
  assert.equal(diagnostic.active, false);
  assert.equal(diagnostic.errors.length, 1);
  assert.equal(diagnostic.errors[0].code, 'GRADE_STORE_NOT_READY');
  assert.equal(JSON.stringify(diagnostic).includes('secret'), false);
  assert.equal(await observed.retryAttempt(), result);
  assert.equal(retryCalls, 1);
  const opaqueError = Object.defineProperty(Error('primary'), 'code', {
    get() { throw Error('diagnostic getter'); } });
  const guarded = fixture.observeListingsBrowserAssessment({ runAttempt: async () => {
    throw opaqueError;
  } }, { qualification: null, errors: [], active: false });
  await assert.rejects(guarded.runAttempt({}), error => error === opaqueError);
});

test('actual original launch sites register profiles before launch and cleanup failures remain failures', async () => {
  const root = path.resolve(__dirname, '..'), receiptPath = path.join(root, 'tasks/qualification/run-browser123/standalone-listings-browser.json');
  const tmp = path.join(path.dirname(receiptPath), 'runtime/tmp'), executablePath = '/controlled/chromium';
  const starts = [source.indexOf('        const profile = await fs.mkdtemp', source.indexOf('async function importFromRendered')),
    source.indexOf('      const customerProfile = await fs.mkdtemp')];
  const ends = [source.indexOf('        const page = await browser.newPage', starts[0]),
    source.indexOf('      const customerPage = await customerBrowser.newPage', starts[1])];
  const browser = { close: async () => { throw Error('close failed'); } };
  for (const [role, site] of [['vulnerable', 0], ['fixed', 0], ['customer', 1]]) {
    const profiles = [], browsers = [], calls = [];
    const run = vm.compileFunction('return (async()=>{'+source.slice(starts[site], ends[site])+'})();',
      ['fs','os','profiles','browsers','launchStandaloneBrowser','root','receiptPath','standalonePrivateReceipt','app','vulnerableApp','executablePath','path'], { filename });
    const io = { mkdtemp: async prefix => { assert.equal(prefix, path.join(tmp, 'owasp-ai-goat-listings-browser-')); return prefix + role; } };
    const launch = async options => { assert.deepEqual(profiles, [options.profile]); calls.push(options); return browser; };
    await run(io, { tmpdir: () => tmp }, profiles, browsers, launch, root, receiptPath, true,
      { origin: 'http://127.0.0.1:1234' }, { origin: 'http://127.0.0.1:1234' }, executablePath, path);
    assert.deepEqual(browsers, [browser]); assert.equal(calls[0].receiptPath, receiptPath);
    profiles.length = 0; browsers.length = 0;
    await run(io, { tmpdir: () => tmp }, profiles, browsers, launch, root, receiptPath, false,
      { origin: 'http://127.0.0.1:1234' }, { origin: 'http://127.0.0.1:1234' }, executablePath, path);
    assert.equal(calls.at(-1).receiptPath, null); assert.deepEqual(browsers, [browser]);
    profiles.length = 0; browsers.length = 0;
    await assert.rejects(run(io, { tmpdir: () => tmp }, profiles, browsers, async options => {
      assert.deepEqual(profiles, [options.profile]); throw Error('launch failed');
    }, root, receiptPath, true, { origin: 'http://127.0.0.1:1234' }, { origin: 'http://127.0.0.1:1234' }, executablePath, path), /launch failed/);
    assert.equal(profiles.length, 1); assert.equal(browsers.length, 0);
  }
  const start = source.indexOf('      for (const browser of browsers.reverse())');
  const end = source.indexOf('      const finalPacket =', start);
  const cleanup = vm.compileFunction('return (async()=>{ const cleanupErrors=[],status={}; const servers=[],composition=null,reset=null,pools={},leasePool={end:async()=>{}}; const standalonePrivateReceipt=false; const assessmentDiagnostic={qualification:null,errors:[]}; const allowedAssessmentToken=()=>null; const ASSESSMENT_ERROR_CODES=new Set(); '+
    source.slice(start, end)+' return {cleanupErrors,status}; })();', ['browsers','profiles','fs','assessmentQualification'], { filename });
  const result = await cleanup([browser], ['/owned/profile'], { rm: async () => { throw Error('profile cleanup failed'); } }, null);
  assert.equal(result.status.fixtureCleaned, false); assert.equal(result.cleanupErrors.length, 2);
  let closed = 0, profileRemoved = 0;
  const failedQualification = { close: async () => { closed++; throw Error('secret unavailable'); } };
  const failure = await cleanup([], ['/owned/assessment-profile'], { rm: async () => { profileRemoved++; } }, failedQualification);
  assert.equal(closed, 1); assert.equal(profileRemoved, 1);
  assert.deepEqual(failure.cleanupErrors, ['assessment browser cleanup failed']);
  assert.equal(failure.status.fixtureCleaned, false);
});

test('actual merchant launch site binds only the admitted private receipt to bounded browser launch', async () => {
  const start = source.indexOf('        const profile = await fs.mkdtemp',
    source.indexOf('      } else if (CHAT_LISTINGS_ENABLED) {'));
  const end = source.indexOf('        const page = await browser.newPage', start);
  assert.ok(start > 0 && end > start);
  const launch = vm.compileFunction('return (async()=>{'+source.slice(start, end)+'return browser;})();',
    ['fs','os','path','profiles','browsers','launchStandaloneBrowser','root',
      'merchantPrivateReceipt','receiptPath','privateReceiptName','vulnerableApp',
      'executablePath'], { filename });
  const root = path.resolve(__dirname, '..');
  const receiptPath = path.join(root, 'tasks/qualification/run-merchant1234/merchant-listings-chat-browser.json');
  const tmp = path.join(path.dirname(receiptPath), 'runtime/tmp');
  const browser = {};
  for (const privateSelected of [true, false]) {
    const profiles = [], browsers = [], calls = [];
    const result = await launch({ mkdtemp: async prefix => {
      assert.equal(prefix, path.join(tmp, 'owasp-ai-goat-listings-browser-'));
      return prefix + 'owned';
    } }, { tmpdir: () => tmp }, path, profiles, browsers, async options => {
      assert.deepEqual(profiles, [options.profile]); calls.push(options); return browser;
    }, root, privateSelected, receiptPath, 'merchant-listings-chat-browser.json',
    { origin: 'http://127.0.0.1:1234' }, '/controlled/chromium');
    assert.equal(result, browser);
    assert.deepEqual(browsers, [browser]);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].receiptPath, privateSelected ? receiptPath : null);
    assert.equal(calls[0].receiptName, 'merchant-listings-chat-browser.json');
  }
});

test('standalone exact repository receipt admission and exclusive writer reject aliases and prior evidence', async () => {
  const fsp = require('node:fs/promises'), root = path.resolve(__dirname, '..');
  const owned = await fsp.mkdtemp(path.join(root, 'tasks/qualification/run-listings-receipt-'));
  const receipt = path.join(owned, 'standalone-listings-browser.json');
  const alias = owned + '-alias', fixture = load();
  try {
    await fsp.chmod(owned, 0o700);
    assert.equal(await fixture.assertStandaloneReceiptPath(root, receipt), owned);
    await assert.rejects(fixture.publishStandaloneReceipt(root, receipt, { bytes: 'x'.repeat(1024 * 1024) }), /bounded standalone receipt/);
    for (const invalid of [path.join(owned, 'other.json'), path.join(root, 'standalone-listings-browser.json'),
      path.join(root, 'tasks/tmp/standalone-listings-browser.json'), '/tmp/standalone-listings-browser.json',
      owned + '/../' + path.basename(owned) + '/standalone-listings-browser.json']) {
      await assert.rejects(fixture.assertStandaloneReceiptPath(root, invalid));
    }
    await fsp.chmod(owned, 0o755);
    await assert.rejects(fixture.assertStandaloneReceiptPath(root, receipt));
    await fsp.chmod(owned, 0o700);
    await fsp.symlink(owned, alias);
    await assert.rejects(fixture.assertStandaloneReceiptPath(root, path.join(alias, path.basename(receipt))));
    await fsp.symlink(path.join(owned, 'absent-target'), receipt);
    await assert.rejects(fixture.assertStandaloneReceiptPath(root, receipt));
    await assert.rejects(fixture.publishStandaloneReceipt(root, receipt, { passed: true }));
    await fsp.unlink(receipt);
    const raced = load({}, false, { fs: { ...fsp, open: async (...args) => {
      await fsp.writeFile(receipt, 'raced original', { flag: 'wx', mode: 0o600 });
      return fsp.open(...args);
    } } });
    await assert.rejects(raced.publishStandaloneReceipt(root, receipt, { passed: true }),
      error => error?.code === 'EEXIST');
    assert.equal(await fsp.readFile(receipt, 'utf8'), 'raced original');
    await fsp.unlink(receipt);
    await fixture.publishStandaloneReceipt(root, receipt, { passed: false, failure: 'preserved' });
    const original = await fsp.readFile(receipt);
    assert.deepEqual(JSON.parse(original), { passed: false, failure: 'preserved' });
    assert.equal((await fsp.stat(receipt)).mode & 0o777, 0o600);
    await assert.rejects(fixture.publishStandaloneReceipt(root, receipt, { passed: true }));
    assert.deepEqual(await fsp.readFile(receipt), original);
  } finally { await fsp.rm(alias, { force: true }); await fsp.rm(owned, { recursive: true }); }
});

test('standalone writer bounds bytes before open and joins close on write or sync failure', async () => {
  const root = path.resolve(__dirname, '..'), receipt = path.join(root,
    'tasks/qualification/run-controlled123/standalone-listings-browser.json');
  let closed = 0, written = 0, opened = 0, failure = 'sync';
  const stat = { isDirectory: () => true, isSymbolicLink: () => false, mode: 0o700, uid: process.getuid() };
  const io = { realpath: async value => value,
    lstat: async value => { if (value === receipt) throw Object.assign(Error('absent'), { code: 'ENOENT' }); return stat; },
    open: async (value, flags, mode) => {
      opened++;
      const C = require('node:fs').constants;
      assert.equal(value, receipt); assert.equal(flags, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW);
      assert.equal(mode, 0o600);
      return { stat: async () => ({ isFile: () => true, mode: 0o600, uid: process.getuid(), nlink: 1 }),
        writeFile: async () => { written++; if (failure === 'write') throw Error('controlled write failure'); },
        sync: async () => { throw Error('controlled sync failure'); },
        close: async () => { closed++; } };
    } };
  const fixture = load({}, false, { fs: io });
  const circular = {}; circular.self = circular;
  await assert.rejects(fixture.publishStandaloneReceipt(root, receipt, circular), /circular/i);
  await assert.rejects(fixture.publishStandaloneReceipt(root, receipt, { text: 'x'.repeat(1024 * 1024) }), /bounded standalone receipt/);
  assert.equal(opened, 0);
  await assert.rejects(fixture.publishStandaloneReceipt(root, receipt, { passed: false }), /controlled sync failure/);
  assert.equal(written, 1); assert.equal(closed, 1);
  failure = 'write';
  await assert.rejects(fixture.publishStandaloneReceipt(root, receipt, { passed: false }), /controlled write failure/);
  assert.equal(written, 2); assert.equal(closed, 2); assert.equal(opened, 2);
  stat.uid++;
  await assert.rejects(fixture.assertStandaloneReceiptPath(root, receipt));
  assert.equal(written, 2);
});

test('actual final publication preserves a primary failure and rejects publication-only failure', async () => {
  const start = source.indexOf('      if (RECOVERY_ENABLED) {', source.indexOf('const finalPacket ='));
  const end = source.indexOf('\n    }\n    if (failure)', start);
  const failureEnd = source.indexOf('    assert.deepEqual(cleanupErrors, []);', end);
  assert.ok(start > 0 && end > start && failureEnd > end);
  const body = source.slice(start, end) + source.slice(end + '\n    }\n'.length, failureEnd);
  const run = vm.compileFunction('return (async()=>{'+body+'})();',
    ['RECOVERY_ENABLED','manualRecovery','privateListingsReceipt','privateReceiptName',
      'publishStandaloneReceipt','root','receiptPath','finalPacket','failure',
      'publicationFailure','fs'], { filename });
  const publication = Object.assign(Error('publication denied'), { code: 'EEXIST' });
  const publish = async (_root, _path, _packet, expectedName) => {
    assert.ok(['standalone-listings-browser.json', 'merchant-listings-chat-browser.json']
      .includes(expectedName));
    throw publication;
  };
  for (const name of ['standalone-listings-browser.json', 'merchant-listings-chat-browser.json']) {
    const original = Error('original scenario failure');
    await assert.rejects(run(false, {}, true, name, publish, '/', '/receipt',
      { passed: false }, original, null, {}),
    error => error === original && error.receiptPublicationCode === 'EEXIST');
    await assert.rejects(run(false, {}, true, name, publish, '/', '/receipt',
      { passed: true }, null, null, {}), error => error === publication);
  }
});

test('actual standalone entry admits only its exact repo receipt before build or resource work', async () => {
  const fsp = require('node:fs/promises'), root = path.resolve(__dirname, '..');
  const owned = await fsp.mkdtemp(path.join(root, 'tasks/qualification/run-listings-entry-'));
  const receipt = path.join(owned, 'standalone-listings-browser.json');
  const env = { OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: root, SECURESHOP_STANDALONE_LISTINGS_NATIVE: '1',
    PG_TEST_DISPOSABLE: 'yes', LIVE_OLLAMA_TEST: '1', SECURESHOP_STANDALONE_LISTINGS_EVIDENCE_PATH: receipt };
  for (const store of ['IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE']) for (const role of ['MIGRATION', 'RUNTIME'])
    env[`PG_SECURESHOP_STANDALONE_LISTINGS_${store}_${role}_URL`] = 'controlled-unused';
  let accesses = 0;
  const io = { ...fsp, access: async () => { accesses++; throw Error('controlled build boundary'); } };
  try {
    await fsp.chmod(owned, 0o700);
    const admitted = load(env, false, { cwd: root, fs: io });
    await assert.rejects(admitted.runStandaloneListingsQualification(), /controlled build boundary/);
    assert.equal(accesses, 1); assert.equal(admitted.allocations(), 0);
    for (const selector of ['SECURESHOP_MERCHANT_LISTINGS_CHAT_BROWSER_NATIVE',
      'SECURESHOP_PRODUCT_MANUAL_BROWSER_NATIVE', 'SECURESHOP_MERCHANT_MANUAL_SEARCH_BROWSER_NATIVE',
      'SECURESHOP_LISTING_GENERATED_BROWSER_FIXED_NATIVE', 'SECURESHOP_LISTING_IMPORT_VULNERABILITY_BROWSER_NATIVE',
      'SECURESHOP_PRODUCT_MANUAL_RECOVERY_BROWSER_NATIVE']) {
      const other = load({ ...env, [selector]: '1',
        SECURESHOP_MERCHANT_LISTINGS_CHAT_BROWSER_EVIDENCE_PATH: receipt,
        SECURESHOP_PRODUCT_MANUAL_EVIDENCE_PATH: receipt,
        SECURESHOP_MERCHANT_MANUAL_SEARCH_EVIDENCE_PATH: receipt,
        SECURESHOP_PRODUCT_MANUAL_RECOVERY_EVIDENCE_PATH: receipt,
        SECURESHOP_LISTING_GENERATED_BROWSER_FIXED_EVIDENCE_PATH: receipt }, false, { cwd: root, fs: io });
      await assert.rejects(other.runStandaloneListingsQualification());
      assert.equal(accesses, 1); assert.equal(other.allocations(), 0);
    }
    const scenarioEnv = { ...env, SECURESHOP_LISTING_IMPORT_VULNERABILITY_BROWSER_NATIVE: '1' };
    delete scenarioEnv.SECURESHOP_STANDALONE_LISTINGS_NATIVE;
    const scenario = load(scenarioEnv, false, { cwd: root, fs: io });
    await assert.rejects(scenario.runStandaloneListingsQualification({ exercise: async () => {},
      objectiveIds: ['ss_listing_prototype_mutation','ss_listing_external_entity'], receiptPath: receipt }));
    assert.equal(accesses, 1); assert.equal(scenario.allocations(), 0);
    // Legacy outside-root admission remains inert here: stop at build access,
    // never allocate or create an outside-repository artifact.
    const legacy = load({ ...env, SECURESHOP_STANDALONE_LISTINGS_EVIDENCE_PATH:
      '/legacy-private/standalone-listings-browser.json' }, false, { cwd: root, fs: io });
    await assert.rejects(legacy.runStandaloneListingsQualification(), /controlled build boundary/);
    assert.equal(accesses, 2); assert.equal(legacy.allocations(), 0);
  } finally { await fsp.rm(owned, { recursive: true }); }
});

test('direct default execution remains explicitly gated and resource-free when disabled', async () => {
  const fixture = load({}, true);
  assert.equal(fixture.registered.length, 1);
  assert.equal(fixture.registered[0][1].skip, true);
  assert.equal(fixture.registered[0][1].timeout, 540000);
  await assert.rejects(fixture.registered[0][2](), /Explicit disposable native cohort/);
  assert.equal(fixture.allocations(), 0);
});

test('scenario options cannot omit isolation, expand objectives or collide with an existing cohort', async () => {
  const options = { exercise: async () => { throw Error('Must not enter'); },
    objectiveIds: ['ss_listing_prototype_mutation', 'ss_listing_external_entity'], receiptPath: '/private/receipt.json' };
  const scenarios = [
    [{}, options, /'1'/],
    [{ SECURESHOP_LISTING_IMPORT_VULNERABILITY_BROWSER_NATIVE: '1' }, options, /'yes'/],
    [{ SECURESHOP_LISTING_IMPORT_VULNERABILITY_BROWSER_NATIVE: '1', PG_TEST_DISPOSABLE: 'yes' }, options, /'1'/],
    [{ SECURESHOP_STANDALONE_LISTINGS_NATIVE: '1' }, options, /also activate/],
    [{}, { ...options, objectiveIds: ['ss_listing_internal_fetch'] }],
    [{}, { ...options, extra: true }],
  ];
  for (const [env, input, expected] of scenarios) {
    const fixture = load(env);
    await assert.rejects(fixture.runStandaloneListingsQualification(input), expected);
    assert.equal(fixture.allocations(), 0);
  }
});

test('scenario remains within the one existing cleanup boundary and cannot publish cleanup success', () => {
  const start = source.indexOf('    try {\n      status.isolatedStores = true;');
  const callback = source.indexOf('const result = await exercise(');
  const catchStart = source.indexOf('    } catch (error) {\n      failure = error;', callback);
  const finalizer = source.indexOf('    finally {', catchStart);
  const finalCheck = source.indexOf('    if (failure) {', finalizer);
  assert(start > 0 && callback > start && catchStart > callback && finalizer > catchStart && finalCheck > finalizer);
  assert(source.slice(callback, catchStart).includes("Object.hasOwn(result, 'fixtureCleaned'), false"));
  const cleanup = source.slice(finalizer, finalCheck);
  for (const text of ['restoreFetch?.()', 'browser.close()', 'closeServer(server)',
    'closeFeatureTransports()', 'pool.end()', 'fs.rm(profile', 'status.fixtureCleaned = cleanupErrors.length === 0']) {
    assert(cleanup.includes(text), text);
  }
  assert(cleanup.indexOf('status.fixtureCleaned =') < cleanup.indexOf('fs.writeFile(receiptPath'));
  const failureBranch=source.slice(finalCheck,source.indexOf('    assert.deepEqual(cleanupErrors, []);',finalCheck));
  assert(failureBranch.includes('failure.receiptPublicationCode ='));
  assert(failureBranch.includes('throw failure;'));
  assert(failureBranch.includes('if (publicationFailure) throw publicationFailure;'));
});

test('import sibling enrolls a distinct tenant before fresh authentication and uses its exact scoped service', async () => {
  const fixture = load(), calls = [];
  const principal = { principalId: 'peer-principal', shopUserId: 1000000001 };
  const base = { session: 'fresh' }, tenant = { tenantId: 'peer-tenant', principalId: principal.principalId };
  const service = {
    async authenticate(token) { calls.push('authenticate'); assert.equal(token, 'fresh-token'); return base; },
    async establishTenantContext(input) { calls.push('context'); assert.equal(input, base); return tenant; },
  };
  const result = await fixture.createImportSiblingTenant({
    migration: { async query(sql, values) { calls.push({ sql, values }); return { rowCount: 1 }; } },
    auth: { async login(input) { calls.push('login'); assert.deepEqual(input, { username: 'peer', password: 'private' }); return { token: 'fresh-token' }; } },
    repositoryFactory(options) { calls.push('repository'); assert.deepEqual(options, { executionTenantSlug: 'peer-slug' }); return 'scoped'; },
    authFactory(repository) { calls.push('service'); assert.equal(repository, 'scoped'); return service; },
    principal, username: 'peer', password: 'private', tenantId: 'peer-tenant', slug: 'peer-slug',
  });
  assert.match(calls[0].sql, /INSERT INTO secureshop_auth.tenants/);
  assert.deepEqual(calls[0].values, ['peer-tenant', 'peer-slug']);
  assert.match(calls[1].sql, /INSERT INTO secureshop_auth.tenant_memberships/);
  assert.deepEqual(calls[1].values, ['peer-tenant', principal.principalId, principal.shopUserId, 'merchant']);
  assert.match(calls[2].sql, /SET seed_merchant_id=\$2/);
  assert.deepEqual(calls[2].values, ['peer-tenant', principal.shopUserId]);
  assert.deepEqual(calls.slice(3), ['login', 'repository', 'service', 'authenticate', 'context']);
  assert.equal(result.service, service); assert.equal(result.base, base); assert.equal(result.tenant, tenant);
});

test('import sibling rejects a returned default tenant or substituted principal', async () => {
  const fixture = load();
  for (const tenant of [{ tenantId: 'default', principalId: 'peer' }, { tenantId: 'isolated', principalId: 'foreign' }]) {
    await assert.rejects(fixture.createImportSiblingTenant({
      migration: { async query() { return { rowCount: 1 }; } },
      auth: { async login() { return { token: 'fresh' }; } },
      repositoryFactory: () => ({}),
      authFactory: () => ({ authenticate: async () => ({}), establishTenantContext: async () => tenant }),
      principal: { principalId: 'peer', shopUserId: 1000000001 },
      username: 'peer', password: 'private', tenantId: 'isolated', slug: 'isolated',
    }));
  }
});
