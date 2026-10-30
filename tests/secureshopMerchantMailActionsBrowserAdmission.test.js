'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const syncFs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { buildInventory } = require('./postgres/adminQ05RenderedScenario');
const { admitMerchantMailActionsBrowser, validateMerchantMailActionsGrant } =
  require('./fixtures/secureshopMerchantMailActionsBrowserAdmission');

const ROOT = path.resolve(__dirname, '..');
const HELPER = path.join(ROOT, 'tests/fixtures/secureshopMerchantMailActionsBrowserAdmission.js');
const SHA = 'a'.repeat(64);

async function owned(t) {
  assert.equal(process.cwd(), ROOT);
  const parent = path.join(ROOT, 'tasks/qualification');
  await fs.mkdir(parent, { recursive: true });
  const run = await fs.mkdtemp(path.join(parent, 'run-mail-actions-contract-'));
  t.after(() => fs.rm(run, { recursive: true, force: true }));
  const runtime = path.join(run, 'runtime'), temp = path.join(runtime, 'tmp');
  await fs.mkdir(runtime, { mode: 0o700 });
  await fs.mkdir(temp, { mode: 0o700 });
  const profile = await fs.mkdtemp(path.join(temp, 'owasp-ai-goat-role-mail-actions-'));
  const evidencePath = path.join(run, 'merchant-mail-actions-browser.json');
  const executablePath = syncFs.realpathSync(process.execPath);
  const buildSha256 = (await buildInventory(path.join(ROOT, 'client/build'))).sha256;
  const env = {
    SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_NATIVE: '1',
    SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_EVIDENCE_PATH: evidencePath,
    SECURESHOP_MAIL_ACTIONS_TEST_NO_SANDBOX: '1',
    SECURESHOP_MAIL_ACTIONS_ADMISSION_FD: '3',
    SECURESHOP_MAIL_ACTIONS_SNAPSHOT_SHA256: SHA,
    SECURESHOP_MAIL_ACTIONS_BUILD_SHA256: buildSha256,
    SECURESHOP_MAIL_ACTIONS_BROWSER_SHA256: 'b'.repeat(64),
    SECURESHOP_MAIL_ACTIONS_BROWSER_RECORD_PATH: path.join(run, 'merchant-mail-actions-browser-birth.json'),
    SECURESHOP_MAIL_ACTIONS_BROWSER_ACK_PATH: path.join(run, 'merchant-mail-actions-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT: path.join(ROOT, 'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON: syncFs.realpathSync('/usr/bin/python3'),
    PUPPETEER_EXECUTABLE_PATH: executablePath,
    PG_TEST_DISPOSABLE: 'yes', LIVE_OLLAMA_TEST: '1', NODE_ENV: 'test',
    OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: ROOT, TMPDIR: temp, MAC_CHROMIUM_TMPDIR: temp,
  };
  return { run, profile, evidencePath, executablePath, env };
}

test('mail-actions FIFO grant is exact, cohort-specific, and binds direct parent, build, source and browser', () => {
  const context = { workspace: ROOT,
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/merchant-mail-actions-browser.json'),
    buildSha256: SHA, snapshotSha256: 'b'.repeat(64), chromium: '/pinned/chromium',
    chromiumSha256: 'c'.repeat(64), launcherPid: 41, workerPid: 42 };
  const grant = { version: 1, cohort: 'merchant-mail-actions-browser', launcherPid: 41,
    workerPid: 42, nonce: 'd'.repeat(64), workspace: context.workspace,
    evidencePath: context.evidencePath, buildSha256: context.buildSha256,
    snapshotSha256: context.snapshotSha256, outerSandbox: 'repository-only',
    chromium: context.chromium, chromiumSha256: context.chromiumSha256 };
  assert.deepEqual(validateMerchantMailActionsGrant(grant, context), { admitted: true });
  for (const [key, wrong] of Object.entries({ cohort: 'standalone-commerce-browser', launcherPid: 43,
    workerPid: 43, nonce: 'short', workspace: '/other', evidencePath: '/other.json',
    buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
    outerSandbox: 'unrestricted', chromium: '/other', chromiumSha256: '0'.repeat(64) }))
    assert.throws(() => validateMerchantMailActionsGrant({ ...grant, [key]: wrong }, context), key);
  assert.throws(() => validateMerchantMailActionsGrant({ ...grant, profile: '/foreign' }, context));
  assert.throws(() => validateMerchantMailActionsGrant({ ...grant, version: 2 }, context));
});

test('ordinary mail-actions evidence remains external; opt-in rejects other cohorts and altered pins or paths', async t => {
  const { evidencePath, executablePath, env } = await owned(t);
  const external = path.join(path.dirname(ROOT), 'external-mail-actions-evidence.json');
  assert.equal(await admitMerchantMailActionsBrowser({},
    { workspace: ROOT, evidencePath: external, executablePath }), null);
  await assert.rejects(admitMerchantMailActionsBrowser({},
    { workspace: ROOT, evidencePath, executablePath }), /outside/);
  const admit = values => admitMerchantMailActionsBrowser(values,
    { workspace: ROOT, evidencePath, executablePath });
  await assert.rejects(admit({ ...env, SECURESHOP_MAIL_ACTIONS_TEST_NO_SANDBOX: '0' }));
  await assert.rejects(admit({ ...env, SECURESHOP_MERCHANT_MAIL_BROWSER_NATIVE: '1' }), /different cohort/);
  await assert.rejects(admit({ ...env, SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE: '1' }), /different cohort/);
  await assert.rejects(admit({ ...env, LIVE_OLLAMA_TEST: '0' }));
  await assert.rejects(admit({ ...env, TMPDIR: '/private/tmp' }));
  await assert.rejects(admit({ ...env, MAC_CHROMIUM_TMPDIR: '/private/tmp' }));
  await assert.rejects(admit({ ...env, SECURESHOP_MAIL_ACTIONS_BUILD_SHA256: '0'.repeat(64) }), /build pin mismatch/);
  await assert.rejects(admit({ ...env, SECURESHOP_MAIL_ACTIONS_ADMISSION_FD: '1' }), /pipe/);
});

test('one inherited FIFO is consumed before browser arguments; only exact loopback origin and one owned page pass', async t => {
  const { profile, evidencePath, executablePath, env } = await owned(t);
  const childScript = `const fs=require('node:fs');const assert=require('node:assert/strict');`
    + `const {EventEmitter}=require('node:events');`
    + `const {admitMerchantMailActionsBrowser}=require(${JSON.stringify(HELPER)});`
    + `const descriptor=Number(process.env.SECURESHOP_MAIL_ACTIONS_ADMISSION_FD);`
    + `const closed=()=>{try{fs.fstatSync(descriptor);return false}catch(e){return e.code==='EBADF'}};`
    + `(async()=>{const admission=await admitMerchantMailActionsBrowser(process.env,`
    + `{workspace:process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH});`
    + `const browser=new EventEmitter();const boundary=admission.watchBrowserTargets(browser);`
    + `let intercept=false,continued=0,aborted=0,unexpectedPageClosed=0;`
    + `const page=new EventEmitter();page.setRequestInterception=async value=>{intercept=value};`
    + `const context={newPage:async()=>{browser.emit('targetcreated',{type:()=> 'page'});return page}};`
    + `assert.equal(await boundary.newPage(context),page);`
    + `await admission.guardPageRequests(page,'http://127.0.0.1:39117');`
    + `for(const url of ['http://127.0.0.1:39117/ok','http://127.0.0.1:39118/no',`
    + `'https://example.invalid/no'])`
    + `page.emit('request',{url:()=>url,continue:()=>{continued++},abort:()=>{aborted++}});`
    + `boundary.assertNoUnexpectedTargets();`
    + `browser.emit('targetcreated',{type:()=> 'service_worker'});`
    + `assert.throws(()=>boundary.assertNoUnexpectedTargets());`
    + `const browser2=new EventEmitter();const boundary2=admission.watchBrowserTargets(browser2);`
    + `browser2.emit('targetcreated',{type:()=> 'page',`
    + `page:async()=>({close:async()=>{unexpectedPageClosed++}})});`
    + `await new Promise(resolve=>setImmediate(resolve));`
    + `assert.throws(()=>boundary2.assertNoUnexpectedTargets());`
    + `console.log(JSON.stringify({closed:closed(),cleared:!process.env.SECURESHOP_MAIL_ACTIONS_ADMISSION_FD,`
    + `args:admission.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}),`
    + `intercept,continued,aborted,unexpectedPageClosed}));`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import json, os, subprocess\n`
    + `read, write = os.pipe()\n`
    + `env = os.environ.copy()\n`
    + `env['SECURESHOP_MAIL_ACTIONS_ADMISSION_FD'] = str(read)\n`
    + `child = subprocess.Popen([env['TEST_NODE_BIN'], '-e', env['TEST_NODE_SCRIPT']], cwd=env['TEST_ROOT'], env=env, pass_fds=(read,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n`
    + `os.close(read)\n`
    + `grant = dict(version=1, cohort='merchant-mail-actions-browser', launcherPid=os.getpid(), workerPid=child.pid, nonce='d'*64, workspace=env['TEST_ROOT'], evidencePath=env['SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_EVIDENCE_PATH'], buildSha256=env['SECURESHOP_MAIL_ACTIONS_BUILD_SHA256'], snapshotSha256=env['SECURESHOP_MAIL_ACTIONS_SNAPSHOT_SHA256'], outerSandbox='repository-only', chromium=env['PUPPETEER_EXECUTABLE_PATH'], chromiumSha256=env['SECURESHOP_MAIL_ACTIONS_BROWSER_SHA256'])\n`
    + `os.write(write, json.dumps(grant).encode())\n`
    + `os.close(write)\n`
    + `out, err = child.communicate(timeout=15)\n`
    + `print(json.dumps(dict(code=child.returncode, out=out, err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 25000,
    env: { ...process.env, ...env, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  const completed = JSON.parse(result.stdout.trim());
  assert.equal(completed.code, 0, completed.err);
  const child = JSON.parse(completed.out.trim());
  assert.equal(child.closed, true);
  assert.equal(child.cleared, true);
  assert(child.args.includes('--no-sandbox'));
  assert(child.args.includes('--proxy-server=http://blocked.invalid:9'));
  assert.deepEqual({ intercept: child.intercept, continued: child.continued,
    aborted: child.aborted, unexpectedPageClosed: child.unexpectedPageClosed },
  { intercept: true, continued: 1, aborted: 2, unexpectedPageClosed: 1 });
  assert.equal(evidencePath, env.SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_EVIDENCE_PATH);
  assert.equal(executablePath, env.PUPPETEER_EXECUTABLE_PATH);
});

test('mail-actions fixture admits before setup, ACKs before first page, and preserves original five-turn criteria', async () => {
  const fixture = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const admit = fixture.indexOf('const mailActionsAdmission = MERCHANT_MAIL_ACTIONS_BROWSER');
  const pools = fixture.indexOf('const pools = Object.fromEntries(STORES.flatMap');
  const ack = fixture.indexOf('await mailActionsAdmission.acknowledgeBrowser({ browser, profile })');
  const page = fixture.indexOf('const page = mailActionsBoundary ? await mailActionsBoundary.newPage(browser)');
  assert.ok(admit > 0 && pools > admit && ack > pools && page > ack);
  assert.match(fixture, /mailActionsAdmission\.guardPageRequests\(page, origin\)/);
  assert.match(fixture, /mailActionsBoundary\?\.assertNoUnexpectedTargets\(\)/);
  assert.match(fixture, /profile && !policyInstructionBrowserAdmission && !mailActionsAdmission && !q05BrowserAdmission && fs\.rm\(profile/);
  assert.match(fixture, /timeout: ADMIN_POLICY_BROWSER \? 840000 : 600000/);
  assert.match(fixture, /assert\.equal\(chats\(\)\.length, 5\)/);
  assert.match(fixture, /assert\.ok\(mailActionWireCalls <= 30/);
  assert.match(fixture, /assert\.equal\(getJudgeCalls\(\), 0\); status\.zeroJudge = true/);
  assert.match(fixture, /mailActionFault\.armed = true/);
});

test('mail-actions production mail composition receives the real tenant publication repository without changing Judge policy', async () => {
  const fixture = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const production = await fs.readFile(path.join(ROOT,
    'server/services/secureshopMailProduction.js'), 'utf8');
  const assessment = await fs.readFile(path.join(ROOT,
    'server/services/secureshopMailHtmlInjectionAssessment.js'), 'utf8');
  assert.match(production, /createMailHtmlInjectionAssessment\(\{\.\.\.guardedDependencies/);
  assert.match(assessment, /publicationModes\?\.getEvaluationScope/);
  assert.match(fixture, /const modeRepository = require\('\.\.\/\.\.\/server\/database\/postgres\/secureshopModeRepository'\)\.createSecureShopModeRepository\(identity\)/);
  const mailFactory = fixture.indexOf('mailProduction = await makeMail({');
  const conditional = fixture.indexOf('MERCHANT_MAIL_ACTIONS_BROWSER || MAIL_HEADER_BROWSER || MAIL_HTML_BROWSER || V11_MAIL_READ_BROWSER', mailFactory);
  const publication = fixture.indexOf('? { publicationModes: modeRepository } : {})', conditional);
  assert.ok(mailFactory > 0 && conditional > mailFactory && publication > conditional);
  assert.match(fixture, /const judge = CONFIGURED_CAPTURE_BROWSER \? systemJudge : async input => \{\s*judgeCalls \+= 1;/);
  assert.match(fixture, /throw new Error\('Role choices must not invoke a Judge'\)/);
  assert.match(fixture, /assert\.equal\(getJudgeCalls\(\), 0\); status\.zeroJudge = true/);
});
