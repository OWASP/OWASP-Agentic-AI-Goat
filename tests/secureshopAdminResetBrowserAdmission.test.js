'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const syncFs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const { buildInventory } = require('./postgres/adminQ05RenderedScenario');
const { admitAdminResetBrowser, validateGrant } =
  require('./fixtures/secureshopAdminResetBrowserAdmission');

const ROOT = path.resolve(__dirname, '..');
const HELPER = path.join(ROOT, 'tests/fixtures/secureshopAdminResetBrowserAdmission.js');
const SHA = 'a'.repeat(64);

async function owned(t) {
  assert.equal(process.cwd(), ROOT);
  const parent = path.join(ROOT, 'tasks/qualification');
  await fs.mkdir(parent, { recursive: true, mode: 0o700 });
  const run = await fs.mkdtemp(path.join(parent, 'run-admin-reset-contract-'));
  t.after(() => fs.rm(run, { recursive: true, force: true }));
  const runtime = path.join(run, 'runtime'), temp = path.join(runtime, 'tmp');
  await fs.mkdir(runtime, { mode: 0o700 });
  await fs.mkdir(temp, { mode: 0o700 });
  const profile = await fs.mkdtemp(path.join(temp, 'dvaia-role-admin-reset-'));
  const evidencePath = path.join(run, 'admin-password-reset-chat-browser.json');
  const executablePath = syncFs.realpathSync(process.execPath);
  const buildSha256 = (await buildInventory(path.join(ROOT, 'client/build'))).sha256;
  const env = {
    SECURESHOP_ADMIN_PASSWORD_RESET_CHAT_BROWSER_NATIVE: '1',
    SECURESHOP_ADMIN_PASSWORD_RESET_CHAT_BROWSER_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_ADMIN_PASSWORD_RESET_CHAT_BROWSER_EVIDENCE_PATH: evidencePath,
    SECURESHOP_ADMIN_RESET_BROWSER_TEST_NO_SANDBOX: '1',
    SECURESHOP_ADMIN_RESET_BROWSER_ADMISSION_FD: '3',
    SECURESHOP_ADMIN_RESET_BROWSER_SNAPSHOT_SHA256: SHA,
    SECURESHOP_ADMIN_RESET_BROWSER_BUILD_SHA256: buildSha256,
    SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_SHA256: 'b'.repeat(64),
    SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_RECORD_PATH: path.join(run, 'admin-reset-browser-birth.json'),
    SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_ACK_PATH: path.join(run, 'admin-reset-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT: path.join(ROOT, 'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON: syncFs.realpathSync('/usr/bin/python3'),
    PUPPETEER_EXECUTABLE_PATH: executablePath,
    PG_TEST_DISPOSABLE: 'yes', LIVE_OLLAMA_TEST: '1', NODE_ENV: 'test',
    DVAIA_CURRENT_MAIN_WORKSPACE: ROOT, TMPDIR: temp, MAC_CHROMIUM_TMPDIR: temp,
    DOCKER_HOST: `unix://${ROOT}/.qualification/goat-q/docker.sock`,
  };
  return { run, profile, evidencePath, executablePath, env };
}

test('reset browser grant is exact and cannot alias another cohort or authority', () => {
  const context = { workspace: ROOT,
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/admin-password-reset-chat-browser.json'),
    buildSha256: SHA, snapshotSha256: 'b'.repeat(64), chromium: '/pinned/chromium',
    chromiumSha256: 'c'.repeat(64), launcherPid: 41, workerPid: 42 };
  const grant = { version: 1, cohort: 'admin-password-reset-chat-browser', launcherPid: 41,
    workerPid: 42, nonce: 'd'.repeat(64), workspace: context.workspace,
    evidencePath: context.evidencePath, buildSha256: context.buildSha256,
    snapshotSha256: context.snapshotSha256, outerSandbox: 'repository-only',
    chromium: context.chromium, chromiumSha256: context.chromiumSha256 };
  assert.equal(validateGrant(grant, context), true);
  for (const [key, wrong] of Object.entries({ cohort: 'admin-user-chat-browser', launcherPid: 43,
    workerPid: 43, nonce: 'short', workspace: '/other', evidencePath: '/other.json',
    buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
    outerSandbox: 'unrestricted', chromium: '/other', chromiumSha256: '0'.repeat(64) }))
    assert.throws(() => validateGrant({ ...grant, [key]: wrong }, context), key);
  assert.throws(() => validateGrant({ ...grant, profile: '/foreign' }, context));
});

test('reset evidence admission rejects wrong identity, selector, path, mode and preexisting receipt', async t => {
  const { run, evidencePath, executablePath, env } = await owned(t);
  const admit = values => admitAdminResetBrowser(values,
    { workspace: ROOT, evidencePath, executablePath });
  await assert.rejects(admit({ ...env, SECURESHOP_ADMIN_RESET_BROWSER_TEST_NO_SANDBOX: '0' }));
  const ordinary = { ...env };
  delete ordinary.SECURESHOP_ADMIN_RESET_BROWSER_TEST_NO_SANDBOX;
  delete ordinary.SECURESHOP_ADMIN_RESET_BROWSER_ADMISSION_FD;
  await assert.rejects(admit(ordinary));
  await assert.rejects(admit({ ...env, SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE: '1' }));
  await assert.rejects(admit({ ...env, LIVE_OLLAMA_TEST: '0' }));
  await assert.rejects(admit({ ...env, DOCKER_HOST: 'unix:///private/tmp/foreign/docker.sock' }));
  await assert.rejects(admit({ ...env, TMPDIR: '/private/tmp' }));
  await assert.rejects(admit({ ...env, SECURESHOP_ADMIN_RESET_BROWSER_BUILD_SHA256: '0'.repeat(64) }));
  await assert.rejects(admit({ ...env, SECURESHOP_ADMIN_RESET_BROWSER_ADMISSION_FD: '1' }));
  await assert.rejects(admitAdminResetBrowser(env, { workspace: ROOT,
    evidencePath: path.join(run, 'wrong.json'), executablePath }));
  await fs.writeFile(evidencePath, '{}', { mode: 0o600 });
  await assert.rejects(admit(env));
  await fs.rm(evidencePath);
  await fs.chmod(run, 0o755);
  await assert.rejects(admit(env));
});

test('inherited reset grant admits exactly two physical pages, guards both and closes an unsolicited target', async t => {
  const { profile, evidencePath, executablePath, env } = await owned(t);
  const childScript = `const fs=require('node:fs');const assert=require('node:assert/strict');`
    + `const {EventEmitter}=require('node:events');`
    + `require(${JSON.stringify(path.join(ROOT, 'tests/fixtures/secureshopDarwinBrowserBirth.js'))}).captureBrowserRecord=({kind,pid})=>({kind,pid,birth:[11,22]});`
    + `const {admitAdminResetBrowser}=require(${JSON.stringify(HELPER)});`
    + `(async()=>{const admission=await admitAdminResetBrowser(process.env,`
    + `{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_ADMIN_PASSWORD_RESET_CHAT_BROWSER_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH});`
    + `const browser=new EventEmitter();browser.process=()=>({pid:process.pid});`
    + `const boundary=admission.watchBrowserTargets(browser);`
    + `const recordPath=process.env.SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_RECORD_PATH;`
    + `const ackPath=process.env.SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_ACK_PATH;`
    + `const ack=async()=>{const until=Date.now()+2000;while(!fs.existsSync(recordPath)){assert(Date.now()<until);await new Promise(r=>setTimeout(r,5));}`
    + `const raw=fs.readFileSync(recordPath);assert.equal(JSON.parse(raw).kind,'admin_reset_browser');`
    + `fs.writeFileSync(ackPath,JSON.stringify({schemaVersion:1,recordSha256:require('node:crypto').createHash('sha256').update(raw).digest('hex'),parentPid:process.pid,browserPid:process.pid,profile:process.env.TEST_PROFILE}),{flag:'wx',mode:0o600});};`
    + `await Promise.all([ack(),admission.acknowledgeBrowser({browser,profile:process.env.TEST_PROFILE})]);`
    + `let continued=0,aborted=0,closed=0;const pages=[];`
    + `for(let i=0;i<2;i++){const page=new EventEmitter();page.setRequestInterception=async()=>{};`
    + `const context={newPage:async()=>{browser.emit('targetcreated',{type:()=> 'page'});return page}};`
    + `assert.equal(await boundary.newPage(context),page);pages.push(page);`
    + `await admission.guardPageRequests(page,'http://127.0.0.1:39117');`
    + `page.emit('request',{url:()=> 'http://127.0.0.1:39117/ok',continue:()=>{continued++},abort:()=>{aborted++}});`
    + `page.emit('request',{url:()=> 'https://example.invalid/no',continue:()=>{continued++},abort:()=>{aborted++}});}`
    + `boundary.assertNoUnexpectedTargets();`
    + `browser.emit('targetcreated',{type:()=> 'page',page:async()=>({close:async()=>{closed++}})});`
    + `await new Promise(resolve=>setImmediate(resolve));`
    + `assert.throws(()=>boundary.assertNoUnexpectedTargets());`
    + `assert.throws(()=>admission.browserArgs({profile:process.env.TEST_PROFILE,origin:'https://127.0.0.1:39117'}));`
    + `assert.throws(()=>admission.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://example.invalid:39117'}));`
    + `assert.throws(()=>admission.browserArgs({profile:process.env.TEST_PROFILE+'-other',origin:'http://127.0.0.1:39117'}));`
    + `console.log(JSON.stringify({continued,aborted,closed,`
    + `args:admission.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'})}));`
    + `})().catch(e=>{console.error(e.stack);process.exitCode=1});`;
  const python = `import json, os, subprocess\n`
    + `read, write = os.pipe()\n`
    + `env = os.environ.copy()\n`
    + `env['SECURESHOP_ADMIN_RESET_BROWSER_ADMISSION_FD'] = str(read)\n`
    + `child = subprocess.Popen([env['TEST_NODE_BIN'], '-e', env['TEST_NODE_SCRIPT']], cwd=env['TEST_ROOT'], env=env, pass_fds=(read,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n`
    + `os.close(read)\n`
    + `grant = dict(version=1, cohort='admin-password-reset-chat-browser', launcherPid=os.getpid(), workerPid=child.pid, nonce='d'*64, workspace=env['TEST_ROOT'], evidencePath=env['SECURESHOP_ADMIN_PASSWORD_RESET_CHAT_BROWSER_EVIDENCE_PATH'], buildSha256=env['SECURESHOP_ADMIN_RESET_BROWSER_BUILD_SHA256'], snapshotSha256=env['SECURESHOP_ADMIN_RESET_BROWSER_SNAPSHOT_SHA256'], outerSandbox='repository-only', chromium=env['PUPPETEER_EXECUTABLE_PATH'], chromiumSha256=env['SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_SHA256'])\n`
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
  assert.deepEqual({ continued: child.continued, aborted: child.aborted, closed: child.closed },
    { continued: 2, aborted: 2, closed: 1 });
  assert(child.args.includes('--no-sandbox'));
  assert(child.args.includes('--proxy-server=http://blocked.invalid:9'));
});

test('malformed independent browser ACK is rejected before any page admission', async t => {
  const { profile, evidencePath, executablePath, env } = await owned(t);
  const childScript = `const fs=require('node:fs');const assert=require('node:assert/strict');`
    + `require(${JSON.stringify(path.join(ROOT, 'tests/fixtures/secureshopDarwinBrowserBirth.js'))}).captureBrowserRecord=({kind,pid})=>({kind,pid,birth:[11,22]});`
    + `const {admitAdminResetBrowser}=require(${JSON.stringify(HELPER)});`
    + `(async()=>{const admission=await admitAdminResetBrowser(process.env,`
    + `{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_ADMIN_PASSWORD_RESET_CHAT_BROWSER_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH});`
    + `const browser={process:()=>({pid:process.pid})};`
    + `const recordPath=process.env.SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_RECORD_PATH;`
    + `const ackPath=process.env.SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_ACK_PATH;`
    + `const reject=admission.acknowledgeBrowser({browser,profile:process.env.TEST_PROFILE});`
    + `const until=Date.now()+2000;while(!fs.existsSync(recordPath)){assert(Date.now()<until);await new Promise(r=>setTimeout(r,5));}`
    + `fs.writeFileSync(ackPath,JSON.stringify({schemaVersion:1,recordSha256:'0'.repeat(64),parentPid:process.pid,browserPid:process.pid,profile:process.env.TEST_PROFILE}),{flag:'wx',mode:0o600});`
    + `await assert.rejects(reject);console.log('ACK_REJECTED_BEFORE_PAGE');`
    + `})().catch(e=>{console.error(e.stack);process.exitCode=1});`;
  const python = `import json, os, subprocess\n`
    + `read, write = os.pipe()\n`
    + `env = os.environ.copy()\n`
    + `env['SECURESHOP_ADMIN_RESET_BROWSER_ADMISSION_FD'] = str(read)\n`
    + `child = subprocess.Popen([env['TEST_NODE_BIN'], '-e', env['TEST_NODE_SCRIPT']], cwd=env['TEST_ROOT'], env=env, pass_fds=(read,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n`
    + `os.close(read)\n`
    + `grant = dict(version=1, cohort='admin-password-reset-chat-browser', launcherPid=os.getpid(), workerPid=child.pid, nonce='d'*64, workspace=env['TEST_ROOT'], evidencePath=env['SECURESHOP_ADMIN_PASSWORD_RESET_CHAT_BROWSER_EVIDENCE_PATH'], buildSha256=env['SECURESHOP_ADMIN_RESET_BROWSER_BUILD_SHA256'], snapshotSha256=env['SECURESHOP_ADMIN_RESET_BROWSER_SNAPSHOT_SHA256'], outerSandbox='repository-only', chromium=env['PUPPETEER_EXECUTABLE_PATH'], chromiumSha256=env['SECURESHOP_ADMIN_RESET_BROWSER_BROWSER_SHA256'])\n`
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
  assert.equal(completed.out.trim(), 'ACK_REJECTED_BEFORE_PAGE');
  assert.equal(syncFs.existsSync(evidencePath), false);
});

test('RoleChoices reset branch consumes ACK before both guarded pages and checks terminal target debt', async () => {
  const source = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const ordered = [
    'const adminResetAdmission = ADMIN_RESET_BROWSER',
    'const adminResetBoundary = adminResetAdmission?.watchBrowserTargets(browser)',
    'if (adminResetAdmission) await adminResetAdmission.acknowledgeBrowser({ browser, profile })',
    ': adminResetBoundary ? await adminResetBoundary.newPage(browser)',
    'else if (adminResetAdmission) await adminResetAdmission.guardPageRequests(page, origin)',
    ': adminResetBoundary ? await adminResetBoundary.newPage(adminContext)',
    'else if (adminResetAdmission) await adminResetAdmission.guardPageRequests(adminPage, origin)',
  ];
  let previous = -1;
  for (const marker of ordered) {
    const index = source.indexOf(marker);
    assert(index > previous, `Missing or out-of-order reset admission: ${marker}`);
    previous = index;
  }
  const resetBranch = source.slice(source.indexOf('} else if (ADMIN_RESET_BROWSER) {',
    source.indexOf('await qualifyAdminUserChat(')));
  assert.match(resetBranch, /await qualifyAdminPasswordResetChat\([\s\S]*?adminResetBoundary\?\.assertNoUnexpectedTargets\(\);/);
});

test('both reset searches ask for the exact tenant-directory card without directing a tool or effect', async () => {
  const source = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const match = source.match(/const search = await send\((`[^\n]+`), searchIndex\);/);
  assert(match, 'actual shared registered/teaching search prompt required');
  for (const username of ['selected_registered_user', 'student_customer']) {
    const prompt = new vm.Script(match[1]).runInNewContext({ username });
    assert.equal(prompt, `Search the tenant account directory for the user with username "${username}" so I can choose its password-reset card.`);
    assert.equal(prompt.split(username).length, 2);
    assert.doesNotMatch(prompt, /admin\.|choiceId|userId|student123|api_key|session_token|reset now/i);
  }
  assert.match(source, /await setup\(\{ username: registeredName,[\s\S]*?await setup\(\{ username: teachingName,/);
});
