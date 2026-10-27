'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const syncFs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { EventEmitter } = require('node:events');
const http = require('node:http');
const { JSDOM } = require('../client/node_modules/jsdom');
const { buildInventory } = require('./postgres/adminQ05RenderedScenario');
const { admitCommerceBrowser, validateCommerceGrant,
  observeProductRequests, readBoundedProductError, observeOriginalListingReadiness,
  exactConsequenceDialogButton, practiceSnapshotMetadata, practiceSummaryReference } =
  require('./fixtures/secureshopCommerceBrowserAdmission');

const ROOT = path.resolve(__dirname, '..');
const HELPER = path.join(ROOT, 'tests/fixtures/secureshopCommerceBrowserAdmission.js');
const SHA = 'a'.repeat(64);

async function owned(t) {
  assert.equal(process.cwd(), ROOT);
  const parent = path.join(ROOT, 'tasks/qualification');
  await fs.mkdir(parent, { recursive: true });
  const run = await fs.mkdtemp(path.join(parent, 'run-commerce-contract-'));
  t.after(() => fs.rm(run, { recursive: true, force: true }));
  const runtime = path.join(run, 'runtime');
  const temp = path.join(runtime, 'tmp');
  await fs.mkdir(runtime, { mode: 0o700 });
  await fs.mkdir(temp, { mode: 0o700 });
  const profile = await fs.mkdtemp(path.join(temp, 'dvaia-standalone-commerce-'));
  const evidencePath = path.join(run, 'standalone-commerce-browser.json');
  const executablePath = syncFs.realpathSync(process.execPath);
  const buildSha256 = (await buildInventory(path.join(ROOT, 'client/build'))).sha256;
  const env = {
    SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1', PG_TEST_DISPOSABLE: 'yes', NODE_ENV: 'test',
    DVAIA_CURRENT_MAIN_WORKSPACE: ROOT,
    SECURESHOP_STANDALONE_COMMERCE_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_TEST_NO_SANDBOX: '1',
    SECURESHOP_COMMERCE_ADMISSION_FD: '3',
    SECURESHOP_COMMERCE_SNAPSHOT_SHA256: SHA,
    SECURESHOP_COMMERCE_BUILD_SHA256: buildSha256,
    SECURESHOP_COMMERCE_BROWSER_SHA256: 'b'.repeat(64),
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'standalone-commerce-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'standalone-commerce-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT: path.join(ROOT, 'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON: syncFs.realpathSync('/usr/bin/python3'),
    PUPPETEER_EXECUTABLE_PATH: executablePath,
    TMPDIR: temp, MAC_CHROMIUM_TMPDIR: temp,
  };
  return { run, profile, evidencePath, executablePath, env };
}

test('commerce current-host grant is exact, one cohort only, and binds source/build/browser identities', () => {
  const context = { workspace: ROOT, evidencePath: path.join(ROOT, 'tasks/qualification/run-example/standalone-commerce-browser.json'),
    buildSha256: SHA, snapshotSha256: 'b'.repeat(64), chromium: '/pinned/chromium',
    chromiumSha256: 'c'.repeat(64), launcherPid: 41, workerPid: 42 };
  const grant = { version: 1, cohort: 'standalone-commerce-browser', launcherPid: 41,
    workerPid: 42, nonce: 'd'.repeat(64), workspace: context.workspace,
    evidencePath: context.evidencePath, buildSha256: context.buildSha256,
    snapshotSha256: context.snapshotSha256, outerSandbox: 'repository-only',
    chromium: context.chromium, chromiumSha256: context.chromiumSha256 };
  assert.deepEqual(validateCommerceGrant(grant, context), { admitted: true });
  for (const [key, wrong] of Object.entries({ cohort: 'admin-q05-current-host', launcherPid: 43,
    workerPid: 43, nonce: 'short', workspace: '/other', evidencePath: '/other.json',
    buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
    outerSandbox: 'unrestricted', chromium: '/other', chromiumSha256: '0'.repeat(64) })) {
    assert.throws(() => validateCommerceGrant({ ...grant, [key]: wrong }, context), key);
  }
  assert.throws(() => validateCommerceGrant({ ...grant, profile: '/foreign' }, context));
  assert.throws(() => validateCommerceGrant({ ...grant, version: 2 }, context));
  const revokeContext = { ...context, variant: 'account-session-revoke',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/account-current-session-revoke-browser-v2.json') };
  const revokeGrant = { ...grant, cohort: 'account-session-revoke-browser',
    evidencePath: revokeContext.evidencePath };
  assert.deepEqual(validateCommerceGrant(revokeGrant, revokeContext), { admitted: true });
  assert.throws(() => validateCommerceGrant(grant, revokeContext));
  assert.throws(() => validateCommerceGrant(revokeGrant, context));
  assert.throws(() => validateCommerceGrant(revokeGrant,
    { ...revokeContext, variant: 'unadmitted' }), /account-session-revoke/);
  const avatarContext = { ...context, variant: 'account-avatar',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/account-avatar-browser-v1.json') };
  const avatarGrant = { ...grant, cohort: 'account-avatar-browser',
    evidencePath: avatarContext.evidencePath };
  assert.deepEqual(validateCommerceGrant(avatarGrant, avatarContext), { admitted: true });
  for (const [key, wrong] of Object.entries({ cohort: revokeGrant.cohort,
    launcherPid: 43, workerPid: 43, evidencePath: revokeGrant.evidencePath,
    buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
    chromium: '/foreign', chromiumSha256: '0'.repeat(64) }))
    assert.throws(() => validateCommerceGrant({ ...avatarGrant, [key]: wrong }, avatarContext), key);
  assert.throws(() => validateCommerceGrant(avatarGrant, revokeContext));
  assert.throws(() => validateCommerceGrant(revokeGrant, avatarContext));
  assert.throws(() => validateCommerceGrant(avatarGrant, context));
  const checkoutContext = { ...context, variant: 'customer-checkout',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/customer-checkout-browser.json') };
  const checkoutGrant = { ...grant, cohort: 'customer-checkout-browser',
    evidencePath: checkoutContext.evidencePath };
  assert.deepEqual(validateCommerceGrant(checkoutGrant, checkoutContext), { admitted: true });
  for (const [key, wrong] of Object.entries({ cohort: grant.cohort, launcherPid: 43,
    workerPid: 43, evidencePath: grant.evidencePath, buildSha256: '0'.repeat(64),
    snapshotSha256: '0'.repeat(64), chromium: '/foreign', chromiumSha256: '0'.repeat(64) }))
    assert.throws(() => validateCommerceGrant({ ...checkoutGrant, [key]: wrong }, checkoutContext), key);
  assert.throws(() => validateCommerceGrant(checkoutGrant, context));
  const manualContext = { ...context, variant: 'customer-manual-checkout',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/customer-manual-checkout-browser.json') };
  const manualGrant = { ...grant, cohort: 'customer-manual-checkout-browser',
    evidencePath: manualContext.evidencePath };
  assert.deepEqual(validateCommerceGrant(manualGrant, manualContext), { admitted: true });
  for (const [key, wrong] of Object.entries({ cohort: checkoutGrant.cohort,
    launcherPid: 43, workerPid: 43, evidencePath: checkoutGrant.evidencePath,
    buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
    chromium: '/foreign', chromiumSha256: '0'.repeat(64) }))
    assert.throws(() => validateCommerceGrant({ ...manualGrant, [key]: wrong }, manualContext), key);
  assert.throws(() => validateCommerceGrant(manualGrant, checkoutContext));
  assert.throws(() => validateCommerceGrant(checkoutGrant, manualContext));
  const profileContext = { ...context, variant: 'customer-profile',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/customer-profile-browser.json') };
  const profileGrant = { ...grant, cohort: 'customer-profile-browser',
    evidencePath: profileContext.evidencePath };
  assert.deepEqual(validateCommerceGrant(profileGrant, profileContext), { admitted: true });
  for (const [key, wrong] of Object.entries({ cohort: checkoutGrant.cohort,
    launcherPid: 43, workerPid: 43, evidencePath: checkoutGrant.evidencePath,
    buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
    chromium: '/foreign', chromiumSha256: '0'.repeat(64) }))
    assert.throws(() => validateCommerceGrant({ ...profileGrant, [key]: wrong }, profileContext), key);
  assert.throws(() => validateCommerceGrant(profileGrant, checkoutContext));
  assert.throws(() => validateCommerceGrant(checkoutGrant, profileContext));
  const cartContext = { ...context, variant: 'customer-cart-lifecycle',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/customer-cart-lifecycle-browser.json') };
  const cartGrant = { ...grant, cohort: 'customer-cart-lifecycle-browser',
    evidencePath: cartContext.evidencePath };
  assert.deepEqual(validateCommerceGrant(cartGrant, cartContext), { admitted: true });
  for (const [key, wrong] of Object.entries({ cohort: checkoutGrant.cohort,
    launcherPid: 43, workerPid: 43, evidencePath: profileGrant.evidencePath,
    buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
    chromium: '/foreign', chromiumSha256: '0'.repeat(64) }))
    assert.throws(() => validateCommerceGrant({ ...cartGrant, [key]: wrong }, cartContext), key);
  for (const other of [context, checkoutContext, profileContext]) {
    assert.throws(() => validateCommerceGrant(cartGrant, other));
  }
  assert.throws(() => validateCommerceGrant(checkoutGrant, cartContext));
  assert.throws(() => validateCommerceGrant(profileGrant, cartContext));
  const paymentContext = { ...context, variant: 'customer-payment-setup',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/customer-payment-setup-browser.json') };
  const paymentGrant = { ...grant, cohort: 'customer-payment-setup-browser',
    evidencePath: paymentContext.evidencePath };
  assert.deepEqual(validateCommerceGrant(paymentGrant, paymentContext), { admitted: true });
  for (const [key, wrong] of Object.entries({ cohort: cartGrant.cohort,
    launcherPid: 43, workerPid: 43, evidencePath: cartGrant.evidencePath,
    buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
    chromium: '/foreign', chromiumSha256: '0'.repeat(64) }))
    assert.throws(() => validateCommerceGrant({ ...paymentGrant, [key]: wrong }, paymentContext), key);
  for (const other of [context, checkoutContext, profileContext, cartContext])
    assert.throws(() => validateCommerceGrant(paymentGrant, other));
  assert.throws(() => validateCommerceGrant(cartGrant, paymentContext));
  const olderContext = { ...context, variant: 'customer-older-orders',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/customer-older-orders-browser.json') };
  const olderGrant = { ...grant, cohort: 'customer-older-orders-browser', evidencePath: olderContext.evidencePath };
  const fencesContext = { ...context, variant: 'customer-checkout-fences',
    evidencePath: path.join(ROOT, 'tasks/qualification/run-example/customer-checkout-fences.json') };
  const fencesGrant = { ...grant, cohort: 'customer-checkout-fences', evidencePath: fencesContext.evidencePath };
  for (const [selected, correct, other] of [
    [olderGrant, olderContext, fencesContext], [fencesGrant, fencesContext, olderContext]]) {
    assert.deepEqual(validateCommerceGrant(selected, correct), { admitted: true });
    for (const [key, wrong] of Object.entries({ cohort: paymentGrant.cohort,
      launcherPid: 43, workerPid: 43, evidencePath: paymentGrant.evidencePath,
      buildSha256: '0'.repeat(64), snapshotSha256: '0'.repeat(64),
      chromium: '/foreign', chromiumSha256: '0'.repeat(64) }))
      assert.throws(() => validateCommerceGrant({ ...selected, [key]: wrong }, correct), key);
    assert.throws(() => validateCommerceGrant(selected, other));
    for (const legacy of [context, checkoutContext, profileContext, cartContext, paymentContext])
      assert.throws(() => validateCommerceGrant(selected, legacy));
  }
});

test('ordinary commerce still requires external evidence; opt-in rejects paths and flags before admission', async t => {
  const { evidencePath, executablePath, env } = await owned(t);
  const external = path.join(path.dirname(ROOT), 'external-commerce-evidence.json');
  assert.equal(await admitCommerceBrowser({}, { workspace: ROOT, evidencePath: external, executablePath }), null);
  await assert.rejects(admitCommerceBrowser({}, { workspace: ROOT, evidencePath, executablePath }), /outside/);
  const admit = values => admitCommerceBrowser(values, { workspace: ROOT, evidencePath, executablePath });
  await assert.rejects(admit({ ...env, SECURESHOP_COMMERCE_TEST_NO_SANDBOX: '0' }));
  await assert.rejects(admit({ ...env, TMPDIR: '/private/tmp' }));
  await assert.rejects(admit({ ...env, MAC_CHROMIUM_TMPDIR: '/private/tmp' }));
  await assert.rejects(admit({ ...env, SECURESHOP_COMMERCE_BUILD_SHA256: '0'.repeat(64) }), /build pin mismatch/);
  await assert.rejects(admit({ ...env, SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION: '/tmp/policy' }));
  await assert.rejects(admit({ ...env, SECURESHOP_COMMERCE_ADMISSION_FD: '1' }), /pipe/);
  const revokePath = path.join(path.dirname(evidencePath), 'account-current-session-revoke-browser-v2.json');
  const revokeEnv = { ...env, SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1',
    SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(path.dirname(evidencePath),
      'account-session-revoke-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(path.dirname(evidencePath),
      'account-session-revoke-browser-ack.json') };
  const revoke = values => admitCommerceBrowser(values, { workspace: ROOT,
    evidencePath: revokePath, executablePath, variant: 'account-session-revoke' });
  await assert.rejects(revoke({ ...revokeEnv, SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' }));
  await assert.rejects(revoke({ ...revokeEnv, SECURESHOP_COMMERCE_BROWSER_ACK_PATH:
    path.join(path.dirname(evidencePath), 'standalone-commerce-browser-ack.json') }));
  await assert.rejects(admitCommerceBrowser(revokeEnv, { workspace: ROOT,
    evidencePath: revokePath, executablePath }));
  const avatarPath = path.join(path.dirname(evidencePath), 'account-avatar-browser-v1.json');
  const avatarEnv = { ...revokeEnv, SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: undefined,
    SECURESHOP_ACCOUNT_AVATAR_NATIVE: '1',
    SECURESHOP_ACCOUNT_AVATAR_EVIDENCE_PATH: avatarPath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(path.dirname(evidencePath),
      'account-avatar-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(path.dirname(evidencePath),
      'account-avatar-browser-ack.json') };
  const avatar = values => admitCommerceBrowser(values, { workspace: ROOT,
    evidencePath: avatarPath, executablePath, variant: 'account-avatar' });
  await assert.rejects(avatar({ ...avatarEnv, SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' }));
  await assert.rejects(avatar({ ...avatarEnv, SECURESHOP_COMMERCE_BUILD_SHA256: '0'.repeat(64) }), /build pin mismatch/);
  await assert.rejects(avatar({ ...avatarEnv, SECURESHOP_COMMERCE_BROWSER_RECORD_PATH:
    path.join(path.dirname(evidencePath), 'account-session-revoke-browser-birth.json') }));
  await assert.rejects(avatar({ ...avatarEnv, SECURESHOP_COMMERCE_BROWSER_ACK_PATH:
    path.join(path.dirname(evidencePath), 'account-session-revoke-browser-ack.json') }));
  await assert.rejects(admitCommerceBrowser(avatarEnv, { workspace: ROOT,
    evidencePath: avatarPath, executablePath, variant: 'account-session-revoke' }));
});

test('one real inherited FIFO grant is consumed and closed before commerce browser args', async t => {
  const { profile, evidencePath, executablePath, env } = await owned(t);
  const childScript = `const fs=require('node:fs');const assert=require('node:assert/strict');`
    + `const {EventEmitter}=require('node:events');`
    + `const {admitCommerceBrowser}=require(${JSON.stringify(HELPER)});`
    + `const descriptor=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const closed=()=>{try{fs.fstatSync(descriptor);return false}catch(e){return e.code==='EBADF'}};`
    + `(async()=>{const admission=await admitCommerceBrowser(process.env,`
    + `{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH,`
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
    + `browser.emit('targetcreated',{type:()=> 'service_worker'});`
    + `assert.throws(()=>boundary.assertNoUnexpectedTargets());`
    + `const browser2=new EventEmitter();const boundary2=admission.watchBrowserTargets(browser2);`
    + `let admittedPages=0;const context2={newPage:async()=>{`
    + `browser2.emit('targetcreated',{type:()=> 'page'});return {admitted:++admittedPages}}};`
    + `assert.deepEqual(await boundary2.newPage(context2),{admitted:1});`
    + `assert.deepEqual(await boundary2.newPage(context2),{admitted:2});`
    + `boundary2.assertNoUnexpectedTargets();`
    + `browser2.emit('targetcreated',{type:()=> 'page',`
    + `page:async()=>({close:async()=>{unexpectedPageClosed++}})});`
    + `await new Promise(resolve=>setImmediate(resolve));`
    + `assert.throws(()=>boundary2.assertNoUnexpectedTargets());`
    + `const opts={profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'};`
    + `assert.throws(()=>admission.browserArgs({...opts,externalMail:true}));`
    + `process.env.SECURESHOP_EXTERNAL_MAIL_RENDERED_SEND='1';`
    + `const external=admission.browserArgs({...opts,externalMail:true});`
    + `assert(external.includes('--proxy-bypass-list=127.0.0.1;localhost;[::1];sharklasers.com;www.sharklasers.com;www.guerrillamail.com'));`
    + `assert(!admission.browserArgs(opts).join(' ').includes('sharklasers'));`
    + `assert.throws(()=>admission.browserArgs({...opts,externalMail:'1'}));`
    + `console.log(JSON.stringify({closed:closed(),cleared:!process.env.SECURESHOP_COMMERCE_ADMISSION_FD,`
    + `args:admission.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}),`
    + `intercept,continued,aborted,admittedPages,unexpectedRejected:true,unexpectedPageClosed}));`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import json, os, subprocess\n`
    + `read, write = os.pipe()\n`
    + `env = os.environ.copy()\n`
    + `env['SECURESHOP_COMMERCE_ADMISSION_FD'] = str(read)\n`
    + `child = subprocess.Popen([env['TEST_NODE_BIN'], '-e', env['TEST_NODE_SCRIPT']], cwd=env['TEST_ROOT'], env=env, pass_fds=(read,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n`
    + `os.close(read)\n`
    + `grant = dict(version=1, cohort='standalone-commerce-browser', launcherPid=os.getpid(), workerPid=child.pid, nonce='d'*64, workspace=env['TEST_ROOT'], evidencePath=env['SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH'], buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'], snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'], outerSandbox='repository-only', chromium=env['PUPPETEER_EXECUTABLE_PATH'], chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
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
  assert(child.args.some(value => value.includes('EXCLUDE 127.0.0.1')));
  assert.deepEqual({ intercept: child.intercept, continued: child.continued,
    aborted: child.aborted, admittedPages: child.admittedPages,
    unexpectedRejected: child.unexpectedRejected,
    unexpectedPageClosed: child.unexpectedPageClosed },
  { intercept: true, continued: 1, aborted: 2, admittedPages: 2, unexpectedRejected: true,
    unexpectedPageClosed: 1 });
  assert.equal(evidencePath, env.SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH);
  assert.equal(executablePath, env.PUPPETEER_EXECUTABLE_PATH);
});

test('focused session-revoke grant is independent and consumed before its browser args', async t => {
  const { run, profile, executablePath, env } = await owned(t);
  const evidencePath = path.join(run, 'account-current-session-revoke-browser-v2.json');
  const focused = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1',
    SECURESHOP_ACCOUNT_SESSION_REVOKE_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'account-session-revoke-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'account-session-revoke-browser-ack.json') };
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_ACCOUNT_SESSION_REVOKE_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'account-session-revoke'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `const args=grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'});`
    + `a(args.includes('--no-sandbox'));process.stdout.write('admitted');`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import json, os, subprocess\n`
    + `read, write = os.pipe()\n`
    + `env = os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='account-session-revoke-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_ACCOUNT_SESSION_REVOKE_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 25000,
    env: { ...process.env, ...focused, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  const completed = JSON.parse(result.stdout.trim());
  assert.deepEqual(completed, { code: 0, out: 'admitted', err: '' });
});

test('focused Account-avatar grant consumes the actual inherited FIFO before browser birth', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-account-avatar-'));
  const evidencePath = path.join(run, 'account-avatar-browser-v1.json');
  const focused = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_ACCOUNT_AVATAR_NATIVE: '1',
    SECURESHOP_ACCOUNT_AVATAR_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'account-avatar-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'account-avatar-browser-ack.json') };
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_ACCOUNT_AVATAR_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'account-avatar'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `const args=grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'});`
    + `a(args.includes('--no-sandbox'));process.stdout.write('admitted');`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import json, os, subprocess\n`
    + `read, write = os.pipe()\n`
    + `env = os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='account-avatar-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_ACCOUNT_AVATAR_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 25000,
    env: { ...process.env, ...focused, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  const completed = JSON.parse(result.stdout.trim());
  assert.deepEqual(completed, { code: 0, out: 'admitted', err: '' });
});

test('owned customer checkout consumes one bound FIFO before browser args and rejects cross-cohort paths', async t => {
  const { run, profile: wrongProfile, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-checkout-'));
  const evidencePath = path.join(run, 'customer-checkout-browser.json');
  const checkout = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1',
    SECURESHOP_CUSTOMER_CHECKOUT_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_CHECKOUT_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-checkout-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-checkout-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-checkout' });
  for (const mutation of [
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '0' },
    { SECURESHOP_CUSTOMER_CHECKOUT_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_ADMISSION_FD: '2' },
  ]) await assert.rejects(admit({ ...checkout, ...mutation }));
  await assert.rejects(admitCommerceBrowser(checkout, { workspace: ROOT,
    evidencePath: env.SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH,
    executablePath, variant: 'customer-checkout' }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {EventEmitter}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_CHECKOUT_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-checkout'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `a.throws(()=>grant.browserArgs({profile:process.env.TEST_WRONG_PROFILE,origin:'http://127.0.0.1:39117'}));`
    + `const browser=new EventEmitter();browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {};};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `browser.emit('targetcreated',{type:()=> 'service_worker'});a.throws(()=>boundary.assertNoUnexpectedTargets());`
    + `process.stdout.write('admitted');})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import json, os, subprocess\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-checkout-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_CHECKOUT_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 25000,
    env: { ...process.env, ...checkout, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_WRONG_PROFILE: wrongProfile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});

test('direct manual checkout consumes its own FIFO and cannot borrow chat checkout authority', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-manual-checkout-'));
  const evidencePath = path.join(run, 'customer-manual-checkout-browser.json');
  const selected = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_NATIVE: '1',
    SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-manual-checkout-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-manual-checkout-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-manual-checkout' });
  for (const mutation of [
    { SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_NATIVE: '0' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
  ]) await assert.rejects(admit({ ...selected, ...mutation }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-manual-checkout'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `process.stdout.write('admitted');})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import json, os, subprocess\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-manual-checkout-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 25000,
    env: { ...process.env, ...selected, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});

test('owned customer profile consumes exact FIFO, publishes browser birth, and waits for its ACK', async t => {
  const { run, profile: wrongProfile, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-profile-'));
  const evidencePath = path.join(run, 'customer-profile-browser.json');
  const profileEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1',
    SECURESHOP_CUSTOMER_PROFILE_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_PROFILE_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-profile-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-profile-browser-ack.json') };
  const admit = (values, selectedPath = evidencePath, variant = 'customer-profile') =>
    admitCommerceBrowser(values, { workspace: ROOT, evidencePath: selectedPath, executablePath, variant });
  for (const mutation of [
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '0' },
    { SECURESHOP_CUSTOMER_PROFILE_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BUILD_SHA256: '0'.repeat(64) },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...profileEnv, ...mutation }));
  await assert.rejects(admit(profileEnv, env.SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH));
  await assert.rejects(admit(profileEnv, evidencePath, 'customer-checkout'));

  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_PROFILE_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-profile'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `a.throws(()=>grant.browserArgs({profile:process.env.TEST_WRONG_PROFILE,origin:'http://127.0.0.1:39117'}));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-profile-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_PROFILE_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned browser birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_profile_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...profileEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_WRONG_PROFILE: wrongProfile, TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});

test('owned cart lifecycle consumes its distinct FIFO, birth and ACK before a page', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-cart-lifecycle-'));
  const evidencePath = path.join(run, 'customer-cart-lifecycle-browser.json');
  const cartEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE: '1',
    SECURESHOP_CUSTOMER_CART_LIFECYCLE_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_CART_LIFECYCLE_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-cart-lifecycle-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-cart-lifecycle-browser-ack.json') };
  const admit = (values, variant = 'customer-cart-lifecycle') =>
    admitCommerceBrowser(values, { workspace: ROOT, evidencePath, executablePath, variant });
  for (const mutation of [
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CART_LIFECYCLE_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...cartEnv, ...mutation }));
  await assert.rejects(admit(cartEnv, 'customer-profile'));

  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_CART_LIFECYCLE_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-cart-lifecycle'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-cart-lifecycle-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_CART_LIFECYCLE_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned cart birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_cart_lifecycle_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...cartEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});



test('owned payment setup consumes distinct FIFO, birth and ACK before a page', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-payment-setup-'));
  const evidencePath = path.join(run, 'customer-payment-setup-browser.json');
  const paymentEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE: '1',
    SECURESHOP_CUSTOMER_PAYMENT_SETUP_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_PAYMENT_SETUP_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-payment-setup-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-payment-setup-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-payment-setup' });
  for (const mutation of [
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PAYMENT_SETUP_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...paymentEnv, ...mutation }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_PAYMENT_SETUP_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-payment-setup'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-payment-setup-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_PAYMENT_SETUP_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned payment birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_payment_setup_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...paymentEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});

test('owned older orders consumes distinct FIFO, birth and ACK before a page', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-older-orders-'));
  const evidencePath = path.join(run, 'customer-older-orders-browser.json');
  const olderEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE: '1',
    SECURESHOP_CUSTOMER_OLDER_ORDERS_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_OLDER_ORDERS_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-older-orders-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-older-orders-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-older-orders' });
  for (const mutation of [
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_OLDER_ORDERS_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...olderEnv, ...mutation }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_OLDER_ORDERS_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-older-orders'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-older-orders-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_OLDER_ORDERS_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned older birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_older_orders_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...olderEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});

test('owned address setup consumes distinct FIFO, birth and ACK before a page', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-address-setup-'));
  const evidencePath = path.join(run, 'customer-address-setup-browser.json');
  const addressEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE: '1',
    SECURESHOP_CUSTOMER_ADDRESS_SETUP_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_ADDRESS_SETUP_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-address-setup-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-address-setup-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-address-setup' });
  for (const mutation of [
    { SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE: '1' },
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_ADDRESS_SETUP_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...addressEnv, ...mutation }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_ADDRESS_SETUP_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-address-setup'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-address-setup-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_ADDRESS_SETUP_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned address birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_address_setup_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...addressEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});
test('owned refund handoff consumes distinct FIFO, birth and ACK before a page', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-refund-handoff-'));
  const evidencePath = path.join(run, 'customer-refund-handoff-browser.json');
  const refundEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE: '1',
    SECURESHOP_CUSTOMER_REFUND_HANDOFF_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_REFUND_HANDOFF_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-refund-handoff-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-refund-handoff-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-refund-handoff' });
  for (const mutation of [
    { SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_REFUND_HANDOFF_BUILD: undefined },
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_REFUND_HANDOFF_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...refundEnv, ...mutation }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_REFUND_HANDOFF_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-refund-handoff'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-refund-handoff-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_REFUND_HANDOFF_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned refund birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_refund_handoff_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...refundEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});
test('owned product details consumes distinct FIFO, birth and ACK before a page', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-product-details-'));
  const evidencePath = path.join(run, 'customer-product-disambiguation-browser.json');
  const productEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE: '1',
    SECURESHOP_CUSTOMER_PRODUCT_DETAILS_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_PRODUCT_DETAILS_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-product-details-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-product-details-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-product-details' });
  for (const mutation of [
    { SECURESHOP_CUSTOMER_PRODUCT_DETAILS_BUILD: undefined },
    { SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE: '1' },
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PRODUCT_DETAILS_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...productEnv, ...mutation }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_PRODUCT_DETAILS_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-product-details'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-product-disambiguation-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_PRODUCT_DETAILS_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned refund birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_product_details_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...productEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});
test('owned stock rejection consumes distinct FIFO, birth and ACK before a page', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-out-of-stock-'));
  const evidencePath = path.join(run, 'customer-out-of-stock-browser.json');
  const stockEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE: '1',
    SECURESHOP_CUSTOMER_OUT_OF_STOCK_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_OUT_OF_STOCK_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-out-of-stock-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-out-of-stock-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-out-of-stock' });
  for (const mutation of [
    { SECURESHOP_CUSTOMER_OUT_OF_STOCK_BUILD: undefined },
    { SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE: '1' },
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_OUT_OF_STOCK_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...stockEnv, ...mutation }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_OUT_OF_STOCK_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-out-of-stock'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-out-of-stock-browser',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_OUT_OF_STOCK_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned stock birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_out_of_stock_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...stockEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});
test('owned checkout fences consumes distinct FIFO, birth and ACK before a page', async t => {
  const { run, executablePath, env } = await owned(t);
  const profile = await fs.mkdtemp(path.join(run, 'runtime/tmp/dvaia-customer-checkout-fences-'));
  const evidencePath = path.join(run, 'customer-checkout-fences.json');
  const fencesEnv = { ...env, SECURESHOP_STANDALONE_COMMERCE_NATIVE: undefined,
    SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE: '1',
    SECURESHOP_CUSTOMER_CHECKOUT_FENCES_BUILD: path.join(ROOT, 'client/build'),
    SECURESHOP_CUSTOMER_CHECKOUT_FENCES_EVIDENCE_PATH: evidencePath,
    SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: path.join(run, 'customer-checkout-fences-browser-birth.json'),
    SECURESHOP_COMMERCE_BROWSER_ACK_PATH: path.join(run, 'customer-checkout-fences-browser-ack.json') };
  const admit = values => admitCommerceBrowser(values, {
    workspace: ROOT, evidencePath, executablePath, variant: 'customer-checkout-fences' });
  for (const mutation of [
    { SECURESHOP_STANDALONE_COMMERCE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PROFILE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE: '1' },
    { SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE: '1' },
    { SECURESHOP_CUSTOMER_CHECKOUT_FENCES_BUILD: '/foreign' },
    { SECURESHOP_COMMERCE_BROWSER_RECORD_PATH: env.SECURESHOP_COMMERCE_BROWSER_RECORD_PATH },
    { SECURESHOP_COMMERCE_BROWSER_ACK_PATH: env.SECURESHOP_COMMERCE_BROWSER_ACK_PATH },
  ]) await assert.rejects(admit({ ...fencesEnv, ...mutation }));
  const childScript = `const fs=require('node:fs');const a=require('node:assert/strict');`
    + `const {spawn}=require('node:child_process');const {once}=require('node:events');`
    + `const h=require(${JSON.stringify(HELPER)});(async()=>{`
    + `const fd=Number(process.env.SECURESHOP_COMMERCE_ADMISSION_FD);`
    + `const grant=await h.admitCommerceBrowser(process.env,{workspace:process.env.DVAIA_CURRENT_MAIN_WORKSPACE,`
    + `evidencePath:process.env.SECURESHOP_CUSTOMER_CHECKOUT_FENCES_EVIDENCE_PATH,`
    + `executablePath:process.env.PUPPETEER_EXECUTABLE_PATH,variant:'customer-checkout-fences'});`
    + `a(grant);a.throws(()=>fs.fstatSync(fd),{code:'EBADF'});`
    + `a(grant.browserArgs({profile:process.env.TEST_PROFILE,origin:'http://127.0.0.1:39117'}).includes('--no-sandbox'));`
    + `const owned=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});`
    + `try{await once(owned,'spawn');await grant.acknowledgeBrowser({browser:{process:()=>owned},profile:process.env.TEST_PROFILE});`
    + `const {EventEmitter}=require('node:events');const browser=new EventEmitter();`
    + `browser.newPage=async()=>{browser.emit('targetcreated',{type:()=> 'page'});return {}};`
    + `const boundary=grant.watchBrowserTargets(browser);await boundary.newPage(browser);boundary.assertNoUnexpectedTargets();`
    + `process.stdout.write('admitted');}finally{if(owned.exitCode===null){const ended=once(owned,'exit');owned.kill('SIGTERM');await ended;}}`
    + `})().catch(e=>{console.error(e.message);process.exitCode=1});`;
  const python = `import hashlib,json,os,subprocess,time\n`
    + `read,write=os.pipe();env=os.environ.copy();env['SECURESHOP_COMMERCE_ADMISSION_FD']=str(read)\n`
    + `child=subprocess.Popen([env['TEST_NODE_BIN'],'-e',env['TEST_NODE_SCRIPT']],cwd=env['TEST_ROOT'],env=env,pass_fds=(read,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n`
    + `os.close(read)\n`
    + `grant=dict(version=1,cohort='customer-checkout-fences',launcherPid=os.getpid(),workerPid=child.pid,nonce='d'*64,workspace=env['TEST_ROOT'],evidencePath=env['SECURESHOP_CUSTOMER_CHECKOUT_FENCES_EVIDENCE_PATH'],buildSha256=env['SECURESHOP_COMMERCE_BUILD_SHA256'],snapshotSha256=env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'],outerSandbox='repository-only',chromium=env['PUPPETEER_EXECUTABLE_PATH'],chromiumSha256=env['SECURESHOP_COMMERCE_BROWSER_SHA256'])\n`
    + `os.write(write,json.dumps(grant).encode());os.close(write)\n`
    + `record=env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'];ack=env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'];deadline=time.monotonic()+12\n`
    + `while not os.path.isfile(record) and time.monotonic()<deadline:time.sleep(.02)\n`
    + `if not os.path.isfile(record):raise RuntimeError('owned fences birth missing')\n`
    + `raw=open(record,'rb').read();birth=json.loads(raw);assert birth['processes'][0]['kind']=='customer_checkout_fences_browser'\n`
    + `payload=dict(schemaVersion=1,recordSha256=hashlib.sha256(raw).hexdigest(),parentPid=child.pid,browserPid=birth['processes'][0]['pid'],profile=env['TEST_PROFILE'])\n`
    + `fd=os.open(ack,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,json.dumps(payload).encode());os.fsync(fd);os.close(fd)\n`
    + `out,err=child.communicate(timeout=15);print(json.dumps(dict(code=child.returncode,out=out,err=err)))\n`;
  const result = spawnSync('/usr/bin/python3', ['-B', '-c', python], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, ...fencesEnv, TEST_ROOT: ROOT, TEST_PROFILE: profile,
      TEST_NODE_BIN: process.execPath, TEST_NODE_SCRIPT: childScript },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { code: 0, out: 'admitted', err: '' });
});



test('customer checkout fixture retains original controls and admits owned browser before first page', async () => {
  const fixture = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js'), 'utf8');
  assert.match(fixture, /timeout: V19_SUMMARY \? 1800000 : 600000/);
  assert.match(fixture, /admitCommerceBrowser\(process\.env/);
  assert.match(fixture, /variant: MANUAL_CHECKOUT \? 'customer-manual-checkout' : PROFILE \? 'customer-profile' : CART_LIFECYCLE \? 'customer-cart-lifecycle'\s*: STOCK_REJECTION \? 'customer-out-of-stock' : PRODUCT_DETAILS \? 'customer-product-details' : REFUND_HANDOFF \? 'customer-refund-handoff' : ADDRESS_SETUP \? 'customer-address-setup' : PAYMENT_SETUP \? 'customer-payment-setup' : OLDER_ORDERS \? 'customer-older-orders'\s*: CHECKOUT_FENCES \? 'customer-checkout-fences' : 'customer-checkout'/);
  assert.match(fixture, /MANUAL_CHECKOUT \? 'PG_SECURESHOP_CUSTOMER_CHECKOUT_'/);
  assert.match(fixture, /browserAdmission && MANUAL_CHECKOUT\s*\? 'dvaia-customer-manual-checkout-'/);
  assert.match(fixture, /browserAdmission && PROFILE\s*\? 'dvaia-customer-profile-'/);
  assert.match(fixture, /browserAdmission && CART_LIFECYCLE\s*\? 'dvaia-customer-cart-lifecycle-'/);
  assert.match(fixture, /browserAdmission && PAYMENT_SETUP\s*\? 'dvaia-customer-payment-setup-'/);
  assert.match(fixture, /browserAdmission && OLDER_ORDERS\s*\? 'dvaia-customer-older-orders-'/);
  assert.match(fixture, /browserAdmission && CHECKOUT_FENCES\s*\? 'dvaia-customer-checkout-fences-'/);
  assert(fixture.indexOf('await browserAdmission.acknowledgeBrowser({ browser, profile })')
    < fixture.indexOf('browserBoundary.newPage(browser)'));
  assert.match(fixture, /stage = 'two-tab-second-open';\s*const secondPage = browserBoundary \? await browserBoundary\.newPage\(browser\) : await browser\.newPage\(\);/);
  assert(fixture.indexOf("stage = 'two-tab-second-open'")
    < fixture.indexOf('await secondPage.setRequestInterception(true); observeRequests(secondPage);'));
  assert(fixture.indexOf('observeRequests(page)') < fixture.indexOf("stage = 'login'"));
  assert.match(fixture, /browserBoundary\.assertNoUnexpectedTargets\(\)/);
  for (const marker of ['checkout/confirm', 'renderedSyntheticDeclineNoEffect',
    'renderedApprovedCheckoutAtomicReceipt', 'renderedCheckoutRecoveryNoReplay',
    'renderedOwnedOrderListAndDetail', 'siblingChoicesDenied', 'fixtureCleaned'])
    assert.ok(fixture.includes(marker), marker);
  for (const marker of ['renderedCartAddPrepared', 'renderedCartUpdateLostAckRecovery',
    'renderedCartRemoveConfirmed', 'exactGetNoReplay', 'siblingCartOperationDenied'])
    assert.ok(fixture.includes(marker), marker);
  for (const marker of ['renderedPaymentSetupHandoff', 'renderedOneMethodReceipt',
    'renderedLostAckExactRecovery', 'siblingMethodDenied', 'noOrderOrJudge'])
    assert.ok(fixture.includes(marker), marker);
  for (const marker of ['controlledSeededOrderPages', 'stableTieTimestampKeyset',
    'renderedPhysicalOlderOrders', 'renderedSelectedOlderOrderDetail', 'siblingOrdersPrivate'])
    assert.ok(fixture.includes(marker), marker);
  for (const marker of ['modelPreparedThreeQuotes', 'renderedStockStaleNoEffect',
    'renderedPriceStaleNoEffect', 'renderedTwoTabRecoveryOneEffect', 'laterRealSessionDenied'])
    assert.ok(fixture.includes(marker), marker);
});

test('whole-commerce fixture keeps original test/work limits and waits for birth ACK before newPage', async () => {
  const fixture = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js'), 'utf8');
  assert.match(fixture, /timeout: 330000/);
  assert.match(fixture, /Date\.now\(\) \+ 280000/);
  assert.match(fixture, /const browserAdmission = await admitCommerceBrowser\(/);
  assert(fixture.indexOf('await browserAdmission.acknowledgeBrowser({ browser, profile })')
    < fixture.indexOf('page = browserBoundary ? await browserBoundary.newPage(browser)'));
  assert(fixture.indexOf('await browserAdmission.guardPageRequests(pageB, origin)')
    < fixture.indexOf('pageB.goto('));
  assert(fixture.indexOf('await browserAdmission.guardPageRequests(practicePage, origin)')
    < fixture.indexOf('practicePage.goto('));
  assert.match(fixture, /browserBoundary\.assertNoUnexpectedTargets\(\)/);
  for (const field of ['checkoutRecovered', 'adminUsersRenderedPagination', 'auditRenderedPagination',
    'customerSelfPasswordChanged', 'manualReviewRejectRecovery', 'policySavedOperationRecovery',
    'customerComposeRecoverySingleEffect', 'merchantComposeRecoverySingleEffect'])
    assert.match(fixture, new RegExp(`${field}: false`));
  assert.match(fixture, /policyRecovery: \{ status: 'not-run'/);
  assert.match(fixture, /baselineAuthenticatedProductAttempts: 2/);
  assert.match(fixture, /assert\.equal\(judgeCalls, 0, 'whole commerce cohort must not invoke a Judge'\)/);
  assert.match(fixture, /response\.once\('finish', \(\) => \{ row\.status = response\.statusCode; row\.finished = true; \}\)/);
  assert.match(fixture, /response\.once\('close', \(\) => \{ row\.closed = true; \}\)/);
  assert.match(fixture, /workStep\('a08-product-summary-response-headers'/);
  assert.match(fixture, /workStep\('a08-product-similar-response-headers'/);
  assert.match(fixture, /productProbe\.snapshot\(\)\[1\]\.requests, 0/);
  assert.match(fixture, /similarButton\.click\(\)/);
  assert.match(fixture, /\['POST', similarSessionPath\], \['POST', expectedProductFailures\[1\]\.path\], \['GET', savedPath\]/);
  assert.match(fixture, /readinessObserver\.arm\(\)/);
  assert.match(fixture, /app\.use\(readinessObserver\.middleware\)/);
  assert.match(fixture, /readinessObserver\.assertBrowserResponse\(listingReadinessHttp, origin\)/);
  assert.match(fixture, /readinessObserver\.stop\(\)/);
  assert.doesNotMatch(fixture, /listingReadinessHttp\.json\(\)/);
});

test('whole-commerce API key mutations require rendered consequence confirmation after a no-effect Cancel', async () => {
  const fixture = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js'), 'utf8');
  const account = await fs.readFile(path.join(ROOT, 'client/src/pages/secureshop/pages/Account.jsx'), 'utf8');
  assert.match(account, /confirmLabel=\{pendingRotation\.kind === 'rotate' \? 'Confirm rotation' : 'Confirm generation'\}/);
  assert.match(fixture, /const keyState = async \(\) => \(await agents\.query\(`SELECT api_key_version::text AS version,/);
  assert.match(fixture, /encode\(api_key_sha256,'hex'\) AS digest/);
  assert.match(fixture, /frame\.waitForFunction\(exactConsequenceDialogButton,/);
  assert.match(fixture, /new Function\(`return \(\$\{exactConsequenceDialogButton\.toString\(\)\}\)\(/);
  assert.match(fixture, /if \(url\.origin === origin && url\.pathname === '\/api\/secureshop\/v2\/auth\/users\/me\/api-keys\/rotate'/);
  assert.match(fixture, /request\.method\(\) === 'POST'\) keyMutationRequests \+= 1/);
  for (const [action, title, confirm] of [
    ['Generate key', 'Generate API key?', 'Confirm generation'],
    ['Rotate key', 'Rotate API key?', 'Confirm rotation'],
  ]) {
    const start = fixture.indexOf(`const keyRequestsBefore${action === 'Generate key' ? 'Generation' : 'Rotation'}`);
    const scope = action === 'Generate key' ? 'generationDialog' : 'rotationDialog';
    const end = fixture.indexOf(`await clickMailButton(accountFrame, '${confirm}', true, ${scope});`, start);
    assert.ok(start > 0 && end > start);
    const section = fixture.slice(start, end);
    assert.ok(section.includes(`await clickMailButton(accountFrame, '${action}');`));
    assert.ok(fixture.includes(`title: '${title}'`));
    assert.ok(section.includes(`await waitKeyDialog(accountFrame, ${scope});`));
    assert.ok(section.includes(`await clickMailButton(accountFrame, 'Cancel', true, ${scope});`));
    assert.ok(section.includes(`await waitKeyDialogClosed(accountFrame, ${scope}.title);`));
    assert.ok(section.includes('JSON.stringify(await keyState()) === JSON.stringify('));
    assert.ok(section.includes('assert.equal(keyMutationRequests, keyRequestsBefore'));
    assert.ok(section.includes("response.request().method() === 'POST', { timeout: 20000 });"));
  }
  assert.match(fixture, /assert\.equal\(keyMutationRequests, keyRequestsBeforeGeneration \+ 1\)/);
  assert.match(fixture, /assert\.equal\(keyMutationRequests, keyRequestsBeforeRotation \+ 1\)/);
  assert.match(fixture, /assert\.equal\(generated\.version, 1\)/);
  assert.match(fixture, /assert\.equal\(rotated\.version, 2\)/);
  assert.match(fixture, /firstKeyOrders\.body\.orders/);
  assert.match(fixture, /retainedKey\.version, 2/);
});

test('exact API-key confirmation selector ignores a mounted hidden Hop sheet and rejects duplicate targets', () => {
  const dom = new JSDOM(`<div role="dialog" aria-hidden="true"><button>Close</button></div>
    <div role="dialog" aria-modal="true"><div><h2 id="ss-dialog-title">Generate API key?</h2>
      <p>A new API key will be created and shown after this request succeeds.</p>
      <button>Cancel</button><button>Confirm generation</button></div></div>`);
  const priorDocument = global.document;
  global.document = dom.window.document;
  try {
    const args = ['Generate API key?',
      'A new API key will be created and shown after this request succeeds.', 'Confirm generation'];
    const confirm = exactConsequenceDialogButton(...args, 'Confirm generation');
    const cancel = exactConsequenceDialogButton(...args, 'Cancel');
    assert.equal(confirm.textContent, 'Confirm generation');
    assert.equal(cancel.textContent, 'Cancel');
    assert.equal(confirm.closest('[role="dialog"]').getAttribute('aria-modal'), 'true');
    // The same source is serialized into Puppeteer's physical locator.
    const serialized = new Function(`return (${exactConsequenceDialogButton.toString()})(
      'Generate API key?', 'A new API key will be created and shown after this request succeeds.',
      'Confirm generation', 'Cancel');`);
    assert.equal(serialized(), cancel);
    const target = confirm.closest('[role="dialog"]');
    const duplicate = target.cloneNode(true);
    dom.window.document.body.append(duplicate);
    assert.equal(exactConsequenceDialogButton(...args, 'Confirm generation'), null);
    duplicate.remove();
    target.append(dom.window.document.createElement('button'));
    target.lastChild.textContent = 'Confirm generation';
    assert.equal(exactConsequenceDialogButton(...args, 'Confirm generation'), null);
    target.lastChild.remove();
    assert.equal(exactConsequenceDialogButton('Rotate API key?', ...args.slice(1), 'Cancel'), null);
  } finally { global.document = priorDocument; dom.window.close(); }
});

test('A18 pre-fault snapshot probe reads only exact scoped keys and returns bounded metadata, never saved values', async () => {
  const scopeKey = 'dvaia:secureshop:11111111-1111-4111-8111-111111111111:1';
  const sceneId = '22222222-2222-4222-8222-222222222222';
  const summaryKey = 'secureshop.product-summary.operations.v1';
  const allowedFields = ['secureshop_v2_token', 'ss_guest_cart', summaryKey,
    'secureshop.customer-chat.pending.v1'];
  const secret = 'secret-operation-33333333-3333-4333-8333-333333333333';
  const values = new Map([[scopeKey, JSON.stringify({ secureshop_v2_token: secret,
    ss_guest_cart: secret, [summaryKey]: JSON.stringify({ version: 2,
      entries: [{ operationId: secret }] }),
    [`sensitive-${secret}`]: secret })]]);
  const reads = [];
  const storage = { getItem(key) { reads.push(key); return values.get(key) ?? null; } };
  const input = { scopeKey, sceneId, allowedFields, summaryKey };
  const result = practiceSnapshotMetadata(input, storage);
  assert.deepEqual(reads, [`${scopeKey}:scene-storage-v1`, scopeKey]);
  assert.deepEqual(result, { marker: 'base', snapshotFound: true, jsonValid: true,
    nonNullFields: [summaryKey], unknownNonNullField: true, summaryRefPresent: true,
    summaryRefParseable: true, summaryRefHasEntries: true, summaryRefEntryCount: 1 });
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(JSON.stringify(result).includes('sensitive-'), false);
  assert.equal(JSON.stringify(result).includes('token'), false);
  values.set(`${scopeKey}:scene-storage-v1`, '1');
  values.set(`${scopeKey}:scene:${sceneId}`, JSON.stringify({
    'secureshop.customer-chat.pending.v1': '{}', [summaryKey]: null }));
  reads.length = 0;
  assert.deepEqual(practiceSnapshotMetadata(input, storage), {
    marker: 'scene', snapshotFound: true, jsonValid: true,
    nonNullFields: ['secureshop.customer-chat.pending.v1'], unknownNonNullField: false,
    summaryRefPresent: false, summaryRefParseable: false,
    summaryRefHasEntries: false, summaryRefEntryCount: 0 });
  assert.deepEqual(reads, [`${scopeKey}:scene-storage-v1`, `${scopeKey}:scene:${sceneId}`]);
  values.set(`${scopeKey}:scene:${sceneId}`, '{invalid');
  assert.equal(practiceSnapshotMetadata(input, storage).jsonValid, false);
  values.set(`${scopeKey}:scene:${sceneId}`, 'x'.repeat(2 * 1024 * 1024 + 1));
  assert.equal(practiceSnapshotMetadata(input, storage).jsonValid, false);
});

test('A18 metadata probe is diagnostic only and leaves original storage-failure criterion intact', async () => {
  const fixture = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js'), 'utf8');
  const capture = fixture.indexOf('const snapshotMetadata = await practicePage.evaluate(practiceSnapshotMetadata');
  const fault = fixture.indexOf("stage = 'a18-storage-failure';", capture);
  const original = fixture.indexOf("?.textContent.includes('Controlled parent storage denial')", fault);
  assert.ok(capture > 0 && fault > capture && original > fault);
  assert.match(fixture, /practicePostRequests: practiceRequests\.filter\(row => row\.method === 'POST'\)\.length/);
  assert.match(fixture, /await import\('\.\.\/\.\.\/client\/src\/pages\/secureshop\/utils\/shopStorage\.mjs'\)/);
  assert.match(fixture, /Object\.entries\(shopStateNames\)/);
  assert.match(fixture, /\^SHOP_\[A-Z_\]\+_KEY\$/);
  assert.match(fixture, /allowedFields: allowedSnapshotFields/);
  assert.match(fixture, /summaryKey: shopStateNames\.SHOP_PRODUCT_SUMMARY_KEY/);
  assert.match(fixture, /scopeKey: `dvaia:secureshop:\$\{beforePractice\.launch\.launchId\.toLowerCase\(\)\}:\$\{beforePractice\.launch\.generation\}`/);
  assert.match(fixture, /sceneId: originalPractice\.id\.toLowerCase\(\)/);
  assert.doesNotMatch(fixture.slice(capture, fault), /Object\.(?:keys|entries)\(localStorage\)|localStorage\.key\(/);
});

test('A18 exact Product reference comparison rejects replacement with the same entry count', () => {
  const scopeKey = 'dvaia:secureshop:11111111-1111-4111-8111-111111111111:1';
  const sceneId = '22222222-2222-4222-8222-222222222222';
  const summaryKey = 'secureshop.product-summary.operations.v1';
  const input = { scopeKey, sceneId, summaryKey };
  const first = JSON.stringify({ version: 2, entries: [
    { operationId: '33333333-3333-4333-8333-333333333333' }] });
  const replacement = JSON.stringify({ version: 2, entries: [
    { operationId: '44444444-4444-4444-8444-444444444444' }] });
  const values = new Map([[scopeKey, JSON.stringify({ [summaryKey]: first })]]);
  const storage = { getItem: key => values.get(key) ?? null };
  const original = practiceSummaryReference(input, undefined, storage);
  assert.equal(typeof original, 'object', 'browser baseline must be an object handle, never a primitive CDP value');
  assert.equal(practiceSummaryReference(input, original, storage), true);
  values.set(scopeKey, JSON.stringify({ [summaryKey]: replacement }));
  assert.equal(practiceSummaryReference(input, original, storage), false);
  assert.equal(practiceSnapshotMetadata({ ...input, allowedFields: [summaryKey] }, storage).summaryRefEntryCount, 1,
    'metadata shape alone cannot distinguish a different saved operation');
  values.set(scopeKey, JSON.stringify({ [summaryKey]: null }));
  assert.equal(practiceSummaryReference(input, original, storage), false);
});

test('A18 proves Product retained-operation denial separately from the clean Catalog recovery matrix', async () => {
  const fixture = await fs.readFile(path.join(ROOT,
    'tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js'), 'utf8');
  const guard = fixture.indexOf("stage = 'a18-product-saved-operation-guard';");
  const clean = fixture.indexOf("stage = 'a18-new-practice';", guard);
  const storage = fixture.indexOf("stage = 'a18-storage-failure';", clean);
  const capacity = fixture.indexOf("stage = 'a18-controlled-capacity';", storage);
  const lostAck = fixture.indexOf("stage = 'a18-published-ack-loss';", capacity);
  const recovery = fixture.indexOf("stage = 'a18-exact-get-recovery';", lostAck);
  assert.ok(guard > 0 && clean > guard && storage > clean && capacity > storage
    && lostAck > capacity && recovery > lostAck);
  const guardFacet = fixture.slice(guard, clean);
  const cleanFacet = fixture.slice(clean, storage);
  assert.match(guardFacet, /contextA18Product = await browser\.createBrowserContext\(\)/);
  assert.match(guardFacet, /guardPageRequests\(productPage, origin\)/);
  assert.match(guardFacet, /guardSnapshot\.summaryRefEntryCount > 0/);
  assert.match(guardFacet, /evaluateHandle\(practiceSummaryReference, guardSnapshotInput\)/);
  assert.match(guardFacet, /evaluate\(practiceSummaryReference, guardSnapshotInput, guardReferenceHandle\), true/);
  assert.match(guardFacet, /guardReferenceHandle\.dispose\(\)/);
  assert.match(guardFacet, /referenceDeadline = Date\.now\(\) \+ 19000/);
  assert.match(guardFacet, /guardProductReads\.some\(row => row\.method === 'POST'/);
  assert.match(guardFacet, /Check saved operation status before choosing another practice\./);
  assert.match(guardFacet, /practiceTraffic\.filter\(row => row\.method === 'POST'\)\.length, guardPostsBefore/);
  assert.match(guardFacet, /scenes\.list\(guardScope\)/);
  assert.match(guardFacet, /guardCartLine/);
  assert.doesNotMatch(guardFacet, /localStorage\.(?:removeItem|clear)\(/);
  assert.match(cleanFacet, /contextA18 = await browser\.createBrowserContext\(\)/);
  assert.match(cleanFacet, /guardPageRequests\(practicePage, origin\)/);
  assert.match(cleanFacet, /secureshop\/catalog\?q=/);
  assert.match(cleanFacet, /catalogAdd\.click\(\)/);
  assert.match(cleanFacet, /practiceProductReads\.length, 0/);
  assert.match(cleanFacet, /snapshotMetadata\.summaryRefPresent, false/);
  assert.doesNotMatch(cleanFacet, /practicePage\.goto\(`\$\{origin\}\/secureshop\/product\//);
  assert.match(fixture.slice(storage, recovery), /Controlled parent storage denial/);
  assert.match(fixture.slice(capacity, recovery), /SHOP_PRACTICE_CAPACITY/);
  assert.match(fixture.slice(recovery), /renderedNewPracticeCartIsolation = true/);
  assert.match(fixture, /expectedProductReads = \[\s*\{ method: 'POST', path: `\/api\/secureshop\/products\/\$\{guardProduct\.product_id\}\/summary` \}/);
});

test('Product diagnostic observes only the two exact request identities and lifecycle events', () => {
  const page = new EventEmitter();
  const origin = 'http://127.0.0.1:39117';
  const expected = [{ method: 'POST', path: '/api/secureshop/products/7/summary' },
    { method: 'POST', path: '/api/secureshop/products/7/similar' }];
  const probe = observeProductRequests(page, origin, expected);
  const request = (method, url) => ({ method: () => method, url: () => url });
  const summary = request('POST', `${origin}/api/secureshop/products/7/summary`);
  const similar = request('POST', `${origin}/api/secureshop/products/7/similar`);
  const unrelated = request('POST', 'http://127.0.0.1:39118/api/secureshop/products/7/summary');
  for (const item of [summary, similar, unrelated]) page.emit('request', item);
  page.emit('response', { request: () => summary, status: () => 503 });
  page.emit('response', { request: () => similar, status: () => 503 });
  page.emit('requestfinished', summary);
  page.emit('requestfailed', similar);
  assert.deepEqual(probe.snapshot(), [
    { ...expected[0], requests: 1, responseStatuses: [503], finished: 1, failed: 0 },
    { ...expected[1], requests: 1, responseStatuses: [503], finished: 0, failed: 1 },
  ]);
  probe.stop();
  page.emit('request', summary);
  assert.equal(probe.snapshot()[0].requests, 1);
});

test('Product error body is bounded, exact, and never accepted on wrong status or JSON', async () => {
  const steps = [];
  const workStep = async (label, work, limit) => {
    steps.push({ label, limit });
    let timer;
    try {
      return await Promise.race([work(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('controlled body timeout')), 10);
      })]);
    } finally { clearTimeout(timer); }
  };
  const label = 'a08-product-summary-body';
  const valid = { status: () => 503,
    json: async () => ({ error: 'Bound SecureShop operation unavailable' }) };
  await readBoundedProductError(valid, { workStep, label });
  assert.deepEqual(steps, [{ label, limit: 5000 }]);
  await assert.rejects(readBoundedProductError({ status: () => 200,
    json: () => { throw new Error('body must not be read'); } }, { workStep, label }), /503/);
  await assert.rejects(readBoundedProductError({ status: () => 503,
    json: async () => ({ error: 'other' }) }, { workStep, label }), /exact unavailable-operation JSON/);
  await assert.rejects(readBoundedProductError({ status: () => 503,
    json: () => new Promise(() => {}) }, { workStep, label }), /controlled body timeout/);
  assert.deepEqual(steps, Array.from({ length: 3 }, () => ({ label, limit: 5000 })));
});

const READINESS = '/api/secureshop/merchant/listings/readiness';
const READINESS_BODY = JSON.stringify({ error: 'Bound SecureShop operation unavailable' });

async function readinessServer(t, observer, route, beforeObserve = () => {}) {
  const server = http.createServer((request, response) => {
    request.path = new URL(request.url, 'http://127.0.0.1').pathname;
    beforeObserve(response);
    observer.middleware(request, response, () => route(request, response));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    observer.stop();
    await new Promise(resolve => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function browserResponse(origin, response, overrides = {}) {
  return { status: () => overrides.status ?? response.status,
    request: () => ({ method: () => overrides.method ?? 'GET' }),
    url: () => overrides.url ?? `${origin}${READINESS}`,
    headers: () => overrides.headers ?? Object.fromEntries(response.headers) };
}

test('original readiness capture is passive, bounded, exact, and joined to browser response', async t => {
  let stage = 'merchant-listings-browser';
  const observer = observeOriginalListingReadiness({ isCurrent: () => stage === 'merchant-listings-browser' });
  let originalWrite, originalEnd, observedResponse, writeReturned, endReturned;
  let firstChunk;
  let writeCallback = false, endCallback = false;
  const origin = await readinessServer(t, observer, (_request, response) => {
    observedResponse = response;
    response.statusCode = 503;
    response.setHeader('content-type', 'application/json; charset=utf-8');
    firstChunk = Buffer.from(READINESS_BODY.slice(0, 10));
    writeReturned = response.write(firstChunk, () => { writeCallback = true; });
    endReturned = response.end(READINESS_BODY.slice(10), () => { endCallback = true; });
  }, response => { originalWrite = response.write; originalEnd = response.end; });
  observer.arm();
  const response = await fetch(`${origin}${READINESS}`);
  await response.arrayBuffer();
  await observer.wait();
  firstChunk.fill(0x20); // Captured bytes must not alias a caller-owned Buffer.
  assert.equal(response.status, 503);
  assert.equal(typeof writeReturned, 'boolean');
  assert.equal(endReturned, observedResponse);
  assert.equal(writeCallback, true);
  assert.equal(endCallback, true);
  observer.assertBrowserResponse(browserResponse(origin, response), origin);
  assert.equal(observedResponse.write, originalWrite);
  assert.equal(observedResponse.end, originalEnd);
  stage = 'retired';
});

test('readiness observer fails closed on browser mismatch and restores wrappers after failed assertion', async t => {
  const observer = observeOriginalListingReadiness({ isCurrent: () => true });
  let responseObject, originalWrite, originalEnd;
  const origin = await readinessServer(t, observer, (_request, response) => {
    responseObject = response;
    response.statusCode = 503;
    response.setHeader('content-type', 'application/json');
    response.end(READINESS_BODY);
  }, response => { originalWrite = response.write; originalEnd = response.end; });
  observer.arm();
  const response = await fetch(`${origin}${READINESS}`);
  await response.arrayBuffer();
  await observer.wait();
  assert.throws(() => observer.assertBrowserResponse(browserResponse(origin, response,
    { headers: {} }), origin), /match this original/);
  assert.equal(responseObject.write, originalWrite);
  assert.equal(responseObject.end, originalEnd);
  assert.throws(() => observer.arm(), /Expected values to be strictly equal/);
});

test('readiness capture remains stage- and path-scoped without recording other traffic', async t => {
  let stage = 'before-listings';
  const observer = observeOriginalListingReadiness({ isCurrent: () => stage === 'merchant-listings-browser' });
  const origin = await readinessServer(t, observer, (_request, response) => {
    response.statusCode = 503;
    response.setHeader('content-type', 'application/json');
    response.end(READINESS_BODY);
  });
  assert.throws(() => observer.arm(), /only in its original UI stage/);
  stage = 'merchant-listings-browser';
  observer.arm();
  const unrelated = await fetch(`${origin}/api/secureshop/merchant/listings/other`);
  assert.equal(unrelated.headers.has('x-dvaia-commerce-readiness-observation'), false);
  const wrongMethod = await fetch(`${origin}${READINESS}`, { method: 'POST' });
  assert.equal(wrongMethod.headers.has('x-dvaia-commerce-readiness-observation'), false);
  stage = 'retired';
  const retired = await fetch(`${origin}${READINESS}`);
  assert.equal(retired.headers.has('x-dvaia-commerce-readiness-observation'), false);
  assert.throws(() => observer.assertBrowserResponse(browserResponse(origin, retired), origin),
    /exactly one/);
});

test('readiness observer rejects duplicate, oversized, wrong-status and incomplete responses', async t => {
  const cases = [
    { kind: 'duplicate', expected: /exactly one/ },
    { kind: 'oversized', expected: /capture bounds/ },
    { kind: 'wrong-status', expected: /503/ },
    { kind: 'wrong-body', expected: /exact/ },
    { kind: 'incomplete', expected: /did not finish/ },
  ];
  for (const { kind, expected } of cases) {
    await t.test(kind, async scope => {
      const observer = observeOriginalListingReadiness({ isCurrent: () => true });
      const origin = await readinessServer(scope, observer, (_request, response) => {
        response.statusCode = kind === 'wrong-status' ? 200 : 503;
        response.setHeader('content-type', 'application/json');
        if (kind === 'incomplete') { response.write('{'); response.destroy(); return; }
        response.end(kind === 'oversized' ? 'x'.repeat(4097)
          : kind === 'wrong-body' ? '{"error":"different"}' : READINESS_BODY);
      });
      observer.arm();
      if (kind === 'incomplete') {
        await fetch(`${origin}${READINESS}`).catch(() => {});
        await observer.wait();
        assert.throws(() => observer.assertBrowserResponse({ status: () => 503 }, origin), expected);
      } else {
        const response = await fetch(`${origin}${READINESS}`);
        await response.arrayBuffer();
        await observer.wait();
        if (kind === 'duplicate') {
          const second = await fetch(`${origin}${READINESS}`);
          await second.arrayBuffer();
        }
        assert.throws(() => observer.assertBrowserResponse(browserResponse(origin, response), origin), expected);
      }
    });
  }
});
