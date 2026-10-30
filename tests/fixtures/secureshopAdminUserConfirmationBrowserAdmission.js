'use strict';

// Closed, test-only current-host admission for the existing four-turn administrator
// user-confirmation browser cohort. The ordinary external-evidence path is retained.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { buildInventory } = require('../postgres/adminQ05RenderedScenario');
const { readInheritedFifoGrant } = require('./inheritedFifoGrant');
const { captureBrowserRecord } = require('./secureshopDarwinBrowserBirth');

const PREFIX = 'SECURESHOP_ADMIN_USER_CONFIRMATION_';
const COHORT = 'admin-user-chat-browser';
const SHA256 = /^[a-f0-9]{64}$/;
const OTHER_COHORT_FLAGS = Object.freeze([
  'SECURESHOP_STANDALONE_ROLE_CHOICES_NATIVE',
  'SECURESHOP_MERCHANT_INVENTORY_CHAT_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_LISTING_EDIT_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_LISTING_CREATE_BROWSER_NATIVE',
  'SECURESHOP_LISTING_RAW_BROWSER_NATIVE',
  'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_ORDER_BROWSER_NATIVE',
  'SECURESHOP_NAMED_ORDER_FILTER_BROWSER_NATIVE',
  'SECURESHOP_CATALOG_PAGE_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_REVIEW_BROWSER_NATIVE',
  'SECURESHOP_REVIEW_INJECTION_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_MAIL_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_MAIL_HEADER_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_MAIL_HTML_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_MAIL_AGENT_READ_BROWSER_NATIVE',
  'SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_NATIVE',
  'SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE',
  'SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE',
  'SECURESHOP_ADMIN_AUDIT_CHAT_BROWSER_NATIVE',
  'SECURESHOP_ADMIN_READ_CHAT_BROWSER_NATIVE',
  'SECURESHOP_SYSTEM_CONFIG_TRAVERSAL_BROWSER_NATIVE',
  'SECURESHOP_SYSTEM_CREDENTIAL_DISCLOSURE_BROWSER_NATIVE',
  'SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE',
  'SECURESHOP_ADMIN_PASSWORD_RESET_CHAT_BROWSER_NATIVE',
  'SECURESHOP_POLICY_TEMPLATE_BROWSER_NATIVE',
  'SECURESHOP_ADMIN_POLICY_CHAT_BROWSER_NATIVE',
  'SECURESHOP_CHAT_STOP_WATCHING_BROWSER_NATIVE',
  'SECURESHOP_CHAT_PRESENTATION_BROWSER_NATIVE',
]);

function privateDirectory(directory) {
  const info = fs.lstatSync(directory);
  assert.ok(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid());
  assert.equal(info.mode & 0o777, 0o700);
  assert.equal(fs.realpathSync(directory), directory);
}

function validateAdminUserConfirmationGrant(grant, { workspace, evidencePath, buildSha256,
  snapshotSha256, chromium, chromiumSha256, launcherPid, workerPid }) {
  assert.ok(grant && typeof grant === 'object' && !Array.isArray(grant));
  assert.deepEqual(Object.keys(grant).sort(), ['version', 'cohort', 'launcherPid', 'workerPid',
    'nonce', 'workspace', 'evidencePath', 'buildSha256', 'snapshotSha256',
    'outerSandbox', 'chromium', 'chromiumSha256'].sort());
  assert.equal(grant.version, 1);
  assert.equal(grant.cohort, COHORT);
  assert.equal(grant.launcherPid, launcherPid);
  assert.equal(grant.workerPid, workerPid);
  assert.match(grant.nonce, SHA256);
  assert.equal(grant.workspace, workspace);
  assert.equal(grant.evidencePath, evidencePath);
  assert.equal(grant.buildSha256, buildSha256);
  assert.equal(grant.snapshotSha256, snapshotSha256);
  assert.equal(grant.outerSandbox, 'repository-only');
  assert.equal(grant.chromium, chromium);
  assert.equal(grant.chromiumSha256, chromiumSha256);
  return { admitted: true };
}

async function admitAdminUserConfirmationBrowser(env, { workspace, evidencePath, executablePath }) {
  if (env[`${PREFIX}TEST_NO_SANDBOX`] === undefined) {
    assert.ok(!path.resolve(evidencePath).startsWith(`${workspace}${path.sep}`),
      'ordinary administrator user-confirmation evidence must remain outside the checkout');
    return null;
  }
  assert.equal(env[`${PREFIX}TEST_NO_SANDBOX`], '1');
  assert.equal(env.SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE, '1');
  for (const flag of OTHER_COHORT_FLAGS) assert.notEqual(env[flag], '1', `${flag} is a different cohort`);
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.LIVE_OLLAMA_TEST, '1');
  assert.equal(env.NODE_ENV, 'test');
  assert.equal(env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE, workspace);
  assert.equal(workspace, process.cwd());
  assert.equal(fs.realpathSync(workspace), workspace);
  assert.ok(path.isAbsolute(evidencePath) && path.resolve(evidencePath) === evidencePath);
  const run = path.dirname(evidencePath);
  assert.equal(path.dirname(run), path.join(workspace, 'tasks/qualification'));
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  assert.equal(evidencePath, path.join(run, 'admin-user-chat-browser.json'));
  const tempRoot = path.join(run, 'runtime/tmp');
  assert.equal(env.TMPDIR, tempRoot);
  assert.equal(env.MAC_CHROMIUM_TMPDIR, tempRoot);
  assert.equal(env[`${PREFIX}BROWSER_RECORD_PATH`],
    path.join(run, 'admin-user-confirmation-browser-birth.json'));
  assert.equal(env[`${PREFIX}BROWSER_ACK_PATH`],
    path.join(run, 'admin-user-confirmation-browser-ack.json'));
  for (const key of ['BROWSER_SHA256', 'SNAPSHOT_SHA256', 'BUILD_SHA256'])
    assert.match(env[`${PREFIX}${key}`], SHA256);
  assert.equal(env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,
    path.join(workspace, 'tests/postgres/secureshop_darwin_browser_birth.py'));
  assert.ok(path.isAbsolute(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON));
  assert.equal(fs.realpathSync(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON),
    env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON);
  assert.equal(executablePath, env.PUPPETEER_EXECUTABLE_PATH);
  assert.equal(fs.realpathSync(executablePath), executablePath);
  assert.equal(env.SECURESHOP_ADMIN_USER_CHAT_BROWSER_BUILD,
    path.join(workspace, 'client/build'));
  const taskRoot = fs.lstatSync(path.join(workspace, 'tasks'));
  assert.ok(taskRoot.isDirectory() && !taskRoot.isSymbolicLink()
    && taskRoot.uid === process.getuid());
  assert.equal(fs.realpathSync(path.join(workspace, 'tasks')), path.join(workspace, 'tasks'));
  for (const directory of [path.join(workspace, 'tasks/qualification'), run,
    path.join(run, 'runtime'), tempRoot])
    privateDirectory(directory);
  const verifyBuild = async () => {
    const inventory = await buildInventory(path.join(workspace, 'client/build'));
    assert.equal(inventory.sha256, env[`${PREFIX}BUILD_SHA256`],
      'admin-user-confirmation existing production build pin mismatch');
  };
  await verifyBuild();
  const grant = await readInheritedFifoGrant(env, `${PREFIX}ADMISSION_FD`, 'Administrator user confirmation');
  validateAdminUserConfirmationGrant(grant, { workspace, evidencePath,
    buildSha256: env[`${PREFIX}BUILD_SHA256`], snapshotSha256: env[`${PREFIX}SNAPSHOT_SHA256`],
    chromium: executablePath, chromiumSha256: env[`${PREFIX}BROWSER_SHA256`],
    launcherPid: process.ppid, workerPid: process.pid });

  function browserArgs({ profile, origin }) {
    privateDirectory(profile);
    assert.equal(path.dirname(profile), tempRoot);
    assert.match(path.basename(profile), /^owasp-ai-goat-role-admin-user-[A-Za-z0-9_-]+$/);
    const target = new URL(origin);
    assert.equal(target.origin, origin);
    assert.equal(target.protocol, 'http:');
    assert.equal(target.hostname, '127.0.0.1');
    assert.match(target.port, /^[1-9]\d{0,4}$/);
    assert.ok(Number(target.port) <= 65535);
    return ['--no-sandbox', '--disable-background-networking', '--disable-component-update',
      '--disable-domain-reliability', '--disable-quic',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--proxy-server=http://blocked.invalid:9', '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]'];
  }

  function watchBrowserTargets(browser) {
    let expectedPageCreations = 0;
    let unexpectedTarget = null;
    browser.on('targetcreated', target => {
      if (target.type() === 'page' && expectedPageCreations > 0) {
        expectedPageCreations -= 1;
        return;
      }
      unexpectedTarget ||= target.type();
      if (target.type() === 'page') void target.page().then(page => page?.close()).catch(() => {});
    });
    return {
      async newPage(context) {
        expectedPageCreations += 1;
        try {
          const page = await context.newPage();
          assert.equal(expectedPageCreations, 0, 'admin-user-confirmation page birth not observed');
          assert.equal(unexpectedTarget, null, 'unexpected admin-user-confirmation browser target');
          return page;
        } catch (error) {
          expectedPageCreations = 0;
          throw error;
        }
      },
      assertNoUnexpectedTargets() {
        assert.equal(expectedPageCreations, 0);
        assert.equal(unexpectedTarget, null, 'unexpected admin-user-confirmation browser target');
      },
    };
  }

  async function guardPageRequests(page, origin) {
    const target = new URL(origin);
    assert.equal(target.origin, origin);
    assert.equal(target.protocol, 'http:');
    assert.equal(target.hostname, '127.0.0.1');
    await page.setRequestInterception(true);
    page.on('request', request => {
      let allowed = false;
      try { allowed = new URL(request.url()).origin === origin; } catch { /* deny malformed URL */ }
      return allowed ? request.continue() : request.abort();
    });
  }

  async function acknowledgeBrowser({ browser, profile }) {
    privateDirectory(profile);
    assert.equal(path.dirname(profile), tempRoot);
    const pid = browser.process()?.pid;
    assert.ok(Number.isSafeInteger(pid) && pid > 1);
    const record = captureBrowserRecord({ root: workspace, kind: 'admin_user_confirmation_browser',
      pid, executablePath, executableSha256: env[`${PREFIX}BROWSER_SHA256`] });
    const recordPath = env[`${PREFIX}BROWSER_RECORD_PATH`];
    const temporary = `${recordPath}.${process.pid}.tmp`;
    await fs.promises.writeFile(temporary, `${JSON.stringify(record)}\n`, { flag: 'wx', mode: 0o600 });
    await fs.promises.rename(temporary, recordPath);
    const expected = createHash('sha256').update(await fs.promises.readFile(recordPath)).digest('hex');
    const until = Date.now() + 15000;
    while (Date.now() < until) {
      let value;
      try { value = JSON.parse(await fs.promises.readFile(env[`${PREFIX}BROWSER_ACK_PATH`], 'utf8')); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        await new Promise(resolve => setTimeout(resolve, 25));
        continue;
      }
      const info = await fs.promises.lstat(env[`${PREFIX}BROWSER_ACK_PATH`]);
      assert.ok(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid()
        && (info.mode & 0o777) === 0o600);
      assert.deepEqual(value, { schemaVersion: 1, recordSha256: expected, parentPid: process.pid,
        browserPid: pid, profile });
      return;
    }
    throw new Error('Administrator user-confirmation independent live browser capture acknowledgement unavailable');
  }
  return { browserArgs, watchBrowserTargets, guardPageRequests, acknowledgeBrowser, verifyBuild };
}

module.exports = { admitAdminUserConfirmationBrowser, validateAdminUserConfirmationGrant };

