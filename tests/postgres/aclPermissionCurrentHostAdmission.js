'use strict';

// Separate, import-inert current-host student deletion fixture. Native execution
// stays closed until the complete sixteen-store oracle and launcher admission
// have been independently reviewed; these helpers never create test authority.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { readInheritedFifoGrant } = require('../fixtures/inheritedFifoGrant');
const { buildInventory, focusQ05MainPage, renderedRowAction } = require('./adminQ05RenderedScenario');
const { admitStores, STORES, BUDGET, createFixturePool, assertPoolSnapshot } =
  require('./adminStudentDeletionRenderedSupport');

const REPO = path.resolve(__dirname, '../..');
const COHORT = 'admin-acl-permission-current-host';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = value => crypto.createHash('sha256').update(value).digest('hex');

function deletionStorePlanSha256(rows) {
  assert(Array.isArray(rows) && rows.length === 16);
  return sha(Buffer.from(JSON.stringify(rows.map(({ database, schema }) => ({ database, schema }))), 'utf8'));
}

function deletionPaths(env, repo = REPO) {
  assert.equal(env.ADMIN_ACL_PERMISSION_CURRENT_HOST, '1');
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  const root = path.join(repo, 'tasks/qualification');
  const evidence = env.ACL_PERMISSION_EVIDENCE_PATH;
  assert.equal(typeof evidence, 'string');
  assert(path.isAbsolute(evidence));
  assert.equal(path.basename(evidence), 'acl-permission-evidence.json');
  const run = path.dirname(evidence);
  assert.equal(path.dirname(run), root);
  assert(/^run-[a-z0-9_-]+$/.test(path.basename(run)));
  const runtime = path.join(run, 'runtime');
  const temp = path.join(runtime, 'tmp');
  assert.equal(env.ACL_PERMISSION_RESOURCE_JOURNAL,
    path.join(temp, 'acl-permission-resources.json'));
  assert.equal(env.ADMIN_ACL_PERMISSION_BROWSER_ACK,
    path.join(runtime, 'browser-ack.json'));
  const buildDirectory = path.join(repo, 'client/build');
  assert.equal(env.ADMIN_ACL_PERMISSION_BUILD_DIRECTORY, buildDirectory);
  for (const key of ['ADMIN_ACL_PERMISSION_BUILD_SHA256',
    'ADMIN_ACL_PERMISSION_SNAPSHOT_SHA256', 'ADMIN_ACL_PERMISSION_STORE_PLAN_SHA256'])
    assert(SHA256.test(env[key] || ''), `${key} pin required`);
  assert.equal(env.PUPPETEER_EXECUTABLE_PATH, env.DVAIA_CHROMIUM_ACTUAL_EXECUTABLE);
  assert(path.isAbsolute(env.PUPPETEER_EXECUTABLE_PATH));
  return { run, runtime, temp, evidence, buildDirectory };
}

function validateDeletionGrant(grant, { env, paths, repo = REPO,
  launcherPid = process.ppid, workerPid = process.pid }) {
  assert(grant && typeof grant === 'object' && !Array.isArray(grant));
  assert.deepEqual(Object.keys(grant).sort(), ['version', 'cohort', 'launcherPid', 'workerPid',
    'nonce', 'workspace', 'buildSha256', 'snapshotSha256', 'outerSandbox', 'chromium',
    'profile', 'storePlanSha256'].sort());
  assert.equal(grant.version, 1);
  assert.equal(grant.cohort, COHORT);
  assert.equal(grant.launcherPid, launcherPid);
  assert.equal(grant.workerPid, workerPid);
  assert(/^[0-9a-f]{12}$/.test(grant.nonce));
  assert.equal(grant.workspace, repo);
  assert.equal(grant.buildSha256, env.ADMIN_ACL_PERMISSION_BUILD_SHA256);
  assert.equal(grant.snapshotSha256, env.ADMIN_ACL_PERMISSION_SNAPSHOT_SHA256);
  assert.equal(grant.storePlanSha256, env.ADMIN_ACL_PERMISSION_STORE_PLAN_SHA256);
  assert.equal(grant.outerSandbox, 'repository-only');
  assert.equal(grant.chromium, env.DVAIA_CHROMIUM_ACTUAL_EXECUTABLE);
  assert.equal(path.dirname(grant.profile), paths.temp);
  assert(/^dvaia-acl-permission-browser-[0-9a-f]{12}$/.test(path.basename(grant.profile)));
  assert.equal(path.basename(grant.profile), `dvaia-acl-permission-browser-${grant.nonce}`);
  return { admitted: true, nonceSha256: sha(grant.nonce), profile: grant.profile };
}

async function admitDeletionCurrentHost(env = process.env, repo = REPO) {
  const paths = deletionPaths(env, repo);
  for (const directory of [paths.run, paths.runtime, paths.temp]) {
    const info = await fs.lstat(directory);
    assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid()
      && (info.mode & 0o077) === 0, 'Student deletion runtime directories must be owned and private');
    assert.equal(await fs.realpath(directory), directory);
  }
  const stores = admitStores(env);
  assert.equal(deletionStorePlanSha256(stores), env.ADMIN_ACL_PERMISSION_STORE_PLAN_SHA256);
  const grant = await readInheritedFifoGrant(env, 'ADMIN_ACL_PERMISSION_ADMISSION_FD',
    'student deletion');
  const admitted = validateDeletionGrant(grant, { env, paths, repo });
  const initial = await buildInventory(paths.buildDirectory);
  assert.equal(initial.sha256, env.ADMIN_ACL_PERMISSION_BUILD_SHA256);
  return { ...paths, ...admitted, stores, async verifyBuild() {
    const current = await buildInventory(paths.buildDirectory);
    assert.equal(current.sha256, initial.sha256);
    assert.deepEqual(current.files, initial.files);
  }, async awaitBrowserAck(pid) {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      let info;
      try { info = await fs.lstat(env.ADMIN_ACL_PERMISSION_BROWSER_ACK); }
      catch (error) { if (error.code === 'ENOENT') { await delay(25); continue; } throw error; }
      assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1
        && (info.mode & 0o077) === 0 && info.uid === process.getuid());
      const ack = JSON.parse(await fs.readFile(env.ADMIN_ACL_PERMISSION_BROWSER_ACK, 'utf8'));
      assert.deepEqual(Object.keys(ack).sort(), ['version', 'pid', 'pgid', 'sessionId', 'uid',
        'startSec', 'startUsec', 'profile', 'executable'].sort());
      assert.equal(ack.version, 1);
      assert.equal(ack.pid, pid);
      assert(Number.isSafeInteger(ack.pgid) && ack.pgid > 0);
      assert(Number.isSafeInteger(ack.sessionId) && ack.sessionId > 0);
      assert.equal(ack.uid, process.getuid());
      assert(Number.isSafeInteger(ack.startSec) && ack.startSec > 0);
      assert(Number.isSafeInteger(ack.startUsec) && ack.startUsec >= 0);
      assert.equal(ack.profile, admitted.profile);
      assert.equal(ack.executable, env.DVAIA_CHROMIUM_ACTUAL_EXECUTABLE);
      return { acknowledged: true, pid };
    }
    throw new Error('Student deletion live browser birth ACK timed out');
  } };
}

module.exports = { admitAclCurrentHost: admitDeletionCurrentHost, validateGrant: validateDeletionGrant, validateStores: admitStores };
