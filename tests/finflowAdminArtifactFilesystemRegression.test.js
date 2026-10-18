'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createTraversalFixture: createBaseFixture, execution } = require('./helpers/finflowTraversalFixture');
function createTraversalFixture(t) {
  const evidenceRoot = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'finflow-admin-artifact-controls-'));
  t.after(() => fs.rmSync(evidenceRoot, { recursive: true, force: true }));
  assert.equal(fs.realpathSync(evidenceRoot), evidenceRoot);
  const stat = fs.lstatSync(evidenceRoot);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.uid, process.getuid());
  assert.equal(stat.mode & 0o777, 0o700);
  return createBaseFixture(t, { baseDirectory: evidenceRoot });
}
const { verifyAdminArtifactReceipt } = require('../server/services/finflowAdminArtifactReceipt');
const { createFinflowTraversalManager } = require('../server/services/finflowTraversalArtifacts');

test('admin config reads actual provisioned bytes and binds exact identity and content', async t => {
  const { manager, repository, root } = createTraversalFixture(t);
  const scope = execution('admin-a');
  for (const configFile of ['secrets.env', 'database.yml', 'server.conf', 'llm_config.yml']) {
    const result = await manager.readAdminConfig({ execution: scope, configFile });
    const target = await repository.get(scope);
    assert.equal(result.content, fs.readFileSync(path.join(root, target.targetToken,
      result.virtualPath.slice('/var/app/'.length)), 'utf8'));
    const args = { receipt: result.artifactReceipt, execution: scope, kind: 'config',
      virtualPath: result.virtualPath, value: result.content };
    assert.equal(verifyAdminArtifactReceipt(args), result.artifactReceipt);
    for (const change of [{ receipt: { ...result.artifactReceipt } },
      { execution: { ...scope } }, { value: result.content + 'forged' },
      { kind: 'directory' }, { virtualPath: '/other' }, { execution: execution('other') }]) {
      assert.equal(verifyAdminArtifactReceipt({ ...args, ...change }), null);
    }
  }
});

test('directory result is an actual owned listing with a bound receipt', async t => {
  const { manager, repository, root } = createTraversalFixture(t);
  const scope = execution('directory-a');
  const result = await manager.listAdminDirectory({ execution: scope,
    directoryPath: '/var/app/sensitive_files/config' });
  const target = await repository.get(scope);
  assert.deepEqual(result.listing, fs.readdirSync(path.join(root, target.targetToken,
    'sensitive_files/config')).sort());
  assert.equal(verifyAdminArtifactReceipt({ receipt: result.artifactReceipt,
    execution: scope, kind: 'directory', virtualPath: result.virtualPath,
    value: JSON.stringify(result.listing) }), result.artifactReceipt);
});

test('unknown and prototype inputs cannot select a fallback artifact', async t => {
  const { manager, repository } = createTraversalFixture(t);
  const scope = execution('unknown-a');
  for (const value of ['__proto__', 'constructor', '../secrets.env', '', null, {}, 42]) {
    await assert.rejects(manager.readAdminConfig({ execution: scope, configFile: value }),
      { code: 'CONTROLLED_ADMIN_ARTIFACT_UNKNOWN' });
    await assert.rejects(manager.listAdminDirectory({ execution: scope, directoryPath: value }),
      { code: 'CONTROLLED_ADMIN_ARTIFACT_UNKNOWN' });
  }
  await assert.rejects(manager.listAdminDirectory({ execution: scope,
    directoryPath: '/var/app/../../outside' }), { code: 'CONTROLLED_ADMIN_ARTIFACT_UNKNOWN' });
  assert.equal(repository.rows.size, 0);
});

test('default app and etc directories list real entries without lifecycle metadata', async t => {
  const { manager } = createTraversalFixture(t);
  const scope = execution('root-list-a');
  const app = await manager.listAdminDirectory({ execution: scope, directoryPath: '/var/app' });
  assert.deepEqual(app.listing, ['config/', 'etc/', 'sensitive_files/']);
  const etc = await manager.listAdminDirectory({ execution: scope, directoryPath: '/etc' });
  assert.deepEqual(etc.listing, ['passwd']);
});

test('linked parent is rejected even when it redirects to another owned directory', async t => {
  const { manager, repository, root } = createTraversalFixture(t);
  const scope = execution('parent-link-a');
  await manager.readAdminConfig({ execution: scope, configFile: 'secrets.env' });
  const target = await repository.get(scope);
  const directory = path.join(root, target.targetToken, 'config');
  fs.rmSync(directory, { recursive: true });
  fs.symlinkSync('sensitive_files/config', directory);
  await assert.rejects(manager.readAdminConfig({ execution: scope, configFile: 'secrets.env' }),
    { code: 'CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE' });
});

test('missing bytes and symlink substitution fail instead of reporting success', async t => {
  const { manager, repository, root } = createTraversalFixture(t);
  const scope = execution('tamper-a');
  await manager.readAdminConfig({ execution: scope, configFile: 'secrets.env' });
  const target = await repository.get(scope);
  const filename = path.join(root, target.targetToken, 'config/secrets.env');
  fs.unlinkSync(filename);
  await assert.rejects(manager.readAdminConfig({ execution: scope, configFile: 'secrets.env' }),
    { code: 'CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE' });
  fs.symlinkSync('../sensitive_files/config/secrets.env', filename);
  await assert.rejects(manager.readAdminConfig({ execution: scope, configFile: 'secrets.env' }),
    { code: 'CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE' });
  await assert.rejects(manager.listAdminDirectory({ execution: scope, directoryPath: '/var/app/config' }),
    { code: 'CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE' });
});

test('retirement removes only the owner target; stale execution cannot create evidence', async t => {
  const { manager } = createTraversalFixture(t);
  const scope = execution('retire-a');
  const sibling = execution('retire-b');
  await manager.readAdminConfig({ execution: scope, configFile: 'secrets.env' });
  await manager.readAdminConfig({ execution: sibling, configFile: 'secrets.env' });
  await manager.retireOwner(scope.ownerId);
  await assert.rejects(manager.readAdminConfig({ execution: scope, configFile: 'secrets.env' }),
    { code: 'TRAVERSAL_TARGET_RETIRED' });
  assert.ok((await manager.readAdminConfig({ execution: sibling, configFile: 'secrets.env' })).content);
  const stale = { ...execution('stale-a'), check: async () => { throw new Error('stale execution'); } };
  await assert.rejects(manager.listAdminDirectory({ execution: stale, directoryPath: '/etc' }), /stale execution/);
});

test('lease loss during the actual file read prevents receipt publication', async t => {
  const { manager, repository, root } = createTraversalFixture(t);
  let revoked = false;
  const scope = { ...execution('lease-read-a'), check: async () => {
    if (revoked) throw new Error('lease revoked during read');
  } };
  await manager.readAdminConfig({ execution: scope, configFile: 'secrets.env' });
  const target = await repository.get(scope);
  const targetFile = path.join(fs.realpathSync(root), target.targetToken, 'config/secrets.env');
  const guardedFs = Object.create(fs);
  guardedFs.readFileSync = (filename, options) => {
    const result = fs.readFileSync(filename, options);
    if (filename === targetFile) revoked = true;
    return result;
  };
  const guardedManager = createFinflowTraversalManager({ repository, root, fsImpl: guardedFs });
  await assert.rejects(guardedManager.readAdminConfig({ execution: scope, configFile: 'secrets.env' }),
    /lease revoked during read/);
  assert.equal(revoked, true, 'the controlled file read must actually trigger the lease change');
});

test('all advertised configs persist across reopen and missing initialized files are not reseeded', async t => {
  const { manager, repository, root } = createTraversalFixture(t);
  const scope = execution('persistent-config-a');
  const first = await manager.readAdminConfig({ execution: scope, configFile: 'database.yml' });
  const reopened = createFinflowTraversalManager({ repository, root });
  const second = await reopened.readAdminConfig({ execution: scope, configFile: 'database.yml' });
  assert.equal(first.content, second.content);
  assert.match(second.content, /Controlled FinFlow teaching fixture/);
  const listing = await reopened.listAdminDirectory({ execution: scope, directoryPath: '/var/app/config' });
  assert.deepEqual(listing.listing, ['database.yml', 'secrets.env', 'server.conf']);
  const target = await repository.get(scope);
  const filename = path.join(root, target.targetToken, 'config/database.yml');
  fs.unlinkSync(filename);
  await assert.rejects(reopened.readAdminConfig({ execution: scope, configFile: 'database.yml' }),
    { code: 'CONTROLLED_ADMIN_ARTIFACT_UNAVAILABLE' });
  assert.equal(fs.existsSync(filename), false);
});
