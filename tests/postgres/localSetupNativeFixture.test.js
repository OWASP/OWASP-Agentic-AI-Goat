'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomBytes } = require('node:crypto');
const {
  MARKER,
  createDockerAdapters,
  inspectOptional,
  inspectPinnedPostgresImage,
  createOwnedDirectory,
  removeOwnedDirectory,
  cleanupOwnedFixture,
  createRecoveryJournal,
  updateRecoveryJournal,
} = require('./localSetupNativeFixture');

const SOCKET = 'unix:///tmp/dvaia-native-fixture.sock';

function missing(kind, name) {
  const label = kind === 'container' ? 'object' : 'volume';
  return Object.assign(new Error('missing'), {
    code: 1,
    stderr: `Error response from daemon: No such ${label}: ${name}\n`,
  });
}

test('strict application adapter requires one exact host and a sanitized environment', async () => {
  assert.throws(() => createDockerAdapters({ socket: 'tcp://remote.invalid:2375' }), /local Docker Unix socket/);
  assert.throws(() => createDockerAdapters({ socket: 'unix:///tmp/../wrong.sock' }), /must be canonical/);
  const calls = [];
  const { applicationExecute } = createDockerAdapters({
    socket: SOCKET,
    environment: { DOCKER_HOST: 'tcp://ambient.invalid', DOCKER_CONTEXT: 'remote', KEEP: 'fixture' },
    executeFile: async (command, args, options) => {
      calls.push({ command, args, options });
      return { stdout: 'ok' };
    },
  });
  await applicationExecute('docker', ['--host', SOCKET, 'info'], { env: { KEEP: 'application' } });
  assert.deepEqual(calls[0].args, ['--host', SOCKET, 'info']);
  assert.deepEqual(calls[0].options.env, { KEEP: 'application' });

  const invalid = [
    ['sh', ['--host', SOCKET, 'info'], { env: {} }],
    ['docker', ['info'], { env: {} }],
    ['docker', ['--host', 'unix:///tmp/wrong.sock', 'info'], { env: {} }],
    ['docker', ['--host', SOCKET, '--host', SOCKET, 'info'], { env: {} }],
    ['docker', ['--host', SOCKET, 'info'], { env: { DOCKER_HOST: SOCKET } }],
    ['docker', ['--host', SOCKET, 'info'], { env: { DOCKER_CONTEXT: 'default' } }],
    ['docker', ['--host', SOCKET, 'info'], { env: { DOCKER_TLS_VERIFY: '1' } }],
    ['docker', ['--host', SOCKET, 'info'], { env: { DOCKER_CERT_PATH: '/tmp/certs' } }],
  ];
  for (const args of invalid) await assert.rejects(applicationExecute(...args));
  assert.equal(calls.length, 1, 'Malformed application calls must not reach Docker');
});

test('owned adapter binds cleanup explicitly without inheriting ambient authority', async () => {
  const calls = [];
  const { ownedDocker } = createDockerAdapters({
    socket: SOCKET,
    environment: { DOCKER_HOST: 'tcp://ambient.invalid', DOCKER_CONTEXT: 'remote',
      DOCKER_TLS_VERIFY: '1', DOCKER_CERT_PATH: '/tmp/certs', KEEP: 'fixture' },
    executeFile: async (command, args, options) => { calls.push({ command, args, options });return { stdout: '[]' }; },
  });
  await ownedDocker(['inspect', 'fixture']);
  assert.deepEqual(calls[0].args, ['--host', SOCKET, 'inspect', 'fixture']);
  assert.deepEqual(calls[0].options.env, { KEEP: 'fixture' });
});

test('absence requires an explicit Docker missing-object response', async () => {
  assert.equal(await inspectOptional(async () => { throw missing('container', 'fixture'); }, 'container', 'fixture'), null);
  assert.equal(await inspectOptional(async () => { throw missing('volume', 'fixture'); }, 'volume', 'fixture'), null);
  assert.equal(await inspectOptional(async () => {
    throw Object.assign(new Error('missing'), { code: 1,
      stderr: 'Error response from daemon: get fixture: no such volume\n' });
  }, 'volume', 'fixture'), null);
  await assert.rejects(inspectOptional(async () => {
    throw Object.assign(new Error('different volume'), { code: 1,
      stderr: 'Error response from daemon: get another-fixture: no such volume\n' });
  }, 'volume', 'fixture'), /different volume/);
  await assert.rejects(inspectOptional(async () => {
    throw Object.assign(new Error('daemon unavailable'), { code: 1, stderr: 'Cannot connect to the Docker daemon\n' });
  }, 'container', 'fixture'), /daemon unavailable/);
  await assert.rejects(inspectOptional(async () => {
    throw Object.assign(new Error('permission denied'), { code: 1, stderr: 'permission denied\n' });
  }, 'volume', 'fixture'), /permission denied/);
});

test('image preflight requires an already-present immutable PostgreSQL digest', async () => {
  const id = `sha256:${'a'.repeat(64)}`;
  assert.deepEqual(await inspectPinnedPostgresImage(async () => ({ stdout: JSON.stringify([{
    Id: id, RepoDigests: [`postgres@sha256:${'b'.repeat(64)}`],
  }]) })), { id, repoDigests: [`postgres@sha256:${'b'.repeat(64)}`] });
  await assert.rejects(inspectPinnedPostgresImage(async () => { throw missing('container', 'postgres:18'); }),
    /must already exist locally.*never pulls/);
  await assert.rejects(inspectPinnedPostgresImage(async () => ({ stdout: JSON.stringify([{
    Id: id, RepoDigests: [],
  }]) })), /immutable repository digest/);
});

test('cleanup refuses unowned resources before any removal', async () => {
  const id = randomBytes(6).toString('hex'), nonce = randomBytes(8).toString('hex');
  const name = `dvaia-postgres-${id}`;
  const directory = await createOwnedDirectory({ id, nonce });
  const calls = [];
  const ownedDocker = async args => {
    calls.push(args);
    if (args[0] === 'inspect') return { stdout: JSON.stringify([{ Config: { Labels: {} } }]) };
    if (args[0] === 'volume' && args[1] === 'inspect') {
      return { stdout: JSON.stringify([{ Labels: { 'org.dvaia.workspace': id } }]) };
    }
    assert.fail('Cleanup must not remove anything after an ownership mismatch');
  };
  await assert.rejects(cleanupOwnedFixture({ ownedDocker, id, name, directory, nonce }), /without exact fixture ownership/);
  assert.deepEqual(calls, [['inspect', name], ['volume', 'inspect', name]]);
  await removeOwnedDirectory({ directory, id, nonce });
});

test('cleanup removes only the exact owned container, volume and marked directory', async () => {
  const id = randomBytes(6).toString('hex'), nonce = randomBytes(8).toString('hex');
  const name = `dvaia-postgres-${id}`;
  const directory = await createOwnedDirectory({ id, nonce });
  let container = { Config: { Labels: { 'org.dvaia.workspace': id } } };
  let volume = { Labels: { 'org.dvaia.workspace': id } };
  const calls = [];
  const ownedDocker = async args => {
    calls.push(args);
    if (args[0] === 'inspect') {
      if (!container) throw missing('container', name);
      return { stdout: JSON.stringify([container]) };
    }
    if (args[0] === 'volume' && args[1] === 'inspect') {
      if (!volume) throw missing('volume', name);
      return { stdout: JSON.stringify([volume]) };
    }
    if (args[0] === 'rm') { container = null;return { stdout: name }; }
    if (args[0] === 'volume' && args[1] === 'rm') { volume = null;return { stdout: name }; }
    assert.fail(`Unexpected cleanup command: ${args.join(' ')}`);
  };
  assert.deepEqual(await cleanupOwnedFixture({ ownedDocker, id, name, directory, nonce }), {
    containerRemoved: true, volumeRemoved: true, containerAbsent: true, volumeAbsent: true, directoryRemoved: true,
  });
  assert.deepEqual(calls, [
    ['inspect', name], ['volume', 'inspect', name], ['rm', '--force', name], ['volume', 'rm', name],
    ['inspect', name], ['volume', 'inspect', name],
  ]);
  await assert.rejects(fs.lstat(directory), { code: 'ENOENT' });
});

test('directory cleanup rejects directory and marker symlinks before resolving or reading them', async t => {
  const id = randomBytes(6).toString('hex'), nonce = randomBytes(8).toString('hex');
  const target = await createOwnedDirectory({ id, nonce });
  const link = path.join(os.tmpdir(), `dvaia-local-pg-link-${randomBytes(4).toString('hex')}`);
  await fs.symlink(target, link);
  t.after(() => fs.rm(link, { force: true }));
  await assert.rejects(removeOwnedDirectory({ directory: link, id, nonce }), /real directory before resolution/);
  await fs.rm(link);

  const marker = path.join(target, MARKER);
  const realMarker = path.join(target, 'retained-marker.json');
  await fs.rename(marker, realMarker);
  await fs.symlink(realMarker, marker);
  await assert.rejects(removeOwnedDirectory({ directory: target, id, nonce }), /marker must be a real file/);
  await fs.rm(marker);
  await fs.rename(realMarker, marker);
  await removeOwnedDirectory({ directory: target, id, nonce });
});

test('recovery journal is private, atomic, outside the workspace and excludes secrets', async t => {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-native-evidence-'));
  await fs.chmod(parent, 0o700);
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const evidencePath = path.join(parent, 'recovery.json');
  const workspace = path.resolve(__dirname, '../..');
  const initial = { version: 1, status: 'preflight', id: 'fixture', name: 'container',
    directory: '/tmp/fixture', canonicalDirectory: '/private/tmp/fixture', nonce: 'nonce',
    sourceHashes: { fixture: 'a'.repeat(64) }, expectedImage: null, daemonId: null,
    containerId: null, phases: [], cleanup: null };
  await createRecoveryJournal({ evidencePath, workspace, state: initial });
  assert.deepEqual(JSON.parse(await fs.readFile(evidencePath, 'utf8')), initial);
  assert.equal((await fs.stat(evidencePath)).mode & 0o777, 0o600);
  const updated = { ...initial, status: 'ready', daemonId: 'daemon', phases: [{ name: 'preflight', complete: true }] };
  await updateRecoveryJournal({ evidencePath, workspace, state: updated });
  assert.deepEqual(JSON.parse(await fs.readFile(evidencePath, 'utf8')), updated);
  await assert.rejects(fs.lstat(`${evidencePath}.pending`), { code: 'ENOENT' });
  await assert.rejects(updateRecoveryJournal({ evidencePath, workspace,
    state: { ...updated, password: 'forbidden' } }), /journal key password is forbidden/);

  await assert.rejects(createRecoveryJournal({ evidencePath: 'relative.json', workspace, state: initial }),
    /path must be absolute/);
  const fakeWorkspace = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-native-workspace-'));
  await fs.chmod(fakeWorkspace, 0o700);
  t.after(() => fs.rm(fakeWorkspace, { recursive: true, force: true }));
  await assert.rejects(createRecoveryJournal({
    evidencePath: path.join(fakeWorkspace, 'forbidden-native-evidence.json'), workspace: fakeWorkspace, state: initial,
  }), /outside the workspace/);
});

test('recovery journal rejects permissive parents and symlink files', async t => {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-native-evidence-'));
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const workspace = path.resolve(__dirname, '../..');
  const evidencePath = path.join(parent, 'recovery.json');
  const state = { version: 1, status: 'preflight' };
  await fs.chmod(parent, 0o755);
  await assert.rejects(createRecoveryJournal({ evidencePath, workspace, state }), /parent must be private/);
  await fs.chmod(parent, 0o700);
  const target = path.join(parent, 'target.json');
  await fs.writeFile(target, '{}', { mode: 0o600 });
  await fs.symlink(target, evidencePath);
  await assert.rejects(updateRecoveryJournal({ evidencePath, workspace, state }), /journal must be a real file/);
});
