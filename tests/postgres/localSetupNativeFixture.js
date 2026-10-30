'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const exec = promisify(execFile);
const MARKER = '.owasp-ai-goat-owned-local-postgres.json';
const POSTGRES_IMAGE = 'postgres:18';
const AUTHORITY_ENV_KEYS = ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'];
const FORBIDDEN_JOURNAL_KEY = /(password|credential|secret|token|url)/i;

function assertLocalTestSocket(socket) {
  assert.equal(typeof socket, 'string', 'PG_LOCAL_DOCKER_TEST_SOCKET must be a string');
  assert.ok(socket.startsWith('unix:///'), 'An explicit local Docker Unix socket is required');
  const socketPath = socket.slice('unix://'.length);
  assert.ok(path.posix.isAbsolute(socketPath), 'The Docker Unix socket path must be absolute');
  assert.equal(path.posix.normalize(socketPath), socketPath, 'The Docker Unix socket path must be canonical');
  return socket;
}

function cleanDockerEnvironment(environment = process.env) {
  const result = { ...environment };
  for (const key of AUTHORITY_ENV_KEYS) delete result[key];
  return result;
}

function createDockerAdapters({
  socket,
  environment = process.env,
  executeFile = exec,
  beforeApplicationRun = async () => {},
} = {}) {
  assertLocalTestSocket(socket);
  const fixtureEnvironment = cleanDockerEnvironment(environment);
  const ownedDocker = (args, options = {}) => executeFile('docker', ['--host', socket, ...args], {
    ...options,
    env: fixtureEnvironment,
    encoding: 'utf8',
  });
  const applicationExecute = async (command, args, options = {}) => {
    assert.equal(command, 'docker', 'The application fixture may execute only Docker');
    assert.deepEqual(args.slice(0, 2), ['--host', socket], 'Application Docker commands must carry the selected host');
    assert.equal(args.filter(value => value === '--host').length, 1, 'Application Docker commands must carry exactly one --host');
    assert.equal(args.includes('-H'), false, 'The fixture must not supply a masking Docker host option');
    assert.ok(options.env && typeof options.env === 'object', 'Application Docker commands must provide a sanitized environment');
    for (const key of AUTHORITY_ENV_KEYS) {
      assert.equal(Object.hasOwn(options.env, key), false, `Application Docker environment must remove ${key}`);
    }
    if (args[2] === 'run') await beforeApplicationRun({ command, args, options, ownedDocker });
    return executeFile(command, args, { ...options, encoding: 'utf8' });
  };
  return { applicationExecute, ownedDocker };
}

async function inspectOptional(ownedDocker, kind, name) {
  const args = kind === 'container' ? ['inspect', name] : ['volume', 'inspect', name];
  try { return JSON.parse((await ownedDocker(args)).stdout)[0] || null; }
  catch (error) {
    const stderr = String(error.stderr || '').trim();
    const missing = kind === 'container'
      ? [`No such object: ${name}`, `No such container: ${name}`]
      : [`No such volume: ${name}`, `get ${name}: no such volume`];
    if (error.code === 1 && missing.some(message => stderr.endsWith(message))) return null;
    throw error;
  }
}

function labelsFor(kind, resource) {
  return kind === 'container' ? resource?.Config?.Labels : resource?.Labels;
}

function assertOwned(kind, resource, id, name) {
  if (resource && labelsFor(kind, resource)?.['org.owasp-ai-goat.workspace'] !== id) {
    throw new Error(`Refusing to remove ${kind} ${name} without exact fixture ownership`);
  }
}

async function inspectPinnedPostgresImage(ownedDocker) {
  let image;
  try { image = JSON.parse((await ownedDocker(['image', 'inspect', POSTGRES_IMAGE])).stdout)[0]; }
  catch { throw new Error(`${POSTGRES_IMAGE} must already exist locally; native qualification never pulls images`); }
  if (!image || !/^sha256:[a-f0-9]{64}$/.test(image.Id || '')
    || !Array.isArray(image.RepoDigests) || !image.RepoDigests.some(value => /^postgres@sha256:[a-f0-9]{64}$/.test(value))) {
    throw new Error(`${POSTGRES_IMAGE} must have a recorded immutable repository digest before native qualification`);
  }
  return Object.freeze({ id: image.Id, repoDigests: [...image.RepoDigests] });
}

async function createOwnedDirectory({ id, nonce, baseDirectory = os.tmpdir() } = {}) {
  const directory = await fs.mkdtemp(path.join(baseDirectory, 'owasp-ai-goat-local-pg-'));
  await fs.chmod(directory, 0o700);
  await fs.writeFile(path.join(directory, MARKER), `${JSON.stringify({ version: 1, id, nonce })}\n`, {
    flag: 'wx', mode: 0o600,
  });
  return directory;
}

function containsPath(parent, child) {
  return child === parent || child.startsWith(`${parent}${path.sep}`);
}

function assertJournalContent(value) {
  const visit = entry => {
    if (!entry || typeof entry !== 'object') return;
    for (const [key, nested] of Object.entries(entry)) {
      assert.equal(FORBIDDEN_JOURNAL_KEY.test(key), false, `Recovery journal key ${key} is forbidden`);
      visit(nested);
    }
  };
  visit(value);
}

async function assertPrivateJournalParent(evidencePath, workspace) {
  assert.equal(typeof evidencePath, 'string', 'PG_LOCAL_DOCKER_TEST_EVIDENCE is required');
  assert.ok(path.isAbsolute(evidencePath), 'Recovery journal path must be absolute');
  assert.equal(path.normalize(evidencePath), evidencePath, 'Recovery journal path must be canonical');
  const parent = path.dirname(evidencePath);
  const stat = await fs.lstat(parent);
  assert.equal(stat.isDirectory() && !stat.isSymbolicLink(), true, 'Recovery journal parent must be a real directory');
  if (typeof process.getuid === 'function') assert.equal(stat.uid, process.getuid(), 'Recovery journal parent owner must match');
  assert.equal(stat.mode & 0o777, 0o700, 'Recovery journal parent must be private');
  const realParent = await fs.realpath(parent);
  const realWorkspace = await fs.realpath(workspace);
  const realTarget = path.join(realParent, path.basename(evidencePath));
  assert.equal(containsPath(realWorkspace, realTarget), false, 'Recovery journal must be outside the workspace');
  return { parent, realTarget };
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await fs.open(directory, 'r');
    await handle.sync();
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
  } finally { await handle?.close(); }
}

async function createRecoveryJournal({ evidencePath, workspace, state } = {}) {
  assertJournalContent(state);
  const { parent } = await assertPrivateJournalParent(evidencePath, workspace);
  const handle = await fs.open(evidencePath, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`);
    await handle.sync();
  } finally { await handle.close(); }
  await fs.chmod(evidencePath, 0o600);
  await syncDirectory(parent);
}

async function updateRecoveryJournal({ evidencePath, workspace, state } = {}) {
  assertJournalContent(state);
  const { parent } = await assertPrivateJournalParent(evidencePath, workspace);
  const current = await fs.lstat(evidencePath);
  assert.equal(current.isFile() && !current.isSymbolicLink(), true, 'Recovery journal must be a real file');
  if (typeof process.getuid === 'function') assert.equal(current.uid, process.getuid(), 'Recovery journal owner must match');
  assert.equal(current.mode & 0o777, 0o600, 'Recovery journal must remain private');
  const pending = `${evidencePath}.pending`;
  const handle = await fs.open(pending, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`);
    await handle.sync();
  } finally { await handle.close(); }
  try {
    await fs.rename(pending, evidencePath);
    await fs.chmod(evidencePath, 0o600);
    await syncDirectory(parent);
  } catch (error) {
    await fs.rm(pending, { force: true });
    throw error;
  }
}

async function removeOwnedDirectory({ directory, id, nonce } = {}) {
  const originalStat = await fs.lstat(directory);
  assert.equal(originalStat.isDirectory() && !originalStat.isSymbolicLink(), true,
    'Fixture path must be a real directory before resolution');
  const markerPath = path.join(directory, MARKER);
  const markerStat = await fs.lstat(markerPath);
  assert.equal(markerStat.isFile() && !markerStat.isSymbolicLink(), true, 'Fixture marker must be a real file');
  if (typeof process.getuid === 'function') {
    assert.equal(originalStat.uid, process.getuid(), 'Fixture directory owner must match');
    assert.equal(markerStat.uid, process.getuid(), 'Fixture marker owner must match');
  }
  assert.equal(originalStat.mode & 0o777, 0o700, 'Fixture directory must remain private');
  assert.equal(markerStat.mode & 0o777, 0o600, 'Fixture marker must remain private');
  const realBase = await fs.realpath(os.tmpdir());
  const realDirectory = await fs.realpath(directory);
  assert.equal(path.dirname(realDirectory), realBase, 'Fixture directory must be a direct child of the system temporary directory');
  assert.ok(path.basename(realDirectory).startsWith('owasp-ai-goat-local-pg-'), 'Fixture directory prefix must match');
  const marker = JSON.parse(await fs.readFile(markerPath, 'utf8'));
  assert.deepEqual(marker, { version: 1, id, nonce }, 'Fixture cleanup marker must match');
  await fs.rm(realDirectory, { recursive: true });
}

async function cleanupOwnedFixture({ ownedDocker, id, name, directory, nonce } = {}) {
  const container = await inspectOptional(ownedDocker, 'container', name);
  const volume = await inspectOptional(ownedDocker, 'volume', name);
  assertOwned('container', container, id, name);
  assertOwned('volume', volume, id, name);
  if (container) await ownedDocker(['rm', '--force', name]);
  if (volume) await ownedDocker(['volume', 'rm', name]);
  const remainingContainer = await inspectOptional(ownedDocker, 'container', name);
  const remainingVolume = await inspectOptional(ownedDocker, 'volume', name);
  assert.equal(remainingContainer, null, 'Owned fixture container must be absent after cleanup');
  assert.equal(remainingVolume, null, 'Owned fixture volume must be absent after cleanup');
  await removeOwnedDirectory({ directory, id, nonce });
  return Object.freeze({ containerRemoved: !!container, volumeRemoved: !!volume,
    containerAbsent: true, volumeAbsent: true, directoryRemoved: true });
}

module.exports = {
  MARKER,
  POSTGRES_IMAGE,
  AUTHORITY_ENV_KEYS,
  assertLocalTestSocket,
  cleanDockerEnvironment,
  createDockerAdapters,
  inspectOptional,
  inspectPinnedPostgresImage,
  createOwnedDirectory,
  removeOwnedDirectory,
  cleanupOwnedFixture,
  createRecoveryJournal,
  updateRecoveryJournal,
};
