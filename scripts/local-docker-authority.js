'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const windowsPrivateState = require('./lib/windows-private-state');
const windowsProvisioningJournal = require('./lib/windows-provisioning-journal');

const exec = promisify(execFile);
const STATE_FILENAME = 'local-docker.json';
const INFO_FORMAT = '{{json .ID}}';
const CONTEXT_HOST_FORMAT = '{{json .Endpoints.docker.Host}}';
const ownedLabSessions = new WeakMap();
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

function serializedAuthority(authority) {
  const result = { version: authority.version, workspaceId: authority.workspaceId,
    host: authority.host, daemonId: authority.daemonId, source: authority.source };
  if (authority.version === 2) Object.assign(result, { installationId: authority.installationId,
    vmId: authority.vmId, bindingSha256: authority.bindingSha256 });
  return result;
}

function ownedLabDescriptor(session) {
  try { return require('./lib/windows-owned-lab').describeOwnedLab(session); }
  catch { throw new LocalDockerAuthorityError('An admitted owned Windows lab session is required.'); }
}

function assertOwnedLabBinding(authority, session) {
  const descriptor = ownedLabDescriptor(session);
  if (authority.platform !== 'win32' || authority.version !== 2
    || ['workspaceId', 'installationId', 'vmId', 'bindingSha256', 'host', 'daemonId']
      .some(key => authority[key] !== descriptor[key])) {
    throw new LocalDockerAuthorityError('The owned Windows lab does not match the retained Docker authority.');
  }
  return session;
}

class LocalDockerAuthorityError extends Error {
  constructor(message, code = 'LOCAL_DOCKER_AUTHORITY_INVALID') {
    super(message);
    this.code = code;
  }
}

function authorityStatePath(directory) {
  return path.join(directory, STATE_FILENAME);
}

function authorityDigest(authority) {
  if (authority.version === 2) return createHash('sha256').update(JSON.stringify(serializedAuthority(authority))).digest('hex');
  return createHash('sha256').update(JSON.stringify({
    version: authority.version,
    workspaceId: authority.workspaceId,
    host: authority.host,
    daemonId: authority.daemonId,
  })).digest('hex');
}

function sanitizeDockerEnvironment(environment = process.env, host) {
  const clean = { ...environment };
  delete clean.DOCKER_CONTEXT;
  delete clean.DOCKER_HOST;
  delete clean.DOCKER_TLS_VERIFY;
  delete clean.DOCKER_CERT_PATH;
  if (host) clean.DOCKER_HOST = host;
  return clean;
}

function isLoopbackServiceUrl(value) {
  if (typeof value !== 'string' || !value || /[\0\r\n]/.test(value)) return false;
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`);
    return ['http:', 'https:'].includes(parsed.protocol)
      && ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname.toLowerCase());
  } catch { return false; }
}

function assertLocalDockerHost(host, platform = process.platform) {
  if (typeof host !== 'string' || !host || host.includes('\0') || /[\r\n]/.test(host)) {
    throw new LocalDockerAuthorityError('Local Docker endpoint is missing or invalid.');
  }
  if (platform === 'win32') {
    if (!/^npipe:\/\/\/\/\.\/pipe\/[A-Za-z0-9_.-]+$/.test(host)) {
      throw new LocalDockerAuthorityError('Docker setup requires a local Windows named pipe; remote Docker endpoints are refused.');
    }
    return host;
  }
  if (!host.startsWith('unix:///')) {
    throw new LocalDockerAuthorityError('Docker setup requires an explicit local Unix socket; remote Docker endpoints are refused.');
  }
  const socketPath = host.slice('unix://'.length);
  if (!path.posix.isAbsolute(socketPath) || path.posix.normalize(socketPath) !== socketPath) {
    throw new LocalDockerAuthorityError('Docker setup requires a canonical absolute Unix socket path.');
  }
  return host;
}

function parseFormattedString(stdout, description) {
  const value = String(stdout || '').trim();
  try {
    const parsed = JSON.parse(value);
    if (typeof parsed === 'string' && parsed && !/[\0\r\n]/.test(parsed)) return parsed;
  } catch {}
  throw new LocalDockerAuthorityError(`Docker returned an invalid ${description}.`);
}

async function resolveLocalDockerHost({ environment = process.env, execute = exec, platform = process.platform } = {}) {
  const configuredHost = environment.DOCKER_HOST || '';
  const configuredContext = environment.DOCKER_CONTEXT || '';
  if (configuredHost && configuredContext) {
    throw new LocalDockerAuthorityError('DOCKER_HOST and DOCKER_CONTEXT are both set; choose one local Docker endpoint before setup.');
  }
  if (configuredHost) return { host: assertLocalDockerHost(configuredHost, platform), source: 'environment-host' };

  const cleanEnv = sanitizeDockerEnvironment(environment);
  let context = configuredContext;
  if (!context) {
    try {
      context = String((await execute('docker', ['context', 'show'], {
        env: cleanEnv, encoding: 'utf8', timeout: 10_000,
      })).stdout || '').trim();
    } catch {
      throw new LocalDockerAuthorityError('Docker context could not be read; start Docker Desktop or Colima and retry setup.', 'LOCAL_DOCKER_UNAVAILABLE');
    }
  }
  if (!context || context.includes('\0') || /[\r\n]/.test(context)) {
    throw new LocalDockerAuthorityError('Docker returned an invalid active context.');
  }
  let stdout;
  try {
    ({ stdout } = await execute('docker', ['context', 'inspect', context, '--format', CONTEXT_HOST_FORMAT], {
      env: cleanEnv, encoding: 'utf8', timeout: 10_000,
    }));
  } catch {
    throw new LocalDockerAuthorityError('Docker context could not be inspected; select a working local Docker Desktop or Colima context.', 'LOCAL_DOCKER_UNAVAILABLE');
  }
  return {
    host: assertLocalDockerHost(parseFormattedString(stdout, 'context endpoint'), platform),
    source: configuredContext ? 'environment-context' : 'active-context',
  };
}

async function inspectDockerDaemon({ authority, execute = exec, environment = process.env } = {}) {
  if (authority?.version === 2) {
    const session = assertOwnedLabBinding(authority, ownedLabSessions.get(authority));
    await session.assertCurrent();
    return parseFormattedString(await session.executeDocker(['info', '--format', INFO_FORMAT]), 'daemon identity');
  }
  assertLocalDockerHost(authority?.host, authority?.platform || process.platform);
  try {
    const { stdout } = await execute('docker', ['--host', authority.host, 'info', '--format', INFO_FORMAT], {
      env: sanitizeDockerEnvironment(environment), encoding: 'utf8', timeout: 10_000,
    });
    return parseFormattedString(stdout, 'daemon identity');
  } catch (error) {
    if (error instanceof LocalDockerAuthorityError) throw error;
    throw new LocalDockerAuthorityError('The selected local Docker daemon is unavailable; start it and retry.', 'LOCAL_DOCKER_UNAVAILABLE');
  }
}

function validateAuthorityState(authority, { workspaceId, platform = process.platform } = {}) {
  if (authority?.version === 2) {
    if (platform !== 'win32' || authority.workspaceId !== workspaceId || authority.source !== 'owned-hyperv'
      || !UUID.test(authority.installationId || '') || !UUID.test(authority.vmId || '')
      || authority.host !== `owned-hyperv:${authority.vmId}` || !/^[a-f0-9]{64}$/.test(authority.bindingSha256 || '')
      || typeof authority.daemonId !== 'string' || !authority.daemonId || authority.daemonId === 'unbound'
      || authority.daemonId.length > 256 || /[\x00-\x1f\x7f]/.test(authority.daemonId)
      || Object.keys(authority).some(key => !['version','workspaceId','source','host','daemonId','installationId','vmId','bindingSha256','platform'].includes(key))) {
      throw new LocalDockerAuthorityError('Owned Windows Docker authority state does not match this workspace.');
    }
    return Object.freeze({ ...authority, platform });
  }
  if (!authority || authority.version !== 1 || authority.workspaceId !== workspaceId
    || typeof authority.daemonId !== 'string' || !authority.daemonId
    || authority.daemonId.length > 256 || /[\0\r\n]/.test(authority.daemonId)
    || !['environment-host', 'environment-context', 'active-context'].includes(authority.source)) {
    throw new LocalDockerAuthorityError('Local Docker authority state does not match this workspace.');
  }
  assertLocalDockerHost(authority.host, platform);
  return Object.freeze({ ...authority, platform });
}

// Filesystem authority follows the host, independently of the Docker platform.
// Providers are explicit controlled-test seams, never environment bypasses.
function createLocalDockerAuthorityStorage({ filesystemPlatform = process.platform,
  privateState = windowsPrivateState, journal = windowsProvisioningJournal, fileSystem = fs } = {}) {
const storagePath = filesystemPlatform === 'win32' ? path.win32 : path;
async function assertPrivateStateFile(filename, {
  uid = typeof process.getuid === 'function' ? process.getuid() : null,
  platform = process.platform,
} = {}) {
  if (filesystemPlatform === 'win32') {
    try {
      const bytes = privateState.readPrivateFile(filename);
      if (!Buffer.isBuffer(bytes) || bytes.length > windowsPrivateState.MAX_FILE_BYTES) throw Error();
      return Buffer.from(bytes);
    } catch { throw new LocalDockerAuthorityError('Local Docker authority state must be a private file owned by the current user.'); }
  }
  const stat = await fileSystem.lstat(filename);
  if (!stat.isFile() || stat.isSymbolicLink()
    || (uid !== null && stat.uid !== uid) || (stat.mode & 0o777) !== 0o600) {
    throw new LocalDockerAuthorityError('Local Docker authority state must be a private file owned by the current user.');
  }
}

async function assertPrivateDirectory(directory, {
  uid = typeof process.getuid === 'function' ? process.getuid() : null,
  platform = process.platform,
} = {}) {
  if (filesystemPlatform === 'win32') {
    try { privateState.inspectPrivateDirectory(directory); return; }
    catch { throw new LocalDockerAuthorityError('Local Docker setup directory must be private and owned by the current user.'); }
  }
  let stat;
  try { stat = await fileSystem.lstat(directory); }
  catch (error) {
    if (error.code === 'ENOENT') throw new LocalDockerAuthorityError('Private local Docker setup directory is missing.');
    throw error;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || (uid !== null && stat.uid !== uid) || (stat.mode & 0o777) !== 0o700) {
    throw new LocalDockerAuthorityError('Local Docker setup directory must be private and owned by the current user.');
  }
}

async function readLocalDockerAuthority({ directory, workspaceId, platform = process.platform, uid } = {}) {
  await assertPrivateDirectory(directory, { uid, platform });
  const filename = storagePath.join(directory, STATE_FILENAME);
  let snapshot;
  try {
    // Metadata establishes only named absence. A denied native read is never
    // converted into missing state or permission to replace an existing file.
    if (filesystemPlatform === 'win32') await fileSystem.lstat(filename);
    snapshot = await assertPrivateStateFile(filename, { uid, platform });
  }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  let parsed;
  try { parsed = JSON.parse(filesystemPlatform === 'win32' ? snapshot.toString('utf8') : await fileSystem.readFile(filename, 'utf8')); }
  catch { throw new LocalDockerAuthorityError('Local Docker authority state is invalid JSON.'); }
  return validateAuthorityState(parsed, { workspaceId, platform });
}

async function writeLocalDockerAuthority({ directory, authority } = {}) {
  await assertPrivateDirectory(directory, { platform: authority.platform });
  const filename = storagePath.join(directory, STATE_FILENAME);
  if (filesystemPlatform === 'win32') {
    try {
      validateAuthorityState(authority, { workspaceId: authority.workspaceId, platform: authority.platform || process.platform });
      try { await fileSystem.lstat(`${filename}.pending`); throw new LocalDockerAuthorityError('A pending local Docker authority file requires review before retrying setup.'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      const bytes = Buffer.from(`${JSON.stringify(serializedAuthority(authority), null, 2)}\n`);
      journal.createJournal({ filePath: filename, bytes });
      const observed = await assertPrivateStateFile(filename, { platform: authority.platform });
      if (!observed.equals(bytes)) throw Error();
      return filename;
    } catch (error) {
      if (error instanceof LocalDockerAuthorityError) throw error;
      throw new LocalDockerAuthorityError('Local Docker authority could not be persisted privately; retained state was not removed.');
    }
  }
  const pending = `${filename}.pending`;
  const handle = await fileSystem.open(pending, 'wx', 0o600).catch(error => {
    if (error.code === 'EEXIST') throw new LocalDockerAuthorityError('A pending local Docker authority file requires review before retrying setup.');
    throw error;
  });
  try {
    await handle.writeFile(`${JSON.stringify({
      version: 1,
      workspaceId: authority.workspaceId,
      host: authority.host,
      daemonId: authority.daemonId,
      source: authority.source,
    }, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await fileSystem.link(pending, filename);
    await fileSystem.chmod(filename, 0o600);
  } catch (error) {
    if (error.code === 'EEXIST') throw new LocalDockerAuthorityError('Local Docker authority already exists; it was not overwritten.');
    throw error;
  } finally {
    await fileSystem.rm(pending, { force: true });
  }
  return filename;
}
const storage = { assertPrivateStateFile, assertPrivateDirectory, readLocalDockerAuthority, writeLocalDockerAuthority };
storage.resolveDockerAuthority = options => resolveDockerAuthority({ ...options, storage });
return Object.freeze(storage);
}

async function resolveDockerAuthority({ directory, workspaceId, environment = process.env, execute = exec,
  platform = process.platform, uid, persist = false, storage = defaultStorage, ownedLabSession } = {}) {
  const existing = await storage.readLocalDockerAuthority({ directory, workspaceId, platform, uid });
  if (ownedLabSession !== undefined) {
    if (platform !== 'win32') throw new LocalDockerAuthorityError('Owned Hyper-V transport requires Windows.');
    const descriptor = ownedLabDescriptor(ownedLabSession);
    if (descriptor.workspaceId !== workspaceId) throw new LocalDockerAuthorityError('Owned lab workspace mismatch.');
    await ownedLabSession.bindDaemon();
    const bound = ownedLabDescriptor(ownedLabSession);
    const candidate = validateAuthorityState({ version: 2, source: 'owned-hyperv', workspaceId,
      installationId: bound.installationId, vmId: bound.vmId, bindingSha256: bound.bindingSha256,
      host: bound.host, daemonId: bound.daemonId }, { workspaceId, platform });
    if (existing && (existing.version !== 2 || authorityDigest(existing) !== authorityDigest(candidate))) {
      throw new LocalDockerAuthorityError('Existing Docker authority differs; no authority was replaced.');
    }
    const authority = existing || candidate;
    assertOwnedLabBinding(authority, ownedLabSession);
    ownedLabSessions.set(authority, ownedLabSession);
    await verifyDockerAuthority({ authority });
    if (!existing && persist) await storage.writeLocalDockerAuthority({ directory, authority });
    return { authority, persisted: Boolean(existing) || persist };
  }
  if (existing) {
    const daemonId = await inspectDockerDaemon({ authority: existing, execute, environment });
    if (daemonId !== existing.daemonId) {
      throw new LocalDockerAuthorityError('The selected Docker socket now identifies a different daemon; setup refused to use it.');
    }
    return { authority: existing, persisted: true };
  }
  const selected = await resolveLocalDockerHost({ environment, execute, platform });
  const candidate = { version: 1, workspaceId, host: selected.host, daemonId: '', source: selected.source, platform };
  const daemonId = await inspectDockerDaemon({ authority: candidate, execute, environment });
  const authority = Object.freeze({ ...candidate, daemonId });
  if (persist) await storage.writeLocalDockerAuthority({ directory, authority });
  return { authority, persisted: persist };
}

async function verifyDockerAuthority({ authority, execute = exec, environment = process.env } = {}) {
  const daemonId = await inspectDockerDaemon({ authority, execute, environment });
  if (daemonId !== authority.daemonId) {
    throw new LocalDockerAuthorityError('The selected Docker socket now identifies a different daemon; no Docker command was run.');
  }
  return authority;
}

async function executeBoundDocker({ authority, execute = exec, environment = process.env, args, options = {} } = {}) {
  if (authority?.version === 2) {
    const session = assertOwnedLabBinding(authority, ownedLabSessions.get(authority));
    return { stdout: await session.executeDocker(args, { scope: 'provision' }), stderr: '' };
  }
  return execute('docker', ['--host', authority.host, ...args], {
    ...options,
    env: sanitizeDockerEnvironment(environment),
  });
}

function defaultAuthorityDirectory({ workspace, homeDirectory = os.homedir() } = {}) {
  const { workspaceId } = require('./application-data-root');
  return path.join(homeDirectory, '.dvaia', workspaceId(workspace));
}

const defaultStorage = createLocalDockerAuthorityStorage();
const { assertPrivateStateFile, assertPrivateDirectory, readLocalDockerAuthority, writeLocalDockerAuthority } = defaultStorage;
module.exports = {
  createLocalDockerAuthorityStorage,
  LocalDockerAuthorityError,
  STATE_FILENAME,
  authorityStatePath,
  authorityDigest,
  sanitizeDockerEnvironment,
  isLoopbackServiceUrl,
  assertLocalDockerHost,
  resolveLocalDockerHost,
  inspectDockerDaemon,
  validateAuthorityState,
  assertPrivateStateFile,
  assertPrivateDirectory,
  readLocalDockerAuthority,
  writeLocalDockerAuthority,
  resolveDockerAuthority,
  verifyDockerAuthority,
  executeBoundDocker,
  defaultAuthorityDirectory,
};
