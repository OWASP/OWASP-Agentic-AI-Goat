'use strict';

const fs = require('node:fs/promises');
const nativeFs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { resolveDockerAuthority, executeBoundDocker, authorityDigest, writeLocalDockerAuthority } = require('./local-docker-authority');

// This digest is the image already accepted by the owned IPI qualification.
// Keep it immutable until a separately reviewed image update replaces it.
const MAILPIT_IMAGE = 'ghcr.io/axllent/mailpit@sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365';
const MAILPIT_IMAGE_DIGEST = 'sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365';
const MAILPIT_IMAGE_VERSION = 'v1.31.1';

const LEGACY_STATE_MESSAGE = 'Existing Mailpit state lacks required ownership metadata. Automatic migration is unavailable. Preserve the private Mailpit state and existing container; no container was adopted or removed.';
class MailpitSetupError extends Error {}

function statePath(directory) { return path.join(directory, 'mailpit.json'); }

function validateMailpitState(state, { id, name, requireContainerId = true }) {
  if (state?.version === 1 && (!Object.hasOwn(state, 'nonce') || !Object.hasOwn(state, 'imageVersion'))) {
    throw Object.assign(new MailpitSetupError(LEGACY_STATE_MESSAGE), { code: 'MAILPIT_LEGACY_STATE_UNSUPPORTED' });
  }
  if (!state || state.version !== 1 || (id !== undefined && state.id !== id) || (name !== undefined && state.name !== name)
    || state.image !== MAILPIT_IMAGE || state.imageVersion !== MAILPIT_IMAGE_VERSION || state.imageDigest !== MAILPIT_IMAGE_DIGEST
    || !/^[a-f0-9]{64}$/.test(state.nonce || '')
    || (requireContainerId && !/^[a-f0-9]{64}$/.test(state.containerId || ''))
    || (!requireContainerId && state.containerId !== undefined && !/^[a-f0-9]{64}$/.test(state.containerId))
    || !/^[a-f0-9]{64}$/.test(state.dockerAuthorityDigest || '')
    || ![state.smtpPort, state.apiPort].every(port => Number.isInteger(port) && port > 0 && port < 65536)
    || state.smtpPort === state.apiPort) {
    throw new MailpitSetupError('Local Mailpit setup state does not match this workspace');
  }
  return state;
}

function assertOwnedContainer(container, { id, name, state }) {
  if (!container) throw new MailpitSetupError(`Owned Mailpit container ${name} is unavailable`);
  if (container.Config?.Labels?.['org.dvaia.workspace'] !== id) {
    throw new MailpitSetupError(`Container ${name} already exists without matching setup ownership`);
  }
  if (container.Config?.Labels?.['org.dvaia.mailpit.nonce'] !== state.nonce) {
    throw new MailpitSetupError(`Container ${name} does not carry the owned Mailpit nonce`);
  }
  const ports = container.HostConfig?.PortBindings || {};
  const smtp = ports['1025/tcp']?.[0];
  const api = ports['8025/tcp']?.[0];
  if (container.Config?.Image !== state.image && container.Image !== state.imageDigest
    && !(Array.isArray(container.Config?.Image) && container.Config.Image.includes(state.imageDigest))) {
    throw new MailpitSetupError(`Container ${name} does not use the reviewed immutable Mailpit image`);
  }
  if (state.containerId && container.Id !== state.containerId) throw new MailpitSetupError(`Container ${name} identity changed`);
  if (smtp?.HostIp !== '127.0.0.1' || smtp?.HostPort !== String(state.smtpPort)
    || api?.HostIp !== '127.0.0.1' || api?.HostPort !== String(state.apiPort)) {
    throw new MailpitSetupError(`Container ${name} does not match the owned Mailpit state`);
  }
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function readPrivateState(file) {
  const stat = await fs.lstat(file);
  if (!stat.isFile() || (stat.mode & 0o777) !== 0o600) throw new MailpitSetupError('Local Mailpit state must be an owner-only regular file');
  return fs.readFile(file, 'utf8');
}

async function writePrivateState(file, state) {
  const pending = `${file}.pending`;
  await fs.writeFile(pending, JSON.stringify(state) + '\n', { flag: 'wx', mode: 0o600 });
  try { await fs.rename(pending, file); await fs.chmod(file, 0o600); }
  finally { await fs.rm(pending, { force: true }); }
}

// Storage follows the actual filesystem platform, independently of the Docker
// sidecar platform option. Overrides below are controlled-test seams only.
function createMailpitStateStorage({ filesystemPlatform = process.platform,
  journal = require('./lib/windows-provisioning-journal'), exists = nativeFs.existsSync } = {}) {
  const windows = filesystemPlatform === 'win32';
  const encode = state => Buffer.from(JSON.stringify(state) + '\n');
  return Object.freeze({
    path: windows ? path.win32 : path,
    async read(file, allowMissing = false) {
      if (windows) {
        journal.inspectDestination({ filePath: file });
        // Missing is an advisory observation, never inferred from a denied
        // native read. CREATE-only publication resolves an absence race safely.
        if (allowMissing && !exists(file)) return null;
        return journal.readJournal({ filePath: file });
      }
      try { return Buffer.from(await readPrivateState(file)); }
      catch (error) { if (allowMissing && error.code === 'ENOENT') return null; throw error; }
    },
    async write(file, state, originalBytes) {
      const resultBytes = encode(state);
      if (windows) {
        if (originalBytes === null) journal.createJournal({ filePath: file, bytes: resultBytes });
        else journal.updateJournal({ filePath: file, originalBytes, resultBytes });
      } else await writePrivateState(file, state);
      // Advance the caller's original snapshot only after native publication
      // acknowledges its exact result and safe reread. Failed publication may
      // leave retained transition artifacts, but never authorizes a new origin.
      return resultBytes;
    },
    async ensureIntent(file, state) {
      const resultBytes = encode(state);
      if (!windows) { await writePrivateState(file, state); return; }
      journal.inspectDestination({ filePath: file });
      if (exists(file)) {
        const original = journal.readJournal({ filePath: file });
        if (!Buffer.isBuffer(original) || !original.equals(resultBytes)) throw new MailpitSetupError('Existing Mailpit creation intent does not match owned state');
      } else journal.createJournal({ filePath: file, bytes: resultBytes });
    },
    async removeIntent(file) { if (!windows) await fs.rm(file, { force: true }); },
  });
}

function probeApi(apiPort, request = http.get) {
  return new Promise((resolve, reject) => {
    let total = 0;
    let settled = false;
    let requestHandle;
    let responseHandle;
    const deadline = setTimeout(() => finish(new MailpitSetupError('Mailpit API readiness timed out')), 3000);
    const finish = error => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      try { requestHandle?.destroy?.(error); } catch {}
      try { responseHandle?.destroy?.(error); } catch {}
      error ? reject(error) : resolve();
    };
    requestHandle = request(`http://127.0.0.1:${apiPort}/api/v1/info`, response => {
      responseHandle = response;
      response.on('data', chunk => { total += chunk.length; if (total > 64 * 1024) { response.destroy(); finish(new MailpitSetupError('Mailpit API readiness response exceeded the limit')); } });
      response.once('end', () => response.statusCode >= 200 && response.statusCode < 300
        ? finish() : finish(new MailpitSetupError(`Mailpit API returned HTTP ${response.statusCode}`)));
      response.once('error', finish);
    });
    requestHandle.once('error', finish);
  });
}

function probeSmtp(smtpPort, connect = net.connect) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port: smtpPort });
    let buffer = '';
    let settled = false;
    const deadline = setTimeout(() => finish(new MailpitSetupError('Mailpit SMTP readiness timed out')), 3000);
    const finish = (error) => { if (settled) return; settled = true; clearTimeout(deadline); try { socket.write?.('QUIT\r\n'); } catch {} socket.destroy(); error ? reject(error) : resolve(); };
    socket.on('data', chunk => { buffer += chunk.toString('utf8'); if (/^220[ -]/.test(buffer)) finish(); else if (buffer.length > 4096) finish(new MailpitSetupError('Mailpit SMTP greeting was invalid')); });
    socket.once('connect', () => {});
    socket.once('error', finish);
    socket.setTimeout?.(3000, () => finish(new MailpitSetupError('Mailpit SMTP readiness timed out')));
  });
}

async function inspectImage(docker, image) {
  let parsed;
  try { parsed = JSON.parse((await docker(['image', 'inspect', image])).stdout)[0]; }
  catch (error) { if (error.code === 1) return null; throw error; }
  const refs = parsed?.RepoDigests || [];
  if (parsed?.Id !== MAILPIT_IMAGE_DIGEST && !refs.includes(MAILPIT_IMAGE)) {
    throw new MailpitSetupError('Local Mailpit image digest does not match the reviewed immutable image');
  }
  return parsed;
}

function assertOwnedMailpitLab(session, ownChild, platform, id) {
  const binding = require('./lib/windows-owned-lab').describeOwnedLab(session);
  if (platform !== 'win32' || binding.workspaceId !== id || typeof ownChild !== 'function') {
    throw new MailpitSetupError('Owned Windows Mailpit requires its matching lab and forwarding owner.');
  }
}

async function ensureLocalMailpit({ directory, id, environment = process.env, execute, platform = process.platform,
  existingOnly = false, request = http.get, connect = net.connect, ownedLabSession, ownLabChild,
  resolveAuthority = resolveDockerAuthority, writeAuthority = writeLocalDockerAuthority,
  stateStorage = createMailpitStateStorage(),
  allocatePort = availablePort,
  wait = ms => new Promise(resolve => setTimeout(resolve, ms)), readinessAttempts = 60, pullImage = true } = {}) {
  if (typeof execute !== 'function') throw new TypeError('A Docker command adapter is required');
  if (ownedLabSession !== undefined) assertOwnedMailpitLab(ownedLabSession, ownLabChild, platform, id);
  const name = `dvaia-mailpit-${id}`;
  const file = stateStorage.path.join(directory, 'mailpit.json');
  let state = null;
  let originalBytes = null;
  originalBytes = await stateStorage.read(file, true);
  if (originalBytes !== null) state = validateMailpitState(JSON.parse(originalBytes), { id, name, requireContainerId: false });
  else if (existingOnly) throw new MailpitSetupError('Existing setup requires the owned Mailpit state');
  const persist = async nextState => { const acknowledged = await stateStorage.write(file, nextState, originalBytes); originalBytes = acknowledged; state = nextState; };
  const resolved = await resolveAuthority({ directory, workspaceId: id, environment, execute, platform, persist: false, ...(ownedLabSession ? { ownedLabSession } : {}) });
  const docker = args => executeBoundDocker({ authority: resolved.authority, execute, environment, args });
  const inspect = async args => {
    try { return JSON.parse((await docker(args)).stdout)[0]; }
    catch (error) { if (error.code === 1) return null; throw error; }
  };
  const existing = await inspect(['inspect', name]);
  if (state && state.dockerAuthorityDigest !== authorityDigest(resolved.authority)) {
    throw new MailpitSetupError('Local Mailpit state is bound to a different Docker authority');
  }
  if (state && existing) assertOwnedContainer(existing, { id, name, state });
  if (state?.containerId && !existing) throw new MailpitSetupError(`Owned Mailpit container ${name} is unavailable`);
  else if (existing && !state) throw new MailpitSetupError(`Container ${name} exists without private setup state`);
  if (!resolved.persisted) await writeAuthority({ directory, authority: resolved.authority });
  if (!state) {
    state = { version: 1, id, name, nonce: randomBytes(32).toString('hex'), image: MAILPIT_IMAGE, imageVersion: MAILPIT_IMAGE_VERSION, imageDigest: MAILPIT_IMAGE_DIGEST,
      smtpPort: await allocatePort(), apiPort: await allocatePort(), dockerAuthorityDigest: authorityDigest(resolved.authority) };
    if (state.smtpPort === state.apiPort) state.apiPort = await allocatePort();
    await persist(state);
  }
  let creationAttempted = false;
  let createdState;
  const intentFile = `${file}.intent`;
  try {
    if (!await inspectImage(docker, MAILPIT_IMAGE)) {
      if (!pullImage) throw new MailpitSetupError('Reviewed Mailpit image is not present locally; pull it explicitly before this isolated run');
      await docker(['pull', MAILPIT_IMAGE]);
      if (!await inspectImage(docker, MAILPIT_IMAGE)) throw new MailpitSetupError('Pulled Mailpit image was not found at the reviewed immutable digest');
    }
    if (existing && state && !state.containerId) {
      const nextState = { ...state, containerId: existing.Id };
      validateMailpitState(nextState, { id, name });
      await persist(nextState);
    } else if (!existing) {
      await stateStorage.ensureIntent(intentFile, { version: 1, id, name, nonce: state.nonce, image: MAILPIT_IMAGE,
        imageVersion: MAILPIT_IMAGE_VERSION, imageDigest: MAILPIT_IMAGE_DIGEST, dockerAuthorityDigest: state.dockerAuthorityDigest });
      creationAttempted = true;
      await docker(['run', '--detach', '--restart', 'unless-stopped', '--name', name,
        '--label', `org.dvaia.workspace=${id}`, '--label', `org.dvaia.mailpit.nonce=${state.nonce}`, '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16777216',
        '--publish', `127.0.0.1:${state.smtpPort}:1025`, '--publish', `127.0.0.1:${state.apiPort}:8025`, MAILPIT_IMAGE]);
      const created = await inspect(['inspect', name]);
      assertOwnedContainer(created, { id, name, state });
      const nextState = { ...state, containerId: created.Id };
      createdState = nextState; // Pin cleanup identity even if publication fails.
      validateMailpitState(nextState, { id, name });
      await persist(nextState);
      await stateStorage.removeIntent(intentFile);
    } else if (!existing.State?.Running) await docker(['start', name]);
    if (ownedLabSession) await ownedLabSession.openLoopbackForwards([
      { local: state.smtpPort, guest: state.smtpPort }, { local: state.apiPort, guest: state.apiPort },
    ], { ownChild: ownLabChild });
    for (let attempt = 0; attempt < readinessAttempts; attempt += 1) {
      try {
        await probeApi(state.apiPort, request);
        await probeSmtp(state.smtpPort, connect);
        return Object.freeze({ ...state, statePath: file, apiUrl: `http://127.0.0.1:${state.apiPort}`, smtpHost: '127.0.0.1' });
      } catch (error) {
        if (attempt === readinessAttempts - 1) throw new MailpitSetupError(`Local Mailpit did not become ready: ${error.message}`);
        await wait(500);
      }
    }
  } catch (error) {
    if (creationAttempted) {
      try {
        const cleanupState = createdState || state;
        const candidate = await inspect(['inspect', cleanupState.containerId || name]);
        if (candidate) {
          assertOwnedContainer(candidate, { id, name, state: cleanupState });
          await docker(['rm', '--force', candidate.Id]);
          try {
            await docker(['inspect', candidate.Id]);
            throw new MailpitSetupError('Owned Mailpit cleanup did not remove the recorded container');
          } catch (absenceError) {
            if (absenceError instanceof MailpitSetupError || absenceError.code !== 1) throw absenceError;
          }
          await persist({ ...state, containerId: undefined });
        }
      } catch (cleanupError) { error.cleanupError = 'owned Mailpit cleanup failed'; }
    }
    throw error;
  }
}

async function assertLocalMailpitReady({ statePath: file, request = http.get, connect = net.connect,
  execute, environment = process.env, platform = process.platform, resolveAuthority = resolveDockerAuthority, ownedLabSession, ownLabChild,
  stateStorage = createMailpitStateStorage() } = {}) {
  if (typeof file !== 'string' || !stateStorage.path.isAbsolute(file)) throw new MailpitSetupError('Mailpit state path is required');
  if (typeof execute !== 'function') throw new MailpitSetupError('Docker command adapter is required for Mailpit startup validation');
  const state = validateMailpitState(JSON.parse(await stateStorage.read(file)), { id: undefined, name: undefined });
  if (ownedLabSession !== undefined) assertOwnedMailpitLab(ownedLabSession, ownLabChild, platform, state.id);
  {
    const resolved = await resolveAuthority({ directory: stateStorage.path.dirname(file), workspaceId: state.id, environment, execute, platform, persist: false, ...(ownedLabSession ? { ownedLabSession } : {}) });
    if (state.dockerAuthorityDigest !== authorityDigest(resolved.authority)) throw new MailpitSetupError('Mailpit Docker authority changed');
    const docker = args => executeBoundDocker({ authority: resolved.authority, execute, environment, args });
    let inspected;
    try { inspected = JSON.parse((await docker(['inspect', state.containerId])).stdout)[0]; }
    catch { throw new MailpitSetupError('Owned Mailpit container is unavailable'); }
    assertOwnedContainer(inspected, { id: state.id, name: state.name, state });
    if (!inspected.State?.Running) {
      await docker(['start', state.containerId]);
      inspected = JSON.parse((await docker(['inspect', state.containerId])).stdout)[0];
      assertOwnedContainer(inspected, { id: state.id, name: state.name, state });
    }
  }
  if (ownedLabSession) await ownedLabSession.openLoopbackForwards([
    { local: state.smtpPort, guest: state.smtpPort }, { local: state.apiPort, guest: state.apiPort },
  ], { ownChild: ownLabChild });
  await probeApi(state.apiPort, request);
  await probeSmtp(state.smtpPort, connect);
  return state;
}

module.exports = { LEGACY_STATE_MESSAGE, MAILPIT_IMAGE, MAILPIT_IMAGE_VERSION, MAILPIT_IMAGE_DIGEST, MailpitSetupError, validateMailpitState,
  assertOwnedContainer, probeApi, probeSmtp, ensureLocalMailpit, assertLocalMailpitReady, statePath, createMailpitStateStorage };
