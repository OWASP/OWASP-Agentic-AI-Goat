'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const privateDefaults = require('./windows-private-state');
const journalDefaults = require('./windows-provisioning-journal');
const ownedLabDefaults = require('./windows-owned-lab');
const { workspaceId } = require('../application-data-root');

const CONFIG_NAME = 'windows-lab-installation.json';
const CONFIG_KEYS = ['version', 'workspaceId', 'workspaceRoot', 'installationId', 'operationId',
  'instanceName', 'multipassExecutable', 'sshExecutable', 'image'];
const denied = () => Object.assign(Error('Windows lab installation unavailable'), { code: 'WINDOWS_LAB_INSTALLATION_DENIED' });
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const sameIdentity = (left, right) => left && right && left.volumeSerial === right.volumeSerial && left.fileId === right.fileId;
const executable = (value, name) => privateDefaults.normalizePrivatePath(value)
  && path.win32.basename(value).toLowerCase() === name;

function createWindowsLabInstallation({ platform = process.platform, fileSystem = fs,
  privateState = privateDefaults, journal = journalDefaults, ownedLab = ownedLabDefaults,
  createForwardOwner = options => require('./windows-lab-forward-owner').createWindowsLabForwardOwner(options),
  randomUUID = crypto.randomUUID } = {}) {
  async function prepareWindowsLabInstallation({ root, homeDirectory, environment = process.env, mode } = {}) {
    let session;
    try {
      if (platform !== 'win32' || !['fresh', 'existing'].includes(mode) || !environment || typeof environment !== 'object') throw denied();
      const normalize = privateDefaults.normalizePrivatePath;
      const canonicalRoot = normalize(fileSystem.realpathSync(normalize(root)));
      const canonicalHome = normalize(fileSystem.realpathSync(normalize(homeDirectory)));
      const id = workspaceId(canonicalRoot, { realpath: () => canonicalRoot });
      const base = normalize(path.win32.join(canonicalHome, '.dvaia'));
      const directory = normalize(path.win32.join(base, id));
      const configPath = normalize(path.win32.join(directory, CONFIG_NAME));
      const lowerRoot = canonicalRoot.toLowerCase(), lowerDirectory = directory.toLowerCase();
      if (lowerRoot === lowerDirectory || lowerRoot.startsWith(lowerDirectory + '\\') || lowerDirectory.startsWith(lowerRoot + '\\')) throw denied();
      privateState.inspectWorkspaceDirectory(canonicalRoot);
      if (mode === 'fresh') {
        privateState.ensurePrivateDirectory(base);
        privateState.ensurePrivateDirectory(directory);
      }
      const baseIdentity = privateState.inspectPrivateDirectory(base).identity;
      const directoryIdentity = privateState.inspectPrivateDirectory(directory).identity;
      const verifyDirectories = () => {
        if (!sameIdentity(baseIdentity, privateState.inspectPrivateDirectory(base).identity)
          || !sameIdentity(directoryIdentity, privateState.inspectPrivateDirectory(directory).identity)) throw denied();
      };
      const configExists = () => {
        try { fileSystem.lstatSync(configPath); return true; }
        catch (error) { if (error.code === 'ENOENT') return false; throw denied(); }
      };
      let config;
      if (configExists() || mode === 'existing') {
        verifyDirectories();
        const bytes = journal.readJournal({ filePath: configPath });
        if (!Buffer.isBuffer(bytes) || bytes.length > 4096) throw denied();
        config = JSON.parse(bytes);
        if (!exact(config, CONFIG_KEYS) || config.version !== 1 || config.workspaceId !== id
          || config.workspaceRoot !== canonicalRoot || config.instanceName !== 'dvaia-lab-' + id
          || !uuid(config.installationId) || !uuid(config.operationId) || config.image !== '24.04'
          || normalize(config.multipassExecutable) !== config.multipassExecutable
          || normalize(config.sshExecutable) !== config.sshExecutable
          || !executable(config.multipassExecutable, 'multipass.exe') || !executable(config.sshExecutable, 'ssh.exe')
          || !bytes.equals(encode(config))) throw denied();
      } else {
        // Only an explicit fresh installation may mint lab identity. Publication
        // precedes VM creation; a later fresh retry reuses these exact bytes.
        const multipassExecutable = normalize(environment.DVAIA_WINDOWS_MULTIPASS_EXECUTABLE);
        const sshExecutable = normalize(environment.DVAIA_WINDOWS_SSH_EXECUTABLE);
        if (!executable(multipassExecutable, 'multipass.exe') || !executable(sshExecutable, 'ssh.exe')) throw denied();
        const installationId = randomUUID(), operationId = randomUUID();
        if (!uuid(installationId) || !uuid(operationId)) throw denied();
        config = { version: 1, workspaceId: id, workspaceRoot: canonicalRoot, installationId, operationId,
          instanceName: 'dvaia-lab-' + id, multipassExecutable, sshExecutable, image: '24.04' };
        verifyDirectories();
        journal.createJournal({ filePath: configPath, bytes: encode(config) });
      }
      verifyDirectories();
      session = await ownedLab.prepareOwnedLab({ directory, workspaceId: config.workspaceId,
        installationId: config.installationId, operationId: config.operationId,
        instanceName: config.instanceName, multipassExecutable: config.multipassExecutable,
        sshExecutable: config.sshExecutable, image: config.image, existingOnly: mode === 'existing' });
      if (!session || typeof session.bindDaemon !== 'function') throw denied();
      await session.bindDaemon();
      const ownLabChild = createForwardOwner({ environment });
      if (typeof ownLabChild !== 'function' || typeof session.closeForwards !== 'function') throw denied();
      let closing;
      const close = () => (closing ||= Promise.resolve().then(() => session.closeForwards()));
      return Object.freeze({ session, ownLabChild, close });
    } catch {
      if (session && typeof session.closeForwards === 'function') {
        try { await session.closeForwards(); } catch { /* Preserve admission denial. */ }
      }
      throw denied();
    }
  }
  return Object.freeze({ prepareWindowsLabInstallation });
}

module.exports = { createWindowsLabInstallation, ...createWindowsLabInstallation() };
