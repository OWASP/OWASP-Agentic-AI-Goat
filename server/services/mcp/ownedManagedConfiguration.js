'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const dotenv = require('dotenv');

const KEYS = Object.freeze([
  'MCP_OWNED_TARGET_APPARMOR_PROFILE',
  'MCP_OWNED_TARGET_PORT',
  'MCP_OWNED_TARGET_URL',
  'MCP_OWNED_TARGET_TOKEN',
  'MCP_OWNED_RESOURCES_ENABLED',
  'MCP_OBSERVED_ACTION_ENABLED',
  'MCP_INDIRECT_INJECTION_ENABLED',
  'MCP_SUPPLY_CHAIN_ENABLED',
  'MCP_PROTECTED_RECOVERY_ENABLED',
  'CODEBOT_SANDBOX_RUNNER_URL',
  'CODEBOT_OWNED_EXECUTION_ENABLED',
]);
const KEY_SET = new Set(KEYS);
const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const EXACT = Object.freeze({
  MCP_OWNED_TARGET_APPARMOR_PROFILE: 'owasp-ai-goat-mcp-sandbox',
  MCP_OWNED_TARGET_PORT: '8092',
  MCP_OWNED_TARGET_URL: 'http://127.0.0.1:8092',
  CODEBOT_SANDBOX_RUNNER_URL: 'http://127.0.0.1:8092',
});

function configurationError(code) {
  return Object.assign(new Error(code), { code });
}

function workspaceId(root) {
  return crypto.createHash('sha256').update(path.resolve(root)).digest('hex').slice(0, 12);
}

function managedConfigurationPath({ root = path.resolve(__dirname, '../../..'), home = os.homedir() } = {}) {
  return path.join(home, '.owasp-ai-goat', workspaceId(root), 'mcp-owned.env');
}

function parseManagedConfiguration(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 16 * 1024) {
    throw configurationError('MCP_MANAGED_CONFIGURATION_INVALID');
  }
  const names = [];
  for (const line of bytes.toString('utf8').split(/\r?\n/)) {
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const match = line.match(/^([A-Z][A-Z0-9_]*)=/);
    if (!match || !KEY_SET.has(match[1]) || names.includes(match[1])) {
      throw configurationError('MCP_MANAGED_CONFIGURATION_INVALID');
    }
    names.push(match[1]);
  }
  const parsed = dotenv.parse(bytes);
  const optional = new Set(['MCP_OBSERVED_ACTION_ENABLED', 'MCP_INDIRECT_INJECTION_ENABLED', 'MCP_SUPPLY_CHAIN_ENABLED','MCP_PROTECTED_RECOVERY_ENABLED']);
  const required = KEYS.filter(key => !optional.has(key));
  if (!required.every(key => Object.hasOwn(parsed, key))
      || names.length !== required.length + [...optional].filter(key => Object.hasOwn(parsed, key)).length) {
    throw configurationError('MCP_MANAGED_CONFIGURATION_INVALID');
  }
  parsed.MCP_OBSERVED_ACTION_ENABLED ??= 'false';
  parsed.MCP_INDIRECT_INJECTION_ENABLED ??= 'false';
  parsed.MCP_SUPPLY_CHAIN_ENABLED ??= 'false';
  parsed.MCP_PROTECTED_RECOVERY_ENABLED ??= 'false';
  if (Object.entries(EXACT).some(([key, value]) => parsed[key] !== value)
      || !TOKEN.test(parsed.MCP_OWNED_TARGET_TOKEN)
      || !['true', 'false'].includes(parsed.MCP_OWNED_RESOURCES_ENABLED)
  || !['true', 'false'].includes(parsed.MCP_OBSERVED_ACTION_ENABLED)
      || !['true', 'false'].includes(parsed.MCP_INDIRECT_INJECTION_ENABLED)
      || !['true', 'false'].includes(parsed.MCP_SUPPLY_CHAIN_ENABLED)
      || !['true','false'].includes(parsed.MCP_PROTECTED_RECOVERY_ENABLED)
      || (parsed.MCP_PROTECTED_RECOVERY_ENABLED==='true'&&parsed.MCP_OWNED_RESOURCES_ENABLED!=='true')
      || !['true', 'false'].includes(parsed.CODEBOT_OWNED_EXECUTION_ENABLED)
      || (parsed.MCP_OBSERVED_ACTION_ENABLED === 'true' && parsed.MCP_OWNED_RESOURCES_ENABLED !== 'true')
      || (parsed.MCP_SUPPLY_CHAIN_ENABLED === 'true'
        && (parsed.MCP_OWNED_RESOURCES_ENABLED !== 'true' || parsed.MCP_OBSERVED_ACTION_ENABLED !== 'true'))
      || (parsed.MCP_INDIRECT_INJECTION_ENABLED === 'true'
        && (parsed.MCP_OWNED_RESOURCES_ENABLED !== 'true' || parsed.MCP_OBSERVED_ACTION_ENABLED !== 'true'))
      || parsed.MCP_OWNED_RESOURCES_ENABLED !== parsed.CODEBOT_OWNED_EXECUTION_ENABLED) {
    throw configurationError('MCP_MANAGED_CONFIGURATION_INVALID');
  }
  return Object.freeze(Object.fromEntries(KEYS.map(key => [key, parsed[key]])));
}

// Shared read-only Windows authority for the three managed configuration files.
// Native admission owns ACL/reparse/link/bounded handle checks; this reader
// additionally binds the private parent identity and the 16KiB service limit.
function createWindowsManagedSnapshotReader({ privateState = require('../../../scripts/lib/windows-private-state'), fileSystem = fs,
  errorCode = 'MCP_MANAGED_CONFIGURATION_UNTRUSTED' } = {}) {
  const denied = () => configurationError(errorCode);
  const validIdentity = value => Number.isInteger(value?.volumeSerial) && value.volumeSerial >= 0 && value.volumeSerial <= 0xffffffff
    && typeof value.fileId === 'string' && /^[a-f0-9]{16}$/.test(value.fileId);
  return function readSnapshot({ file, flush = false } = {}) {
    try {
      if (typeof flush !== 'boolean') throw denied();
      const target = require('../../../scripts/lib/windows-private-state').normalizePrivatePath(file), parent = path.win32.dirname(target);
      const directory = privateState.inspectPrivateDirectory(parent);
      if (directory?.path !== parent || !validIdentity(directory.identity)) throw denied();
      const assertDirectory = () => {
        const after = privateState.inspectPrivateDirectory(parent);
        if (after?.path !== parent || !validIdentity(after.identity) || after.identity.volumeSerial !== directory.identity.volumeSerial
          || after.identity.fileId !== directory.identity.fileId) throw denied();
      };
      // A denied private parent or native read can never authorize replacement.
      try { fileSystem.lstatSync(target); } catch (error) { if (error.code === 'ENOENT') { assertDirectory(); return null; } throw error; }
      const snapshot = privateState[flush ? 'readAndFlushPrivateFileSnapshot' : 'readPrivateFileSnapshot'](target), bytes = snapshot?.bytes;
      if (snapshot?.path !== target || !Buffer.isBuffer(bytes) || bytes.length > 16384 || snapshot.size !== bytes.length
          || !validIdentity(snapshot.identity)) throw denied();
      assertDirectory();
      const saved = Buffer.from(bytes);
      return Object.freeze({ path: target, size: saved.length, identity: Object.freeze({ ...snapshot.identity }),
        get bytes() { return Buffer.from(saved); } });
    } catch { throw denied(); }
  };
}
function createManagedConfiguration({ filesystemPlatform = process.platform, privateState, fileSystem = fs } = {}) {
  const snapshot = createWindowsManagedSnapshotReader({ privateState, fileSystem });
  function loadOwnedManagedConfiguration({ root, home, file = managedConfigurationPath({ root, home }) } = {}) {
    if (filesystemPlatform === 'win32') {
      const observed = snapshot({ file });
      return observed ? parseManagedConfiguration(observed.bytes) : Object.freeze({});
    }
    let stat;
    try { stat = fileSystem.lstatSync(file); }
    catch (error) { if (error.code === 'ENOENT') return Object.freeze({}); throw error; }
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0
        || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
      throw configurationError('MCP_MANAGED_CONFIGURATION_UNTRUSTED');
    }
    return parseManagedConfiguration(fileSystem.readFileSync(file));
  }
  return Object.freeze({ loadOwnedManagedConfiguration });
}
const { loadOwnedManagedConfiguration } = createManagedConfiguration();

module.exports = { KEYS, EXACT, workspaceId, managedConfigurationPath, parseManagedConfiguration,
  loadOwnedManagedConfiguration, createManagedConfiguration, createWindowsManagedSnapshotReader };
