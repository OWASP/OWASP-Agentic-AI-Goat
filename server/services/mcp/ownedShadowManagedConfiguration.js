'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { workspaceId, createWindowsManagedSnapshotReader } = require('./ownedManagedConfiguration');
function managedPath({ root = path.resolve(__dirname, '../../..'), home = os.homedir() } = {}) {
  return path.join(home, '.dvaia', workspaceId(root), 'mcp-owned-shadow.json');
}
function validate(value) {
  const keys = ['version', 'enabled', 'url', 'token', 'profile', 'container', 'image', 'runtimeDigest'];
  if (!value || Object.keys(value).sort().join() !== keys.sort().join() || value.version !== 1
      || typeof value.enabled !== 'boolean' || !/^http:\/\/127\.0\.0\.1:[0-9]{4,5}$/.test(value.url || '')
      || Number(value.url.split(':').at(-1)) < 1024 || Number(value.url.split(':').at(-1)) > 65535
      || !/^[A-Za-z0-9_-]{43,128}$/.test(value.token || '')
      || !/^dvaia-owned-shadow-[a-f0-9]{12}$/.test(value.profile || '')
      || (value.runtimeDigest !== null && !/^[a-f0-9]{64}$/.test(value.runtimeDigest || ''))
      || (value.enabled && value.runtimeDigest === null)
      || value.container !== value.profile || !/^sha256:[a-f0-9]{64}$/.test(value.image || '')) {
    throw new Error('MCP_SHADOW_CONFIGURATION_INVALID');
  }
  return Object.freeze(value);
}
function createManagedConfiguration({ filesystemPlatform = process.platform, privateState = require('../../../scripts/lib/windows-private-state'), fileSystem = fs } = {}) {
  const readSnapshot = createWindowsManagedSnapshotReader({ privateState, fileSystem, errorCode: 'MCP_SHADOW_CONFIGURATION_UNTRUSTED' });
  function loadSnapshot({ file = managedPath(), flush = false } = {}) {
    if (filesystemPlatform !== 'win32') throw new Error('MCP_SHADOW_CONFIGURATION_UNTRUSTED');
    const snapshot = readSnapshot({ file, flush }); if (!snapshot) return null;
    let value; try { value = validate(JSON.parse(snapshot.bytes)); } catch { throw new Error('MCP_SHADOW_CONFIGURATION_INVALID'); }
    return Object.freeze({ value, path: snapshot.path, size: snapshot.size, identity: snapshot.identity,
      get bytes() { return snapshot.bytes; } });
  }
  function load({ file = managedPath() } = {}) {
    if (filesystemPlatform === 'win32') return loadSnapshot({ file })?.value ?? null;
    let fd;
    try {
      fd = fileSystem.openSync(file, fileSystem.constants.O_RDONLY | fileSystem.constants.O_NOFOLLOW);
      const stat = fileSystem.fstatSync(fd);
      if (!stat.isFile() || stat.size > 16384 || stat.mode & 0o077
          || typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('MCP_SHADOW_CONFIGURATION_UNTRUSTED');
      return validate(JSON.parse(fileSystem.readFileSync(fd, 'utf8')));
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    finally { if (fd !== undefined) fileSystem.closeSync(fd); }
  }
  return Object.freeze({ managedPath, validate, load, loadSnapshot });
}
module.exports = { ...createManagedConfiguration(), createManagedConfiguration };
