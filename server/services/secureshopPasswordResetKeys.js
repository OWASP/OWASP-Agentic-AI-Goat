'use strict';

const fs = require('node:fs');
const path = require('node:path');
const windowsPrivateState = require('../../scripts/lib/windows-private-state');
const unavailable = () => Object.assign(new Error('Private password reset key unavailable'), {
  code: 'PASSWORD_RESET_KEY_UNAVAILABLE',
});

// Controlled dependency injection is a policy test seam, not native qualification.
function createPasswordResetKeyLoader({ platform = process.platform, privateState = windowsPrivateState } = {}) {
const privatePath = platform === 'win32' ? path.win32 : path;
function assertPrivateDirectory(directory) {
  if (platform === 'win32') {
    try { return privateState.inspectPrivateDirectory(directory); } catch { throw unavailable(); }
  }
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077)) throw unavailable();
  return stat;
}

function loadPasswordResetKeys({ filePath } = {}) {
  let descriptor;
  try {
    if (typeof filePath !== 'string' || !privatePath.isAbsolute(filePath)) throw unavailable();
    if (platform === 'win32') {
      assertPrivateDirectory(privatePath.dirname(filePath));
      return parsePasswordResetKeys(privateState.readPrivateFile(filePath));
    }
    const parent = assertPrivateDirectory(path.dirname(filePath));
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.uid !== process.getuid() || before.nlink !== 1
        || (before.mode & 0o077) || before.size > 4096) throw unavailable();
    const buffer = Buffer.alloc(4097);
    const count = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    const parentAfter = assertPrivateDirectory(path.dirname(filePath));
    if (count !== before.size || after.size !== before.size
        || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs
        || named.isSymbolicLink() || named.dev !== before.dev || named.ino !== before.ino
        || named.mode !== after.mode || named.nlink !== 1
        || parentAfter.dev !== parent.dev || parentAfter.ino !== parent.ino) throw unavailable();
    return parsePasswordResetKeys(buffer.subarray(0, count));
  } catch { throw unavailable(); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

return Object.freeze({ loadPasswordResetKeys, assertPrivateDirectory });
}
function parsePasswordResetKeys(bytes) {
    if (!Buffer.isBuffer(bytes) || bytes.length > 4096) throw unavailable();
    const value = JSON.parse(bytes.toString('utf8'));
    if (!value || Object.keys(value).sort().join(',') !== 'activeKeyId,keys,version'
        || value.version !== 1 || typeof value.activeKeyId !== 'string'
        || !value.keys || Array.isArray(value.keys) || typeof value.keys !== 'object') throw unavailable();
    const entries = Object.entries(value.keys);
    if (!entries.length || entries.length > 4) throw unavailable();
    const keys = new Map(entries.map(([id, encoded]) => {
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(id) || typeof encoded !== 'string') throw unavailable();
      const bytes = Buffer.from(encoded, 'base64url');
      if (bytes.length !== 32 || bytes.toString('base64url') !== encoded) throw unavailable();
      return [id, bytes];
    }));
    if (!keys.has(value.activeKeyId)) throw unavailable();
    return { activeKeyId: value.activeKeyId, keys };
}
module.exports = { ...createPasswordResetKeyLoader(), createPasswordResetKeyLoader };

