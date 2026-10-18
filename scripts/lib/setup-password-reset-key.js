'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const passwordResetKeys = require('../../server/services/secureshopPasswordResetKeys');
const windowsPrivateState = require('./windows-private-state');

function createPasswordResetKeySetup({ platform = process.platform, privateState = windowsPrivateState, fileSystem = fs, keyLoader = passwordResetKeys.createPasswordResetKeyLoader({ platform, privateState }) } = {}) {
const { loadPasswordResetKeys, assertPrivateDirectory } = keyLoader;
const privatePath = platform === 'win32' ? path.win32 : path;

function readPublished(filePath) {
  // An atomic hard-link publication briefly has two names until its private
  // staging link is removed. Only explicit setup waits for that bounded window.
  for (let attempt = 0; attempt < 25; attempt += 1) {
    try { return loadPasswordResetKeys({ filePath }); }
    catch (error) {
      let stat;
      try { stat = fs.lstatSync(filePath); } catch { throw error; }
      // The publisher may already have removed its staging link between the
      // failed read and this stat. Revalidate that completed publication once.
      if (stat.nlink === 1) return loadPasswordResetKeys({ filePath });
      if (stat.nlink !== 2 || attempt === 24) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
  }
}

// Explicit setup only. Runtime callers must never create or replace a lost key.
function ensurePasswordResetKey({ directory } = {}) {
  if (typeof directory !== 'string' || !privatePath.isAbsolute(directory)) throw TypeError('Private setup directory required');
  assertPrivateDirectory(directory);
  const filePath = privatePath.join(directory, 'secureshop-reset-key.json');
  if (platform === 'win32') {
    // Determine absence before reading. Once a named key is observed, any
    // native denial or malformed bytes must fail without a creation fallback.
    let exists = true;
    try { fileSystem.lstatSync(filePath); }
    catch (error) { if (error.code !== 'ENOENT') throw error; exists = false; }
    if (exists) {
      loadPasswordResetKeys({ filePath });
      return { filePath, created: false };
    }
    const activeKeyId = randomBytes(12).toString('base64url');
    const bytes = Buffer.from(JSON.stringify({ version: 1, activeKeyId, keys: { [activeKeyId]: randomBytes(32).toString('base64url') } }) + '\n');
    privateState.createPrivateFile(filePath, bytes);
    loadPasswordResetKeys({ filePath });
    return { filePath, created: true };
  }
  try {
    readPublished(filePath);
    return { filePath, created: false };
  } catch (error) {
    try { fs.lstatSync(filePath); throw error; }
    catch (statError) { if (statError.code !== 'ENOENT') throw statError; }
  }
  const activeKeyId = randomBytes(12).toString('base64url');
  const value = { version: 1, activeKeyId, keys: { [activeKeyId]: randomBytes(32).toString('base64url') } };
  const temporary = path.join(directory, `.reset-key-${randomBytes(12).toString('hex')}.pending`);
  let descriptor;
  let created = false;
  let temporaryCreated = false;
  try {
    descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    temporaryCreated = true;
    fs.writeFileSync(descriptor, JSON.stringify(value) + '\n');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
    try { fs.linkSync(temporary, filePath); created = true; }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (temporaryCreated) fs.unlinkSync(temporary);
  }
  readPublished(filePath);
  const parent = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  return { filePath, created };
}

return Object.freeze({ ensurePasswordResetKey });
}
module.exports = { ...createPasswordResetKeySetup(), createPasswordResetKeySetup };
