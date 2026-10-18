'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const dotenv = require('dotenv');
const windowsPrivateState = require('../lib/windows-private-state');

async function readRetryEnvironment({ root, platform = process.platform, environment = process.env,
  fileSystem = fs, privateState = windowsPrivateState, service } = {}) {
  if (!['HTTP', 'SHADOW'].includes(service)) throw new TypeError('Owned service required');
  const file = (platform === 'win32' ? path.win32 : path).join(root, '.env');
  let stat;
  try { stat = await fileSystem.lstat(file); }
  catch (error) {
    if (platform !== 'win32') throw error;
    const code = error?.code === 'ENOENT' ? `MCP_${service}_SETUP_ENV_REQUIRED` : `MCP_${service}_SETUP_ENV_UNTRUSTED`;
    throw Object.assign(new Error(code), { code });
  }
  if (!stat.isFile() || stat.isSymbolicLink() || (platform !== 'win32' && (stat.mode & 0o077))) {
    const code = `MCP_${service}_SETUP_ENV_UNTRUSTED`;
    throw Object.assign(new Error(code), { code });
  }
  let bytes;
  if (platform === 'win32') {
    try { bytes = privateState.readPrivateWorkspaceFile(file); }
    catch { const code = `MCP_${service}_SETUP_ENV_UNTRUSTED`; throw Object.assign(new Error(code), { code }); }
    if (!Buffer.isBuffer(bytes) || bytes.length > 1024 * 1024) {
      const code = `MCP_${service}_SETUP_ENV_UNTRUSTED`;
      throw Object.assign(new Error(code), { code });
    }
  } else bytes = await fileSystem.readFile(file);
  return { ...environment, ...dotenv.parse(bytes) };
}

module.exports = { readRetryEnvironment };
