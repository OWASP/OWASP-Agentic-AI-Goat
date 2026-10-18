'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const config = require('../../server/services/secureshopQualifiedManagedConfiguration');

function invalid(code) { return Object.assign(new Error(code), { code }); }
async function privateDirectory(value) {
  await fs.mkdir(value, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(value);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) throw invalid('SECURESHOP_FIXTURE_ROOT_UNTRUSTED');
}
function encode(values) { return Buffer.from(config.KEYS.map(key => `${key}=${values[key]}`).join('\n') + '\n'); }
async function snapshotExisting({ root, home } = {}) {
  const file = config.managedPath(root, home);
  try {
    const bytes = await fs.readFile(file);
    config.load({ root, home, file });
    return Object.freeze({ present:true, bytes });
  } catch (error) {
    if (error.code === 'ENOENT') return Object.freeze({ present:false, bytes:null });
    throw error;
  }
}
async function writePrivateAtomic(file, bytes) {
  const parent = path.dirname(file); await privateDirectory(parent);
  const pending = `${file}.pending-${process.pid}`;
  let handle;
  try {
    handle = await fs.open(pending, 'wx', 0o600); await handle.writeFile(bytes); await handle.sync();
    await handle.close(); handle = null; await fs.rename(pending, file);
    const directoryHandle = await fs.open(parent, 'r'); try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
  } finally { if (handle) await handle.close(); await fs.rm(pending, { force: true }); }
}
async function provision({ root = path.resolve(__dirname, '../..'), home, enabled = true } = {}) {
  if (typeof enabled !== 'boolean') throw invalid('SECURESHOP_MANAGED_CONFIGURATION_INVALID');
  const previous = await snapshotExisting({ root, home });
  const roots = config.expectedRoots(root, home);
  await Promise.all(Object.values(roots).map(privateDirectory));
  const state = enabled ? 'true' : 'false';
  const values = { SS_ENABLE: 'true', ...Object.fromEntries(config.BOOLEAN_KEYS.map(key => [key, state])), ...roots };
  const bytes = encode(values); config.parse(bytes, { root, home });
  const file = config.managedPath(root, home); await writePrivateAtomic(file, bytes);
  config.load({ root, home, file });
  return Object.freeze({ file, enabled, fixtureRoots: Object.freeze(Object.values(roots)), previous });
}
async function restore({ root = path.resolve(__dirname, '../..'), home, previous } = {}) {
  if (!previous || typeof previous.present !== 'boolean'
      || (previous.present && !Buffer.isBuffer(previous.bytes))
      || (!previous.present && previous.bytes !== null)) throw invalid('SECURESHOP_MANAGED_CONFIGURATION_RECOVERY_INVALID');
  const file = config.managedPath(root, home);
  if (previous.present) {
    config.parse(previous.bytes, { root, home }); await writePrivateAtomic(file, previous.bytes);
  } else {
    await fs.rm(file, { force:true });
  }
  return Object.freeze({ file, restored:true, present:previous.present });
}

module.exports = { provision, restore, snapshotExisting, encode };
