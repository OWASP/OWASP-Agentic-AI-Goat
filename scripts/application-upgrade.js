'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const dotenv = require('dotenv');
const windowsPrivateState = require('./lib/windows-private-state');

function upgradeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

async function readPrivateFile(filename, code) {
  let stat;
  try { stat = await fs.lstat(filename); }
  catch (error) { throw upgradeError(error.code === 'ENOENT' ? code : 'UPGRADE_PRIVATE_STATE_INVALID'); }
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID');
  }
  return fs.readFile(filename);
}

function managedKeys(plan) {
  return new Set(plan.flatMap(row => [row.runtimeVariable, row.migrationVariable]));
}

function assertNoManagedDuplicates(source, keys) {
  const seen = new Set();
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (!match || !keys.has(match[1])) continue;
    if (seen.has(match[1])) throw upgradeError('UPGRADE_ENV_CONFLICT');
    seen.add(match[1]);
  }
}

// Controlled adapters prove caller dispatch, not native Windows qualification.
function createUpgradeStateInspector({ platform = process.platform, privateState = windowsPrivateState, fileSystem = fs } = {}) {
async function inspectUpgradeState({ envPath, manifestPath, currentPlan }) {
  const pendingPath = `${envPath}.upgrade`;
  try { await fileSystem.lstat(pendingPath); throw upgradeError('UPGRADE_ENV_RECOVERY_REQUIRED'); }
  catch (error) {
    if (error.code !== 'ENOENT') {
      if (platform === 'win32' && error.code !== 'UPGRADE_ENV_RECOVERY_REQUIRED') throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID');
      throw error;
    }
  }
  const nativeRead = (operation, filename) => {
    try {
      const bytes = privateState[operation](filename);
      if (!Buffer.isBuffer(bytes) || bytes.length > 1024 * 1024) throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID');
      return bytes;
    } catch { throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID'); }
  };
  const [envBytes, manifestBytes] = await Promise.all([
    platform === 'win32' ? nativeRead('readPrivateWorkspaceFile', envPath) : readPrivateFile(envPath, 'EXISTING_ENV_REQUIRED'),
    platform === 'win32' ? nativeRead('readPrivateFile', manifestPath) : readPrivateFile(manifestPath, 'EXISTING_MANIFEST_REQUIRED'),
  ]);
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString('utf8')); }
  catch { throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID'); }
  if (manifest?.version !== 1 || manifest.status !== 'complete' || !Array.isArray(manifest.plan) ||
      !manifest.configuration || typeof manifest.configuration !== 'object') {
    throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID');
  }
  const currentKeys = managedKeys(currentPlan);
  const source = envBytes.toString('utf8');
  assertNoManagedDuplicates(source, currentKeys);
  const parsed = dotenv.parse(source);
  const oldKeys = managedKeys(manifest.plan);
  const upgradingPriorPlan = manifest.plan.length < currentPlan.length;
  let missingSuffix = false;
  for (const row of manifest.plan) {
    const keys = [row.runtimeVariable, row.migrationVariable];
    if (keys.some(key => typeof manifest.configuration[key] !== 'string' || !manifest.configuration[key])) {
      throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID');
    }
    const present = keys.map(key => Object.hasOwn(parsed, key));
    if (present.some(Boolean) && !present.every(Boolean)) throw upgradeError('UPGRADE_ENV_MANIFEST_MISMATCH');
    if (present.every(Boolean)) {
      if (missingSuffix || keys.some(key => parsed[key] !== manifest.configuration[key])) {
        throw upgradeError('UPGRADE_ENV_MANIFEST_MISMATCH');
      }
    } else {
      if (upgradingPriorPlan) throw upgradeError('UPGRADE_ENV_MANIFEST_MISMATCH');
      missingSuffix = true;
    }
  }
  for (const key of currentKeys) {
    if (!oldKeys.has(key) && Object.hasOwn(parsed, key)) throw upgradeError('UPGRADE_ENV_CONFLICT');
  }
  return { envBytes, parsed, manifest, pendingPath };
}

return Object.freeze({ inspectUpgradeState: async options => {
  try { return await inspectUpgradeState(options); }
  catch (error) {
    if (platform === 'win32' && !['UPGRADE_ENV_RECOVERY_REQUIRED', 'UPGRADE_PRIVATE_STATE_INVALID', 'UPGRADE_ENV_CONFLICT', 'UPGRADE_ENV_MANIFEST_MISMATCH'].includes(error.code)) {
      throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID');
    }
    throw error;
  }
} });
}
const { inspectUpgradeState } = createUpgradeStateInspector();

function reconcileConfiguration({ envBytes, parsed, plan, configuration }) {
  const missing = [];
  for (const row of plan) {
    const keys = [row.runtimeVariable, row.migrationVariable];
    const present = keys.map(key => Object.hasOwn(parsed, key));
    if (present.every(Boolean)) {
      if (keys.some(key => parsed[key] !== configuration[key])) throw upgradeError('UPGRADE_ENV_CONFLICT');
      continue;
    }
    if (present.some(Boolean) || keys.some(key => typeof configuration[key] !== 'string' || !configuration[key])) {
      throw upgradeError('UPGRADE_ENV_CONFLICT');
    }
    missing.push(row);
  }
  const additions = Object.fromEntries(missing.flatMap(row => [
    [row.runtimeVariable, configuration[row.runtimeVariable]],
    [row.migrationVariable, configuration[row.migrationVariable]],
  ]));
  return { envBytes, parsed, missing, additions };
}

function createEnvironmentAppender({ platform = process.platform,
  preparePublication = require('./lib/setup-additive-environment-publication').prepareAdditiveEnvironmentPublication,
} = {}) {
async function appendPrivateEnvironment({ envPath, pendingPath, originalBytes, encodedAdditions, publicationContext }) {
  if (!encodedAdditions) return;
  if (platform === 'win32') {
    try {
      const { normalizePrivatePath } = windowsPrivateState;
      if (!publicationContext || normalizePrivatePath(envPath) !== path.win32.join(normalizePrivatePath(publicationContext.root), '.env') ||
          envPath !== normalizePrivatePath(envPath) || pendingPath !== `${envPath}.upgrade`) throw Error();
      // The caller holds the maintenance lease. Native publication retains its
      // private journal/original and accepts only the bound original or result.
      const publication = preparePublication({ ...publicationContext, originalBytes, encodedAdditions });
      publication.publish();
      return;
    } catch { throw upgradeError('UPGRADE_PRIVATE_STATE_INVALID'); }
  }
  let handle;
  try {
    handle = await fs.open(pendingPath, 'wx', 0o600);
    const separator = originalBytes.length && originalBytes[originalBytes.length - 1] !== 0x0a ? '\n' : '';
    await handle.writeFile(Buffer.concat([originalBytes, Buffer.from(separator + encodedAdditions)]));
    await handle.sync();
    await handle.close(); handle = null;
    const directory = await fs.open(path.dirname(envPath), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
    const current = await readPrivateFile(envPath, 'EXISTING_ENV_REQUIRED');
    if (!current.equals(originalBytes)) throw upgradeError('UPGRADE_ENV_CHANGED');
    await fs.rename(pendingPath, envPath);
    const promotedDirectory = await fs.open(path.dirname(envPath), 'r');
    try { await promotedDirectory.sync(); } finally { await promotedDirectory.close(); }
  } finally {
    if (handle) await handle.close();
  }
}

return Object.freeze({ appendPrivateEnvironment });
}
const { appendPrivateEnvironment } = createEnvironmentAppender();

module.exports = { inspectUpgradeState, reconcileConfiguration, appendPrivateEnvironment, upgradeError, createUpgradeStateInspector, createEnvironmentAppender };
