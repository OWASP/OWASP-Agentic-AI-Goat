'use strict';

// Local activation configuration helper. It reads the application's private
// environment without changing it and writes owned runtime values to a
// separate workspace-scoped private file.
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const dotenv = require('dotenv');
const windowsPrivateState = require('../lib/windows-private-state');
const windowsJournal = require('../lib/windows-provisioning-journal');
const { assertPlatformSigningConfiguration } = require('../../server/services/platformSigningConfiguration');
const { KEYS, managedConfigurationPath, parseManagedConfiguration } = require('../../server/services/mcp/ownedManagedConfiguration');

const TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const PROFILE = 'owasp-ai-goat-mcp-sandbox';
const MANAGED = Object.freeze({
  MCP_OWNED_TARGET_APPARMOR_PROFILE: PROFILE,
  MCP_OWNED_TARGET_PORT: '8092',
  MCP_OWNED_TARGET_URL: 'http://127.0.0.1:8092',
  MCP_OWNED_RESOURCES_ENABLED: 'false',
  MCP_INDIRECT_INJECTION_ENABLED: 'false',
  MCP_PROTECTED_RECOVERY_ENABLED: 'false',
  CODEBOT_SANDBOX_RUNNER_URL: 'http://127.0.0.1:8092',
  CODEBOT_OWNED_EXECUTION_ENABLED: 'false',
});
function fail(code) { throw Object.assign(new Error(code), { code }); }
async function readPrivate(file) {
  let stat; try { stat = await fs.lstat(file); } catch(error) { fail(error.code==='ENOENT'?'MCP_INSTALL_ENV_REQUIRED':'MCP_INSTALL_ENV_INVALID'); }
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) fail('MCP_INSTALL_ENV_INVALID');
  return fs.readFile(file);
}
function createOwnedPrivateStorage({filesystemPlatform=process.platform,fileSystem=fs,
  privateState=windowsPrivateState,journal=windowsJournal}={}) {
  const windows=filesystemPlatform==='win32',storagePath=windows?path.win32:path;
  return Object.freeze({
    path:storagePath,
    async read(file,{workspace=false}={}) {
      if(!windows)return readPrivate(file);
      try{privateState.normalizePrivatePath(file);}catch{fail('MCP_INSTALL_ENV_INVALID');}
      try{await fileSystem.lstat(file);}catch(error){fail(error.code==='ENOENT'?'MCP_INSTALL_ENV_REQUIRED':'MCP_INSTALL_ENV_INVALID');}
      try{const bytes=workspace?privateState.readPrivateWorkspaceFile(file):privateState.readPrivateFile(file);
        if(!Buffer.isBuffer(bytes)||bytes.length>1024*1024)throw Error();return Buffer.from(bytes);
      }catch{fail('MCP_INSTALL_ENV_INVALID');}
    },
    async write(file,bytes,originalBytes) {
      if(!windows)return writePrivateAtomic(file,bytes);
      try{try{await fileSystem.lstat(file+'.pending');fail('MCP_INSTALL_RECOVERY_REQUIRED');}catch(error){if(error.code!=='ENOENT')throw error;}
        journal.inspectDestination({filePath:file});
        if(originalBytes===null)journal.createJournal({filePath:file,bytes});
        else journal.updateJournal({filePath:file,originalBytes,resultBytes:bytes});
      }catch{fail('MCP_INSTALL_RECOVERY_REQUIRED');}
    },
  });
}
const defaultStorage=createOwnedPrivateStorage();
function assertNoDuplicates(source, keys) {
  const seen = new Set();
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=/);
    if (!match || !keys.has(match[1])) continue;
    if (seen.has(match[1])) fail('MCP_INSTALL_ENV_CONFLICT');
    seen.add(match[1]);
  }
}
async function prepareOwnedEnvironment({ envPath, randomToken = () => crypto.randomBytes(48).toString('base64url') } = {}) {
  if(process.platform==='win32')fail('MCP_INSTALL_PLATFORM_UNSUPPORTED');
  if (!path.isAbsolute(envPath || '')) fail('MCP_INSTALL_ENV_INVALID');
  const pending = `${envPath}.mcp-owned`;
  try { await fs.lstat(pending); fail('MCP_INSTALL_RECOVERY_REQUIRED'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const original = await readPrivate(envPath); const source = original.toString('utf8');
  const keys = new Set([...Object.keys(MANAGED), 'MCP_OWNED_TARGET_TOKEN']);
  assertNoDuplicates(source, keys);
  const parsed = dotenv.parse(source); assertPlatformSigningConfiguration(parsed);
  const token = parsed.MCP_OWNED_TARGET_TOKEN || randomToken();
  if (!TOKEN.test(token || '')) fail('MCP_INSTALL_TOKEN_INVALID');
  for (const [key, expected] of Object.entries(MANAGED)) {
    if (Object.hasOwn(parsed, key) && parsed[key] !== expected) fail('MCP_INSTALL_ENV_CONFLICT');
  }
  const additions = { ...MANAGED, MCP_OWNED_TARGET_TOKEN: token };
  const missing = Object.entries(additions).filter(([key]) => !Object.hasOwn(parsed, key));
  if (!missing.length) return Object.freeze({ changed: false, tokenPreserved: true, profile: PROFILE, port: 8092 });
  const separator = original.length && original.at(-1) !== 0x0a ? '\n' : '';
  const encoded = missing.map(([key, value]) => `${key}=${JSON.stringify(value)}`).join('\n') + '\n';
  let handle;
  try {
    handle = await fs.open(pending, 'wx', 0o600); await handle.writeFile(Buffer.concat([original, Buffer.from(separator + encoded)]));
    await handle.sync(); await handle.close(); handle = null;
    const current = await readPrivate(envPath); if (!current.equals(original)) fail('MCP_INSTALL_ENV_CHANGED');
    await fs.rename(pending, envPath);
    const directory = await fs.open(path.dirname(envPath), 'r'); try { await directory.sync(); } finally { await directory.close(); }
  } finally { if (handle) await handle.close(); }
  return Object.freeze({ changed: true, tokenPreserved: Object.hasOwn(parsed, 'MCP_OWNED_TARGET_TOKEN'),
    profile: PROFILE, port: 8092 });
}

function encodeManaged(values) {
  return KEYS.map(key => `${key}=${JSON.stringify(values[key])}`).join('\n') + '\n';
}

async function writePrivateAtomic(file, bytes) {
  const directory = path.dirname(file);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await fs.chmod(directory, 0o700);
  const pending = `${file}.pending`;
  try { await fs.lstat(pending); fail('MCP_INSTALL_RECOVERY_REQUIRED'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  let handle;
  try {
    handle = await fs.open(pending, 'wx', 0o600);
    await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = null;
    await fs.rename(pending, file);
    const parent = await fs.open(directory, 'r'); try { await parent.sync(); } finally { await parent.close(); }
  } finally { if (handle) await handle.close(); }
}

function snapshotApplicationEnvironment(environment) {
  if (!environment || typeof environment !== 'object' || Array.isArray(environment)
    || Object.values(environment).some(value => typeof value !== 'string')) fail('MCP_INSTALL_ENV_INVALID');
  const snapshot = Object.freeze({ ...environment });
  assertPlatformSigningConfiguration(snapshot);
  return snapshot;
}

async function prepareOwnedManagedConfiguration({ envPath, managedPath, applicationEnvironment,
  randomToken = () => crypto.randomBytes(48).toString('base64url'), activateQualified = false,
  activateObservedAction = false, activateSupplyChain = false,
  activateIndirectInjection = false, activateProtectedRecovery = false, protectedRecoveryQualified = false,
  forceDisabled = false, storage=defaultStorage } = {}) {
  if (!storage.path.isAbsolute(envPath || '') || !storage.path.isAbsolute(managedPath || '')) fail('MCP_INSTALL_ENV_INVALID');
  const original = applicationEnvironment === undefined ? await storage.read(envPath,{workspace:true}) : null;
  const privateParsed = applicationEnvironment === undefined
    ? dotenv.parse(original) : snapshotApplicationEnvironment(applicationEnvironment);
  assertPlatformSigningConfiguration(privateParsed);
  let existing = null,existingBytes=null;
  try { existingBytes=await storage.read(managedPath);existing = parseManagedConfiguration(existingBytes); }
  catch (error) { if (error.code !== 'MCP_INSTALL_ENV_REQUIRED') throw error; }
  const token = existing?.MCP_OWNED_TARGET_TOKEN || privateParsed.MCP_OWNED_TARGET_TOKEN || randomToken();
  if (!TOKEN.test(token || '')) fail('MCP_INSTALL_TOKEN_INVALID');
  if (activateQualified && forceDisabled) fail('MCP_INSTALL_ENV_INVALID');
  if (activateObservedAction && (!activateQualified || forceDisabled)) fail('MCP_INSTALL_ENV_INVALID');
  if (activateSupplyChain && (!activateQualified || !activateObservedAction || forceDisabled)) {
    fail('MCP_INSTALL_ENV_INVALID');
  }
  if (activateIndirectInjection && (!activateQualified || !activateObservedAction || forceDisabled)) {
    fail('MCP_INSTALL_ENV_INVALID');
  }
  if(activateProtectedRecovery&&(!activateQualified||!protectedRecoveryQualified||forceDisabled))fail('MCP_INSTALL_PROTECTED_RECOVERY_UNQUALIFIED');
  const enabled = activateQualified || (!forceDisabled && existing?.MCP_OWNED_RESOURCES_ENABLED === 'true'
    && existing?.CODEBOT_OWNED_EXECUTION_ENABLED === 'true');
  const values = { ...MANAGED, MCP_OWNED_TARGET_TOKEN: token,
    MCP_OWNED_RESOURCES_ENABLED: enabled ? 'true' : 'false',
    MCP_PROTECTED_RECOVERY_ENABLED: enabled&&(activateProtectedRecovery||(!forceDisabled&&existing?.MCP_PROTECTED_RECOVERY_ENABLED==='true'))?'true':'false',
    MCP_OBSERVED_ACTION_ENABLED: enabled && (activateObservedAction
      || (!forceDisabled && existing?.MCP_OBSERVED_ACTION_ENABLED === 'true')) ? 'true' : 'false',
    MCP_SUPPLY_CHAIN_ENABLED: enabled && (activateSupplyChain
      || (!forceDisabled && existing?.MCP_SUPPLY_CHAIN_ENABLED === 'true')) ? 'true' : 'false',
    MCP_INDIRECT_INJECTION_ENABLED: enabled && (activateIndirectInjection
      || (!forceDisabled && existing?.MCP_INDIRECT_INJECTION_ENABLED === 'true')) ? 'true' : 'false',
    CODEBOT_OWNED_EXECUTION_ENABLED: enabled ? 'true' : 'false' };
  for (const [key, expected] of Object.entries(values)) {
    if (Object.hasOwn(privateParsed, key) && privateParsed[key] !== expected
        && key !== 'MCP_OWNED_RESOURCES_ENABLED' && key !== 'MCP_SUPPLY_CHAIN_ENABLED'
        && key !== 'MCP_OBSERVED_ACTION_ENABLED' && key !== 'MCP_INDIRECT_INJECTION_ENABLED'
        && key !== 'CODEBOT_OWNED_EXECUTION_ENABLED' && key !== 'MCP_PROTECTED_RECOVERY_ENABLED') {
      fail('MCP_INSTALL_ENV_CONFLICT');
    }
  }
  const encoded = Buffer.from(encodeManaged(values));
  if (!existing || !Buffer.from(encodeManaged(existing)).equals(encoded)) await storage.write(managedPath, encoded,existingBytes);
  if (original !== null && !(await storage.read(envPath,{workspace:true})).equals(original)) fail('MCP_INSTALL_ENV_CHANGED');
  return Object.freeze({ values, managedPath, activationEnabled: enabled,
    tokenPreserved: Boolean(existing?.MCP_OWNED_TARGET_TOKEN || privateParsed.MCP_OWNED_TARGET_TOKEN) });
}

function localProfilePlan({ platform = process.platform, root = path.resolve(__dirname, '../..'),
  home = os.homedir(), colimaProfile, ownedLabSession } = {}) {
  const template = path.join(root, 'sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in');
  const renderer = path.join(root, 'scripts/render-mcp-sandbox-apparmor.js');
  if (platform === 'linux') return Object.freeze({ platform, profile: PROFILE, template, renderer,
    destination: '/etc/apparmor.d/owasp-ai-goat-mcp-sandbox', dockerHost: 'unix:///var/run/docker.sock',
    privilegedSteps: 'sudo-non-interactive' });
  if (platform === 'darwin') {
    if (typeof colimaProfile !== 'string' || !/^colima-[a-z0-9][a-z0-9-]{0,47}$/.test(colimaProfile)) {
      fail('MCP_INSTALL_COLIMA_PROFILE_REQUIRED');
    }
    // Colima names the default Lima VM "colima", while named profiles retain their prefix.
    const vmName = colimaProfile === 'colima-default' ? 'colima' : colimaProfile;
    return Object.freeze({ platform, profile: PROFILE, template, renderer, colimaProfile,
      sshConfig: path.join(home, '.colima/_lima', vmName, 'ssh.config'),
      sshHost: `lima-${vmName}`, destination: '/etc/apparmor.d/owasp-ai-goat-mcp-sandbox',
      dockerHost: `unix://${path.join(home, '.colima', colimaProfile.slice('colima-'.length), 'docker.sock')}`,
      privilegedSteps: 'remote-sudo-non-interactive' });
  }
  if(platform==='win32') {
    if(!ownedLabSession)fail('MCP_INSTALL_PLATFORM_UNSUPPORTED');
    let sessionBinding;try{sessionBinding=require('../lib/windows-owned-lab').describeOwnedLab(ownedLabSession);}catch{fail('MCP_INSTALL_OWNED_LAB_REQUIRED');}
    if(sessionBinding.workspaceId!==require('../application-data-root').workspaceId(root)
      ||typeof sessionBinding.daemonId!=='string'||!sessionBinding.daemonId||sessionBinding.daemonId==='unbound'
      ||!/^[a-f0-9]{64}$/.test(sessionBinding.bindingSha256||''))fail('MCP_INSTALL_OWNED_LAB_REQUIRED');
    return Object.freeze({platform,profile:PROFILE,template,renderer,
      destination:'/etc/apparmor.d/'+PROFILE,privilegedSteps:'owned-windows-lab',sessionBinding});
  }
  fail('MCP_INSTALL_PLATFORM_UNSUPPORTED');
}

module.exports = { snapshotApplicationEnvironment, createOwnedPrivateStorage, prepareOwnedEnvironment, prepareOwnedManagedConfiguration, managedConfigurationPath,
  localProfilePlan, PROFILE, MANAGED };
