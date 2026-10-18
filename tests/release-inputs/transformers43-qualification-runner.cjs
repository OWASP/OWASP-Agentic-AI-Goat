'use strict';

// Detached qualification process control. This module deliberately does not
// contain authority to run the real Transformers candidate: the reviewed
// package/model/retrieval/asset manifest does not exist yet. Its exported API
// is useful for controlled process tests only when every input file is pinned.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

const REQUIRED = Object.freeze({
  '@huggingface/transformers': '4.3.0',
  'onnxruntime-node': '1.30.0',
  'onnxruntime-web': '1.31.0-dev.20260914-8d85527a0',
  'onnxruntime-common': '1.30.0',
  sharp: '0.35.4',
  'adm-zip': '0.6.1'
});
const MAX_OUTPUT_BYTES = 1024 * 1024;
const TERMINATION_GRACE_MS = 500;
const CLI_DISABLED_REASON = 'actual Transformers qualification requires a reviewed package/native/retrieval/asset manifest';
const SHA256 = /^[0-9a-f]{64}$/;

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function absolute(value, name) {
  if (typeof value !== 'string' || !value || !path.isAbsolute(value) || value.includes('\0')) {
    throw new Error(`${name} must be absolute`);
  }
  return path.resolve(value);
}

function ownedStat(value, name, kind) {
  const requested = absolute(value, name);
  const row = fs.lstatSync(requested);
  if (row.isSymbolicLink()) {
    throw new Error(`${name} must not be a symlink`);
  }
  // macOS exposes /var through the trusted /private/var system alias. Use the
  // canonical target for all containment checks while still rejecting an
  // explicitly supplied symlink as the owned object itself.
  const resolved = fs.realpathSync(requested);
  if (typeof process.getuid === 'function' && row.uid !== process.getuid()) {
    throw new Error(`${name} must be owned by the current uid`);
  }
  if (kind === 'directory' && !row.isDirectory()) throw new Error(`${name} must be a directory`);
  if (kind === 'file' && !row.isFile()) throw new Error(`${name} must be a regular file`);
  return { resolved, row };
}

function inside(parent, candidate) {
  return candidate.startsWith(`${parent}${path.sep}`);
}

function assertNoSymlinkPath(base, relative, name) {
  let current = base;
  for (const part of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (fs.lstatSync(current).isSymbolicLink()) throw new Error(`${name} must not contain symlinks`);
  }
}

function assertOwnedPrefix(prefix, workspace = process.cwd()) {
  const { resolved } = ownedStat(prefix, 'prefix', 'directory');
  const workspacePath = absolute(workspace, 'workspace');
  let workspaceReal = workspacePath;
  if (fs.existsSync(workspacePath)) workspaceReal = fs.realpathSync(workspacePath);
  if (resolved === workspaceReal || inside(workspaceReal, resolved)) {
    throw new Error('qualification prefix must be outside the workspace');
  }
  return resolved;
}

function assertOwnedDirectory(value, name, prefix, requestedPrefix = prefix) {
  const requested = absolute(value, name);
  if (requestedPrefix) {
    const requestedRoot = absolute(requestedPrefix, 'requested prefix');
    if (!inside(requestedRoot, requested)) throw new Error(`${name} must be inside prefix`);
    assertNoSymlinkPath(requestedRoot, path.relative(requestedRoot, requested), name);
  }
  const { resolved } = ownedStat(value, name, 'directory');
  if (prefix && !inside(prefix, resolved)) throw new Error(`${name} must be inside prefix`);
  return resolved;
}

function assertOwnedFile(value, name, prefix, { executable = false, requestedPrefix = prefix } = {}) {
  const requested = absolute(value, name);
  if (requestedPrefix) {
    const requestedRoot = absolute(requestedPrefix, 'requested prefix');
    if (!inside(requestedRoot, requested)) throw new Error(`${name} must be inside prefix`);
    assertNoSymlinkPath(requestedRoot, path.relative(requestedRoot, requested), name);
  }
  const { resolved, row } = ownedStat(value, name, 'file');
  if (prefix && !inside(prefix, resolved)) throw new Error(`${name} must be inside prefix`);
  if (executable && !(row.mode & 0o111)) throw new Error(`${name} must be executable`);
  return resolved;
}

function validateIntegrity(prefix, verifier, node, integrity) {
  if (!integrity || typeof integrity !== 'object' || Array.isArray(integrity)
      || integrity.version !== 1 || integrity.scope !== 'controlled_process_test'
      || typeof integrity.files !== 'object' || !integrity.files || Array.isArray(integrity.files)
      || !SHA256.test(integrity.nodeSha256 || '') || !SHA256.test(integrity.networkDenySha256 || '')) {
    throw new Error(CLI_DISABLED_REASON);
  }
  if (sha256(node) !== integrity.nodeSha256) throw new Error('node executable digest mismatch');
  const guard = path.join(__dirname, 'transformers43-network-deny.cjs');
  if (sha256(guard) !== integrity.networkDenySha256) throw new Error('network deny preload digest mismatch');
  const required = new Set(['package-lock.json', path.relative(prefix, verifier)]);
  for (const name of Object.keys(REQUIRED)) required.add(`node_modules/${name}/package.json`);
  const declared = Object.keys(integrity.files);
  if (declared.length < required.size || [...required].some(file => !declared.includes(file))) {
    throw new Error('integrity manifest omits required installed files');
  }
  const observed = {};
  for (const relative of declared) {
    if (typeof relative !== 'string' || !relative || path.isAbsolute(relative)
        || relative.split('/').some(part => part === '' || part === '.' || part === '..')) {
      throw new Error('integrity manifest path is invalid');
    }
    const expected = integrity.files[relative];
    if (!SHA256.test(expected)) throw new Error('integrity manifest digest is invalid');
    assertNoSymlinkPath(prefix, relative, `integrity file ${relative}`);
    const file = assertOwnedFile(path.join(prefix, relative), `integrity file ${relative}`, prefix);
    const actual = sha256(file);
    if (actual !== expected) throw new Error(`installed file digest mismatch: ${relative}`);
    observed[relative] = actual;
  }
  return Object.freeze(observed);
}

function installedInventory(prefix, integrity, verifier, node) {
  const files = validateIntegrity(prefix, verifier, node, integrity);
  const lock = JSON.parse(fs.readFileSync(path.join(prefix, 'package-lock.json'), 'utf8'));
  if (!lock || typeof lock !== 'object' || typeof lock.packages !== 'object' || !lock.packages) {
    throw new Error('package lock packages map is required');
  }
  const inventory = {};
  for (const [name, expected] of Object.entries(REQUIRED)) {
    const relative = `node_modules/${name}/package.json`;
    const manifest = JSON.parse(fs.readFileSync(path.join(prefix, relative), 'utf8'));
    const lockEntry = lock.packages[`node_modules/${name}`];
    if (!lockEntry || lockEntry.version !== expected || manifest.version !== expected) {
      throw new Error(`${name} is not exact ${expected}`);
    }
    if (typeof lockEntry.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]+=*$/.test(lockEntry.integrity)) {
      throw new Error(`${name} lock integrity is missing or malformed`);
    }
    inventory[name] = Object.freeze({ version: manifest.version,
      integrity: lockEntry.integrity, packageJsonSha256: files[relative] });
  }
  return Object.freeze({ packages: Object.freeze(inventory), files });
}

function childEnvironment({ cache, mode, home, npmCache }) {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('TLS verification cannot be disabled');
  const env = { PATH: process.env.PATH || '', LANG: process.env.LANG || 'C',
    HOME: home, npm_config_cache: npmCache, XENOVA_CACHE: cache };
  if (mode === 'offline') {
    env.HF_HUB_OFFLINE = '1';
    env.TRANSFORMERS_OFFLINE = '1';
    env.NODE_OPTIONS = `--require=${path.join(__dirname, 'transformers43-network-deny.cjs')}`;
  }
  return env;
}

function processRows() {
  const result = spawnSync('/bin/ps', ['-axo', 'pid=,pgid=,uid='], {
    encoding: 'utf8', timeout: 2000, maxBuffer: 1024 * 1024
  });
  if (result.status !== 0 || result.error) throw new Error('bounded process inventory failed');
  return result.stdout.split('\n').map(line => line.trim().split(/\s+/).map(Number))
    .filter(row => row.length === 3 && row.every(Number.isSafeInteger))
    .map(([pid, pgid, uid]) => ({ pid, pgid, uid }));
}

function processExists(pid) {
  return Number.isSafeInteger(pid) && pid > 0 && processRows().some(row => row.pid === pid);
}

function groupRows(pgid) {
  if (process.platform === 'win32') throw new Error('owned process-group qualification requires POSIX');
  if (!Number.isSafeInteger(pgid) || pgid <= 0) return [];
  return processRows().filter(row => row.pgid === pgid);
}

function groupExists(pgid) {
  return groupRows(pgid).length > 0;
}

function assertOwnedGroup(pgid) {
  const rows = groupRows(pgid);
  if (typeof process.getuid === 'function' && rows.some(row => row.uid !== process.getuid())) {
    throw new Error('process group contains a foreign uid');
  }
  return rows;
}

const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function waitAbsent(check, value, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (check(value)) {
    if (Date.now() >= deadline) return false;
    await pause(10);
  }
  return true;
}

async function terminateOwnedGroup(pgid, graceMs = TERMINATION_GRACE_MS) {
  if (!Number.isSafeInteger(pgid) || pgid <= 0) return { termSent: false, killSent: false, groupAbsent: true };
  let termSent = false;
  if (assertOwnedGroup(pgid).length) {
    try { process.kill(-pgid, 'SIGTERM'); termSent = true; }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  if (await waitAbsent(groupExists, pgid, graceMs)) return { termSent, killSent: false, groupAbsent: true };
  let killSent = false;
  try { process.kill(-pgid, 'SIGKILL'); killSent = true; }
  catch (error) { if (error.code !== 'ESRCH') throw error; }
  return { termSent, killSent, groupAbsent: await waitAbsent(groupExists, pgid, graceMs) };
}

function validateRun(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new Error('run options object required');
  const requestedPrefix = absolute(options.prefix, 'prefix');
  // The workspace boundary is code-owned. An exported caller cannot redefine
  // it to admit a workspace path as an allegedly detached prefix.
  const prefix = assertOwnedPrefix(requestedPrefix, path.resolve(__dirname, '../..'));
  const verifier = assertOwnedFile(options.verifier, 'verifier', prefix, { requestedPrefix });
  const cache = assertOwnedDirectory(options.cache, 'cache', prefix, requestedPrefix);
  const home = assertOwnedDirectory(options.home, 'home', prefix, requestedPrefix);
  const npmCache = assertOwnedDirectory(options.npmCache, 'npm cache', prefix, requestedPrefix);
  if (new Set([cache, home, npmCache]).size !== 3) throw new Error('cache, home and npm cache must be distinct');
  const node = assertOwnedFile(options.node || process.execPath, 'node', null, { executable: true });
  const mode = options.mode || 'online';
  if (!['online', 'offline'].includes(mode)) throw new Error('mode must be online or offline');
  const timeoutMs = options.timeoutMs ?? 600000;
  const maxOutputBytes = options.maxOutputBytes ?? MAX_OUTPUT_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 3600000) throw new Error('bounded timeout required');
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 64 || maxOutputBytes > MAX_OUTPUT_BYTES) throw new Error('bounded output limit required');
  const inventory = installedInventory(prefix, options.integrity, verifier, node);
  return { prefix, verifier, cache, home, npmCache, node, mode, timeoutMs, maxOutputBytes, inventory };
}

async function runVerifier(options) {
  const input = validateRun(options);
  // Refuse before creating a detached process when cleanup inventory is unavailable.
  processRows();
  const env = childEnvironment(input);
  let child;
  try {
    child = spawn(input.node, ['--use-system-ca', input.verifier, '--cache-dir', input.cache], {
      cwd: input.prefix, env, detached: true, stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (error) {
    throw Object.assign(new Error(`qualification spawn failed: ${error.message}`), { cause: error,
      result: { spawned: false, closeObserved: false, pidAbsent: true, pgidAbsent: true } });
  }

  const pid = child.pid;
  const pgid = Number.isSafeInteger(pid) && pid > 0 ? pid : null;
  let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), totalBytes = 0;
  let failure = null, timedOut = false, timeout;
  let stopPromise = null, cleanupError = null, resolveStopped, closeDeadline;
  const stopped = new Promise(resolve => { resolveStopped = resolve; });
  const unproven = () => resolveStopped({ code: null, signal: null, spawnError: null, closeObserved: false });
  const requestStop = error => {
    if (!failure) failure = error;
    if (!stopPromise && pgid) {
      stopPromise = terminateOwnedGroup(pgid);
      // A fast cleanup failure can precede the child close event. Attach a
      // handler immediately; the same promise is still awaited below.
      stopPromise.catch(error => { cleanupError = error; unproven(); });
    }
    if (!closeDeadline) closeDeadline = setTimeout(unproven, TERMINATION_GRACE_MS * 3);
  };
  const append = (name, chunk) => {
    const bytes = Buffer.from(chunk); totalBytes += bytes.length;
    if (totalBytes > input.maxOutputBytes) {
      requestStop(new Error('qualification output limit exceeded'));
      return;
    }
    if (name === 'stdout') stdout = Buffer.concat([stdout, bytes]);
    else stderr = Buffer.concat([stderr, bytes]);
  };
  child.stdout.on('data', chunk => append('stdout', chunk));
  child.stderr.on('data', chunk => append('stderr', chunk));

  const terminal = await Promise.race([stopped, new Promise(resolve => {
    let spawnError = null;
    child.once('error', error => { spawnError = error; requestStop(new Error(`qualification spawn failed: ${error.message}`)); });
    child.once('close', (code, signal) => resolve({ code, signal, spawnError, closeObserved: true }));
    timeout = setTimeout(() => {
      timedOut = true;
      requestStop(new Error('qualification timeout'));
    }, input.timeoutMs);
  })]);
  clearTimeout(timeout); clearTimeout(closeDeadline);
  let cleanup = { termSent: null, killSent: null, groupAbsent: false }, pidAbsent = false, pgidAbsent = false;
  try {
    cleanup = stopPromise ? await stopPromise : await terminateOwnedGroup(pgid);
    pidAbsent = pid ? await waitAbsent(processExists, pid, TERMINATION_GRACE_MS) : true;
    pgidAbsent = pgid ? await waitAbsent(groupExists, pgid, TERMINATION_GRACE_MS) : true;
  } catch (error) { cleanupError = error; }
  if (!terminal.closeObserved || cleanupError) {
    // Return failed proof to the outer owner; never signal an unverified group.
    child.stdout.destroy(); child.stderr.destroy(); child.unref();
  }
  const reaped = terminal.closeObserved && (child.exitCode !== null || child.signalCode !== null || terminal.spawnError !== null);
  const result = Object.freeze({ spawned: !terminal.spawnError && Boolean(pid), pid: pid || null, pgid,
    code: terminal.code, signal: terminal.signal, timedOut, closeObserved: terminal.closeObserved,
    reaped, pidAbsent, pgidAbsent, cleanup, cleanupUnproven: Boolean(cleanupError) || !terminal.closeObserved, outputBytes: totalBytes,
    stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8'), mode: input.mode,
    cache: input.cache, inventory: input.inventory });
  if (cleanupError || !reaped || !pidAbsent || !pgidAbsent || !cleanup.groupAbsent) {
    throw Object.assign(new Error('qualification process cleanup was not proven'), { result });
  }
  if (failure || terminal.spawnError || timedOut || terminal.code !== 0) {
    throw Object.assign(failure || new Error('embedding qualification failed'), { result });
  }
  return result;
}

if (require.main === module) {
  console.error(CLI_DISABLED_REASON);
  process.exitCode = 2;
}

module.exports = { REQUIRED, MAX_OUTPUT_BYTES, CLI_DISABLED_REASON, assertOwnedPrefix,
  assertOwnedDirectory, assertOwnedFile, childEnvironment, installedInventory,
  processExists, groupExists, terminateOwnedGroup, validateRun, runVerifier, sha256 };
