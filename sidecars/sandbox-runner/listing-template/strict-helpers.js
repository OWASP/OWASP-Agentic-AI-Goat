'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const COMPILER_SHA256 = 'e6d212d621f5f38de578c929afb5d2ac835f0b95bcd3fd0d61511eab1c8112d2';
const DEFAULT_SUPERVISOR = '/usr/local/libexec/dvaia-listing-template-supervisor';
const DEFAULT_INIT = '/usr/local/libexec/dvaia-listing-template-init';
const CLEAN_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const COMPILER_PATH = path.join(__dirname, '..', 'policy-render', 'assets', 'nunjucks-3.2.4.js');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const runtimeMounts = (exists = fs.existsSync) => ['/usr', '/bin', '/lib', '/lib64'].filter(entry => exists(entry));
const namespace = ['--cap-drop', 'ALL', '--cap-add', 'CAP_NET_ADMIN', '--cap-add', 'CAP_SETPCAP',
  '--unshare-user', '--unshare-net', '--unshare-pid', '--unshare-uts', '--unshare-ipc'];

function checkedCompiler(read = fs.readFileSync) {
  const bytes = read(COMPILER_PATH);
  if (hash(bytes) !== COMPILER_SHA256 || !bytes.subarray(0, 80).toString('utf8').includes('nunjucks 3.2.4')) {
    throw Object.assign(new Error('Pinned template compiler unavailable'), { code: 'LISTING_TEMPLATE_ASSET_INVALID' });
  }
  return Buffer.from(bytes);
}
function buildProbeArgv(mounts = runtimeMounts()) {
  return [...namespace, '--die-with-parent', '--new-session', '--clearenv',
    ...mounts.flatMap(entry => ['--ro-bind', entry, entry]), '--tmpfs', '/usr/local/libexec',
    '--ro-bind', DEFAULT_INIT, DEFAULT_INIT, '--dev', '/dev', '--dir', '/proc', '--tmpfs', '/tmp',
    '--tmpfs', '/work', '--chdir', '/work', '--setenv', 'PATH', CLEAN_PATH, DEFAULT_INIT, '--probe'];
}
function strictProbe(run = spawnSync, mounts) {
  const result = run('bwrap', buildProbeArgv(mounts), { timeout: 5000, env: { PATH: CLEAN_PATH } });
  return result?.status === 0;
}
function decodeEnvelope(stdout, marker) {
  const index = stdout.toString('utf8').lastIndexOf(marker);
  if (index < 0) return null;
  try { return JSON.parse(Buffer.from(stdout.toString('utf8').slice(index + marker.length).trim(), 'base64').toString('utf8')); }
  catch { return null; }
}
function observeEffect(root, expected) {
  const filename = path.join(root, 'command-effect');
  try {
    const names = fs.readdirSync(root);
    if (names.length !== 1 || names[0] !== 'command-effect') return Object.freeze({ commandEffectObserved: false });
    const before = fs.lstatSync(filename);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
        || (before.mode & 0o777) !== 0o600 || before.size !== expected.length) return Object.freeze({ commandEffectObserved: false });
    const bytes = fs.readFileSync(filename);
    const after = fs.lstatSync(filename);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) return Object.freeze({ commandEffectObserved: false });
    return Object.freeze({ commandEffectObserved: crypto.timingSafeEqual(bytes, expected), effectSha256: hash(bytes) });
  } catch (error) {
    if (error?.code === 'ENOENT') return Object.freeze({ commandEffectObserved: false });
    throw error;
  }
}
function cleanupEffectRoot(root) {
  try { fs.chmodSync(root, 0o700); } catch {}
  fs.rmSync(root, { recursive: true, force: true });
}

module.exports = { COMPILER_SHA256, COMPILER_PATH, DEFAULT_SUPERVISOR, DEFAULT_INIT, CLEAN_PATH, namespace,
  hash, runtimeMounts, checkedCompiler, buildProbeArgv, strictProbe, decodeEnvelope, observeEffect, cleanupEffectRoot };
