'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fileSha256 = filename => sha256(fs.readFileSync(filename));

function assertPrivateDirectory(directory) {
  const actual = fs.realpathSync(directory), stat = fs.lstatSync(actual);
  if (actual !== directory || !stat.isDirectory() || stat.isSymbolicLink()
      || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) {
    throw new Error('Receipt directory must be private and canonical');
  }
  return actual;
}

function writeJsonExclusive(directory, name, value) {
  directory = assertPrivateDirectory(directory);
  if (!/^[a-z][a-z0-9-]*\.json$/.test(name)) throw new Error('Invalid receipt name');
  const target = path.join(directory, name), temporary = path.join(directory, `.${name}.${process.pid}.tmp`);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  try { fs.linkSync(temporary, target); } finally { fs.unlinkSync(temporary); }
  const directoryFd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
  return { path: target, sha256: sha256(bytes) };
}

function discoveryReceipt({ mode, focused, files, deferredNative = [], nodeExecutable = process.execPath,
  nodeVersion = process.version, boundaryKind = process.platform } = {}) {
  if (!['unit', 'secureshop'].includes(mode) || typeof focused !== 'boolean'
      || !Array.isArray(files) || !files.length || files.some(file =>
        typeof file !== 'string' || !/^tests\/[A-Za-z0-9_./-]+\.test\.js$/.test(file))) {
    throw new Error('Invalid discovery receipt');
  }
  const normalized = [...new Set(files)].sort();
  if (normalized.length !== files.length) throw new Error('Duplicate discovered test');
  const registry = require('./native-secureshop-suites');
  if (!Array.isArray(deferredNative) || (mode !== 'secureshop' && deferredNative.length)) throw new Error('Invalid deferred native inventory');
  const deferredFiles = new Set();
  const deferred = deferredNative.map(row => {
    const registered = registry.deferredNative.find(entry => entry.file === row?.file);
    if (!registered || deferredFiles.has(row.file) || normalized.includes(row.file)
        || Object.keys(registered).some(key => row[key] !== registered[key])) throw new Error('Invalid deferred native registration');
    deferredFiles.add(row.file);
    return registered;
  }).sort((a, b) => a.file.localeCompare(b.file));
  const inventorySha256 = sha256(Buffer.from(`${normalized.join('\n')}\n`));
  return Object.freeze({ schemaVersion: 1, kind: 'isolated-test-discovery', mode,
    scope: focused ? 'focused' : 'aggregate', files: normalized,
    fileCount: normalized.length, inventorySha256, deferredNative: Object.freeze(deferred),
    deferredNativeSha256: sha256(Buffer.from(`${JSON.stringify(deferred)}\n`)),
    nativeQualificationAccepted: false, nodeExecutable, nodeVersion, boundaryKind });
}

function tapCounts(output) {
  const count = name => {
    const matches = [...output.matchAll(new RegExp(`^(?:# |ℹ )${name} (\\d+)$`, 'gm'))];
    return matches.length ? Number(matches.at(-1)[1]) : null;
  };
  return Object.freeze({ tests: count('tests'), pass: count('pass'), fail: count('fail'),
    skipped: count('skipped') ?? count('skip') });
}

function resultReceipt({ discovery, discoverySha256, argv, result, testsLog } = {}) {
  if (discovery?.kind !== 'isolated-test-discovery' || !/^[a-f0-9]{64}$/.test(discoverySha256 || '')
      || !Array.isArray(argv) || argv.some(value => typeof value !== 'string')
      || !result || !testsLog || !fs.statSync(testsLog).isFile()) throw new Error('Invalid result receipt');
  const output = fs.readFileSync(testsLog, 'utf8'), counts = tapCounts(output);
  const passed = result.code === 0 && result.signal == null && result.timedOut === false
    && counts.fail === 0 && counts.tests !== null && counts.pass !== null;
  return Object.freeze({ schemaVersion: 1, kind: 'isolated-test-result', mode: discovery.mode,
    scope: discovery.scope, passed, code: result.code, signal: result.signal,
    timedOut: result.timedOut, counts, argv, testsLogSha256: sha256(Buffer.from(output)),
    discoverySha256, inventorySha256: discovery.inventorySha256,
    deferredNative: discovery.deferredNative, deferredNativeSha256: discovery.deferredNativeSha256,
    nativeQualificationAccepted: false,
    sourceReadOnlyBoundary: true, applicationDatabaseAccessDenied: true,
    limitation: discovery.scope === 'focused'
      ? 'Focused result covers only the exact listed tests; it is not an aggregate pass.'
      : 'Controlled aggregate only; native PostgreSQL, browser and actual-model qualifications are separate.' });
}

module.exports = { discoveryReceipt, fileSha256, resultReceipt, tapCounts, writeJsonExclusive };
