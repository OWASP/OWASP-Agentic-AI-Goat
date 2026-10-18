'use strict';

const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const {
  verifyAssetBundle,
  MAX_FILE_BYTES,
  MAX_FILES,
  MAX_TOTAL_BYTES,
  MAX_MANIFEST_BYTES,
} = require('./asset-bundle');

const RESTORE_FORMAT = 'dvaia-asset-restore-v1';
const RESTORE_MANIFEST = 'restore.json';
const INCOMPLETE = 'INCOMPLETE';
const PROOFS = new WeakSet();
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW;
const WRITE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
const RESTORE_MANIFEST_KEYS = ['bundleManifestDigest', 'complete', 'files', 'format'];
const RESTORE_ENTRY_KEYS = ['bytes', 'sha256', 'sourcePath', 'targetPath'];

function fail(code) {
  throw Object.assign(new Error(code), { code });
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function exactKeys(value, expected, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) fail(code);
}

function validateDigest(value, code) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail(code);
  return value;
}

function relative(value) {
  if (typeof value !== 'string' || !value || value.includes('\0') || value.includes('\\')
      || path.win32.isAbsolute(value) || path.posix.isAbsolute(value)
      || /^[A-Za-z]:/.test(value)
      || value.split('/').some(part => !part || part === '.' || part === '..')) {
    fail('UNSAFE_RESTORE_PATH');
  }
  return value;
}

function validateBytes(value, code = 'INVALID_ASSET_RESTORE_BYTES') {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_FILE_BYTES) fail(code);
  return value;
}

function sameStat(before, after) {
  return ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].every(field => before[field] === after[field]);
}

async function assertNoSymlinkPath(root, relativePath, location) {
  let current = root;
  for (const part of relativePath.split('/')) {
    current = path.join(current, part);
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink()) fail('ASSET_RESTORE_SYMLINK', location);
  }
}

async function readStableFile(root, relativePath, {
  maximum,
  tooLargeCode,
  changedCode = 'ASSET_RESTORE_CHANGED',
  location = relativePath,
} = {}) {
  relative(relativePath);
  await assertNoSymlinkPath(root, relativePath, location);
  const absolute = path.join(root, ...relativePath.split('/'));
  const expected = await fs.lstat(absolute);
  if (!expected.isFile()) fail('ASSET_RESTORE_NOT_REGULAR', location);
  if (!Number.isSafeInteger(expected.size) || expected.size > maximum) fail(tooLargeCode);
  const handle = await fs.open(absolute, READ_FLAGS);
  try {
    const before = await handle.stat();
    if (!before.isFile() || !sameStat(expected, before) || before.size > maximum) fail(changedCode, location);
    const buffer = Buffer.alloc(before.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const result = await handle.read(buffer, length, buffer.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    const after = await handle.stat();
    if (!sameStat(before, after) || length !== before.size) fail(changedCode, location);
    return buffer.subarray(0, length);
  } finally {
    await handle.close();
  }
}

async function exclusive(file, bytes) {
  const handle = await fs.open(file, WRITE_FLAGS, 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readRestoreManifest(root) {
  const bytes = await readStableFile(root, RESTORE_MANIFEST, {
    maximum: MAX_MANIFEST_BYTES,
    tooLargeCode: 'ASSET_RESTORE_MANIFEST_BYTES_LIMIT',
    changedCode: 'ASSET_RESTORE_CHANGED',
    location: RESTORE_MANIFEST,
  });
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('INVALID_ASSET_RESTORE_MANIFEST');
  }
  exactKeys(manifest, RESTORE_MANIFEST_KEYS, 'UNKNOWN_ASSET_RESTORE_MANIFEST_FIELDS');
  if (manifest.format !== RESTORE_FORMAT || manifest.complete !== true || !Array.isArray(manifest.files)) {
    fail('INVALID_ASSET_RESTORE_MANIFEST');
  }
  validateDigest(manifest.bundleManifestDigest, 'INVALID_ASSET_BUNDLE_HASH');
  if (manifest.files.length > MAX_FILES) fail('ASSET_FILE_COUNT_LIMIT');
  const files = [];
  const seenSources = new Set();
  const seenTargets = new Set();
  let totalBytes = 0;
  for (let index = 0; index < manifest.files.length; index += 1) {
    const entry = manifest.files[index];
    exactKeys(entry, RESTORE_ENTRY_KEYS, 'UNKNOWN_ASSET_RESTORE_ENTRY_FIELDS');
    const sourcePath = relative(entry.sourcePath);
    const targetPath = relative(entry.targetPath);
    if (seenSources.has(sourcePath) || seenTargets.has(targetPath)) fail('DUPLICATE_ASSET_RESTORE_ENTRY');
    seenSources.add(sourcePath);
    seenTargets.add(targetPath);
    validateBytes(entry.bytes);
    validateDigest(entry.sha256, 'INVALID_ASSET_RESTORE_HASH');
    totalBytes += entry.bytes;
    if (totalBytes > MAX_TOTAL_BYTES) fail('ASSET_TOTAL_BYTES_LIMIT');
    files.push({ sourcePath, targetPath, bytes: entry.bytes, sha256: entry.sha256 });
  }
  const canonical = Buffer.from(`${JSON.stringify({
    format: manifest.format,
    complete: manifest.complete,
    bundleManifestDigest: manifest.bundleManifestDigest,
    files,
  }, null, 2)}\n`, 'utf8');
  if (!canonical.equals(bytes)) fail('NONCANONICAL_ASSET_RESTORE_MANIFEST');
  return { manifestBytes: bytes, manifest, files };
}

async function listAssetTree(assetRoot) {
  const files = new Set();
  const directories = new Set();
  async function visit(current, prefix) {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const name = entry.name;
      if (!name || name === '.' || name === '..' || name.includes('\0') || name.includes('/')) {
        fail('UNSAFE_RESTORE_PATH');
      }
      const relativePath = prefix ? `${prefix}/${name}` : name;
      if (entry.isSymbolicLink()) fail('ASSET_RESTORE_SYMLINK', relativePath);
      if (entry.isDirectory()) {
        directories.add(relativePath);
        await visit(path.join(current, name), relativePath);
      } else if (entry.isFile()) {
        files.add(relativePath);
      } else {
        fail('ASSET_RESTORE_NOT_REGULAR', relativePath);
      }
    }
  }
  await visit(assetRoot, '');
  return { files, directories };
}

function expectedDirectories(files) {
  const directories = new Set();
  for (const file of files) {
    const parts = file.targetPath.split('/');
    parts.pop();
    for (let index = 1; index <= parts.length; index += 1) directories.add(parts.slice(0, index).join('/'));
  }
  return directories;
}

/**
 * Verify an existing restore staging directory without copying, activating,
 * rewriting references, or mutating the directory.
 *
 * `destinationRoot` is the canonical option name. `restoreRoot` is accepted as
 * a compatibility alias for callers that describe the same staging directory.
 */
async function verifyRestoredAssetBundle({ destinationRoot, restoreRoot, expectedRestoreManifestDigest } = {}) {
  const rootInput = destinationRoot ?? restoreRoot;
  if (typeof rootInput !== 'string' || !rootInput || rootInput.includes('\0')) fail('INVALID_ASSET_RESTORE_ROOT');
  validateDigest(expectedRestoreManifestDigest, 'INVALID_EXPECTED_RESTORE_MANIFEST_DIGEST');
  const rootStat = await fs.lstat(rootInput);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) fail('ASSET_RESTORE_ROOT_NOT_DIRECTORY');
  const root = await fs.realpath(rootInput);
  try {
    await fs.lstat(path.join(root, INCOMPLETE));
    fail('INCOMPLETE_ASSET_RESTORE');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const entries = await fs.readdir(root, { withFileTypes: true });
  const names = entries.map(entry => entry.name).sort();
  if (names.join(',') !== 'assets,restore.json') fail('UNEXPECTED_ASSET_RESTORE_ENTRY');
  const assetEntry = entries.find(entry => entry.name === 'assets');
  if (!assetEntry || assetEntry.isSymbolicLink() || !assetEntry.isDirectory()) fail('ASSET_RESTORE_ASSETS_NOT_DIRECTORY');
  const assetRoot = path.join(root, 'assets');
  const { manifestBytes, manifest, files } = await readRestoreManifest(root);
  const restoreManifestDigest = digest(manifestBytes);
  if (restoreManifestDigest !== expectedRestoreManifestDigest) fail('ASSET_RESTORE_MANIFEST_MISMATCH');

  const expectedFiles = new Set(files.map(file => file.targetPath));
  const expectedDirs = expectedDirectories(files);
  for (const file of files) {
    const parts = file.targetPath.split('/');
    parts.pop();
    for (let index = 1; index <= parts.length; index += 1) {
      if (expectedFiles.has(parts.slice(0, index).join('/'))) fail('ASSET_RESTORE_PATH_CONFLICT');
    }
  }
  const actual = await listAssetTree(assetRoot);
  if (actual.files.size !== expectedFiles.size || [...expectedFiles].some(file => !actual.files.has(file))) {
    fail('ASSET_RESTORE_FILE_SET_MISMATCH');
  }
  if (actual.directories.size !== expectedDirs.size || [...expectedDirs].some(dir => !actual.directories.has(dir))) {
    fail('ASSET_RESTORE_DIRECTORY_SET_MISMATCH');
  }

  for (const file of files) {
    const bytes = await readStableFile(assetRoot, file.targetPath, {
      maximum: MAX_FILE_BYTES,
      tooLargeCode: 'ASSET_FILE_TOO_LARGE',
      changedCode: 'ASSET_RESTORE_CHANGED',
      location: file.targetPath,
    });
    if (bytes.length !== file.bytes || digest(bytes) !== file.sha256) fail('ASSET_RESTORE_HASH_MISMATCH', file.targetPath);
  }
  const proofFiles = files.map(file => Object.freeze({ ...file }));
  const proof = Object.freeze({
    destinationRoot: root,
    assetRoot,
    bundleManifestDigest: manifest.bundleManifestDigest,
    restoreManifestDigest,
    files: Object.freeze(proofFiles),
    activated: false,
  });
  PROOFS.add(proof);
  return proof;
}

/** Restores only an explicitly captured subset. Does not rewrite DB references or activate assets. */
async function restoreAssetBundle({ bundleRoot, expectedManifestDigest, destinationRoot, bindings } = {}) {
  if (typeof expectedManifestDigest !== 'string' || !/^[a-f0-9]{64}$/.test(expectedManifestDigest)
      || typeof destinationRoot !== 'string' || !destinationRoot || destinationRoot.includes('\0')
      || !Array.isArray(bindings) || bindings.length > MAX_FILES) fail('INVALID_ASSET_RESTORE_INPUT');
  const supplied = structuredClone(bindings);
  const bundle = await verifyAssetBundle(bundleRoot);
  if (bundle.manifestDigest !== expectedManifestDigest) fail('ASSET_RESTORE_MANIFEST_MISMATCH');
  const mapping = new Map();
  const targets = new Set();
  for (const binding of supplied) {
    if (!binding || Array.isArray(binding) || Object.keys(binding).sort().join(',') !== 'sourcePath,targetPath') fail('INVALID_ASSET_RESTORE_BINDING');
    const source = relative(binding.sourcePath);
    const target = relative(binding.targetPath);
    if (mapping.has(source) || targets.has(target)) fail('DUPLICATE_ASSET_RESTORE_BINDING');
    mapping.set(source, target);
    targets.add(target);
  }
  if (mapping.size !== bundle.files.length || bundle.files.some(entry => !mapping.has(entry.sourcePath))) fail('INCOMPLETE_ASSET_RESTORE_BINDINGS');
  for (const target of targets) {
    const parts = target.split('/');
    parts.pop();
    while (parts.length) {
      if (targets.has(parts.join('/'))) fail('ASSET_RESTORE_PATH_CONFLICT');
      parts.pop();
    }
  }
  const destination = path.resolve(destinationRoot);
  try {
    await fs.mkdir(destination, { mode: 0o700 });
  } catch (error) {
    if (error.code === 'EEXIST') fail('ASSET_RESTORE_DESTINATION_EXISTS');
    throw error;
  }
  await exclusive(path.join(destination, INCOMPLETE), Buffer.from('Restore incomplete. Do not activate this directory.\n'));
  const assets = path.join(destination, 'assets');
  await fs.mkdir(assets, { mode: 0o700 });
  const directories = new Set([assets]);
  const files = [];
  for (const entry of bundle.files) {
    const targetPath = mapping.get(entry.sourcePath);
    const parts = targetPath.split('/');
    let parent = assets;
    for (const part of parts.slice(0, -1)) {
      parent = path.join(parent, part);
      if (!directories.has(parent)) {
        await fs.mkdir(parent, { mode: 0o700 });
        directories.add(parent);
      }
    }
    const bytes = await readStableFile(bundle.bundleRoot, entry.bundlePath, {
      maximum: MAX_FILE_BYTES,
      tooLargeCode: 'ASSET_FILE_TOO_LARGE',
      changedCode: 'ASSET_BUNDLE_CHANGED',
      location: entry.bundlePath,
    });
    if (bytes.length !== entry.bytes || digest(bytes) !== entry.sha256) fail('ASSET_BUNDLE_CHANGED');
    await exclusive(path.join(assets, targetPath), bytes);
    files.push({ sourcePath: entry.sourcePath, targetPath, bytes: entry.bytes, sha256: entry.sha256 });
  }
  const manifest = { format: RESTORE_FORMAT, complete: true, bundleManifestDigest: bundle.manifestDigest, files };
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  if (bytes.length > MAX_MANIFEST_BYTES) fail('ASSET_RESTORE_MANIFEST_BYTES_LIMIT');
  await exclusive(path.join(destination, RESTORE_MANIFEST), bytes);
  await fs.unlink(path.join(destination, INCOMPLETE));
  const proof = Object.freeze({
    destinationRoot: destination,
    assetRoot: assets,
    bundleManifestDigest: bundle.manifestDigest,
    restoreManifestDigest: digest(bytes),
    files: Object.freeze(files.map(Object.freeze)),
    activated: false,
  });
  PROOFS.add(proof);
  return proof;
}

function isAssetRestoreProof(value) {
  return PROOFS.has(value);
}

module.exports = { restoreAssetBundle, verifyRestoredAssetBundle, isAssetRestoreProof };
