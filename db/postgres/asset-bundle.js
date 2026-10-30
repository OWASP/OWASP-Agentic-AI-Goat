'use strict';

const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const VERSION = 1;
const FORMAT = 'owasp-ai-goat-asset-bundle-v1';
const INCOMPLETE = 'INCOMPLETE';
const MANIFEST = 'manifest.json';
const FILES_DIR = 'files';
const MARKER = 'Asset bundle is incomplete until manifest.json is written. Never import a partial bundle.\n';
const QUIESCENCE_POLICY = 'Caller must quiesce the explicit source files for the duration of capture; this bundle does not claim full symlink-race immunity.';
const MAX_FILES = 10_000;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const PROOFS = new WeakSet();
const ALLOWED_MANIFEST_KEYS = ['complete', 'consistency', 'files', 'format', 'version'];
const ALLOWED_ENTRY_KEYS = ['bundlePath', 'bytes', 'sha256', 'sourcePath'];
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW;
const WRITE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;

function fail(code, location) {
  const error = new Error(code);
  error.code = code;
  if (location) error.location = location;
  throw error;
}

function keys(value) {
  return Object.keys(value).sort().join(',');
}

function exactKeys(value, expected, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || keys(value) !== [...expected].sort().join(',')) fail(code);
}

function digest(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function validateRelativePath(value, location = 'relativePath') {
  if (typeof value !== 'string' || !value || value.includes('\0') || value.includes('\\')
      || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)
      || /^[A-Za-z]:/.test(value)) fail('UNSAFE_ASSET_PATH', location);
  const parts = value.split('/');
  if (parts.some(part => !part || part === '.' || part === '..')) fail('UNSAFE_ASSET_PATH', location);
  return value;
}

function bundlePath(index) {
  return `${FILES_DIR}/${String(index).padStart(8, '0')}.bin`;
}

function validateDigest(value, code = 'INVALID_ASSET_HASH') {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail(code);
  return value;
}

function validateBytes(value, code = 'INVALID_ASSET_BYTES', maximum = MAX_FILE_BYTES, tooLargeCode = 'ASSET_FILE_TOO_LARGE') {
  if (!Number.isSafeInteger(value) || value < 0) fail(code);
  if (value > maximum) fail(tooLargeCode);
  return value;
}

function sameStat(before, after) {
  return ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].every(field => before[field] === after[field]);
}

async function lstatRegular(root, relativePath, location) {
  const parts = relativePath.split('/');
  let current = root;
  let finalStat;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    let stat;
    try {
      stat = await fs.lstat(current);
    } catch (error) {
      if (error.code === 'ENOENT') fail('ASSET_SOURCE_MISSING', location);
      throw error;
    }
    if (stat.isSymbolicLink()) fail('ASSET_SOURCE_SYMLINK', location);
    if (index < parts.length - 1 && !stat.isDirectory()) fail('ASSET_SOURCE_PARENT_NOT_DIRECTORY', location);
    if (index === parts.length - 1 && !stat.isFile()) fail('ASSET_SOURCE_NOT_REGULAR', location);
    finalStat = stat;
  }
  return finalStat;
}

async function openSource(root, relativePath, location) {
  const absolute = path.join(root, ...relativePath.split('/'));
  const expected = await lstatRegular(root, relativePath, location);
  const handle = await fs.open(absolute, READ_FLAGS);
  if (!sameStat(expected, await handle.stat())) {
    await handle.close();
    fail('ASSET_SOURCE_CHANGED', location);
  }
  return handle;
}

// Allocate only the validated original size plus one sentinel byte. A writer
// growing the file cannot make FileHandle.readFile allocate beyond the limit.
async function readBounded(handle, size) {
  const buffer = Buffer.alloc(size + 1);
  let length = 0;
  while (length < buffer.length) {
    const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length);
    if (!bytesRead) break;
    length += bytesRead;
  }
  return buffer.subarray(0, length);
}

async function readSourceWithExpected(root, relativePath, location, priorBytes = 0, expected) {
  const handle = await openSource(root, relativePath, location);
  try {
    const before = await handle.stat();
    if (!before.isFile()) fail('ASSET_SOURCE_NOT_REGULAR', location);
    if (expected && !sameStat(expected, before)) fail('ASSET_SOURCE_CHANGED', location);
    validateBytes(before.size, 'INVALID_ASSET_BYTES');
    if (priorBytes + before.size > MAX_TOTAL_BYTES) fail('ASSET_TOTAL_BYTES_LIMIT');
    const bytes = await readBounded(handle, before.size);
    const after = await handle.stat();
    if (!sameStat(before, after) || after.size !== bytes.length) fail('ASSET_SOURCE_CHANGED', location);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function sourceMetadata(root, relativePath, location) {
  const handle = await openSource(root, relativePath, location);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) fail('ASSET_SOURCE_NOT_REGULAR', location);
    validateBytes(stat.size, 'INVALID_ASSET_BYTES');
    return stat;
  } finally {
    await handle.close();
  }
}

async function createPrivateDirectory(destinationRoot) {
  if (typeof destinationRoot !== 'string' || !destinationRoot || destinationRoot.includes('\0')) fail('INVALID_ASSET_DESTINATION');
  const absolute = path.resolve(destinationRoot);
  try {
    await fs.mkdir(absolute, { mode: 0o700 });
  } catch (error) {
    if (error.code === 'EEXIST') fail('ASSET_DESTINATION_EXISTS');
    throw error;
  }
  return absolute;
}

async function writeExclusive(file, content, mode = 0o600) {
  const handle = await fs.open(file, WRITE_FLAGS, mode);
  try {
    await handle.writeFile(content);
  } finally {
    await handle.close();
  }
}

async function captureAssetBundle({ sourceRoot, relativePaths, destinationRoot } = {}) {
  if (typeof sourceRoot !== 'string' || !sourceRoot || sourceRoot.includes('\0') || !Array.isArray(relativePaths) || typeof destinationRoot !== 'string') fail('INVALID_ASSET_CAPTURE_INPUT');
  const sourceStat = await fs.lstat(sourceRoot);
  if (sourceStat.isSymbolicLink() || !sourceStat.isDirectory()) fail('ASSET_SOURCE_ROOT_NOT_DIRECTORY');
  const root = await fs.realpath(sourceRoot);
  if (relativePaths.length > MAX_FILES) fail('ASSET_FILE_COUNT_LIMIT');
  const seen = new Set();
  const paths = [];
  for (let index = 0; index < relativePaths.length; index += 1) {
    if (!Object.hasOwn(relativePaths, index)) fail('INVALID_ASSET_PATH', `relativePaths[${index}]`);
    const value = relativePaths[index];
    const normalized = validateRelativePath(value, `relativePaths[${index}]`);
    if (seen.has(normalized)) fail('DUPLICATE_ASSET_REFERENCE', normalized);
    seen.add(normalized);
    paths.push(normalized);
  }
  paths.sort();
  const metadata = [];
  let plannedBytes = 0;
  for (const relativePath of paths) {
    const stat = await sourceMetadata(root, relativePath, `relativePaths.${relativePath}`);
    plannedBytes += stat.size;
    if (plannedBytes > MAX_TOTAL_BYTES) fail('ASSET_TOTAL_BYTES_LIMIT');
    metadata.push(stat);
  }

  const destination = await createPrivateDirectory(destinationRoot);
  await writeExclusive(path.join(destination, INCOMPLETE), MARKER);
  await fs.mkdir(path.join(destination, FILES_DIR), { mode: 0o700 });
  const files = [];
  let totalBytes = 0;
  for (let index = 0; index < paths.length; index += 1) {
    const relativePath = paths[index];
    const bytes = await readSourceWithExpected(root, relativePath, `relativePaths.${relativePath}`, totalBytes, metadata[index]);
    totalBytes += bytes.length;
    if (totalBytes > MAX_TOTAL_BYTES) fail('ASSET_TOTAL_BYTES_LIMIT');
    const target = bundlePath(index);
    await writeExclusive(path.join(destination, target), bytes);
    files.push({ sourcePath: relativePath, bundlePath: target, bytes: bytes.length, sha256: digest(bytes) });
  }
  const manifest = {
    version: VERSION,
    format: FORMAT,
    complete: true,
    consistency: QUIESCENCE_POLICY,
    files,
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  if (manifestBytes.length > MAX_MANIFEST_BYTES) fail('ASSET_MANIFEST_BYTES_LIMIT');
  await writeExclusive(path.join(destination, MANIFEST), manifestBytes);
  await fs.unlink(path.join(destination, INCOMPLETE));
  return verifyAssetBundle(destination);
}

async function readBundleFile(root, relativePath, location, maximum) {
  validateRelativePath(relativePath, location);
  const handle = await fs.open(path.join(root, ...relativePath.split('/')), READ_FLAGS);
  try {
    const before = await handle.stat();
    if (!before.isFile()) fail('ASSET_BUNDLE_FILE_NOT_REGULAR', location);
    validateBytes(before.size, 'INVALID_ASSET_BYTES', maximum, maximum === MAX_MANIFEST_BYTES ? 'ASSET_MANIFEST_BYTES_LIMIT' : 'ASSET_FILE_TOO_LARGE');
    const bytes = await readBounded(handle, before.size);
    const after = await handle.stat();
    if (!sameStat(before, after) || after.size !== bytes.length) fail('ASSET_BUNDLE_CHANGED', location);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function verifyAssetBundle(bundleRoot) {
  if (typeof bundleRoot !== 'string' || !bundleRoot || bundleRoot.includes('\0')) fail('INVALID_ASSET_BUNDLE_ROOT');
  const rootStat = await fs.lstat(bundleRoot);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) fail('ASSET_BUNDLE_ROOT_NOT_DIRECTORY');
  const root = await fs.realpath(bundleRoot);
  try {
    await fs.lstat(path.join(root, INCOMPLETE));
    fail('INCOMPLETE_ASSET_BUNDLE');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const manifestBytes = await readBundleFile(root, MANIFEST, MANIFEST, MAX_MANIFEST_BYTES);
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString('utf8')); } catch { fail('INVALID_ASSET_MANIFEST'); }
  exactKeys(manifest, ALLOWED_MANIFEST_KEYS, 'UNKNOWN_ASSET_MANIFEST_FIELDS');
  if (manifest.version !== VERSION || manifest.format !== FORMAT || manifest.complete !== true || manifest.consistency !== QUIESCENCE_POLICY || !Array.isArray(manifest.files)) fail('INVALID_ASSET_MANIFEST');
  if (manifest.files.length > MAX_FILES) fail('ASSET_FILE_COUNT_LIMIT');
  const names = await fs.readdir(root, { withFileTypes: true });
  const rootNames = names.map(entry => entry.name).sort();
  if (rootNames.join(',') !== `${FILES_DIR},${MANIFEST}`) fail('UNEXPECTED_ASSET_BUNDLE_ENTRY');
  const filesEntry = names.find(entry => entry.name === FILES_DIR);
  if (!filesEntry || filesEntry.isSymbolicLink() || !filesEntry.isDirectory()) fail('ASSET_BUNDLE_FILES_NOT_DIRECTORY');
  const entries = await fs.readdir(path.join(root, FILES_DIR), { withFileTypes: true });
  const expectedNames = [];
  const files = [];
  const seenSources = new Set();
  let totalBytes = 0;
  for (let index = 0; index < manifest.files.length; index += 1) {
    const entry = manifest.files[index];
    exactKeys(entry, ALLOWED_ENTRY_KEYS, 'UNKNOWN_ASSET_ENTRY_FIELDS');
    const sourcePath = validateRelativePath(entry.sourcePath, `files[${index}].sourcePath`);
    if (seenSources.has(sourcePath)) fail('DUPLICATE_ASSET_REFERENCE', sourcePath);
    seenSources.add(sourcePath);
    const expectedPath = bundlePath(index);
    if (entry.bundlePath !== expectedPath) fail('NONDETERMINISTIC_ASSET_BUNDLE_PATH', `files[${index}].bundlePath`);
    validateBytes(entry.bytes);
    validateDigest(entry.sha256);
    totalBytes += entry.bytes;
    if (totalBytes > MAX_TOTAL_BYTES) fail('ASSET_TOTAL_BYTES_LIMIT');
    expectedNames.push(path.basename(expectedPath));
    files.push({ sourcePath, bundlePath: expectedPath, bytes: entry.bytes, sha256: entry.sha256 });
  }
  const actualNames = entries.map(entry => {
    if (entry.isSymbolicLink() || !entry.isFile()) fail('UNEXPECTED_ASSET_BUNDLE_ENTRY', entry.name);
    return entry.name;
  }).sort();
  if (actualNames.join(',') !== expectedNames.sort().join(',')) fail('UNEXPECTED_ASSET_BUNDLE_ENTRY');
  for (const entry of files) {
    const bundleBytes = await readBundleFile(root, entry.bundlePath, entry.bundlePath, MAX_FILE_BYTES);
    if (bundleBytes.length !== entry.bytes || digest(bundleBytes) !== entry.sha256) fail('ASSET_BUNDLE_HASH_MISMATCH', entry.bundlePath);
  }
  const canonical = Buffer.from(`${JSON.stringify({ version: manifest.version, format: manifest.format, complete: manifest.complete, consistency: manifest.consistency, files }, null, 2)}\n`, 'utf8');
  if (!canonical.equals(manifestBytes)) fail('NONCANONICAL_ASSET_MANIFEST');
  const proofFiles = files.map(file => Object.freeze(file));
  const proof = { version: VERSION, bundleRoot: root, manifestDigest: digest(manifestBytes), files: proofFiles };
  Object.freeze(proofFiles);
  Object.freeze(proof);
  PROOFS.add(proof);
  return proof;
}

function isAssetBundleProof(value) {
  return PROOFS.has(value);
}

module.exports = {
  FORMAT, QUIESCENCE_POLICY, MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_MANIFEST_BYTES,
  captureAssetBundle, verifyAssetBundle, isAssetBundleProof,
  readBounded,
};
