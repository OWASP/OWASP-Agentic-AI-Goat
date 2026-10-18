'use strict';

const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { createHash, randomBytes } = require('node:crypto');
const { verifyAssetBundle, MAX_FILE_BYTES, readBounded } = require('./asset-bundle');
const { restoreAssetBundle, verifyRestoredAssetBundle } = require('./restore-asset-bundle');

const REVIEW_FORMAT = 'dvaia-fixed-tree-asset-review-v1';
const RECEIPT_FORMAT = 'dvaia-fixed-tree-asset-receipt-v1';
const MARKER = 'COPY_INCOMPLETE';
const RECEIPT = 'fixed-tree-receipt.json';
const RECEIPT_KEYS = ['applicationActivated', 'bundleManifestDigest', 'candidateFilesInstalled', 'candidateStateDigest', 'complete', 'crossFileAtomic', 'files', 'format', 'includeFinflow', 'restoreManifestDigest'];
const RECEIPT_FILE_KEYS = ['action', 'bytes', 'path', 'sha256'];
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW;
const WRITE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;

function fail(code, location) {
  const error = new Error(code);
  error.code = code;
  if (location) error.location = location;
  throw error;
}

function hash(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonical(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function exactKeys(value, expected, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) fail(code);
}

function validatePath(value) {
  if (typeof value !== 'string' || !value || value.includes('\0') || value.includes('\\')
      || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)
      || value.split('/').some(part => !part || part === '.' || part === '..')) fail('UNSAFE_FIXED_TREE_PATH', value);
  const allowed = value.startsWith('server/uploads/')
      && value !== 'server/uploads/secureshop'
      && !value.startsWith('server/uploads/secureshop/')
    || value.startsWith('server/sensitive_files/');
  return { value, allowed };
}

function isFinflowPath(value) {
  return value.startsWith('server/workshop_data/documents/')
    || value.startsWith('server/workshop_data/transactions/')
    || value === 'server/config/secrets.env'
    || value === 'server/config/server.conf';
}

function assertAllowed(value, includeFinflow) {
  const checked = validatePath(value);
  if (!checked.allowed && !(includeFinflow === true && isFinflowPath(value))) fail('FIXED_TREE_PATH_NOT_ALLOWED', value);
  return value;
}

function sameStat(left, right) {
  return ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].every(field => left[field] === right[field]);
}

async function assertRoot(input) {
  if (typeof input !== 'string' || !input || input.includes('\0')) fail('INVALID_FIXED_TREE_CANDIDATE');
  const stat = await fs.lstat(input);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail('FIXED_TREE_CANDIDATE_NOT_DIRECTORY');
  return fs.realpath(input);
}

function pathsOverlap(left, right) {
  return left === right || left.startsWith(`${right}${path.sep}`) || right.startsWith(`${left}${path.sep}`);
}

async function prospectiveRealPath(input) {
  if (typeof input !== 'string' || !input || input.includes('\0')) fail('INVALID_FIXED_TREE_OPERATION_ROOT');
  let current = path.resolve(input);
  const missing = [];
  while (true) {
    try {
      await fs.lstat(current);
      const resolved = await fs.realpath(current);
      return path.join(resolved, ...missing.reverse());
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const parent = path.dirname(current);
      if (parent === current) throw error;
      missing.push(path.basename(current));
      current = parent;
    }
  }
}

async function inspectTarget(root, relativePath) {
  const parts = relativePath.split('/');
  let current = root;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    let stat;
    try { stat = await fs.lstat(current); } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
    if (stat.isSymbolicLink()) fail('FIXED_TREE_CANDIDATE_SYMLINK', relativePath);
    if (index < parts.length - 1) {
      if (!stat.isDirectory()) fail('FIXED_TREE_CANDIDATE_PARENT_NOT_DIRECTORY', relativePath);
      continue;
    }
    if (!stat.isFile()) fail('FIXED_TREE_CANDIDATE_NOT_REGULAR', relativePath);
    if (!Number.isSafeInteger(stat.size) || stat.size > MAX_FILE_BYTES) fail('FIXED_TREE_FILE_TOO_LARGE', relativePath);
    const handle = await fs.open(current, READ_FLAGS);
    try {
      const before = await handle.stat();
      if (!sameStat(stat, before)) fail('FIXED_TREE_CANDIDATE_CHANGED', relativePath);
      const bytes = await readBounded(handle, before.size);
      const after = await handle.stat();
      if (bytes.length !== before.size || !sameStat(before, after)) fail('FIXED_TREE_CANDIDATE_CHANGED', relativePath);
      return { sha256: hash(bytes), bytes: bytes.length };
    } finally { await handle.close(); }
  }
  return null;
}

function stateFor(bundle, entries, includeFinflow) {
  return {
    format: REVIEW_FORMAT,
    bundleManifestDigest: bundle.manifestDigest,
    includeFinflow,
    files: entries.map(entry => ({
      path: entry.path,
      sourceSha256: entry.sourceSha256,
      sourceBytes: entry.sourceBytes,
      candidateSha256: entry.candidateSha256,
      candidateBytes: entry.candidateBytes,
    })),
  };
}

async function planFixedTreeAssets({
  bundleRoot, expectedManifestDigest, candidateRoot, candidateStopped, candidateIsStaged, includeFinflow = false,
} = {}) {
  if (candidateStopped !== true) fail('FIXED_TREE_CANDIDATE_NOT_STOPPED');
  if (candidateIsStaged !== true) fail('FIXED_TREE_CANDIDATE_NOT_STAGED');
  if (typeof expectedManifestDigest !== 'string' || !/^[a-f0-9]{64}$/.test(expectedManifestDigest)) fail('INVALID_EXPECTED_ASSET_MANIFEST_DIGEST');
  if (typeof includeFinflow !== 'boolean') fail('INVALID_FIXED_TREE_FINFLOW_OPTION');
  const [bundle, candidate] = await Promise.all([verifyAssetBundle(bundleRoot), assertRoot(candidateRoot)]);
  if (bundle.manifestDigest !== expectedManifestDigest) fail('ASSET_BUNDLE_MANIFEST_MISMATCH');
  if (pathsOverlap(bundle.bundleRoot, candidate)) fail('FIXED_TREE_ROOTS_OVERLAP');
  const entries = [];
  for (const source of bundle.files) {
    const relativePath = assertAllowed(source.sourcePath, includeFinflow);
    const current = await inspectTarget(candidate, relativePath);
    entries.push({
      path: relativePath,
      sourceSha256: source.sha256,
      sourceBytes: source.bytes,
      candidateSha256: current?.sha256 ?? null,
      candidateBytes: current?.bytes ?? null,
    });
  }
  entries.sort((a, b) => a.path.localeCompare(b.path));
  const candidateStateDigest = hash(canonical(stateFor(bundle, entries, includeFinflow)));
  const decisions = entries.map(entry => ({
    path: entry.path,
    sourceSha256: entry.sourceSha256,
    candidateSha256: entry.candidateSha256,
    action: entry.candidateSha256 === null ? 'install'
      : entry.candidateSha256 === entry.sourceSha256 ? 'keep_identical' : 'review_required',
  }));
  const frozenDecisions = Object.freeze(decisions.map(item => Object.freeze({ ...item })));
  const review = Object.freeze({
    format: REVIEW_FORMAT,
    bundleManifestDigest: bundle.manifestDigest,
    candidateStateDigest,
    includeFinflow,
    decisions: frozenDecisions,
  });
  return Object.freeze({
    ...review,
    review,
    candidateRoot: candidate,
    report: Object.freeze({
      files: decisions.length,
      missing: decisions.filter(item => item.action === 'install').length,
      identical: decisions.filter(item => item.action === 'keep_identical').length,
      collisions: decisions.filter(item => item.action === 'review_required').length,
      requiresReview: decisions.some(item => item.action === 'review_required'),
      writes: false,
      applicationActivated: false,
    }),
  });
}

function validateFixedTreeAssetReview(plan, review) {
  exactKeys(review, ['format', 'bundleManifestDigest', 'candidateStateDigest', 'includeFinflow', 'decisions'], 'INVALID_FIXED_TREE_REVIEW');
  if (review.format !== REVIEW_FORMAT
      || review.bundleManifestDigest !== plan.bundleManifestDigest
      || review.candidateStateDigest !== plan.candidateStateDigest
      || review.includeFinflow !== plan.includeFinflow
      || !Array.isArray(review.decisions)
      || review.decisions.length !== plan.decisions.length) fail('FIXED_TREE_REVIEW_MISMATCH');
  const expected = new Map(plan.decisions.map(item => [item.path, item]));
  const seen = new Set();
  const decisions = review.decisions.map(item => {
    exactKeys(item, ['path', 'sourceSha256', 'candidateSha256', 'action'], 'INVALID_FIXED_TREE_DECISION');
    const original = expected.get(item.path);
    if (!original || seen.has(item.path) || item.sourceSha256 !== original.sourceSha256
        || item.candidateSha256 !== original.candidateSha256) fail('FIXED_TREE_REVIEW_MISMATCH');
    seen.add(item.path);
    const allowed = original.candidateSha256 === null ? ['install']
      : original.candidateSha256 === original.sourceSha256 ? ['keep_identical']
        : ['replace_with_bundle', 'keep_candidate'];
    if (!allowed.includes(item.action)) fail('FIXED_TREE_COLLISION_REVIEW_REQUIRED', item.path);
    return { ...item };
  }).sort((a, b) => a.path.localeCompare(b.path));
  if (seen.size !== expected.size) fail('FIXED_TREE_REVIEW_MISMATCH');
  return Object.freeze({ ...review, decisions: Object.freeze(decisions.map(Object.freeze)) });
}

async function mkdirParents(root, relativePath) {
  const parts = relativePath.split('/').slice(0, -1);
  let current = root;
  for (const part of parts) {
    current = path.join(current, part);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) fail('FIXED_TREE_CANDIDATE_PARENT_NOT_DIRECTORY', relativePath);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await fs.mkdir(current, { mode: 0o700 });
    }
  }
}

async function atomicWrite(root, relativePath, bytes) {
  await mkdirParents(root, relativePath);
  const target = path.join(root, ...relativePath.split('/'));
  const temporary = `${target}.dvaia-${randomBytes(8).toString('hex')}.tmp`;
  let handle;
  try {
    handle = await fs.open(temporary, WRITE_FLAGS, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, target);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

async function writeExclusive(file, bytes) {
  const handle = await fs.open(file, WRITE_FLAGS, 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}

async function readStablePath(root, relativePath, maximum, codes = {}) {
  const parts = relativePath.split('/');
  let current = root;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    const item = await fs.lstat(current);
    if (item.isSymbolicLink()) fail(codes.symlink || 'FIXED_TREE_SOURCE_SYMLINK', relativePath);
    if (index < parts.length - 1 && !item.isDirectory()) fail(codes.invalid || 'FIXED_TREE_SOURCE_NOT_REGULAR', relativePath);
    if (index === parts.length - 1 && !item.isFile()) fail(codes.invalid || 'FIXED_TREE_SOURCE_NOT_REGULAR', relativePath);
  }
  const stat = await fs.lstat(current);
  if (!Number.isSafeInteger(stat.size) || stat.size > maximum) fail(codes.tooLarge || 'FIXED_TREE_FILE_TOO_LARGE', relativePath);
  const handle = await fs.open(current, READ_FLAGS);
  try {
    const before = await handle.stat();
    if (!sameStat(stat, before)) fail(codes.changed || 'FIXED_TREE_SOURCE_CHANGED', relativePath);
    const bytes = await readBounded(handle, before.size);
    if (bytes.length !== before.size || !sameStat(before, await handle.stat())) fail(codes.changed || 'FIXED_TREE_SOURCE_CHANGED', relativePath);
    return bytes;
  } finally { await handle.close(); }
}

async function readReviewFile(input) {
  if (typeof input !== 'string' || !input || input.includes('\0')) fail('INVALID_FIXED_TREE_REVIEW');
  const absolute = path.resolve(input);
  const parent = await fs.realpath(path.dirname(absolute));
  return readStablePath(parent, path.basename(absolute), 4 * 1024 * 1024, {
    symlink: 'FIXED_TREE_REVIEW_SYMLINK',
    invalid: 'INVALID_FIXED_TREE_REVIEW',
    tooLarge: 'FIXED_TREE_REVIEW_TOO_LARGE',
    changed: 'FIXED_TREE_REVIEW_CHANGED',
  });
}

async function verifyFixedTreeAssetReceipt({ candidateRoot, operationRoot, expectedReceiptDigest } = {}) {
  if (typeof expectedReceiptDigest !== 'string' || !/^[a-f0-9]{64}$/.test(expectedReceiptDigest)) fail('INVALID_FIXED_TREE_RECEIPT_DIGEST');
  const [candidate, operation] = await Promise.all([assertRoot(candidateRoot), assertRoot(operationRoot)]);
  if (pathsOverlap(candidate, operation)) fail('FIXED_TREE_ROOTS_OVERLAP');
  try {
    await fs.lstat(path.join(operation, MARKER));
    fail('INCOMPLETE_FIXED_TREE_COPY');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const receiptPath = path.join(operation, RECEIPT);
  const stat = await fs.lstat(receiptPath);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 4 * 1024 * 1024) fail('INVALID_FIXED_TREE_RECEIPT');
  if ((stat.mode & 0o077) !== 0) fail('FIXED_TREE_RECEIPT_NOT_PRIVATE');
  const handle = await fs.open(receiptPath, READ_FLAGS);
  let bytes;
  try {
    const before = await handle.stat();
    bytes = await readBounded(handle, before.size);
    if (bytes.length !== before.size || !sameStat(before, await handle.stat())) fail('FIXED_TREE_RECEIPT_CHANGED');
  } finally { await handle.close(); }
  if (hash(bytes) !== expectedReceiptDigest) fail('FIXED_TREE_RECEIPT_DIGEST_MISMATCH');
  let receipt;
  try { receipt = JSON.parse(bytes.toString('utf8')); } catch { fail('INVALID_FIXED_TREE_RECEIPT'); }
  exactKeys(receipt, RECEIPT_KEYS, 'INVALID_FIXED_TREE_RECEIPT');
  if (receipt.format !== RECEIPT_FORMAT || receipt.complete !== true || receipt.candidateFilesInstalled !== true
      || receipt.applicationActivated !== false || receipt.crossFileAtomic !== false
      || typeof receipt.includeFinflow !== 'boolean' || !Array.isArray(receipt.files)) fail('INVALID_FIXED_TREE_RECEIPT');
  for (const key of ['bundleManifestDigest', 'candidateStateDigest', 'restoreManifestDigest']) {
    if (typeof receipt[key] !== 'string' || !/^[a-f0-9]{64}$/.test(receipt[key])) fail('INVALID_FIXED_TREE_RECEIPT');
  }
  const seen = new Set();
  let previous = null;
  for (const file of receipt.files) {
    exactKeys(file, RECEIPT_FILE_KEYS, 'INVALID_FIXED_TREE_RECEIPT_FILE');
    assertAllowed(file.path, receipt.includeFinflow);
    if (seen.has(file.path) || (previous !== null && previous.localeCompare(file.path) >= 0)
        || !['install', 'keep_identical', 'replace_with_bundle', 'keep_candidate'].includes(file.action)
        || typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256)
        || !Number.isSafeInteger(file.bytes) || file.bytes < 0 || file.bytes > MAX_FILE_BYTES) fail('INVALID_FIXED_TREE_RECEIPT_FILE');
    seen.add(file.path);
    previous = file.path;
    const current = await inspectTarget(candidate, file.path);
    if (!current || current.sha256 !== file.sha256 || current.bytes !== file.bytes) fail('FIXED_TREE_DESTINATION_HASH_MISMATCH', file.path);
  }
  if (!canonical(receipt).equals(bytes)) fail('NONCANONICAL_FIXED_TREE_RECEIPT');
  return Object.freeze({ ...receipt, receiptDigest: expectedReceiptDigest, candidateRoot: candidate, operationRoot: operation });
}

async function applyFixedTreeAssets(options = {}) {
  const plan = await planFixedTreeAssets(options);
  const review = validateFixedTreeAssetReview(plan, options.review);
  const operation = await prospectiveRealPath(options.operationRoot);
  const bundle = await fs.realpath(options.bundleRoot);
  if (pathsOverlap(operation, plan.candidateRoot) || pathsOverlap(operation, bundle)) fail('FIXED_TREE_ROOTS_OVERLAP');
  const bindings = review.decisions.map(item => ({ sourcePath: item.path, targetPath: item.path }));
  const restored = await restoreAssetBundle({
    bundleRoot: options.bundleRoot,
    expectedManifestDigest: plan.bundleManifestDigest,
    destinationRoot: operation,
    bindings,
  });
  await verifyRestoredAssetBundle({
    destinationRoot: restored.destinationRoot,
    expectedRestoreManifestDigest: restored.restoreManifestDigest,
  });
  await writeExclusive(path.join(restored.destinationRoot, MARKER), Buffer.from('Copy incomplete. The staged candidate must not be activated.\n'));
  const installed = [];
  let receiptPath;
  try {
    for (let index = 0; index < review.decisions.length; index += 1) {
      const decision = review.decisions[index];
      const current = await inspectTarget(plan.candidateRoot, decision.path);
      if ((current?.sha256 ?? null) !== decision.candidateSha256) fail('FIXED_TREE_CANDIDATE_CHANGED', decision.path);
      if (typeof options.beforeWrite === 'function') await options.beforeWrite({ index, decision: { ...decision } });
      if (decision.action === 'install' || decision.action === 'replace_with_bundle') {
        const bytes = await readStablePath(restored.assetRoot, decision.path, MAX_FILE_BYTES, {
          symlink: 'ASSET_RESTORE_SYMLINK',
          invalid: 'ASSET_RESTORE_NOT_REGULAR',
          tooLarge: 'ASSET_FILE_TOO_LARGE',
          changed: 'ASSET_RESTORE_CHANGED',
        });
        if (hash(bytes) !== decision.sourceSha256) fail('ASSET_RESTORE_CHANGED', decision.path);
        await atomicWrite(plan.candidateRoot, decision.path, bytes);
      }
      const final = await inspectTarget(plan.candidateRoot, decision.path);
      const expected = decision.action === 'keep_candidate' ? decision.candidateSha256 : decision.sourceSha256;
      if (!final || final.sha256 !== expected) fail('FIXED_TREE_DESTINATION_HASH_MISMATCH', decision.path);
      installed.push({ path: decision.path, action: decision.action, sha256: final.sha256, bytes: final.bytes });
    }
    const receipt = {
      format: RECEIPT_FORMAT,
      complete: true,
      bundleManifestDigest: plan.bundleManifestDigest,
      restoreManifestDigest: restored.restoreManifestDigest,
      candidateStateDigest: plan.candidateStateDigest,
      includeFinflow: plan.includeFinflow,
      files: installed,
      crossFileAtomic: false,
      candidateFilesInstalled: true,
      applicationActivated: false,
    };
    const receiptBytes = canonical(receipt);
    receiptPath = path.join(restored.destinationRoot, RECEIPT);
    await writeExclusive(receiptPath, receiptBytes);
    try {
      await fs.unlink(path.join(restored.destinationRoot, MARKER));
    } catch (error) {
      await fs.unlink(receiptPath).catch(() => {});
      receiptPath = null;
      throw error;
    }
    const receiptDigest = hash(receiptBytes);
    await verifyFixedTreeAssetReceipt({ candidateRoot: plan.candidateRoot, operationRoot: restored.destinationRoot, expectedReceiptDigest: receiptDigest });
    return { ...receipt, receiptDigest, receiptPath };
  } catch (error) {
    if (receiptPath) await fs.unlink(receiptPath).catch(() => {});
    try {
      await fs.lstat(path.join(restored.destinationRoot, MARKER));
    } catch (markerError) {
      if (markerError.code === 'ENOENT') {
        await writeExclusive(path.join(restored.destinationRoot, MARKER), Buffer.from('Copy incomplete. The staged candidate must not be activated.\n')).catch(() => {});
      }
    }
    error.operationRoot = restored.destinationRoot;
    throw error;
  }
}

async function dryRunFixedTreeAssets(options = {}) {
  const plan = await planFixedTreeAssets(options);
  validateFixedTreeAssetReview(plan, options.review);
  return { ...plan.report, dryRun: true, reviewValidated: true };
}

function argumentsFor(argv) {
  const values = {};
  const flags = new Set(['--candidate-stopped', '--candidate-is-staged', '--include-finflow', '--apply']);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (flags.has(token)) {
      if (Object.hasOwn(values, token.slice(2))) fail('INVALID_FIXED_TREE_ARGUMENTS');
      values[token.slice(2)] = true;
      continue;
    }
    if (!['--bundle', '--manifest-digest', '--candidate', '--review', '--operation-root'].includes(token)
        || index + 1 >= argv.length || argv[index + 1].startsWith('--')) fail('INVALID_FIXED_TREE_ARGUMENTS');
    const key = token.slice(2);
    if (Object.hasOwn(values, key)) fail('INVALID_FIXED_TREE_ARGUMENTS');
    values[key] = argv[++index];
  }
  return values;
}

async function runCli(argv = process.argv.slice(2), io = process) {
  const args = argumentsFor(argv);
  const options = {
    bundleRoot: args.bundle,
    expectedManifestDigest: args['manifest-digest'],
    candidateRoot: args.candidate,
    candidateStopped: args['candidate-stopped'],
    candidateIsStaged: args['candidate-is-staged'],
    includeFinflow: args['include-finflow'] === true,
  };
  let output;
  if (!args.review) {
    if (args.apply || args['operation-root']) fail('FIXED_TREE_REVIEW_REQUIRED');
    output = await planFixedTreeAssets(options);
  } else {
    const bytes = await readReviewFile(args.review);
    let review;
    try { review = JSON.parse(bytes.toString('utf8')); } catch { fail('INVALID_FIXED_TREE_REVIEW'); }
    if (args.apply) output = await applyFixedTreeAssets({ ...options, review, operationRoot: args['operation-root'] });
    else {
      if (args['operation-root']) fail('INVALID_FIXED_TREE_ARGUMENTS');
      output = await dryRunFixedTreeAssets({ ...options, review });
    }
  }
  io.stdout.write(canonical(output));
  return output;
}

if (require.main === module) {
  runCli().catch(error => {
    process.stderr.write(`${error.code || 'FIXED_TREE_ASSET_ERROR'}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  REVIEW_FORMAT,
  RECEIPT_FORMAT,
  planFixedTreeAssets,
  validateFixedTreeAssetReview,
  dryRunFixedTreeAssets,
  applyFixedTreeAssets,
  verifyFixedTreeAssetReceipt,
  argumentsFor,
  runCli,
};
