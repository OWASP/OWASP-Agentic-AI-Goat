'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { captureAssetBundle } = require('../db/postgres/asset-bundle');
const {
  planFixedTreeAssets,
  dryRunFixedTreeAssets,
  applyFixedTreeAssets,
  verifyFixedTreeAssetReceipt,
  argumentsFor,
  runCli,
} = require('../db/postgres/fixed-tree-assets');

async function write(root, relativePath, value) {
  const target = path.join(root, ...relativePath.split('/'));
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, value);
}

async function fixture(relativePaths = [
  ['server/uploads/report.txt', 'source-report'],
  ['server/sensitive_files/config/secret.txt', 'source-secret'],
]) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-fixed-tree-'));
  const source = path.join(root, 'source');
  const oldInstall = path.join(root, 'old-install');
  const candidate = path.join(root, 'candidate');
  await Promise.all([fs.mkdir(source), fs.mkdir(oldInstall), fs.mkdir(candidate)]);
  for (const [name, value] of relativePaths) {
    await write(source, name, value);
    await write(oldInstall, name, `old:${value}`);
  }
  const bundleRoot = path.join(root, 'bundle');
  const bundle = await captureAssetBundle({
    sourceRoot: source,
    relativePaths: relativePaths.map(([name]) => name),
    destinationRoot: bundleRoot,
  });
  return { root, source, oldInstall, candidate, bundleRoot, bundle };
}

function reviewFor(plan, actions = {}) {
  return {
    format: plan.format,
    bundleManifestDigest: plan.bundleManifestDigest,
    candidateStateDigest: plan.candidateStateDigest,
    includeFinflow: plan.includeFinflow,
    decisions: plan.decisions.map(item => ({ ...item, action: actions[item.path] || item.action })),
  };
}

function options(state, extra = {}) {
  return {
    bundleRoot: state.bundleRoot,
    expectedManifestDigest: state.bundle.manifestDigest,
    candidateRoot: state.candidate,
    candidateStopped: true,
    candidateIsStaged: true,
    ...extra,
  };
}

test('plan binds missing, identical, and differing collision decisions to hashes', async t => {
  const state = await fixture();
  t.after(() => fs.rm(state.root, { recursive: true, force: true }));
  await write(state.candidate, 'server/uploads/report.txt', 'different');
  await write(state.candidate, 'server/sensitive_files/config/secret.txt', 'source-secret');

  const plan = await planFixedTreeAssets(options(state));
  assert.deepEqual(plan.decisions.map(({ path: name, action }) => [name, action]), [
    ['server/sensitive_files/config/secret.txt', 'keep_identical'],
    ['server/uploads/report.txt', 'review_required'],
  ]);
  assert.equal(plan.report.requiresReview, true);
  assert.deepEqual(plan.review, reviewFor(plan));
  const keep = reviewFor(plan, { 'server/uploads/report.txt': 'keep_candidate' });
  assert.equal((await dryRunFixedTreeAssets({ ...options(state), review: keep })).reviewValidated, true);
  assert.equal(await fs.readFile(path.join(state.candidate, 'server/uploads/report.txt'), 'utf8'), 'different');
  await assert.rejects(
    applyFixedTreeAssets({ ...options(state), review: reviewFor(plan), operationRoot: path.join(state.root, 'operation') }),
    { code: 'FIXED_TREE_COLLISION_REVIEW_REQUIRED' },
  );
  await assert.rejects(fs.lstat(path.join(state.root, 'operation')), { code: 'ENOENT' });
  assert.equal(await fs.readFile(path.join(state.candidate, 'server/uploads/report.txt'), 'utf8'), 'different');
});

test('reviewed apply copies exact bytes into staged candidate and emits a private inactive receipt', async t => {
  const state = await fixture();
  t.after(() => fs.rm(state.root, { recursive: true, force: true }));
  await write(state.candidate, 'server/uploads/report.txt', 'different');
  const oldBefore = await fs.readFile(path.join(state.oldInstall, 'server/uploads/report.txt'));
  const sourceBefore = await fs.readFile(path.join(state.source, 'server/uploads/report.txt'));
  const plan = await planFixedTreeAssets(options(state));
  const operationRoot = path.join(state.root, 'operation');
  const receipt = await applyFixedTreeAssets({
    ...options(state),
    review: reviewFor(plan, { 'server/uploads/report.txt': 'replace_with_bundle' }),
    operationRoot,
  });

  assert.equal(await fs.readFile(path.join(state.candidate, 'server/uploads/report.txt'), 'utf8'), 'source-report');
  assert.equal(await fs.readFile(path.join(state.candidate, 'server/sensitive_files/config/secret.txt'), 'utf8'), 'source-secret');
  assert.deepEqual(await fs.readFile(path.join(state.oldInstall, 'server/uploads/report.txt')), oldBefore);
  assert.deepEqual(await fs.readFile(path.join(state.source, 'server/uploads/report.txt')), sourceBefore);
  assert.equal(receipt.applicationActivated, false);
  assert.equal(receipt.crossFileAtomic, false);
  assert.equal(receipt.candidateFilesInstalled, true);
  assert.equal((await fs.stat(receipt.receiptPath)).mode & 0o777, 0o600);
  await assert.rejects(fs.lstat(path.join(operationRoot, 'COPY_INCOMPLETE')), { code: 'ENOENT' });
  const verified = await verifyFixedTreeAssetReceipt({
    candidateRoot: state.candidate,
    operationRoot,
    expectedReceiptDigest: receipt.receiptDigest,
  });
  assert.equal(verified.complete, true);
  await fs.writeFile(path.join(state.candidate, 'server/uploads/report.txt'), 'post-receipt-tamper');
  await assert.rejects(verifyFixedTreeAssetReceipt({
    candidateRoot: state.candidate,
    operationRoot,
    expectedReceiptDigest: receipt.receiptDigest,
  }), { code: 'FIXED_TREE_DESTINATION_HASH_MISMATCH' });
});

test('dry run and candidate hash mismatch never write', async t => {
  const state = await fixture();
  t.after(() => fs.rm(state.root, { recursive: true, force: true }));
  const plan = await planFixedTreeAssets(options(state));
  const review = reviewFor(plan);
  const before = JSON.stringify(review);
  const result = await dryRunFixedTreeAssets({ ...options(state), review });
  assert.equal(result.dryRun, true);
  assert.equal(result.writes, false);
  assert.equal(JSON.stringify(review), before);

  await write(state.candidate, 'server/uploads/report.txt', 'arrived-after-review');
  await assert.rejects(
    applyFixedTreeAssets({ ...options(state), review, operationRoot: path.join(state.root, 'operation') }),
    { code: 'FIXED_TREE_REVIEW_MISMATCH' },
  );
  await assert.rejects(fs.lstat(path.join(state.root, 'operation')), { code: 'ENOENT' });
});

test('bundle corruption fails before an operation or candidate write', async t => {
  const state = await fixture();
  t.after(() => fs.rm(state.root, { recursive: true, force: true }));
  const plan = await planFixedTreeAssets(options(state));
  const bundleFile = state.bundle.files.find(item => item.sourcePath === 'server/uploads/report.txt');
  await fs.writeFile(path.join(state.bundleRoot, bundleFile.bundlePath), 'tampered');
  await assert.rejects(
    applyFixedTreeAssets({
      ...options(state), review: reviewFor(plan), operationRoot: path.join(state.root, 'operation'),
    }),
    { code: 'ASSET_BUNDLE_HASH_MISMATCH' },
  );
  await assert.rejects(fs.lstat(path.join(state.root, 'operation')), { code: 'ENOENT' });
  await assert.rejects(fs.lstat(path.join(state.candidate, 'server/uploads/report.txt')), { code: 'ENOENT' });
});

test('mid-copy failure remains explicitly inactive and leaves source and old installation untouched', async t => {
  const state = await fixture();
  t.after(() => fs.rm(state.root, { recursive: true, force: true }));
  const plan = await planFixedTreeAssets(options(state));
  const operationRoot = path.join(state.root, 'operation');
  const oldSnapshot = await Promise.all(plan.decisions.map(item => fs.readFile(path.join(state.oldInstall, ...item.path.split('/')))));
  await assert.rejects(
    applyFixedTreeAssets({
      ...options(state), review: reviewFor(plan), operationRoot,
      beforeWrite({ index }) { if (index === 1) throw Object.assign(new Error('injected'), { code: 'INJECTED_COPY_FAILURE' }); },
    }),
    { code: 'INJECTED_COPY_FAILURE' },
  );
  assert.match(await fs.readFile(path.join(operationRoot, 'COPY_INCOMPLETE'), 'utf8'), /must not be activated/);
  await assert.rejects(fs.lstat(path.join(operationRoot, 'fixed-tree-receipt.json')), { code: 'ENOENT' });
  for (let index = 0; index < plan.decisions.length; index += 1) {
    assert.deepEqual(await fs.readFile(path.join(state.oldInstall, ...plan.decisions[index].path.split('/'))), oldSnapshot[index]);
  }
});

test('allowlist rejects SecureShop, arbitrary paths, symlinks, and FinFlow without opt in', async t => {
  for (const name of ['server/uploads/secureshop', 'server/uploads/secureshop/a.png', 'server/config/other.env', 'outside.txt']) {
    const state = await fixture([[name, 'x']]);
    t.after(() => fs.rm(state.root, { recursive: true, force: true }));
    await assert.rejects(planFixedTreeAssets(options(state)), { code: 'FIXED_TREE_PATH_NOT_ALLOWED' });
  }
  const finflow = await fixture([['server/workshop_data/documents/a.txt', 'x'], ['server/config/server.conf', 'y']]);
  t.after(() => fs.rm(finflow.root, { recursive: true, force: true }));
  await assert.rejects(planFixedTreeAssets(options(finflow)), { code: 'FIXED_TREE_PATH_NOT_ALLOWED' });
  const accepted = await planFixedTreeAssets(options(finflow, { includeFinflow: true }));
  assert.equal(accepted.decisions.length, 2);

  const linked = await fixture();
  t.after(() => fs.rm(linked.root, { recursive: true, force: true }));
  await fs.mkdir(path.join(linked.candidate, 'server'), { recursive: true });
  await fs.symlink(linked.source, path.join(linked.candidate, 'server/uploads'));
  await assert.rejects(planFixedTreeAssets(options(linked)), { code: 'FIXED_TREE_CANDIDATE_SYMLINK' });
});

test('bundle, candidate, and operation roots must remain disjoint', async t => {
  const state = await fixture();
  t.after(() => fs.rm(state.root, { recursive: true, force: true }));
  const plan = await planFixedTreeAssets(options(state));
  await assert.rejects(applyFixedTreeAssets({
    ...options(state), review: reviewFor(plan), operationRoot: path.join(state.candidate, 'operation'),
  }), { code: 'FIXED_TREE_ROOTS_OVERLAP' });

  const nestedSource = path.join(state.root, 'nested-source');
  const nestedCandidate = path.join(state.root, 'nested-candidate');
  await Promise.all([fs.mkdir(nestedSource), fs.mkdir(nestedCandidate)]);
  await write(nestedSource, 'server/uploads/a.txt', 'a');
  const nestedBundle = await captureAssetBundle({
    sourceRoot: nestedSource,
    relativePaths: ['server/uploads/a.txt'],
    destinationRoot: path.join(nestedCandidate, 'bundle'),
  });
  await assert.rejects(planFixedTreeAssets({
    bundleRoot: nestedBundle.bundleRoot,
    expectedManifestDigest: nestedBundle.manifestDigest,
    candidateRoot: nestedCandidate,
    candidateStopped: true,
    candidateIsStaged: true,
  }), { code: 'FIXED_TREE_ROOTS_OVERLAP' });
});

test('CLI parser accepts the documented flags and rejects unknown arguments', () => {
  assert.deepEqual(argumentsFor([
    '--bundle', '/bundle', '--manifest-digest', 'a'.repeat(64), '--candidate', '/candidate',
    '--candidate-stopped', '--candidate-is-staged', '--include-finflow', '--review', '/review.json',
    '--apply', '--operation-root', '/operation',
  ]), {
    bundle: '/bundle', 'manifest-digest': 'a'.repeat(64), candidate: '/candidate',
    'candidate-stopped': true, 'candidate-is-staged': true, 'include-finflow': true,
    review: '/review.json', apply: true, 'operation-root': '/operation',
  });
  assert.throws(() => argumentsFor(['--unknown']), { code: 'INVALID_FIXED_TREE_ARGUMENTS' });
  assert.throws(() => argumentsFor(['--apply', '--apply']), { code: 'INVALID_FIXED_TREE_ARGUMENTS' });
});

test('candidate and review reads are bounded and reject symlinks', async t => {
  const state = await fixture();
  t.after(() => fs.rm(state.root, { recursive: true, force: true }));
  const target = path.join(state.candidate, 'server/uploads/report.txt');
  await fs.mkdir(path.dirname(target), { recursive: true });
  const handle = await fs.open(target, 'w');
  await handle.truncate(64 * 1024 * 1024 + 1);
  await handle.close();
  await assert.rejects(planFixedTreeAssets(options(state)), { code: 'FIXED_TREE_FILE_TOO_LARGE' });

  await fs.rm(state.candidate, { recursive: true });
  await fs.mkdir(state.candidate);
  const plan = await planFixedTreeAssets(options(state));
  const reviewPath = path.join(state.root, 'review.json');
  const reviewLink = path.join(state.root, 'review-link.json');
  await fs.writeFile(reviewPath, JSON.stringify(reviewFor(plan)));
  await fs.symlink(reviewPath, reviewLink);
  const argv = [
    '--bundle', state.bundleRoot, '--manifest-digest', state.bundle.manifestDigest,
    '--candidate', state.candidate, '--candidate-stopped', '--candidate-is-staged', '--review', reviewLink,
  ];
  await assert.rejects(runCli(argv, { stdout: { write() {} } }), { code: 'FIXED_TREE_REVIEW_SYMLINK' });

  const oversized = path.join(state.root, 'oversized-review.json');
  const oversizedHandle = await fs.open(oversized, 'w');
  await oversizedHandle.truncate(4 * 1024 * 1024 + 1);
  await oversizedHandle.close();
  argv[argv.length - 1] = oversized;
  await assert.rejects(runCli(argv, { stdout: { write() {} } }), { code: 'FIXED_TREE_REVIEW_TOO_LARGE' });
});
