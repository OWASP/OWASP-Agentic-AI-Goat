'use strict';
// Controlled API and oracle checks only. No PostgreSQL, browser, model, or fixture seeding.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const support = require('./adminStudentDeletionArtifactSupport');
const ROOT = path.resolve(__dirname, '../..');

function runtime(t) {
  const run = fs.mkdtempSync(path.join(ROOT, 'tasks/qualification/run-artifact-support-'));
  const owned = path.join(run, 'runtime');
  fs.mkdirSync(owned, { mode: 0o700 });
  t.after(() => fs.rmSync(run, { recursive: true, force: false }));
  return owned;
}
function person(id) { return { id, sessionId: id + 1000, token: `controlled-${id}` }; }
function positiveSnapshot() {
  const rag = [0, 1, 2].map(n => ({ documentId: `doc-${n}`, sourceSha256: `source-${n}`,
    chunkManifestSha256: `manifest-${n}`, hasSource: true, vectors: 1, retired: false }));
  const one = { rag, ipiEmail: [{ artifactId: 'email', hasBody: true, retired: false }],
    ipiRun: [{ runId: 'ipi-run', ownerKey: '["IndirectEmail","10"]', generation: '0' }],
    finflowBackups: [{ backupId: 'backup', contentSha256: 'backup-digest',
      status: 'ready', scrubbed: false, filePresent: true }],
    finflowTraversal: [{ targetToken: 'traversal', state: 'active', directoryPresent: true }],
    legacyUpload: [{ intentId: 'intent', state: 'published', fileSha256: 'content' }],
    runGeneration: [{ ownerKey: '["MCP","10"]', generation: '0' }] };
  return { version: 1, target: structuredClone(one), sibling: structuredClone(one) };
}
function cleaned(before) {
  const after = structuredClone(before);
  after.target.rag = after.target.rag.map(row => ({ ...row, hasSource: false, vectors: 0, retired: true }));
  after.target.ipiEmail = [];
  after.target.finflowBackups = [{ ...after.target.finflowBackups[0], status: 'retired', scrubbed: true,
    filePresent: false }];
  after.target.finflowTraversal = [{ ...after.target.finflowTraversal[0], state: 'retired', directoryPresent: false }];
  after.target.legacyUpload = [{ intentId: 'intent', state: 'retired' }];
  after.target.runGeneration[0].generation = '1';
  return after;
}

test('owned artifact root is exact repository runtime; import remains inert', t => {
  const owned = runtime(t);
  assert.equal(support.assertRuntimeRoot(owned), owned);
  assert.throws(() => support.assertRuntimeRoot(ROOT), { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
  assert.throws(() => support.assertRuntimeRoot('/tmp/run-foreign/runtime'),
    { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
  const alias = path.join(path.dirname(owned), 'alias');
  fs.symlinkSync(owned, alias);
  assert.throws(() => support.assertRuntimeRoot(alias), { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
});

test('seed preflight rejects missing real authorities before production import or mutation', async t => {
  const scopeRoot = runtime(t);
  const previous = process.env.PG_TEST_DISPOSABLE;
  process.env.PG_TEST_DISPOSABLE = 'yes';
  t.after(() => { if (previous === undefined) delete process.env.PG_TEST_DISPOSABLE;
    else process.env.PG_TEST_DISPOSABLE = previous; });
  const input = { scopeRoot, target: person(10), sibling: person(20), pools: {},
    ledger: {}, ragComposition: {}, recordStage: async () => {} };
  await assert.rejects(support.seedDeletionArtifacts(input),
    { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
  await assert.rejects(support.seedDeletionArtifacts({ ...input, sibling: person(10) }),
    /Distinct target and sibling/);
  assert.throws(() => support.startHeldTargetLease({ ledger: {}, targetId: 10 }),
    { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
});

test('redacted target cleanup oracle retains immutable lineage and exact sibling bytes', () => {
  const before = positiveSnapshot(), after = cleaned(before);
  assert.deepEqual(support.assertDeletionArtifacts(before, after), {
    targetArtifactsCleaned: true, immutableEvidenceRetained: true,
    siblingArtifactsPreserved: true, modelCreditClaimed: false, fullDeletionClaimed: false });
  for (const change of [
    value => { value.sibling.rag[0].sourceSha256 = 'tampered'; },
    value => { value.target.rag[0].sourceSha256 = 'tampered'; },
    value => { value.target.rag[0].hasSource = true; },
    value => { value.target.ipiEmail = [{ artifactId: 'email', hasBody: true, retired: false }]; },
    value => { value.target.ipiRun = []; },
    value => { value.target.ipiRun[0].runId = 'wrong-run'; },
    value => { value.target.finflowBackups[0].filePresent = true; },
    value => { value.target.finflowBackups[0].contentSha256 = 'wrong-digest'; },
    value => { value.target.finflowTraversal[0].directoryPresent = true; },
    value => { value.target.legacyUpload[0].intentId = 'substituted'; },
    value => { value.target.runGeneration[0].generation = '0'; },
    value => { value.target.rag.pop(); },
  ]) {
    const altered = structuredClone(after);
    change(altered);
    assert.throws(() => support.assertDeletionArtifacts(before, altered));
  }
  const missing = positiveSnapshot();
  missing.target.ipiEmail = [];
  assert.throws(() => support.assertDeletionArtifacts(missing, after),
    { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
});

test('empty-owner cleanup rejects an unjournaled or aliased path', async () => {
  await assert.rejects(support.cleanupEmptyLegacyOwnerDirs([]),
    { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
  await assert.rejects(support.cleanupEmptyLegacyOwnerDirs([
    { version: 1, phase: 'reserved', kind: 'legacyUpload', ownerId: 10, ownerDirectory: '/foreign/10' },
    { version: 1, phase: 'reserved', kind: 'legacyUpload', ownerId: 20,
      ownerDirectory: path.join(ROOT, 'server/uploads/managed/20') },
  ]), { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
});

function reservedOwners() {
  return [10, 20].map(ownerId => ({ version: 1, phase: 'reserved', kind: 'legacyUpload',
    ownerId, ownerDirectory: path.join(ROOT, 'server/uploads/managed', String(ownerId)) }));
}

test('missing managed root after verified ancestors is a no-artifact cleanup, not an error', async t => {
  const managedRoot = path.join(ROOT, 'server/uploads/managed');
  const originalLstat = fsp.lstat.bind(fsp);
  t.mock.method(fsp, 'lstat', async file => {
    if (file === managedRoot) throw Object.assign(new Error('absent'), { code: 'ENOENT' });
    return originalLstat(file);
  });
  const remove = t.mock.method(fsp, 'rmdir', async () => { throw Error('No removal permitted'); });
  const result = await support.cleanupEmptyLegacyOwnerDirs(reservedOwners());
  assert.deepEqual(result, { emptyOwnerDirectoriesRemoved: [], artifactContentCleanupClaimed: false });
  assert.equal(remove.mock.callCount(), 0);
});

test('missing pre-managed ancestor and aliased managed root still fail closed', async t => {
  const uploadsRoot = path.join(ROOT, 'server/uploads');
  const managedRoot = path.join(uploadsRoot, 'managed');
  const originalLstat = fsp.lstat.bind(fsp);
  const missing = t.mock.method(fsp, 'lstat', async file => {
    if (file === uploadsRoot) throw Object.assign(new Error('absent'), { code: 'ENOENT' });
    return originalLstat(file);
  });
  const remove = t.mock.method(fsp, 'rmdir', async () => { throw Error('No removal permitted'); });
  await assert.rejects(support.cleanupEmptyLegacyOwnerDirs(reservedOwners()), { code: 'ENOENT' });
  missing.mock.restore();
  t.mock.method(fsp, 'lstat', async file => {
    if (file === managedRoot) return { isDirectory: () => true, isSymbolicLink: () => true,
      uid: typeof process.getuid === 'function' ? process.getuid() : 0 };
    return originalLstat(file);
  });
  await assert.rejects(support.cleanupEmptyLegacyOwnerDirs(reservedOwners()),
    { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
  assert.equal(remove.mock.callCount(), 0);
});

test('actual FinFlow root shape projects only admitted ready-journal fields', t => {
  const scopeRoot = runtime(t);
  const { controlledRoots } = require('../../server/services/finflowDurableResourceComposition');
  const roots = controlledRoots({ appDataRoot: scopeRoot, env: {} });
  assert.deepEqual(Object.keys(roots).sort(), ['appDataRoot', 'backupRoot', 'traversalRoot']);
  assert.deepEqual(support.finflowRootsReadyStage(roots, scopeRoot), {
    phase: 'ready', kind: 'finflowRoots',
    backupRoot: path.join(scopeRoot, 'finflow-backups'),
    traversalRoot: path.join(scopeRoot, 'finflow-traversal-targets'),
  });
  assert.throws(() => support.finflowRootsReadyStage({ ...roots,
    backupRoot: path.join(scopeRoot, 'wrong-backup-root') }, scopeRoot),
  { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
});

test('production FinFlow backup token resolves to its exact controlled artifact path', async t => {
  const scopeRoot = runtime(t);
  const { createFinflowDurableResources, createFinflowBackupFileStore } =
    require('../../server/services/finflowDurableResources');
  const files = createFinflowBackupFileStore({ root: path.join(scopeRoot, 'finflow-backups') });
  let reserved;
  const repository = Object.fromEntries(['readDataset', 'deleteDataset', 'readBackup', 'listBackups',
    'recordBackupRead', 'beginRetirement', 'completeRetirement', 'readRetirement']
    .map(name => [name, async () => { throw Error(`Unexpected ${name}`); }]));
  repository.reserveBackup = async value => {
    reserved = { ...value, records: value.initialRecords, datasetRevision: 0, status: 'writing' };
    return reserved;
  };
  repository.commitBackup = async value => ({ ...value, status: 'ready' });
  const resources = createFinflowDurableResources({ repository, files, initialRecords: [{ id: 1 }] });
  const runId = '10000000-0000-4000-8000-000000000001';
  const execution = { ownerKey: '["FinFlow","10"]', durableGeneration: 0, runId,
    async check() {}, async effect(_key, work) { return work(); } };
  const receipt = await resources.createBackup({ scope: { ownerId: 10, generation: 0 },
    execution, backupName: 'controlled' });
  assert.equal(receipt.metadata.backupId, reserved.backupId);
  assert.match(reserved.fileToken, /^[a-f0-9]{8}-[a-f0-9]{4}-5[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  const file = support.finflowBackupPath(scopeRoot, reserved.fileToken);
  assert.equal(file, path.join(scopeRoot, 'finflow-backups', 'artifacts', reserved.fileToken, 'artifact.bak'));
  assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
    receipt.metadata.contentSha256);
  for (const token of ['../../escape', 'not-a-uuid', '10000000-0000-9000-8000-000000000001']) {
    assert.throws(() => support.finflowBackupPath(scopeRoot, token),
      { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
  }
});

test('pre-write legacy journal binds exact owned path and content on partial seed failure', async t => {
  const owned = runtime(t);
  const uploadRoot = path.join(owned, 'legacy-upload-root');
  const ownerDirectory = path.join(uploadRoot, 'managed', '10');
  const intentId = '11111111-1111-4111-8111-111111111111';
  const leaseDirectory = path.join(ownerDirectory, intentId);
  fs.mkdirSync(leaseDirectory, { recursive: true, mode: 0o700 });
  const journal = [];
  const failure = new Error('controlled bind failure');
  const lifecycle = { uploadRoot, runUpload: async (_owner, callback) => callback({
    intentId, directory: leaseDirectory,
    bindFilename: async () => { throw failure; },
  }) };
  await assert.rejects(support.seedLegacy(person(10), lifecycle, undefined, async stage => {
    journal.push(stage);
    if (stage.phase === 'admitted') assert.equal(fs.existsSync(stage.filePath), false);
  }), error => error === failure);
  const admitted = journal.find(stage => stage.phase === 'admitted');
  assert(admitted);
  assert.equal(admitted.ownerId, 10);
  assert.equal(admitted.intentId, intentId);
  assert.equal(admitted.ownerDirectory, ownerDirectory);
  assert.equal(admitted.filePath, path.join(leaseDirectory, 'deletion-owned.txt'));
  assert.match(admitted.contentSha256, /^[a-f0-9]{64}$/);
  assert.equal(createHash('sha256').update(fs.readFileSync(admitted.filePath)).digest('hex'),
    admitted.contentSha256);
  assert.equal(journal.some(stage => stage.phase === 'bound'), false);
});

test('all four controlled seed runs pass the caller signal and bounded timeout', () => {
  const controller = new AbortController();
  const options = support.runOptions(controller.signal);
  assert.equal(options.signal, controller.signal);
  assert.equal(options.timeoutMs, 120000);
  const source = fs.readFileSync(path.join(__dirname, 'adminStudentDeletionArtifactSupport.js'), 'utf8');
  assert.equal((source.match(/\.run\(String\(person\.id\), runOptions\(signal\)/g) || []).length, 4);
  controller.abort(new Error('controlled cancellation'));
  assert.throws(() => support.runOptions(controller.signal), /controlled cancellation/);
  assert.throws(() => support.runOptions(undefined, 300000),
    { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' });
});

test('held target lease abort settles without a caller release', async () => {
  const ledger = { async begin() { return { durableGeneration: '0' }; },
    async assertCurrent() {}, async finish() {} };
  const controller = new AbortController();
  const held = support.startHeldTargetLease({ ledger, targetId: 10, signal: controller.signal,
    timeoutMs: 1000 });
  assert.equal((await held.started).ownerKey, '["MCP","10"]');
  controller.abort(new Error('controlled midflight abort'));
  const outcome = await held.settled;
  assert.equal(outcome.error?.name, 'AbortError');
  held.release();
});

test('empty-owner cleanup code rechecks every canonical ancestor before rmdir', () => {
  const source = fs.readFileSync(path.join(__dirname, 'adminStudentDeletionArtifactSupport.js'), 'utf8');
  const cleanup = source.slice(source.indexOf('async function cleanupEmptyLegacyOwnerDirs'),
    source.indexOf('function assertSeeded'));
  assert.match(cleanup, /ROOT, path\.join\(ROOT, 'server'\), path\.join\(ROOT, 'server\/uploads'\)/);
  assert.match(cleanup, /const managedRoot = path\.join\(ROOT, 'server\/uploads\/managed'\)/);
  assert.match(cleanup, /managedRoot, expected/);
  assert.match(cleanup, /stat\.isSymbolicLink\(\) \|\| await fsp\.realpath\(directory\) !== directory/);
  assert.match(cleanup, /stat\.uid !== process\.getuid\(\)/);
  assert.match(cleanup, /await fsp\.rmdir\(expected\)/);
  assert.doesNotMatch(cleanup, /rm\(expected.*recursive/);
});
