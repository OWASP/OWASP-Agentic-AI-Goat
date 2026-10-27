'use strict';
// Native fixture support only. Importing this file neither opens a pool nor creates files.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');

const ROOT = path.resolve(__dirname, '../..');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const FINFLOW_BACKUP_TOKEN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const sha256 = value => createHash('sha256').update(value).digest('hex');
const ownerKey = (family, id) => JSON.stringify([family, String(id)]);
const scopeNames = Object.freeze(['rag', 'ipiEmail', 'finflowBackup', 'finflowTraversal', 'legacyUpload', 'runGeneration']);

function fail(message) { throw Object.assign(new Error(message), { code: 'STUDENT_DELETION_ARTIFACT_UNSUPPORTED' }); }
function owner(value, label) {
  if (!Number.isSafeInteger(value?.id) || value.id < 1 || !Number.isSafeInteger(value.sessionId)
      || value.sessionId < 1 || typeof value.token !== 'string' || !value.token) fail(`${label} current platform session required`);
  return value;
}
function pool(value, label) {
  if (typeof value?.query !== 'function') fail(`${label} real PostgreSQL pool required`);
  return value;
}
function assertRuntimeRoot(scopeRoot) {
  if (typeof scopeRoot !== 'string' || !path.isAbsolute(scopeRoot)) fail('Absolute owned runtime root required');
  const expected = path.resolve(scopeRoot);
  const parent = path.dirname(expected);
  if (path.basename(expected) !== 'runtime' || path.dirname(parent) !== path.join(ROOT, 'tasks/qualification')
      || !/^run-[A-Za-z0-9_-]+$/.test(path.basename(parent))) fail('Runtime root must belong to one repository qualification run');
  for (const directory of [ROOT, path.join(ROOT, 'tasks'), path.join(ROOT, 'tasks/qualification'), parent, expected]) {
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || fs.realpathSync(directory) !== directory) fail('Noncanonical runtime ancestor');
    if ((directory === parent || directory === expected) && ((stat.mode & 0o077) !== 0
        || (typeof process.getuid === 'function' && stat.uid !== process.getuid())))
      fail('Owned private runtime directory required');
  }
  return expected;
}
function validateInput(input) {
  const runtimeRoot = assertRuntimeRoot(input?.scopeRoot); // before production imports
  if (process.env.PG_TEST_DISPOSABLE !== 'yes') fail('Disposable PostgreSQL authority required');
  const target = owner(input.target, 'Target'), sibling = owner(input.sibling, 'Sibling');
  if (target.id === sibling.id) fail('Distinct target and sibling required');
  const identityRuntime = pool(input.pools?.identity?.runtime, 'Identity runtime');
  const identityMigration = pool(input.pools?.identity?.migration, 'Identity migration');
  const finflowRuntime = pool(input.pools?.finflow?.runtime, 'FinFlow runtime');
  const finflowMigration = pool(input.pools?.finflow?.migration, 'FinFlow migration');
  if (typeof input.ledger?.invalidate !== 'function' || typeof input.ledger?.begin !== 'function') fail('Canonical run ledger required');
  if (typeof input.ragComposition?.resolveRequest !== 'function' || !input.ragComposition.isReady?.()) fail('Initialized durable RAG composition required');
  if (typeof input.recordStage !== 'function') fail('Durable artifact stage journal required');
  const uploadRoot = path.join(ROOT, 'server/uploads');
  const uploadStat = fs.lstatSync(uploadRoot);
  if (!uploadStat.isDirectory() || uploadStat.isSymbolicLink() || fs.realpathSync(uploadRoot) !== uploadRoot)
    fail('Canonical repository upload root required');
  const managedRoot = path.join(uploadRoot, 'managed');
  try {
    const managedStat = fs.lstatSync(managedRoot);
    if (!managedStat.isDirectory() || managedStat.isSymbolicLink() || fs.realpathSync(managedRoot) !== managedRoot)
      fail('Canonical managed upload root required');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  for (const person of [target, sibling]) {
    const ownerDirectory = path.join(managedRoot, String(person.id));
    try { fs.lstatSync(ownerDirectory); fail('Fresh synthetic upload owner required'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  if (path.resolve(process.env.DVAIA_APP_DATA_ROOT || '') !== runtimeRoot) fail('Production FinFlow application root must match fixture runtime');
  input.signal?.throwIfAborted();
  return { runtimeRoot, target, sibling, identityRuntime, identityMigration, finflowRuntime, finflowMigration };
}
function request(person) {
  return { user: { id: person.id }, identitySession: { id: person.sessionId },
    headers: { authorization: `Bearer ${person.token}` } };
}
function controlledCoordinator(family, ledger) {
  return require('../../server/agent-runtime/runCoordinator').createRunCoordinator({ family, ledger });
}
function runOptions(signal, timeoutMs = 120000) {
  if (signal !== undefined && (!signal || typeof signal.aborted !== 'boolean'
      || typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function'))
    fail('Valid artifact run abort signal required');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000)
    fail('Bounded artifact run required');
  signal?.throwIfAborted();
  return Object.freeze({ timeoutMs, ...(signal === undefined ? {} : { signal }) });
}
async function seedRag(person, composition, ledger, signal, recordStage) {
  const result = [];
  for (const [family, slot] of [['RAG', 'current'], ['CSRF', 'clean'], ['CSRF', 'poison']]) {
    signal?.throwIfAborted();
    const authority = await composition.resolveRequest(request(person));
    const documentId = randomUUID(), operationId = randomUUID();
    const body = `Owned deletion lifecycle document ${family}/${slot} ${documentId}. Exact durable source text.`;
    await recordStage({ phase: 'before', ownerId: person.id, kind: 'rag', family, slot, documentId, operationId });
    const receipt = await controlledCoordinator(family, ledger).run(String(person.id), runOptions(signal), async execution =>
      (await authority.bind(execution, { family, slot })).ingestAndSelect({ documentId, operationId,
        sourceBuffer: Buffer.from(body), filename: `${family.toLowerCase()}-${slot}.txt`,
        ingestionKind: slot === 'clean' ? 'canonical_clean' : slot === 'poison' ? 'poison_upload' : 'upload' }));
    assert.equal(receipt.documentId, documentId);
    await recordStage({ phase: 'after', ownerId: person.id, kind: 'rag', family, slot, documentId, operationId });
    result.push(Object.freeze({ documentId, family, slot, sourceSha256: sha256(body), operationId }));
  }
  return Object.freeze(result);
}
async function seedEmail(person, repository, ledger, signal, recordStage) {
  signal?.throwIfAborted();
  const artifactId = randomUUID(), body = `Owned deletion email ${artifactId}`;
  await recordStage({ phase: 'before', ownerId: person.id, kind: 'ipiEmail', artifactId });
  const [receipt] = await controlledCoordinator('IndirectEmail', ledger).run(String(person.id), runOptions(signal), execution =>
    repository.createMany({ ownerId: person.id, ownerKey: execution.ownerKey,
      generation: execution.durableGeneration, runId: execution.runId, artifacts: [{ artifactId,
        ingestionKind: 'manual_entry', provider: 'manual_entry', recipient: 'student@example.invalid',
        subject: 'Owned lifecycle fixture', body }] }));
  assert.equal(receipt.artifactId, artifactId);
  await recordStage({ phase: 'after', ownerId: person.id, kind: 'ipiEmail', artifactId,
    runId: receipt.runId, generation: receipt.generation });
  return Object.freeze({ artifactId, bodySha256: receipt.bodySha256, provider: receipt.provider,
    ingestionKind: receipt.ingestionKind, runId: receipt.runId, generation: receipt.generation });
}
async function seedFinflow(person, lifecycle, traversal, ledger, signal, recordStage) {
  signal?.throwIfAborted();
  const backupName = `owned-${randomUUID().slice(0,8)}`;
  await recordStage({ phase: 'before', ownerId: person.id, kind: 'finflow', backupName });
  const result = await controlledCoordinator('FinFlow', ledger).run(String(person.id), runOptions(signal), async execution => {
    const backup = await lifecycle.resources.createBackup({ scope: { ownerId: person.id,
      generation: Number(execution.durableGeneration) }, execution, backupName });
    const target = await traversal.manager.active(execution);
    return { backup, target, runId: execution.runId, generation: String(execution.durableGeneration) };
  });
  if (result.backup?.metadata?.kind !== 'backup_created' || result.target?.state !== 'active') fail('Canonical FinFlow artifacts not committed');
  await recordStage({ phase: 'after', ownerId: person.id, kind: 'finflow', backupName,
    backupId: result.backup.metadata.backupId, targetToken: result.target.targetToken });
  return Object.freeze({ backupId: result.backup.metadata.backupId,
    contentSha256: result.backup.metadata.contentSha256, fileToken: result.backup.metadata.fileToken || null,
    targetToken: result.target.targetToken, runId: result.runId, generation: result.generation });
}
async function seedLegacy(person, lifecycle, signal, recordStage) {
  signal?.throwIfAborted();
  const body = Buffer.from(`Owned managed legacy upload ${randomUUID()}\n`);
  const contentSha256 = sha256(body);
  await recordStage({ phase: 'before', ownerId: person.id, kind: 'legacyUpload',
    ownerDirectory: path.join(lifecycle.uploadRoot, 'managed', String(person.id)) });
  const result = await lifecycle.runUpload({ ownerId: person.id, sessionId: person.sessionId }, async lease => {
    signal?.throwIfAborted();
    const filename = 'deletion-owned.txt';
    await recordStage({ phase: 'admitted', ownerId: person.id, kind: 'legacyUpload', intentId: lease.intentId,
      ownerDirectory: path.join(lifecycle.uploadRoot, 'managed', String(person.id)),
      filePath: path.join(lease.directory, filename), contentSha256 });
    await fsp.writeFile(path.join(lease.directory, filename), body, { flag: 'wx', mode: 0o600 });
    await lease.bindFilename(filename);
    await recordStage({ phase: 'bound', ownerId: person.id, kind: 'legacyUpload', intentId: lease.intentId });
    return Object.freeze({ intentId: lease.intentId, relativeName: filename, contentSha256 });
  });
  await recordStage({ phase: 'published', ownerId: person.id, kind: 'legacyUpload', intentId: result.intentId });
  return result;
}
async function seedGeneration(person, ledger, signal, recordStage) {
  signal?.throwIfAborted();
  await recordStage({ phase: 'before', ownerId: person.id, kind: 'runGeneration', ownerKey: ownerKey('MCP', person.id) });
  const receipt = await controlledCoordinator('MCP', ledger).run(String(person.id), runOptions(signal), async execution =>
    ({ ownerKey: execution.ownerKey, runId: execution.runId,
      generation: String(execution.durableGeneration) }));
  if (receipt.ownerKey !== ownerKey('MCP', person.id)) fail('Canonical run owner mismatch');
  await recordStage({ phase: 'after', ownerId: person.id, kind: 'runGeneration', ...receipt });
  return Object.freeze(receipt);
}

function finflowRootsReadyStage(roots, runtimeRoot) {
  const backupRoot = path.join(runtimeRoot, 'finflow-backups');
  const traversalRoot = path.join(runtimeRoot, 'finflow-traversal-targets');
  if (roots?.backupRoot !== backupRoot || roots?.traversalRoot !== traversalRoot ||
      roots?.appDataRoot !== runtimeRoot) fail('Canonical FinFlow roots required');
  return Object.freeze({ phase: 'ready', kind: 'finflowRoots', backupRoot, traversalRoot });
}

function finflowBackupPath(scopeRoot, fileToken) {
  if (!FINFLOW_BACKUP_TOKEN.test(fileToken || '')) fail('FinFlow backup file token invalid');
  return path.join(scopeRoot, 'finflow-backups', 'artifacts', fileToken, 'artifact.bak');
}

async function seedDeletionArtifacts(input) {
  const c = validateInput(input);
  const journal = [];
  const recordStage = async value => {
    const entry = Object.freeze({ version: 1, ...value });
    await input.recordStage(entry);
    journal.push(entry);
  };
  const cleanupEmptyOwnerDirs = () => cleanupEmptyLegacyOwnerDirs(journal);
  try {
  for (const person of [c.target, c.sibling]) await recordStage({ phase: 'reserved', ownerId: person.id,
    kind: 'legacyUpload', ownerDirectory: path.join(ROOT, 'server/uploads/managed', String(person.id)) });
  const legacy = require('../../server/services/legacyUploadLifecycle').getLegacyUploadLifecycle();
  if (legacy.uploadRoot !== path.join(ROOT, 'server/uploads') || typeof legacy.runUpload !== 'function')
    fail('Canonical production managed upload lifecycle required');
  const { createEmailArtifactRepository } = require('../../server/database/postgres/emailArtifactRepository');
  const { createFinflowDurableResourceLifecycle } = require('../../server/services/finflowDurableResourceComposition');
  const { createFinflowDeletionTraversal } = require('../../server/services/studentDeletionProduction');
  const email = createEmailArtifactRepository(c.identityRuntime); await email.assertReady();
  await recordStage({ phase: 'before', kind: 'finflowRoots',
    backupRoot: path.join(c.runtimeRoot, 'finflow-backups'),
    traversalRoot: path.join(c.runtimeRoot, 'finflow-traversal-targets') });
  const finflow = await createFinflowDurableResourceLifecycle({ pool: c.finflowRuntime, appDataRoot: c.runtimeRoot });
  const traversal = await createFinflowDeletionTraversal({ pool: c.finflowRuntime, root: finflow.roots.traversalRoot });
  await recordStage(finflowRootsReadyStage(finflow.roots, c.runtimeRoot));
  const refs = {};
  for (const [label, person] of [['target', c.target], ['sibling', c.sibling]]) {
    input.signal?.throwIfAborted();
    refs[label] = Object.freeze({ ownerId: person.id,
      rag: await seedRag(person, input.ragComposition, input.ledger, input.signal, recordStage),
      ipiEmail: await seedEmail(person, email, input.ledger, input.signal, recordStage),
      finflow: await seedFinflow(person, finflow, traversal, input.ledger, input.signal, recordStage),
      legacyUpload: await seedLegacy(person, legacy, input.signal, recordStage),
      runGeneration: await seedGeneration(person, input.ledger, input.signal, recordStage) });
  }
  const immutable = Object.freeze({ version: 1, scope: 'controlled lifecycle artifact support; no model or objective credit',
    supportedScopes: scopeNames, target: refs.target, sibling: refs.sibling });
  const observed = await readDeletionArtifacts({ pools: input.pools, refs: immutable, scopeRoot: c.runtimeRoot });
  assertSeeded(immutable, observed);
  return Object.freeze({ refs: immutable, before: observed, journal: Object.freeze(journal),
    cleanupEmptyOwnerDirs, authorities: Object.freeze({ finflow, traversal }), modelCalled: false,
    objectiveCreditClaimed: false });
  } catch (error) {
    if (error && typeof error === 'object') {
      error.artifactJournal = Object.freeze([...journal]);
      error.cleanupEmptyOwnerDirs = cleanupEmptyOwnerDirs;
    }
    throw error;
  }
}

async function cleanupEmptyLegacyOwnerDirs(journal) {
  if (!Array.isArray(journal)) fail('Recorded owner-directory journal required');
  const reserved = journal.filter(entry => entry?.version === 1 && entry.kind === 'legacyUpload'
    && entry.phase === 'reserved');
  if (reserved.length !== 2 || reserved[0].ownerId === reserved[1].ownerId) fail('Exact two reserved upload owners required');
  const removed = [];
  for (const entry of reserved) {
    if (!Number.isSafeInteger(entry.ownerId) || entry.ownerId < 1 || entry.ownerId > 2147483647)
      fail('Reserved upload owner invalid');
    const expected = path.join(ROOT, 'server/uploads/managed', String(entry.ownerId));
    if (entry.ownerDirectory !== expected) fail('Reserved upload directory mismatch');
    try {
      let ownerMissing = false;
      const managedRoot = path.join(ROOT, 'server/uploads/managed');
      for (const directory of [ROOT, path.join(ROOT, 'server'), path.join(ROOT, 'server/uploads'),
        managedRoot, expected]) {
        let stat;
        try { stat = await fsp.lstat(directory); }
        catch (error) {
          // A seed that failed before the legacy lifecycle ran may not have
          // created managed/ at all. Existing ancestors were already checked.
          if (error.code === 'ENOENT' && (directory === managedRoot || directory === expected)) {
            ownerMissing = true; break;
          }
          throw error;
        }
        if (!stat.isDirectory() || stat.isSymbolicLink() || await fsp.realpath(directory) !== directory
            || (typeof process.getuid === 'function' && stat.uid !== process.getuid()))
          fail('Owned upload ancestor is unsafe');
      }
      if (ownerMissing) continue;
      await fsp.rmdir(expected); // only an empty directory; never recursive or an existing sibling
      removed.push(expected);
    } catch (error) { if (error.code !== 'ENOTEMPTY') throw error; }
  }
  return Object.freeze({ emptyOwnerDirectoriesRemoved: Object.freeze(removed),
    artifactContentCleanupClaimed: false });
}

function assertSeeded(refs, observed) {
  for (const label of ['target', 'sibling']) {
    const row = observed[label];
    if (row.rag.length !== 3 || row.ipiEmail.length !== 1 || row.ipiRun.length !== 1 || row.finflowBackups.length !== 1
        || row.finflowTraversal.length !== 1 || row.legacyUpload.length !== 1 || row.runGeneration.length !== 1)
      fail(`${label} durable artifact seed incomplete`);
    if (row.rag.some(value => value.hasSource !== true || value.vectors < 1 || value.retired !== false)
        || row.ipiEmail[0].hasBody !== true || row.finflowBackups[0].status !== 'ready'
        || row.finflowBackups[0].filePresent !== true
        || row.finflowBackups[0].fileSha256 !== row.finflowBackups[0].contentSha256
        || row.finflowTraversal[0].state !== 'active' || row.finflowTraversal[0].directoryPresent !== true
        || row.legacyUpload[0].state !== 'published' || !row.legacyUpload[0].fileSha256)
      fail(`${label} durable artifact seed did not persist`);
    const observedRag = new Map(row.rag.map(value => [value.documentId, value]));
    for (const expected of refs[label].rag) {
      const value = observedRag.get(expected.documentId);
      if (!value || value.family !== expected.family || value.slot !== expected.slot
          || value.sourceSha256 !== expected.sourceSha256 || !value.chunkManifestSha256)
        fail(`${label} RAG source lineage mismatch`);
    }
    if (row.ipiEmail[0].artifactId !== refs[label].ipiEmail.artifactId
        || row.ipiEmail[0].bodySha256 !== refs[label].ipiEmail.bodySha256
        || row.ipiEmail[0].runId !== refs[label].ipiEmail.runId
        || row.ipiEmail[0].generation !== refs[label].ipiEmail.generation
        || row.ipiRun[0].runId !== refs[label].ipiEmail.runId
        || row.ipiRun[0].ownerKey !== ownerKey('IndirectEmail', refs[label].ownerId)
        || row.ipiRun[0].generation !== refs[label].ipiEmail.generation
        || row.finflowBackups[0].backupId !== refs[label].finflow.backupId
        || row.finflowBackups[0].contentSha256 !== refs[label].finflow.contentSha256
        || row.finflowTraversal[0].targetToken !== refs[label].finflow.targetToken
        || row.legacyUpload[0].intentId !== refs[label].legacyUpload.intentId
        || row.legacyUpload[0].fileSha256 !== refs[label].legacyUpload.contentSha256)
      fail(`${label} artifact source lineage mismatch`);
    if (row.runGeneration[0].ownerKey !== refs[label].runGeneration.ownerKey) fail('Run generation owner mismatch');
  }
}

async function readOne(pools, personRef, scopeRoot) {
  const id = personRef.ownerId;
  if (!Number.isSafeInteger(id) || id < 1 || id > 2147483647) fail('Artifact snapshot owner invalid');
  const identity = pool(pools?.identity?.migration, 'Identity migration');
  const finflow = pool(pools?.finflow?.migration, 'FinFlow migration');
  const rag = (await identity.query(`SELECT d.document_id AS "documentId", d.family,d.slot,
    d.source_sha256 AS "sourceSha256",d.chunk_manifest_sha256 AS "chunkManifestSha256",
    d.retired_at IS NOT NULL AS retired,s.document_id IS NOT NULL AS "hasSource",
    (SELECT count(*)::integer FROM workshop_rag.embedding_vectors v
      JOIN workshop_rag.embedding_revisions r USING(revision_id) WHERE r.document_id=d.document_id) AS vectors
    FROM workshop_rag.documents d LEFT JOIN workshop_rag.sources s USING(document_id)
    WHERE d.owner_id=$1 ORDER BY d.document_id`, [id])).rows;
  const ipiEmail = (await identity.query(`SELECT artifact_id AS "artifactId",body_sha256 AS "bodySha256",
    body_text IS NOT NULL AS "hasBody",retired_at IS NOT NULL AS retired,
    run_id AS "runId",generation::text AS generation FROM identity.ipi_email_artifacts
    WHERE owner_id=$1 ORDER BY artifact_id`, [id])).rows;
  const legacyUpload = (await identity.query(`SELECT intent_id AS "intentId",state,
    file_path AS "filePath" FROM identity.legacy_upload_intents WHERE owner_id=$1 ORDER BY intent_id`, [id])).rows;
  const finflowBackups = (await finflow.query(`SELECT backup_id AS "backupId",file_token AS "fileToken",
    content_sha256 AS "contentSha256",status,snapshot_records='[]'::jsonb AS scrubbed
    FROM finflow.backup_artifacts WHERE owner_id=$1 ORDER BY backup_id`, [id])).rows;
  const finflowTraversal = (await finflow.query(`SELECT owner_key AS "ownerKey",target_token AS "targetToken",state
    FROM finflow.traversal_targets WHERE owner_key=$1 ORDER BY target_token`, [ownerKey('FinFlow', id)])).rows;
  const runGeneration = (await identity.query(`SELECT owner_key AS "ownerKey",generation::text AS generation
    FROM graph_runtime.owners WHERE owner_key=$1`, [ownerKey('MCP', id)])).rows;
  const ipiRun = (await identity.query(`SELECT run_id AS "runId",owner_key AS "ownerKey",
    generation::text AS generation FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2`,
  [personRef.ipiEmail.runId, ownerKey('IndirectEmail', id)])).rows;
  for (const row of legacyUpload) {
    if (!UUID.test(row.intentId || '')) fail('Managed upload intent invalid');
    if (row.filePath !== null) {
      const directory = path.join(ROOT, 'server/uploads', 'managed', String(id), row.intentId);
      if (path.dirname(row.filePath) !== directory) fail('Managed upload escaped runtime root');
      const stat = await fsp.lstat(row.filePath);
      if (!stat.isFile() || stat.isSymbolicLink()) fail('Managed upload is not a regular file');
      row.fileSha256 = sha256(await fsp.readFile(row.filePath));
    }
    delete row.filePath;
  }
  for (const row of finflowBackups) {
    const file = finflowBackupPath(scopeRoot, row.fileToken);
    row.filePresent = fs.existsSync(file);
    if (row.filePresent) {
      const stat = await fsp.lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink()) fail('FinFlow backup file is not regular');
      row.fileSha256 = sha256(await fsp.readFile(file));
    }
  }
  for (const row of finflowTraversal) {
    if (!UUID.test(row.targetToken || '')) fail('FinFlow traversal token invalid');
    row.directoryPresent = fs.existsSync(path.join(scopeRoot, 'finflow-traversal-targets', row.targetToken));
  }
  return Object.freeze({ rag, ipiEmail, ipiRun, finflowBackups, finflowTraversal, legacyUpload, runGeneration });
}
async function readDeletionArtifacts({ pools, refs, scopeRoot }) {
  const runtimeRoot = assertRuntimeRoot(scopeRoot);
  if (refs?.version !== 1 || !refs.target?.ownerId || !refs.sibling?.ownerId
      || refs.target.ownerId === refs.sibling.ownerId) fail('Exact target and sibling refs required');
  return Object.freeze({ version: 1, target: await readOne(pools, refs.target, runtimeRoot),
    sibling: await readOne(pools, refs.sibling, runtimeRoot) });
}

function assertDeletionArtifacts(before, after) {
  if (before?.version !== 1 || after?.version !== 1 || !before.target || !before.sibling || !after.target || !after.sibling)
    fail('Complete before/after artifact snapshots required');
  assert.deepEqual(after.sibling, before.sibling, 'Sibling artifact rows and bytes must remain exact');
  if (before.target.rag.length !== 3 || before.target.ipiEmail.length !== 1 || before.target.ipiRun.length !== 1
      || before.target.finflowBackups.length !== 1 || before.target.finflowTraversal.length !== 1
      || before.target.legacyUpload.length !== 1 || before.target.runGeneration.length !== 1)
    fail('Complete pre-deletion target artifact inventory required');
  const byId = rows => new Map(rows.map(row => [row.documentId, row]));
  const retained = byId(after.target.rag);
  if (before.target.rag.length !== 3 || retained.size !== before.target.rag.length) fail('RAG manifest loss');
  for (const prior of before.target.rag) {
    const next = retained.get(prior.documentId);
    if (!next || next.sourceSha256 !== prior.sourceSha256 || next.chunkManifestSha256 !== prior.chunkManifestSha256
        || next.hasSource !== false || next.vectors !== 0 || next.retired !== true) fail('RAG immutable manifest or content cleanup failed');
  }
  if (after.target.ipiEmail.length !== 0
      || after.target.legacyUpload.some(row => row.state !== 'retired' || row.fileSha256 !== undefined)
      || after.target.finflowBackups.some(row => row.status !== 'retired' || !row.scrubbed || row.filePresent)
      || after.target.finflowTraversal.some(row => row.state !== 'retired' || row.directoryPresent))
    fail('Target artifact content cleanup incomplete');
  if (after.target.finflowBackups.length !== before.target.finflowBackups.length
      || after.target.finflowTraversal.length !== before.target.finflowTraversal.length
      || after.target.legacyUpload.length !== before.target.legacyUpload.length
      || after.target.ipiRun.length !== 1 || after.target.runGeneration.length !== 1)
    fail('Target immutable artifact lineage missing');
  if (after.target.ipiRun[0].runId !== before.target.ipiRun[0].runId
      || after.target.ipiRun[0].ownerKey !== before.target.ipiRun[0].ownerKey
      || after.target.ipiRun[0].generation !== before.target.ipiRun[0].generation)
    fail('IPI run lineage changed');
  if (after.target.runGeneration[0].ownerKey !== before.target.runGeneration[0].ownerKey
      || !/^(0|[1-9][0-9]*)$/.test(after.target.runGeneration[0].generation)
      || BigInt(after.target.runGeneration[0].generation) <= BigInt(before.target.runGeneration[0].generation))
    fail('Target run generation was not fenced');
  for (const [kind, key] of [['finflowBackups', 'backupId'], ['finflowTraversal', 'targetToken'], ['legacyUpload', 'intentId']]) {
    if (after.target[kind][0][key] !== before.target[kind][0][key]) fail('Target artifact lineage changed');
  }
  if (after.target.finflowBackups[0].contentSha256 !== before.target.finflowBackups[0].contentSha256)
    fail('FinFlow backup digest lineage changed');
  return Object.freeze({ targetArtifactsCleaned: true, immutableEvidenceRetained: true,
    siblingArtifactsPreserved: true, modelCreditClaimed: false, fullDeletionClaimed: false });
}

function startHeldTargetLease({ ledger, targetId, signal, timeoutMs = 30000 }) {
  if (!Number.isSafeInteger(targetId) || targetId < 1 || typeof ledger?.begin !== 'function') fail('Real target run ledger required');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) fail('Bounded target lease required');
  let release, ready, rejectStarted;
  const gate = new Promise(resolve => { release = resolve; });
  const started = new Promise((resolve, reject) => { ready = resolve; rejectStarted = reject; });
  started.catch(() => {});
  const settled = controlledCoordinator('MCP', ledger).run(String(targetId),
    runOptions(signal, timeoutMs), async execution => {
    ready(Object.freeze({ ownerKey: execution.ownerKey, runId: execution.runId,
      generation: String(execution.durableGeneration) }));
    let onAbort;
    try {
      await Promise.race([gate, new Promise((_, reject) => {
        onAbort = () => { release(); reject(execution.signal.reason); };
        execution.signal.addEventListener('abort', onAbort, { once: true });
        if (execution.signal.aborted) onAbort();
      })]);
    } finally { execution.signal.removeEventListener('abort', onAbort); }
    await execution.check(); return { completed: true };
  }).then(value => ({ value }), error => { rejectStarted(error); return { error }; });
  return Object.freeze({ started, settled, release });
}

module.exports = Object.freeze({ assertRuntimeRoot, seedDeletionArtifacts, readDeletionArtifacts,
  assertDeletionArtifacts, startHeldTargetLease, cleanupEmptyLegacyOwnerDirs, runOptions, scopeNames,
  seedLegacy, finflowRootsReadyStage, finflowBackupPath });
