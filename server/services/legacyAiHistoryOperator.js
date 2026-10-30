'use strict';

const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { canonicalManifest, computeManifestDigest, computeSourceStoreDigest,
  createLegacyAiHistoryArchiveAttestation, bindSourceStoreIdentity } = require('../database/postgres/legacyAiHistoryArchiveAttestation');
const { canonicalRow, digest, createLegacyAiHistoryDraftImporter } = require('../database/postgres/legacyAiHistoryDraftImporter');
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function failure() {
  return Object.assign(new Error('Legacy AI history operator action failed; check private files, reviewed store bindings and migration readiness'), {
    code: 'LEGACY_AI_HISTORY_OPERATOR_FAILED',
  });
}
function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw failure();
}
function locator(value, role) {
  const url = new URL(value);
  const database = decodeURIComponent(url.pathname.slice(1));
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname || url.hash
      || decodeURIComponent(url.username) !== role || !database || database.includes('/')
      || /[\0\r\n]/.test(database) || Buffer.byteLength(database) > 63
      || [...url.searchParams.keys()].some(key => key !== 'sslmode')
      || url.searchParams.getAll('sslmode').length > 1
      || (url.searchParams.has('sslmode') && !['disable','prefer','require','verify-ca','verify-full'].includes(url.searchParams.get('sslmode')))) throw failure();
  const endpoint = `postgresql://${url.hostname.toLowerCase()}:${url.port || '5432'}/${encodeURIComponent(database)}`;
  if (Buffer.byteLength(endpoint) > 400) throw failure();
  return Object.freeze({ database, endpoint });
}
function stores(env) {
  const source = locator(env.LEGACY_CHALLENGE_MIGRATION_DATABASE_URL, 'dvaia_legacy_challenge_migration');
  const target = locator(env.IDENTITY_MIGRATION_DATABASE_URL, 'dvaia_identity_migration');
  if (source.database === target.database) throw failure();
  return { source, target };
}
function sourceIdentity(source) { return `legacy-ai-history-source-v1:${source.endpoint}`; }
function validateLocator(value) {
  exact(value, ['database','endpoint']);
  if (typeof value.database !== 'string' || typeof value.endpoint !== 'string') throw failure();
  return { database: value.database, endpoint: value.endpoint };
}
function canonicalPlan(value) {
  exact(value, ['version','purpose','source','target','attestationId','manifest','manifestDigest','planDigest']);
  if (value.version !== 1 || value.purpose !== 'quarantine-only' || !UUID.test(value.attestationId || '')
      || !HASH.test(value.planDigest || '') || !HASH.test(value.manifestDigest || '')) throw failure();
  const source = validateLocator(value.source), target = validateLocator(value.target);
  const manifest = canonicalManifest(value.manifest); // Nonempty ownership claims fail closed.
  const manifestDigest = computeManifestDigest(manifest);
  if (manifest.sourceStoreIdentity !== sourceIdentity(source) || value.manifestDigest !== manifestDigest) throw failure();
  const plan = { version: 1, purpose: 'quarantine-only', source, target,
    attestationId: value.attestationId.toLowerCase(), manifest, manifestDigest };
  const planDigest = hash(plan);
  if (value.planDigest !== planDigest) throw failure();
  return Object.freeze({ ...plan, planDigest });
}
function attestationFor(plan) {
  // An explicit operator review record, not a signature or proof of ownership.
  const attestationReceipt = hash({ version: 1, attestationId: plan.attestationId, planDigest: plan.planDigest });
  const claimsDigest = digest([]);
  return { attestationReceipt, claimsDigest, boundSourceStoreIdentity: bindSourceStoreIdentity({
    sourceStoreDigest: plan.manifest.sourceStoreDigest, manifestDigest: plan.manifestDigest,
    claimsDigest, attestationReceipt,
  }) };
}
function receiptFor(plan) {
  return { version: 1, purpose: 'unknown-history-quarantined', planDigest: plan.planDigest,
    batchId: plan.manifest.batchId, aggregateDigest: plan.manifest.aggregateDigest,
    manifestDigest: plan.manifestDigest, quarantinedRows: plan.manifest.rows.length,
    ...attestationFor(plan) };
}
function validateReceipt(value, plan) {
  const expected = receiptFor(plan);
  exact(value, Object.keys(expected));
  for (const key of Object.keys(expected)) if (value[key] !== expected[key]) throw failure();
  return expected;
}
async function safePath(value) {
  if (typeof value !== 'string' || !value.length || value.includes('\0') || Buffer.byteLength(value) > 4096) throw failure();
  const absolute = path.resolve(value), parent = path.dirname(absolute);
  let current = path.parse(parent).root;
  for (const part of parent.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw failure();
  }
  const stat = await fs.lstat(parent);
  if (stat.uid !== process.getuid() || (stat.mode & 0o022) !== 0) throw failure();
  return absolute;
}
async function readPrivateJson(value) {
  const filename = await safePath(value);
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== process.getuid() || (before.mode & 0o077) !== 0
        || before.nlink !== 1 || before.size > MAX_FILE_BYTES) throw failure();
    const buffer = Buffer.alloc(before.size + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const read = await handle.read(buffer, bytes, buffer.length - bytes, bytes);
      if (!read.bytesRead) break;
      bytes += read.bytesRead;
    }
    const after = await handle.stat();
    if (bytes !== before.size || after.size !== before.size || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs) throw failure();
    return JSON.parse(buffer.subarray(0, bytes).toString('utf8'));
  } finally { await handle.close(); }
}
async function writePrivateJson(value, data) {
  const filename = await safePath(value);
  const bytes = JSON.stringify(data, null, 2) + '\n';
  if (Buffer.byteLength(bytes) > MAX_FILE_BYTES) throw failure();
  const temporary = path.join(path.dirname(filename), `.history-operator-${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = null;
    // link is an atomic no-overwrite publish; an existing symlink also fails.
    await fs.link(temporary, filename);
    const directory = await fs.open(path.dirname(filename), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  } finally {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
  }
}
function createLegacyAiHistoryOperator({ env = process.env,
  createPool = options => new (require('pg').Pool)(options),
  createSnapshot = (...args) => require('../database/postgres/legacyAiHistorySourceSnapshot').createLegacyAiHistorySourceSnapshot(...args),
  createAttestation = createLegacyAiHistoryArchiveAttestation,
  createTarget = (...args) => require('../database/postgres/legacyAiHistoryImportTarget').createLegacyAiHistoryImportTarget(...args),
  createImporter = createLegacyAiHistoryDraftImporter,
  createCoordinator = options => require('../database/postgres/legacyAiHistoryCutoverCoordinator').createLegacyAiHistoryCutoverCoordinator(options),
} = {}) {
  if (!env || typeof env !== 'object' || [createPool,createSnapshot,createAttestation,createTarget,createImporter,createCoordinator].some(fn => typeof fn !== 'function')) throw failure();
  return Object.freeze({ async execute(options) {
    const pools = [];
    try {
      if (!options || !['plan','quarantine','cleanup'].includes(options.command)) throw failure();
      exact(options, options.command === 'plan' ? ['command','planPath'] : ['command','planPath','receiptPath']);
      await safePath(options.planPath);
      if (options.command !== 'plan') {
        await safePath(options.receiptPath);
        if (path.resolve(options.planPath) === path.resolve(options.receiptPath)) throw failure();
      }
      const configured = stores(env);
      let plan;
      if (options.command !== 'plan') {
        plan = canonicalPlan(await readPrivateJson(options.planPath));
        if (JSON.stringify(plan.source) !== JSON.stringify(configured.source)
            || JSON.stringify(plan.target) !== JSON.stringify(configured.target)) throw failure();
      }
      const pool = key => {
        const result = createPool({ connectionString: env[key], max: 1, connectionTimeoutMillis: 10000,
          statement_timeout: 120000, application_name: 'owasp-ai-goat-history-operator' });
        if (typeof result?.end !== 'function') throw failure();
        pools.push(result); return result;
      };
      const batchId = plan?.manifest.batchId || randomUUID();
      const sourcePool = pool('LEGACY_CHALLENGE_MIGRATION_DATABASE_URL');
      const source = createSnapshot(sourcePool, { batchId, database: configured.source.database,
        sourceStoreIdentity: sourceIdentity(configured.source) });
      if (options.command === 'plan') {
        const snapshot = await source.readSnapshot();
        if (snapshot.batchId !== batchId || snapshot.sourceStoreIdentity !== sourceIdentity(configured.source)) throw failure();
        const rows = snapshot.rows.map(canonicalRow).sort((a,b) => a.id - b.id)
          .map(row => ({ sourceRowId: row.id, sourceDigest: digest(row) }));
        const manifest = canonicalManifest({ envelopeVersion: 1, batchId, sourceStoreIdentity: snapshot.sourceStoreIdentity,
          sourceStoreDigest: computeSourceStoreDigest(snapshot.sourceStoreIdentity), aggregateDigest: digest(rows), rows, claims: [] });
        const unsigned = { version: 1, purpose: 'quarantine-only', ...configured, attestationId: randomUUID(),
          manifest, manifestDigest: computeManifestDigest(manifest) };
        plan = canonicalPlan({ ...unsigned, planDigest: hash(unsigned) });
        await writePrivateJson(options.planPath, plan);
        return Object.freeze({ command: 'plan', batchId, rowCount: rows.length, planDigest: plan.planDigest,
          classification: 'unknown', sourceRemoved: false, ownershipProven: false });
      }
      if (options.command === 'cleanup') {
        const receipt = validateReceipt(await readPrivateJson(options.receiptPath), plan);
        // Reuses exact role/ledger/readonly preflight. A cleanup replay may have
        // an empty source; do not demand the original row aggregate here.
        await source.readSnapshot();
        const targetPool = pool('IDENTITY_MIGRATION_DATABASE_URL');
        const result = await createCoordinator({ sourcePool, targetPool,
          sourceDatabase: configured.source.database, targetDatabase: configured.target.database })
          .removeQuarantinedSource({ batchId, boundSourceStoreIdentity: receipt.boundSourceStoreIdentity,
            aggregateDigest: receipt.aggregateDigest });
        if (result?.batchId !== batchId || result.removedCount !== plan.manifest.rows.length
            || typeof result.replayed !== 'boolean'
            || !['source_removed','source_removed_archive_invalidated'].includes(result.state)) throw failure();
        return Object.freeze({ command: 'cleanup', batchId, removedCount: result.removedCount,
          replayed: result.replayed, state: result.state, ownershipProven: false });
      }
      let priorReceipt;
      try { priorReceipt = validateReceipt(await readPrivateJson(options.receiptPath), plan); }
      catch (error) { if (error?.code !== 'ENOENT') throw error; }
      const targetPool = pool('IDENTITY_MIGRATION_DATABASE_URL');
      const attestation = attestationFor(plan);
      const result = await createImporter({ sourceSnapshotCapability: source,
        ownershipAttestationCapability: createAttestation({ manifest: plan.manifest,
          manifestDigest: plan.manifestDigest, attestationReceipt: attestation.attestationReceipt }),
        targetImportCapability: createTarget(targetPool, { database: configured.target.database }),
      }).quarantine();
      if (result?.batchId !== batchId || result.manifestDigest !== plan.manifestDigest
          || result.aggregateDigest !== plan.manifest.aggregateDigest || result.sourceStoreDigest !== plan.manifest.sourceStoreDigest
          || !Array.isArray(result.claims) || result.claims.length
          || result.claimsDigest !== attestation.claimsDigest || result.attestationReceipt !== attestation.attestationReceipt
          || result.boundSourceStoreIdentity !== attestation.boundSourceStoreIdentity
          || result.targetReceipt?.batchId !== batchId || result.targetReceipt.sourceRemovalReceipt !== plan.manifest.aggregateDigest) throw failure();
      if (!priorReceipt) await writePrivateJson(options.receiptPath, receiptFor(plan));
      return Object.freeze({ command: 'quarantine', batchId, quarantinedRows: plan.manifest.rows.length,
        classification: 'unknown', sourceRemoved: false, ownershipProven: false });
    } catch { throw failure(); }
    finally { await Promise.all(pools.map(pool => Promise.resolve().then(() => pool.end()).catch(() => {}))); }
  } });
}
module.exports = { createLegacyAiHistoryOperator };
