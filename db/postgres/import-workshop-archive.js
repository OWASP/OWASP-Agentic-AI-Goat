'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const { readBounded } = require('./asset-bundle');
const { createPool } = require('../../server/database/postgres');
const {
  normalizeArchiveOwnerBinding,
  normalizeOpaqueResolutions,
  verifyArchiveOwnerBinding,
} = require('./archive-owner-binding');
const { readWorkshopArchive } = require('./read-workshop-archive');
const { importWorkshopSnapshot } = require('./import-workshop-snapshot');

const REVIEW_MAX_BYTES = 1024 * 1024;

function reject(code) {
  throw Object.assign(new Error(code), { code });
}

function exactKeys(value, expected, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) reject(code);
}

function validateReviewShape(envelope, family) {
  exactKeys(envelope, ['family', 'naiveTimestamps', 'review', 'ownerBinding', 'opaqueOwnerResolutions'], 'INVALID_WORKSHOP_REVIEW');
  if (envelope.family !== family || !['reject', 'UTC'].includes(envelope.naiveTimestamps)) reject('INVALID_WORKSHOP_REVIEW');
  exactKeys(envelope.review, ['archiveDigest', 'retainedOtherSources'], 'INVALID_WORKSHOP_REVIEW');
  if (!/^[a-f0-9]{64}$/.test(envelope.review.archiveDigest || '') || !Array.isArray(envelope.review.retainedOtherSources)
      || envelope.review.retainedOtherSources.some(value => typeof value !== 'string' || !value)) reject('INVALID_WORKSHOP_REVIEW');
  const binding = normalizeArchiveOwnerBinding(envelope.ownerBinding);
  if (binding.archiveDigest !== envelope.review.archiveDigest) reject('OWNER_ARCHIVE_MISMATCH');
  if (!Array.isArray(envelope.opaqueOwnerResolutions)) reject('INVALID_OPAQUE_OWNER_RESOLUTIONS');
  normalizeOpaqueResolutions(envelope.opaqueOwnerResolutions);
  return binding;
}

async function readReviewDocument(filename, family) {
  if (typeof filename !== 'string' || !filename || filename.includes('\0')) reject('INVALID_WORKSHOP_REVIEW_FILE');
  let handle;
  try { handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW); } catch { reject('INVALID_WORKSHOP_REVIEW_FILE'); }
  let bytes;
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > REVIEW_MAX_BYTES) reject('INVALID_WORKSHOP_REVIEW_FILE');
    bytes = await readBounded(handle, before.size);
    const after = await handle.stat();
    if (bytes.length !== before.size || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) reject('WORKSHOP_REVIEW_CHANGED');
  } finally { await handle.close(); }
  let envelope;
  try { envelope = JSON.parse(bytes.toString('utf8')); } catch { reject('INVALID_WORKSHOP_REVIEW_JSON'); }
  validateReviewShape(envelope, family);
  return { envelope, reviewSha256: crypto.createHash('sha256').update(bytes).digest('hex') };
}

async function readReview(filename, family) {
  return (await readReviewDocument(filename, family)).envelope;
}

function validateReview(review, family, archiveDigest, retainedOtherSources) {
  const binding = validateReviewShape(review, family);
  if (review.review.archiveDigest !== archiveDigest
      || JSON.stringify([...review.review.retainedOtherSources].sort()) !== JSON.stringify([...retainedOtherSources].sort())) {
    reject('STALE_WORKSHOP_ARCHIVE_REVIEW');
  }
  return binding;
}

async function importWorkshopArchive({ archive, family, databaseEnv, reviewFile, review, apply = false, env = process.env,
  identityDatabaseEnv = 'IDENTITY_MIGRATION_DATABASE_URL', ownerProof } = {}) {
  if (!['aria', 'nova'].includes(family) || typeof archive !== 'string' || !archive
      || typeof apply !== 'boolean' || (reviewFile === undefined && review === undefined)) reject('INVALID_WORKSHOP_IMPORT_OPTIONS');
  let envelope, reviewSha256;
  try {
    if (review === undefined) {
      const document = await readReviewDocument(reviewFile, family);
      envelope = structuredClone(document.envelope);
      reviewSha256 = document.reviewSha256;
    } else {
      envelope = structuredClone(review);
      reviewSha256 = crypto.createHash('sha256').update(JSON.stringify(envelope)).digest('hex');
    }
  }
  catch (error) { if (error && error.code) throw error; reject('INVALID_WORKSHOP_REVIEW'); }
  // Validate the policy and owner binding before touching either archive data or a database.
  validateReviewShape(envelope, family);
  const read = await readWorkshopArchive({ archive, family, naiveTimestamps: envelope.naiveTimestamps });
  const binding = validateReview(envelope, family, read.archiveDigest, read.report.retainedOtherSources);
  const reviewMetadata = {
    source: 'archive_review',
    naiveTimestamps: envelope.naiveTimestamps,
    archiveDigest: read.archiveDigest,
    reviewSha256,
    normalizations: read.report.normalizations,
    retainedOtherSources: read.report.retainedOtherSources,
    opaqueOwnerResolutions: envelope.opaqueOwnerResolutions,
  };
  const proof = ownerProof || await (async () => {
    const identityPool = createPool(env, identityDatabaseEnv);
    try { return await verifyArchiveOwnerBinding(identityPool, envelope.ownerBinding); }
    finally { await identityPool.end(); }
  })();
  const key = databaseEnv || (family === 'aria' ? 'SQL_WORKSHOP_MIGRATION_DATABASE_URL' : 'NOSQL_WORKSHOP_MIGRATION_DATABASE_URL');
  if (!/^[A-Z][A-Z0-9_]*$/.test(key)) reject('INVALID_DATABASE_ENV');
  const pool = createPool(env, key);
  try {
    const result = await importWorkshopSnapshot(pool, read.snapshot, {
      apply,
      archiveDigest: read.archiveDigest,
      ownerBinding: envelope.ownerBinding,
      ownerProof: proof,
      opaqueOwnerResolutions: envelope.opaqueOwnerResolutions,
      reviewMetadata,
    });
    return { ...result, mapping: read.report };
  } finally { await pool.end(); }
}

if (require.main === module) {
  const args = process.argv.slice(2), options = {};
  try {
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index];
      if (arg === '--apply') options.apply = true;
      else if (['--archive', '--family', '--review', '--database-env'].includes(arg)) {
        const key = { '--archive': 'archive', '--family': 'family', '--review': 'reviewFile', '--database-env': 'databaseEnv' }[arg];
        if (!args[index + 1] || args[index + 1].startsWith('--')) throw new Error('INVALID_WORKSHOP_IMPORT_OPTIONS');
        options[key] = args[++index];
      } else throw new Error('INVALID_WORKSHOP_IMPORT_OPTIONS');
    }
    if (!options.archive || !options.family || !options.reviewFile) throw new Error('INVALID_WORKSHOP_IMPORT_OPTIONS');
    importWorkshopArchive(options).then(result => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
      .catch(error => { process.stderr.write(`${JSON.stringify({ error: error.code || 'WORKSHOP_IMPORT_FAILED' })}\n`); process.exitCode = 1; });
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ error: error.code || 'WORKSHOP_IMPORT_FAILED' })}\n`);
    process.exitCode = 1;
  }
}

module.exports = { readReview, validateReview, importWorkshopArchive };
