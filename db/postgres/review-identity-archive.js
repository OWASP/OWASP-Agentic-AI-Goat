'use strict';

const { mapIdentityArchive } = require('./map-identity-archive');

const NORMALIZATION_POLICY = 'apply_native_metadata_policy_retain_source_archive';
const RECORD_FIELDS = ['collection', 'sourceId', 'field', 'reason', 'policy'];

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function exactObject(value, fields, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== [...fields].sort().join(',')) reject(code);
}
function key(row) {
  return JSON.stringify([row.collection, row.sourceId, row.field, row.reason]);
}

/**
 * Pure review gate. The caller must keep the verified source archive: approval
 * authorizes the native metadata policy, not deletion of the original values.
 * `identity` is private importer data and still includes raw session tokens.
 */
function reviewIdentityArchive(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).some(field => !['tables', 'archiveDigest', 'naiveTimestamps', 'review'].includes(field))) {
    reject('INVALID_IDENTITY_REVIEW_INPUT');
  }
  const { tables, archiveDigest, naiveTimestamps = 'reject', review } = raw;
  const mapped = mapIdentityArchive({ tables, archiveDigest, naiveTimestamps });
  exactObject(review, ['archiveDigest', 'normalizations'], 'IDENTITY_NORMALIZATION_REVIEW_REQUIRED');
  if (review.archiveDigest !== archiveDigest) reject('STALE_IDENTITY_NORMALIZATION_REVIEW');
  if (!Array.isArray(review.normalizations)) reject('INVALID_IDENTITY_NORMALIZATION_REVIEW');
  const expected = new Map(mapped.report.normalizations.map(row => [key(row), row]));
  const seen = new Set();
  for (const decision of review.normalizations) {
    exactObject(decision, RECORD_FIELDS, 'INVALID_IDENTITY_NORMALIZATION_DECISION');
    if (decision.policy !== NORMALIZATION_POLICY) reject('UNSUPPORTED_IDENTITY_NORMALIZATION_POLICY');
    const recordKey = key(decision);
    if (seen.has(recordKey)) reject('DUPLICATE_IDENTITY_NORMALIZATION_DECISION');
    if (!expected.has(recordKey)) reject('STALE_OR_EXTRA_IDENTITY_NORMALIZATION_DECISION');
    seen.add(recordKey);
  }
  if (seen.size !== expected.size) reject('MISSING_IDENTITY_NORMALIZATION_DECISION');
  // Build the public report from regenerated records, not caller-controlled values.
  const approvedNormalizations = mapped.report.normalizations.map(({ requiresReview, ...row }) => ({ ...row, policy: NORMALIZATION_POLICY }));
  return {
    identity: mapped.identity,
    report: {
      ...mapped.report,
      normalizations: mapped.report.normalizations.map(row => ({ ...row, requiresReview: false })),
      approvedNormalizations,
      normalizationReviewComplete: true,
      requiresReview: false,
      readyToApply: false,
      scope: 'identity_metadata_normalizations_only',
      sourceRetention: 'Original values remain in the source archive and private input DTO; native metadata is intentionally normalized.',
      coverageReviewRequired: mapped.report.unknownPopulatedTables.length > 0,
    },
  };
}

module.exports = { NORMALIZATION_POLICY, reviewIdentityArchive };
