'use strict';

const { createHash } = require('node:crypto');
const { ENVELOPE_VERSION, bindSourceStoreIdentity, computeSourceStoreDigest } = require(
  './legacyAiHistoryArchiveAttestation');

const DIGEST = /^[a-f0-9]{64}$/;
const ROUTES = new Set(['prompt_injection', 'chain_of_thought', 'context_stuffing', 'multi_turn_jailbreak']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const APPLICATION_TIMESTAMP = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)\.\d{6}Z$/;
const INT4_MIN = -2147483648;
const INT4_MAX = 2147483647;

const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const freeze = value => Object.freeze(value);
const isInt4 = value => Number.isInteger(value) && value >= INT4_MIN && value <= INT4_MAX;
const isNullableInt4 = value => value === null || isInt4(value);
const isNullableString = value => value === null || typeof value === 'string';
const hasBytesBetween = (value, minimum, maximum) => typeof value === 'string'
  && Buffer.byteLength(value, 'utf8') >= minimum && Buffer.byteLength(value, 'utf8') <= maximum;
const isApplicationTimestamp = value => {
  if (typeof value !== 'string') return false;
  const match = APPLICATION_TIMESTAMP.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [0, 31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return year > 0 && month >= 1 && month <= 12 && day >= 1 && day <= days[month]
    && hour <= 23 && minute <= 59 && second <= 59;
};

function exactObject(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError(`Exact ${label} fields required`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some(key => typeof key !== 'string')) throw new TypeError(`Exact ${label} fields required`);
  const actual = ownKeys.sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`Exact ${label} fields required`);
  }
  const copy = {};
  for (const key of expected) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field || !Object.hasOwn(field, 'value') || field.enumerable !== true) {
      throw new TypeError(`Plain ${label} fields required`);
    }
    copy[key] = field.value;
  }
  return Object.freeze(copy);
}

function exactArray(value, maximum, label) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || Object.getOwnPropertySymbols(value).length) {
    throw new TypeError(`Bounded ${label} required`);
  }
  const lengthField = Object.getOwnPropertyDescriptor(value, 'length');
  const length = lengthField && Object.hasOwn(lengthField, 'value') ? lengthField.value : null;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum) {
    throw new TypeError(`Bounded ${label} required`);
  }
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== length + 1 || names.at(-1) !== 'length') {
    throw new TypeError(`Plain ${label} required`);
  }
  return Object.freeze(Array.from({ length }, (_, index) => {
    const field = Object.getOwnPropertyDescriptor(value, String(index));
    if (!field || !Object.hasOwn(field, 'value') || field.enumerable !== true) {
      throw new TypeError(`Plain ${label} required`);
    }
    return field.value;
  }));
}

function canonicalRow(row) {
  if (!row || !isInt4(row.id) || !isNullableInt4(row.userId) || typeof row.prompt !== 'string'
      || !isNullableString(row.response) || !isNullableString(row.modelUsed)
      || !isNullableString(row.createdAt) || !isNullableInt4(row.platformOwnerId)) {
    throw new TypeError('Exact legacy AI source row required');
  }
  return freeze({ id: row.id, userId: row.userId, prompt: row.prompt, response: row.response,
    modelUsed: row.modelUsed, createdAt: row.createdAt, platformOwnerId: row.platformOwnerId });
}

function isPromotionEligible(row) {
  return hasBytesBetween(row.prompt, 1, 65536)
    && hasBytesBetween(row.response, 1, 262144)
    && hasBytesBetween(row.modelUsed, 1, 256)
    && isApplicationTimestamp(row.createdAt);
}

// Frozen capability objects make accidental route-level injection harder; they
// are not cryptographic evidence of operator issuance. A future launcher must
// construct these from a reviewed migration/operator authority.
function createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability, ownershipAttestationCapability, targetImportCapability }) {
  for (const capability of [sourceSnapshotCapability, ownershipAttestationCapability, targetImportCapability]) {
    if (!capability || typeof capability !== 'object' || Object.isExtensible(capability)) {
      throw new TypeError('Frozen reviewed import capability required');
    }
  }
  if (typeof sourceSnapshotCapability.readSnapshot !== 'function' || typeof ownershipAttestationCapability.attest !== 'function'
      || typeof targetImportCapability.begin !== 'function' || typeof targetImportCapability.archive !== 'function'
      || typeof targetImportCapability.promote !== 'function' || typeof targetImportCapability.readArchived !== 'function'
      || typeof targetImportCapability.readPromoted !== 'function' || typeof targetImportCapability.verify !== 'function') {
    throw new TypeError('Complete typed import capabilities required');
  }
  return freeze({
    async quarantine() {
      const supplied = await sourceSnapshotCapability.readSnapshot();
      if (!supplied || typeof supplied.batchId !== 'string' || !UUID.test(supplied.batchId)
          || !hasBytesBetween(supplied.sourceStoreIdentity, 1, 512) || !Array.isArray(supplied.rows)) {
        throw new TypeError('Trusted source snapshot required');
      }
      // Snapshot metadata as well as row bytes before invoking any awaited
      // capability. Provider-owned objects must not redirect later batch calls.
      const snapshot = freeze({ batchId: supplied.batchId.toLowerCase(),
        sourceStoreIdentity: supplied.sourceStoreIdentity,
        sourceStoreDigest: computeSourceStoreDigest(supplied.sourceStoreIdentity) });
      const rows = freeze(supplied.rows.map(canonicalRow).sort((a, b) => a.id - b.id));
      if (new Set(rows.map(row => row.id)).size !== rows.length) throw new Error('Duplicate legacy AI source row');
      const descriptors = freeze(rows.map(row => freeze({ sourceRowId: row.id, sourceDigest: digest(row) })));
      const aggregateDigest = digest(descriptors);
      const attested = await ownershipAttestationCapability.attest(freeze({ batchId: snapshot.batchId,
        sourceStoreIdentity: snapshot.sourceStoreIdentity, sourceStoreDigest: snapshot.sourceStoreDigest,
        aggregateDigest, rows: descriptors }));
      const attestation = exactObject(attested, ['envelopeVersion', 'batchId', 'sourceStoreDigest', 'aggregateDigest',
        'manifestDigest', 'claims', 'claimsDigest', 'attestationReceipt', 'boundSourceStoreIdentity'],
      'ownership attestation');
      const suppliedClaims = exactArray(attestation.claims, 100000, 'ownership claims');
      if (attestation.envelopeVersion !== ENVELOPE_VERSION || typeof attestation.batchId !== 'string'
          || !UUID.test(attestation.batchId) || attestation.batchId.toLowerCase() !== snapshot.batchId
          || attestation.sourceStoreDigest !== snapshot.sourceStoreDigest
          || attestation.aggregateDigest !== aggregateDigest || !DIGEST.test(attestation.manifestDigest)
          || !DIGEST.test(attestation.claimsDigest) || !DIGEST.test(attestation.attestationReceipt)) {
        throw new Error('Trusted ownership attestation differs from source snapshot');
      }
      const known = new Map(descriptors.map(row => [row.sourceRowId, row.sourceDigest]));
      const claims = new Map(), requestIds = new Set();
      for (const suppliedClaim of suppliedClaims) {
        const claim = exactObject(suppliedClaim, ['sourceRowId', 'sourceDigest', 'ownerId', 'requestId',
          'sourceRoute'], 'ownership claim');
        if (!known.has(claim.sourceRowId) || claims.has(claim.sourceRowId)
          || claim.sourceDigest !== known.get(claim.sourceRowId) || !Number.isSafeInteger(claim.ownerId)
          || claim.ownerId < 1 || claim.ownerId > 2147483647
          || typeof claim.requestId !== 'string' || !UUID.test(claim.requestId) || !ROUTES.has(claim.sourceRoute)) {
          throw new Error('Trusted ownership attestation contains an invalid or conflicting claim');
        }
        if (requestIds.has(claim.requestId.toLowerCase())) throw new Error('Trusted ownership attestation reuses a request ID');
        requestIds.add(claim.requestId.toLowerCase());
        // PostgreSQL returns UUIDs in canonical lowercase. Snapshot the claim
        // before asynchronous target calls so both hashing and replay use the
        // same identity and cannot observe later caller mutation.
        claims.set(claim.sourceRowId, freeze({ sourceRowId: claim.sourceRowId,
          sourceDigest: claim.sourceDigest, ownerId: claim.ownerId,
          requestId: claim.requestId.toLowerCase(), sourceRoute: claim.sourceRoute }));
      }
      const canonicalClaims = freeze([...claims.values()].sort((a, b) => a.sourceRowId - b.sourceRowId));
      if (digest(canonicalClaims) !== attestation.claimsDigest) {
        throw new Error('Trusted ownership claim digest differs from attestation');
      }
      const boundSourceStoreIdentity = bindSourceStoreIdentity({
        sourceStoreDigest: snapshot.sourceStoreDigest, manifestDigest: attestation.manifestDigest,
        claimsDigest: attestation.claimsDigest, attestationReceipt: attestation.attestationReceipt,
      });
      if (attestation.boundSourceStoreIdentity !== boundSourceStoreIdentity) {
        throw new Error('Trusted ownership attestation source binding differs');
      }
      const begun=await targetImportCapability.begin(freeze({ batchId: snapshot.batchId,
        sourceStoreIdentity: boundSourceStoreIdentity, expectedCount: rows.length, aggregateDigest }));
      const replayOnly=begun && begun.state==='verified';
      if (!replayOnly) for (const row of rows) {
        const sourceDigest = digest(row), claim = claims.get(row.id);
        await targetImportCapability.archive(freeze({ batchId: snapshot.batchId, sourceRowId: row.id,
          sourceRecord: row, sourceDigest, classification: claim ? 'owned' : 'unknown',
          ownerId: claim ? claim.ownerId : null }));
      }
      // This receipt supports a future independently provisioned source-cleanup
      // capability. It is not a deletion authorization and this importer has no remove method.
      const archived = await targetImportCapability.readArchived(freeze({ batchId: snapshot.batchId }));
      const observed = archived.map(item => {
        const sourceRecord = canonicalRow(item.sourceRecord);
        if (item.sourceRowId !== sourceRecord.id || item.sourceDigest !== digest(sourceRecord)) throw new Error('Target archive bytes differ from source digest');
        const claim=claims.get(item.sourceRowId), classification=claim?'owned':'unknown', ownerId=claim?claim.ownerId:null;
        if (item.classification!==classification || item.ownerId!==ownerId) throw new Error('Target archive ownership differs from current attestation');
        return freeze({ sourceRowId: item.sourceRowId, sourceDigest: item.sourceDigest });
      })
        .sort((a, b) => a.sourceRowId - b.sourceRowId);
      if (JSON.stringify(observed) !== JSON.stringify(descriptors)) throw new Error('Target quarantine bytes differ from source snapshot');
      const unpromotable = rows.find(row => claims.has(row.id) && !isPromotionEligible(row));
      if (unpromotable) {
        throw new Error('Attested legacy AI source row is not eligible for application history promotion');
      }
      if (!replayOnly) for (const row of rows) if (claims.has(row.id)) {
        const claim=claims.get(row.id), sourceDigest=digest(row);
        await targetImportCapability.promote(freeze({ batchId: snapshot.batchId, sourceRowId: row.id, sourceDigest,
          ownerId: claim.ownerId, requestId: claim.requestId, sourceRoute: claim.sourceRoute, prompt: row.prompt,
          response: row.response, modelUsed: row.modelUsed, createdAt: row.createdAt,
          historyDigest: digest({ ownerId: claim.ownerId, requestId: claim.requestId, sourceRoute: claim.sourceRoute, row }) }));
      }
      for (const row of rows) if (claims.has(row.id)) {
        const claim=claims.get(row.id), promoted=await targetImportCapability.readPromoted(freeze({batchId:snapshot.batchId,sourceRowId:row.id}));
        const historyDigest=digest({ ownerId: claim.ownerId, requestId: claim.requestId, sourceRoute: claim.sourceRoute, row });
        if (!promoted || promoted.ownerId!==claim.ownerId || promoted.requestId!==claim.requestId || promoted.sourceRoute!==claim.sourceRoute
          || promoted.sourceDigest!==digest(row) || promoted.historyDigest!==historyDigest || promoted.createdAt!==row.createdAt
          || promoted.prompt!==row.prompt || promoted.response!==row.response || promoted.modelUsed!==row.modelUsed) throw new Error('Target owned history bytes differ from verified archive');
      }
      const targetReceipt = await targetImportCapability.verify(freeze({ batchId: snapshot.batchId,
        expectedCount: rows.length, aggregateDigest, replayOnly }));
      if (!targetReceipt || targetReceipt.batchId !== snapshot.batchId
          || targetReceipt.sourceRemovalReceipt !== aggregateDigest) {
        throw new Error('Target verification receipt differs from attested archive');
      }
      return freeze({ batchId: snapshot.batchId, sourceStoreDigest: snapshot.sourceStoreDigest,
        aggregateDigest, manifestDigest: attestation.manifestDigest, claims: canonicalClaims,
        claimsDigest: attestation.claimsDigest, attestationReceipt: attestation.attestationReceipt,
        boundSourceStoreIdentity, targetReceipt });
    },
  });
}

module.exports = { createLegacyAiHistoryDraftImporter, canonicalRow, digest };
