'use strict';

const { createHash } = require('node:crypto');

const ARCHIVE_RE = /^[a-f0-9]{64}$/;
const SOURCE_ID_RE = /^[1-9][0-9]{0,18}$/;
const NUMERIC_LIKE_RE = /^[0-9]+$/;
const ANONYMOUS_OWNER_RE = /^anon_[A-Za-z0-9._:-]{1,194}$/;
const MAX_SOURCE_ID = 9223372036854775807n;
const MAX_TARGET_ID = 2147483647;
const normalizedBindings = new WeakSet();
const verifiedProofs = new WeakSet();

function reject(code, location) {
  const error = new Error(code);
  error.code = code;
  if (location) error.location = location;
  throw error;
}

function canonicalSourceId(value, location = 'owner') {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) reject('INVALID_ARCHIVE_OWNER_ID', location);
    value = String(value);
  }
  if (typeof value !== 'string' || !SOURCE_ID_RE.test(value)
      || BigInt(value) > MAX_SOURCE_ID) reject('INVALID_ARCHIVE_OWNER_ID', location);
  return value;
}

function normalizeArchiveOwnerBinding(value) {
  if (value && typeof value === 'object' && normalizedBindings.has(value)) return value;
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'archiveDigest,identityMap') {
    reject('INVALID_ARCHIVE_OWNER_BINDING');
  }
  if (typeof value.archiveDigest !== 'string' || !ARCHIVE_RE.test(value.archiveDigest)) {
    reject('ARCHIVE_DIGEST_REQUIRED', 'archiveDigest');
  }
  if (!value.identityMap || typeof value.identityMap !== 'object' || Array.isArray(value.identityMap)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value.identityMap))) {
    reject('INVALID_ARCHIVE_IDENTITY_MAP', 'identityMap');
  }

  const targets = new Set();
  const entries = Object.entries(value.identityMap).map(([source, target]) => {
    const sourceId = canonicalSourceId(source, `identityMap.${source}`);
    if (!Number.isInteger(target) || target < 1 || target > MAX_TARGET_ID) {
      reject('INVALID_ARCHIVE_IDENTITY_TARGET', `identityMap.${source}`);
    }
    if (targets.has(target)) reject('AMBIGUOUS_ARCHIVE_IDENTITY_MERGE', `identityMap.${source}`);
    targets.add(target);
    return [sourceId, target];
  }).sort((left, right) => {
    const a = BigInt(left[0]), b = BigInt(right[0]);
    return a < b ? -1 : a > b ? 1 : 0;
  });

  const identityMap = Object.freeze(Object.fromEntries(entries));
  const identityMapSha256 = createHash('sha256').update(JSON.stringify(entries)).digest('hex');
  const binding = Object.freeze({
    archiveDigest: value.archiveDigest,
    identityMap,
    identityMapSha256,
    entries: Object.freeze(entries.map(entry => Object.freeze([...entry]))),
  });
  normalizedBindings.add(binding);
  return binding;
}

function sameBinding(left, right) {
  return left.archiveDigest === right.archiveDigest
    && left.identityMapSha256 === right.identityMapSha256
    && JSON.stringify(left.entries) === JSON.stringify(right.entries);
}

function normalizeOpaqueResolutions(value) {
  if (value === undefined) return new Map();
  if (!Array.isArray(value)) reject('INVALID_OPAQUE_OWNER_RESOLUTIONS');
  const result = new Map();
  const mappedSources = new Set();
  for (const [index, row] of value.entries()) {
    const location = `opaqueOwnerResolutions[${index}]`;
    if (!row || typeof row !== 'object' || Array.isArray(row)
        || typeof row.sourceKey !== 'string' || !row.sourceKey.length || row.sourceKey.length > 200
        || row.sourceKey.includes('\0')) reject('INVALID_OPAQUE_OWNER_RESOLUTION', location);
    if (result.has(row.sourceKey)) reject('DUPLICATE_OPAQUE_OWNER_RESOLUTION', location);
    if (row.disposition === 'preserve_opaque') {
      if (Object.keys(row).sort().join(',') !== 'disposition,sourceKey'
          || NUMERIC_LIKE_RE.test(row.sourceKey) || ANONYMOUS_OWNER_RE.test(row.sourceKey)) {
        reject('INVALID_OPAQUE_OWNER_ALIAS', location);
      }
      result.set(row.sourceKey, Object.freeze({ sourceKey: row.sourceKey, disposition: row.disposition }));
      continue;
    }
    if (row.disposition !== 'map_source_identity'
        || Object.keys(row).sort().join(',') !== 'disposition,sourceId,sourceKey'
        || !NUMERIC_LIKE_RE.test(row.sourceKey) || SOURCE_ID_RE.test(row.sourceKey)
        || ANONYMOUS_OWNER_RE.test(row.sourceKey)) reject('INVALID_OPAQUE_OWNER_RESOLUTION', location);
    const sourceId = canonicalSourceId(row.sourceId, `${location}.sourceId`);
    if (BigInt(row.sourceKey) !== BigInt(sourceId)) reject('MISMATCHED_NUMERIC_OWNER_ALIAS', location);
    if (mappedSources.has(sourceId)) reject('AMBIGUOUS_OWNER_RESOLUTION_TARGET', location);
    mappedSources.add(sourceId);
    result.set(row.sourceKey, Object.freeze({ sourceKey: row.sourceKey, disposition: row.disposition, sourceId }));
  }
  return result;
}

function mappedTarget(sourceId, binding, location) {
  if (!Object.hasOwn(binding.identityMap, sourceId)) reject('UNMAPPED_ARCHIVE_OWNER', location);
  return binding.identityMap[sourceId];
}

function mapAuthenticatedOwner(value, rawBinding, { location = 'owner', as = 'number' } = {}) {
  if (!['number', 'string'].includes(as)) reject('INVALID_ARCHIVE_OWNER_OUTPUT', location);
  const binding = normalizeArchiveOwnerBinding(rawBinding);
  const target = mappedTarget(canonicalSourceId(value, location), binding, location);
  return as === 'string' ? String(target) : target;
}

function mapOwnerKey(value, rawBinding, {
  location = 'owner', allowAnonymous = false, opaqueOwnerResolutions,
} = {}) {
  const binding = normalizeArchiveOwnerBinding(rawBinding);
  if (typeof value !== 'string' || !value.length || value.length > 200 || value.includes('\0')) {
    reject('INVALID_ARCHIVE_OWNER_KEY', location);
  }
  if (SOURCE_ID_RE.test(value)) return String(mappedTarget(canonicalSourceId(value, location), binding, location));
  if (ANONYMOUS_OWNER_RE.test(value)) {
    if (!allowAnonymous) reject('ANONYMOUS_ARCHIVE_OWNER_NOT_ALLOWED', location);
    return value;
  }
  const opaque = normalizeOpaqueResolutions(opaqueOwnerResolutions);
  const resolution = opaque.get(value);
  if (!resolution) reject('UNRESOLVED_OPAQUE_ARCHIVE_OWNER', location);
  if (resolution.disposition === 'map_source_identity') {
    return String(mappedTarget(resolution.sourceId, binding, location));
  }
  return resolution.sourceKey;
}

function mapDerivedOwnerKey(value, rawBinding, {
  prefix, location = 'owner', opaqueOwnerResolutions,
} = {}) {
  if (typeof prefix !== 'string' || !prefix.length || prefix.includes('\0')) reject('INVALID_DERIVED_OWNER_PREFIX', location);
  if (typeof value !== 'string' || !value.startsWith(prefix)) {
    return mapOwnerKey(value, rawBinding, { location, opaqueOwnerResolutions });
  }
  const suffix = value.slice(prefix.length);
  if (SOURCE_ID_RE.test(suffix)) {
    return `${prefix}${mapAuthenticatedOwner(suffix, rawBinding, { location, as: 'string' })}`;
  }
  if (NUMERIC_LIKE_RE.test(suffix)) {
    return `${prefix}${mapOwnerKey(suffix, rawBinding, { location, opaqueOwnerResolutions })}`;
  }
  const opaque = normalizeOpaqueResolutions(opaqueOwnerResolutions);
  const resolution = opaque.get(value);
  if (!resolution || resolution.disposition !== 'preserve_opaque') reject('UNRESOLVED_OPAQUE_ARCHIVE_OWNER', location);
  return resolution.sourceKey;
}

async function currentTargets(client, binding) {
  const targets = binding.entries.map(([, target]) => target);
  if (!targets.length) return;
  const result = await client.query('SELECT id::int AS id FROM identity.users WHERE id=ANY($1::int[]) ORDER BY id', [targets]);
  const found = result.rows.map(row => Number(row.id));
  const expected = [...targets].sort((a, b) => a - b);
  if (JSON.stringify(found) !== JSON.stringify(expected)) reject('ARCHIVE_OWNER_TARGET_MISSING');
}

async function recordArchiveOwnerBinding(client, rawBinding) {
  const binding = normalizeArchiveOwnerBinding(rawBinding);
  await currentTargets(client, binding);
  await client.query(`INSERT INTO identity.archive_owner_bindings
    (archive_sha256,identity_map_sha256,identity_map) VALUES($1,$2,$3::jsonb)`, [
    binding.archiveDigest, binding.identityMapSha256, JSON.stringify(binding.identityMap),
  ]);
  return binding;
}

async function readArchiveOwnerBinding(client, archiveDigest) {
  if (typeof archiveDigest !== 'string' || !ARCHIVE_RE.test(archiveDigest)) reject('ARCHIVE_DIGEST_REQUIRED');
  const result = await client.query(`SELECT archive_sha256,identity_map_sha256,identity_map
    FROM identity.archive_owner_bindings WHERE archive_sha256=$1`, [archiveDigest]);
  if (result.rowCount !== 1) reject('ARCHIVE_OWNER_BINDING_NOT_FOUND');
  const row = result.rows[0];
  const binding = normalizeArchiveOwnerBinding({ archiveDigest: row.archive_sha256, identityMap: row.identity_map });
  if (row.identity_map_sha256 !== binding.identityMapSha256) reject('ARCHIVE_OWNER_BINDING_CORRUPT');
  return binding;
}

async function verifyArchiveOwnerBinding(client, rawBinding) {
  const requested = normalizeArchiveOwnerBinding(rawBinding);
  const stored = await readArchiveOwnerBinding(client, requested.archiveDigest);
  if (!sameBinding(requested, stored)) reject('ARCHIVE_OWNER_BINDING_MISMATCH');
  await currentTargets(client, stored);
  const proof = Object.freeze({
    archiveDigest: stored.archiveDigest,
    identityMapSha256: stored.identityMapSha256,
  });
  verifiedProofs.add(proof);
  return proof;
}

function assertVerifiedArchiveOwnerBinding(proof, rawBinding) {
  const binding = normalizeArchiveOwnerBinding(rawBinding);
  if (!proof || typeof proof !== 'object' || !verifiedProofs.has(proof)
      || proof.archiveDigest !== binding.archiveDigest
      || proof.identityMapSha256 !== binding.identityMapSha256) {
    reject('VERIFIED_ARCHIVE_OWNER_BINDING_REQUIRED');
  }
  return binding;
}

module.exports = {
  normalizeArchiveOwnerBinding,
  normalizeOpaqueResolutions,
  mapAuthenticatedOwner,
  mapOwnerKey,
  mapDerivedOwnerKey,
  recordArchiveOwnerBinding,
  readArchiveOwnerBinding,
  verifyArchiveOwnerBinding,
  assertVerifiedArchiveOwnerBinding,
};
