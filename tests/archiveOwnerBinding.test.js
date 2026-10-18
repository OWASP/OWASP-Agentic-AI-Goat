'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeArchiveOwnerBinding,
  normalizeOpaqueResolutions,
  mapAuthenticatedOwner,
  mapOwnerKey,
  mapDerivedOwnerKey,
  verifyArchiveOwnerBinding,
  assertVerifiedArchiveOwnerBinding,
} = require('../db/postgres/archive-owner-binding');

const raw = () => ({ archiveDigest: 'a'.repeat(64), identityMap: { 70: 7, 8: 81 } });

test('normalizes a one-to-one owner map and maps authenticated owner shapes', () => {
  const binding = normalizeArchiveOwnerBinding(raw());
  assert.deepEqual(binding.entries, [['8', 81], ['70', 7]]);
  assert.equal(mapAuthenticatedOwner(70, binding, { as: 'number' }), 7);
  assert.equal(mapAuthenticatedOwner('8', binding, { as: 'string' }), '81');
  assert.equal(mapOwnerKey('70', binding), '7');
  assert.equal(mapDerivedOwnerKey('csrf_8', binding, { prefix: 'csrf_' }), 'csrf_81');
  assert.equal(binding.identityMapSha256.length, 64);
});

test('rejects ambiguous, noncanonical and unmapped authenticated identities', () => {
  assert.throws(() => normalizeArchiveOwnerBinding({ ...raw(), identityMap: { 7: 71, 8: 71 } }), { code: 'AMBIGUOUS_ARCHIVE_IDENTITY_MERGE' });
  assert.throws(() => normalizeArchiveOwnerBinding({ ...raw(), identityMap: { '007': 71 } }), { code: 'INVALID_ARCHIVE_OWNER_ID' });
  assert.throws(() => normalizeArchiveOwnerBinding({ ...raw(), identityMap: { 7: 2147483648 } }), { code: 'INVALID_ARCHIVE_IDENTITY_TARGET' });
  assert.throws(() => mapAuthenticatedOwner('9', raw()), { code: 'UNMAPPED_ARCHIVE_OWNER' });
  assert.throws(() => mapOwnerKey('0007', raw()), { code: 'UNRESOLVED_OPAQUE_ARCHIVE_OWNER' });
});

test('preserves anonymous and opaque keys only through their explicit contracts', () => {
  assert.throws(() => mapOwnerKey('anon_fixture', raw()), { code: 'ANONYMOUS_ARCHIVE_OWNER_NOT_ALLOWED' });
  assert.equal(mapOwnerKey('anon_fixture', raw(), { allowAnonymous: true }), 'anon_fixture');
  const opaqueOwnerResolutions = [{ sourceKey: 'historical-demo', disposition: 'preserve_opaque' }];
  assert.equal(mapOwnerKey('historical-demo', raw(), { opaqueOwnerResolutions }), 'historical-demo');
  assert.equal(mapDerivedOwnerKey('legacy-session', raw(), { prefix: 'csrf_', opaqueOwnerResolutions: [{ sourceKey: 'legacy-session', disposition: 'preserve_opaque' }] }), 'legacy-session');
  const numericAlias = [{ sourceKey: '0070', disposition: 'map_source_identity', sourceId: '70' }];
  assert.equal(mapOwnerKey('0070', raw(), { opaqueOwnerResolutions: numericAlias }), '7');
  assert.equal(mapDerivedOwnerKey('csrf_0070', raw(), { prefix: 'csrf_', opaqueOwnerResolutions: numericAlias }), 'csrf_7');
  assert.throws(() => normalizeOpaqueResolutions([{ sourceKey: '70', disposition: 'preserve_opaque' }]), { code: 'INVALID_OPAQUE_OWNER_ALIAS' });
  assert.throws(() => normalizeOpaqueResolutions([{ sourceKey: '0070', disposition: 'preserve_opaque' }]), { code: 'INVALID_OPAQUE_OWNER_ALIAS' });
  assert.throws(() => normalizeOpaqueResolutions([{ sourceKey: 'anon_fixture', disposition: 'preserve_opaque' }]), { code: 'INVALID_OPAQUE_OWNER_ALIAS' });
  assert.throws(() => normalizeOpaqueResolutions([{ sourceKey: '0070', disposition: 'map_source_identity', sourceId: '8' }]), { code: 'MISMATCHED_NUMERIC_OWNER_ALIAS' });
  assert.throws(() => normalizeOpaqueResolutions([
    { sourceKey: '070', disposition: 'map_source_identity', sourceId: '70' },
    { sourceKey: '0070', disposition: 'map_source_identity', sourceId: '70' },
  ]), { code: 'AMBIGUOUS_OWNER_RESOLUTION_TARGET' });
});

test('verified proofs are module-branded and bound to the exact archive mapping', async () => {
  const binding = normalizeArchiveOwnerBinding(raw());
  const client = { query: async (sql, params) => {
    if (sql.includes('FROM identity.archive_owner_bindings')) return { rowCount: 1, rows: [{
      archive_sha256: binding.archiveDigest,
      identity_map_sha256: binding.identityMapSha256,
      identity_map: binding.identityMap,
    }] };
    if (sql.includes('FROM identity.users')) return { rows: params[0].sort((a, b) => a - b).map(id => ({ id })) };
    throw new Error('unexpected query');
  } };
  const proof = await verifyArchiveOwnerBinding(client, raw());
  assert.deepEqual(assertVerifiedArchiveOwnerBinding(proof, raw()).entries, binding.entries);
  assert.throws(() => assertVerifiedArchiveOwnerBinding(structuredClone(proof), raw()), { code: 'VERIFIED_ARCHIVE_OWNER_BINDING_REQUIRED' });
  assert.throws(() => assertVerifiedArchiveOwnerBinding(proof, { ...raw(), identityMap: { 70: 7 } }), { code: 'VERIFIED_ARCHIVE_OWNER_BINDING_REQUIRED' });

  const missingTarget = { query: async (sql) => {
    if (sql.includes('FROM identity.archive_owner_bindings')) return { rowCount: 1, rows: [{
      archive_sha256: binding.archiveDigest,
      identity_map_sha256: binding.identityMapSha256,
      identity_map: binding.identityMap,
    }] };
    if (sql.includes('FROM identity.users')) return { rows: [{ id: 7 }] };
    throw new Error('unexpected query');
  } };
  await assert.rejects(verifyArchiveOwnerBinding(missingTarget, raw()), { code: 'ARCHIVE_OWNER_TARGET_MISSING' });
});
