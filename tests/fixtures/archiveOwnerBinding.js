'use strict';

const {
  normalizeArchiveOwnerBinding,
  verifyArchiveOwnerBinding,
} = require('../../db/postgres/archive-owner-binding');

/**
 * Create a module-branded proof for mapper/importer unit tests without a
 * database. Native integration tests must use verifyArchiveOwnerBinding with a
 * real disposable identity database instead.
 */
async function fixtureOwnerProof(rawBinding) {
  const binding = normalizeArchiveOwnerBinding(rawBinding);
  const targets = binding.entries.map(([, target]) => target).sort((a, b) => a - b);
  const client = {
    async query(sql, params) {
      if (/FROM identity\.archive_owner_bindings WHERE archive_sha256=\$1/.test(sql)) {
        if (params.length !== 1 || params[0] !== binding.archiveDigest) throw new Error('Unexpected binding query');
        return { rowCount: 1, rows: [{
          archive_sha256: binding.archiveDigest,
          identity_map_sha256: binding.identityMapSha256,
          identity_map: binding.identityMap,
        }] };
      }
      if (/FROM identity\.users WHERE id=ANY\(\$1::int\[\]\)/.test(sql)) {
        if (params.length !== 1 || JSON.stringify([...params[0]].sort((a, b) => a - b)) !== JSON.stringify(targets)) {
          throw new Error('Unexpected identity target query');
        }
        return { rowCount: targets.length, rows: targets.map(id => ({ id })) };
      }
      throw new Error('Unexpected owner proof query');
    },
  };
  return verifyArchiveOwnerBinding(client, binding);
}

module.exports = { fixtureOwnerProof };
