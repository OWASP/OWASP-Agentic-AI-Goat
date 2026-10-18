'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
test('historical 0055 snapshot bytes bind all eight immutable migration documents', () => {
  const sqlBytes = fs.readFileSync(path.join(__dirname, '../db/postgres/identity-migrations/0055_finflow_admin_artifact_defaults.sql'));
  assert.equal(hash(sqlBytes), '56a19e666f359082a89995ef89d943d99b3a99e98330f680e84cc173b5812580');
  const sql = sqlBytes.toString('utf8');
  for (const [name, prefix, digest] of [
    ['before', 'old', '89e8437b0fc4296b113a16e0882f6c746b29349bd941da411bd93e22cf8732d8'],
    ['proposed', 'new', '05204f2a0962c23433fbb344168a0aec1315de8a9b993dcd11baf71591f76ca5']
  ]) {
    const bytes = fs.readFileSync(path.join(__dirname, `postgres/fixtures/admin-curriculum-${name}.json`));
    assert.equal(hash(bytes), digest);
    const snapshot = JSON.parse(bytes);
    const ids = ['admin_secrets', 'admin_dirlist'];
    assert.deepEqual(Object.keys(snapshot).sort(), [...ids].sort());
    ids.forEach((id, index) => {
      assert.deepEqual(Object.keys(snapshot[id]).sort(), ['hint', 'solution']);
      for (const field of ['solution', 'hint']) {
        const marker = `$${prefix}_${index}_${field}$`;
        const pieces = sql.split(marker);
        assert.ok(pieces.length >= 3 && pieces.length % 2 === 1, `${marker}: paired dollar quotes`);
        for (let occurrence = 1; occurrence < pieces.length; occurrence += 2) {
          assert.deepEqual(JSON.parse(pieces[occurrence]), snapshot[id][field], `${id}/${name}/${field}/${occurrence}`);
        }
      }
    });
  }
});

// Restored from the archived 0055 regression's unrelated-field protection.
// This is a static immutable-SQL assertion, not execution/provenance/no-op proof.
function assertContentOnlyUpdates(sql) {
  // Ignore trusted dollar-quoted JSON contents so prose cannot appear to be SQL.
  const structure = sql.replace(/\$([a-zA-Z_][a-zA-Z_0-9]*)\$[\s\S]*?\$\1\$/g, "'snapshot'")
    .replace(/--[^\n]*/g, '');
  const updates = [...structure.matchAll(/UPDATE\s+workshop_platform\.objectives\s+SET\s+([\s\S]*?)\s+WHERE\s+workshop_key/g)];
  assert.equal(updates.length, 2, 'Exactly the two reviewed objective updates');
  for (const [, clause] of updates) {
    // After removing CASE expressions, the remaining top-level assignments must
    // only update these two content fields and their modification timestamp.
    const assignments = clause.replace(/CASE\b[\s\S]*?\bEND/g, 'content');
    assert.deepEqual([...assignments.matchAll(/(?:^|,)\s*([a-z_]+)\s*=/g)].map(x => x[1]),
      ['solution_content', 'hint_content', 'updated_at']);
    assert.doesNotMatch(clause, /\b(?:is_enabled|catalog_active|hint_enabled|solution_enabled|updated_by|label|ordinal)\s*=/,
      'Preserve gates, catalog identity, instructor ownership and ordering');
  }
  assert.equal((structure.match(/UPDATE\s+workshop_platform\.config_revision\b/g) || []).length, 1);
  assert.match(structure, /WHERE id=1 AND \(EXISTS\(SELECT 1 FROM changed_0\) OR EXISTS\(SELECT 1 FROM changed_1\)\)/);
}

test('0055 only updates reviewed content and conditional configuration revision', () => {
  const sql = fs.readFileSync(path.join(__dirname, '../db/postgres/identity-migrations/0055_finflow_admin_artifact_defaults.sql'), 'utf8');
  assertContentOnlyUpdates(sql);
  for (const field of ['is_enabled', 'catalog_active', 'hint_enabled', 'solution_enabled', 'updated_by', 'label', 'ordinal']) {
    assert.throws(() => assertContentOnlyUpdates(sql.replace('updated_at=now() WHERE workshop_key',
      `${field}=NULL,updated_at=now() WHERE workshop_key`)), undefined, `Unexpected ${field} mutation must be rejected`);
  }
  assert.throws(() => assertContentOnlyUpdates(sql.replace('WHERE id=1 AND (EXISTS', 'WHERE id=1 OR (EXISTS')),
    undefined, 'Unconditional revision mutation must be rejected');
});
