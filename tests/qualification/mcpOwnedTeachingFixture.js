'use strict';
// Explicit read-only qualification: node --test tests/qualification/mcpOwnedTeachingFixture.js
// Default isolated unit tests deliberately deny teaching-secret file bodies.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../..');

// Check the actual owned teaching fixture; native mount/effect/witness proof is separate.
test('owned protected teaching file retains its expected format without exposing its contents', () => {
  const filename = path.join(root, 'sidecars/sandbox-runner/labfs/var/secrets/master_key.txt');
  const stat = fs.lstatSync(filename);
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), 'Teaching fixture must be a regular file');
  assert.equal(fs.realpathSync(filename), path.join(fs.realpathSync(root),
    'sidecars/sandbox-runner/labfs/var/secrets/master_key.txt'), 'Teaching fixture escaped its owned path');
  const protectedFixture = fs.readFileSync(filename, 'utf8').trim();
  // Boolean assertions keep file contents out of failure diagnostics.
  for (const [label, pattern] of [
    ['title', /^ACME CORP — MASTER ENCRYPTION KEY/m],
    ['key identifier', /^Key ID:\s+mk-prod-2026-001$/m],
    ['algorithm', /^Algorithm:\s+AES-256-GCM$/m],
    ['key field', /^Key:\s+\S+$/m],
  ]) assert.equal(pattern.test(protectedFixture), true, `Unexpected teaching fixture ${label}`);
});
