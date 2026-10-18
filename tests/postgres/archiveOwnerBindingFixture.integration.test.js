'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createPool } = require('../../server/database/postgres');
const {
  normalizeArchiveOwnerBinding,
  assertVerifiedArchiveOwnerBinding,
} = require('../../db/postgres/archive-owner-binding');
const { createNativeOwnerProof } = require('./helpers/archiveOwnerBinding');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env.PG_ARCHIVE_OWNER_FIXTURE_TEST_URL);

test('native owner proof fixture uses actual binding SQL and keeps source user unrelated', {
  skip: !enabled,
}, async () => {
  const url = new URL(process.env.PG_ARCHIVE_OWNER_FIXTURE_TEST_URL);
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  const pool = createPool(process.env, 'PG_ARCHIVE_OWNER_FIXTURE_TEST_URL');
  let fixture;
  try {
    const binding = normalizeArchiveOwnerBinding({
      archiveDigest: '9'.repeat(64),
      identityMap: { 7: 71 },
    });
    fixture = await createNativeOwnerProof(pool, binding);
    assert.equal(assertVerifiedArchiveOwnerBinding(fixture.ownerProof, binding).identityMap['7'], 71);
    assert.deepEqual((await pool.query('SELECT id FROM identity.users ORDER BY id')).rows, [
      { id: 7 },
      { id: 71 },
    ]);
    await assert.rejects(
      pool.query("UPDATE identity.archive_owner_bindings SET identity_map='{}'::jsonb"),
      { code: '55000' },
    );
  } finally {
    if (fixture?.cleanup) await fixture.cleanup();
    assert.equal((await pool.query("SELECT to_regnamespace('identity') IS NOT NULL AS present")).rows[0].present, false);
    await pool.end();
  }
});
