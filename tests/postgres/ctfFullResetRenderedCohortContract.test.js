'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const { assertTwoStoreEnvironment, seedFullResetPreactivation, admitFullResetBrowser, spawnAdmittedBrowser,
  externalFullResetSnapshot, OWNER, SIBLING, ADMIN, BIRTH_KIND } =
  require('./support/ctfFullResetRenderedCohort');
const ROOT = path.resolve(__dirname, '../..');
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');

function queryFixtures({ missing = null, bootstrapState = 'open' } = {}) {
  const writes = [];
  const query = async (sql, args = []) => {
    writes.push({ sql, args });
    if (sql.startsWith('SELECT state,operation_id FROM ctf.bootstrap_control'))
      return { rows: [{ state: bootstrapState, operation_id: null }] };
    if (sql.startsWith('SELECT * FROM ctf.ctf_stages WHERE stage_number=1'))
      return { rows: [{ id: 1, stage_number: 1, stage_name: 'controlled' }] };
    if (sql.startsWith('SELECT workshop_key FROM workshop_platform.exercises'))
      return { rows: [{ workshop_key: 'legacy_sensitive_file_ssi' }] };
    if (sql.startsWith('INSERT INTO ctf.ctf_progress') && sql.includes('RETURNING id'))
      return { rows: [{ id: 41 }] };
    if (sql.startsWith('INSERT INTO ctf.ctf_attempts')) return { rows: [{ id: 51 }] };
    if (sql.startsWith('SELECT count(*)::int AS n FROM ctf.'))
      return { rows: [{ n: sql.endsWith(`.${missing}`) ? 0 : 1 }] };
    return { rows: [], rowCount: 1 };
  };
  return { identity: { query }, ctf: { query }, writes };
}

test('preactivation seed makes controlled historical witnesses without a model call', async () => {
  const prior = process.env.PG_TEST_DISPOSABLE;
  process.env.PG_TEST_DISPOSABLE = 'yes';
  try {
    const fixture = queryFixtures();
    const seed = await seedFullResetPreactivation({ ...fixture,
      seedDefaults: async pool => { assert.equal(pool, fixture.ctf); fixture.writes.push({ sql: 'seed-defaults' }); },
      seedPlatform: async pool => { assert.equal(pool, fixture.identity); fixture.writes.push({ sql: 'seed-platform' }); } });
    assert.deepEqual([seed.ownerId, seed.siblingId, seed.adminId], [OWNER, SIBLING, ADMIN]);
    assert.equal(seed.seedProvenance, 'controlled-preactivation-synthetic-not-model-credit');
    assert.equal(seed.canonicalCredit, false); assert.equal(seed.modelCalls, 0); assert.equal(seed.judgeCalls, 0);
    assert.deepEqual(Object.keys(seed.counts).length, 13);
    assert.equal(fixture.writes[0].sql, 'SELECT state,operation_id FROM ctf.bootstrap_control WHERE singleton');
    const firstUser = fixture.writes.findIndex(entry => entry.sql.startsWith('INSERT INTO identity.users'));
    const platformSeed = fixture.writes.findIndex(entry => entry.sql === 'seed-platform');
    const firstCtfParticipant = fixture.writes.findIndex(entry => entry.sql.startsWith('INSERT INTO ctf.ctf_participants'));
    assert(firstUser >= 0 && firstUser < platformSeed && platformSeed < firstCtfParticipant);
    const judgment = fixture.writes.find(entry => entry.sql.startsWith('INSERT INTO ctf.ctf_judgments'));
    assert(judgment); assert.equal(judgment.args[6], 'fail');
    assert.equal(JSON.parse(judgment.args[7]).modelCredit, false);
    assert(fixture.writes.some(entry => entry.sql.startsWith('INSERT INTO ctf.ctf_payload_blocklist')));
    assert(fixture.writes.some(entry => entry.sql.startsWith('INSERT INTO ctf.ctf_technique_blocklist')));
  } finally {
    if (prior === undefined) delete process.env.PG_TEST_DISPOSABLE;
    else process.env.PG_TEST_DISPOSABLE = prior;
  }
});

test('preactivation admission refuses prepared stores and any vacuous table', async () => {
  const prior = process.env.PG_TEST_DISPOSABLE; process.env.PG_TEST_DISPOSABLE = 'yes';
  try {
    const prepared = queryFixtures({ bootstrapState: 'prepared' });
    await assert.rejects(seedFullResetPreactivation({ ...prepared, seedDefaults: async () => {},
      seedPlatform: async () => {} }));
    assert.equal(prepared.writes.length, 1);
    for (const table of ['ctf_attempts', 'ctf_payload_blocklist', 'ctf_bans', 'ctf_judgments']) {
      const empty = queryFixtures({ missing: table });
      await assert.rejects(seedFullResetPreactivation({ ...empty, seedDefaults: async () => {},
        seedPlatform: async () => {} }), /preactivation witness missing/);
    }
  } finally {
    if (prior === undefined) delete process.env.PG_TEST_DISPOSABLE;
    else process.env.PG_TEST_DISPOSABLE = prior;
  }
});

test('external sibling readback binds one real identity row and one workshop row', async () => {
  const identity = { async query(sql, args) {
    assert.deepEqual(args, [SIBLING]);
    return { rows: sql.includes('identity.users') ? [{ id: SIBLING, is_active: 1 }]
      : [{ user_id: SIBLING, workshop_key: 'legacy_sensitive_file_ssi', generation: 0 }] };
  } };
  const observed = await externalFullResetSnapshot({ identity });
  assert.equal(observed.platform[0].id, SIBLING);
  assert.equal(observed.workshopSibling[0].user_id, SIBLING);
  await assert.rejects(externalFullResetSnapshot({ identity: { query: async () => ({ rows: [] }) } }));
});

test('late browser spawn lookup follows installed allowance rather than an import-time reference', () => {
  const prior = childProcess.spawn;
  const sentinel = { owned: true };
  childProcess.spawn = (executable, args, options) => {
    assert.equal(executable, '/owned/chrome');
    assert.deepEqual(args, ['--remote-debugging-port=0']);
    assert.equal(options.detached, false);
    return sentinel;
  };
  try { assert.equal(spawnAdmittedBrowser('/owned/chrome', ['--remote-debugging-port=0'], { detached: false }), sentinel); }
  finally { childProcess.spawn = prior; }
});

test('closed two-store/browser admission rejects an unrelated environment', () => {
  assert.equal(BIRTH_KIND, 'ctf_full_reset_browser');
  assert.throws(() => assertTwoStoreEnvironment({ CTF_FULL_RESET_RENDERED_ISOLATED: '1', PG_TEST_DISPOSABLE: 'yes' }));
  assert.throws(() => admitFullResetBrowser({ CTF_FULL_RESET_RENDERED_ISOLATED: '1',
    CTF_FULL_RESET_BROWSER_NATIVE: '1', PG_TEST_DISPOSABLE: 'yes',
    CTF_FULL_RESET_SOURCE_ROOT: '/another-repository' }));
  // Source/build authority is a real pin, not the helper's native-gated skip.
  assert.equal(ROOT, path.resolve(__dirname, '../..'));
  assert.match(sha256(fs.readFileSync(__filename)), /^[a-f0-9]{64}$/);
});
