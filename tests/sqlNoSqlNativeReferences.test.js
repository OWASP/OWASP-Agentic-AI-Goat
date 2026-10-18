'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readNovaNativeReferences } = require('./fixtures/sqlNoSqlNativeReferences');
function fixture(overrides = {}) {
  const calls = []; let releases = 0;
  const rawPaper = { paper_id: 'P1', title: 'Fixture', authors: '["Author"]', topics: '["Topic"]', cited_by: '[]' };
  const client = { release() { releases++; }, async query(sql, params) {
    calls.push({ sql, params });
    if (overrides.query) { const result = await overrides.query(sql, params); if (result) return result; }
    if (/^(BEGIN|COMMIT|ROLLBACK)/.test(sql)) return { rows: [] };
    if (sql.startsWith('SELECT current_database')) return { rows: [{ database: 'dvaia_test_nova_reference', role: 'dvaia_nova_runtime', ...overrides.identity }] };
    if (sql.includes("current_setting('server_version')")) return { rows: [{ version: '18.0' }] };
    if (sql.startsWith('SELECT * FROM nova.papers')) return { rows: [rawPaper] };
    if (sql.startsWith('SELECT * FROM nova.authors')) return { rows: [{ author_id: 'A1', expertise: '["Topic"]' }] };
    if (sql.includes('COUNT(*)')) return { rows: [{ n: sql.includes('chat_history') ? 17 : 2 }] };
    if (sql.includes('pg_attribute')) return { rows: [{ name: 'id', data_type: 'integer', indexed: true, unique: true }, { name: 'title', data_type: 'text', indexed: false, unique: false }] };
    throw Error('Unexpected query');
  } };
  return { pool: { connect: async () => client }, calls, released: () => releases, rawPaper };
}

test('native reference snapshot reads exact tables/catalogs and parameterizes the ordinary baseline', async () => {
  const f = fixture(); const attack = "MiXeD%' OR 1=1--";
  const result = await readNovaNativeReferences({ pool: f.pool, literalQuery: attack });
  assert.deepEqual(result.papers[0].authors, ['Author']); assert.deepEqual(result.papers[0].topics, ['Topic']);
  assert.deepEqual(result.authors[0].expertise, ['Topic']); assert.equal(result.novaVersion, '18.0');
  assert.deepEqual(result.novaCollections.map(row => row.name), ['papers','authors','reading_lists','chat_history']);
  assert.equal(result.novaCollections[3].documents, 17, 'retain the observed temporal count exactly');
  assert.deepEqual(result.novaSchema.map(row => row.collection), ['papers','authors']);
  assert.equal(result.novaSchema[0].fields[0].type, 'Integer'); assert.equal(result.novaSchema[0].fields[1].type, 'String');
  assert.equal(f.calls[0].sql, 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  assert.equal(f.calls.at(-1).sql, 'COMMIT'); assert.equal(f.released(), 1);
  const baseline = f.calls.find(call => call.sql.includes("access_level='public'"));
  assert.deepEqual(baseline.params, [`%${attack.toLowerCase()}%`]); assert.ok(!baseline.sql.includes(attack));
  assert.match(baseline.sql, /ORDER BY citations DESC LIMIT 10$/);
  assert.deepEqual(f.calls.filter(call => call.sql.includes('tablename=$1')).map(call => call.params), [['papers'],['authors'],['reading_lists'],['chat_history']]);
  assert.deepEqual(f.calls.filter(call => call.sql.includes('pg_attribute')).map(call => call.params), [['papers'],['authors']]);
  assert.ok(f.calls.every(call => /^(SELECT|BEGIN|COMMIT)/.test(call.sql)));
  assert.throws(() => { result.papers[0].authors.push('tampered'); }, TypeError);
  assert.equal(f.rawPaper.authors, '["Author"]');
});

test('ownership mismatch stops before workshop reads and always releases', async () => {
  for (const identity of [{ database: 'application_nova' }, { role: 'dvaia_nova_migration' }]) {
    const f = fixture({ identity });
    await assert.rejects(readNovaNativeReferences({ pool: f.pool, literalQuery: '' }), /Owned disposable/);
    assert.equal(f.calls.at(-1).sql, 'ROLLBACK'); assert.equal(f.calls.length, 3); assert.equal(f.released(), 1);
  }
});

test('failed native metadata and partial reads roll back without fabricated counts', async () => {
  for (const query of [
    sql => sql.includes('COUNT(*)') ? { rows: [{ n: null }] } : null,
    sql => sql.includes('pg_attribute') ? { rows: [] } : null,
    sql => { if (sql.includes("current_setting")) throw Error('controlled failure'); },
  ]) {
    const f = fixture({ query });
    await assert.rejects(readNovaNativeReferences({ pool: f.pool, literalQuery: '' }));
    assert.equal(f.calls.at(-1).sql, 'ROLLBACK'); assert.equal(f.released(), 1);
  }
});

test('requires explicit pool and query; malformed fixture JSON follows tool normalization', async () => {
  await assert.rejects(readNovaNativeReferences(), /Explicit owned/);
  const f = fixture(); f.rawPaper.topics = 'invalid-json';
  assert.deepEqual((await readNovaNativeReferences({ pool: f.pool, literalQuery: '' })).papers[0].topics, []);
});
