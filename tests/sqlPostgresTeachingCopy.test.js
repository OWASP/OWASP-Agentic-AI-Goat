'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
function historicalBase() {
  const filename = require.resolve('../server/data/sqlInjectionWorkshopSolutions');
  const module = { exports:{} };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
    module, exports:module.exports, require:createRequire(filename), __filename:filename,
    __dirname:path.dirname(filename), process:{ env:{ ...process.env, WORKSHOP_DATABASE_ENGINE:'legacy' } },
  }, { filename });
  return JSON.parse(JSON.stringify(module.exports));
}
const base = historicalBase();
const postgres = require('../server/data/postgres/sqlInjectionWorkshopSolutions')(base);
const { CATALOG_VERSION } = require('../server/database/postgres/workshopPlatformSeed');

const migrationPath = path.join(__dirname,
  '../db/postgres/identity-migrations/0069_sql_injection_postgres_copy_defaults.sql');
const catalogVersion = 'workshop-defaults-2026-09-15-v4-secureshop-coherence';
const migrationVersion = 'workshop-defaults-2026-09-18-v5-postgres-sql-copy';

function clientFor(current, appliedDefault, state = 'managed') {
  const calls = [];
  return { calls, async query(sql, params = []) {
    calls.push({ sql, params });
    if (/SELECT revision/.test(sql)) return { rows: [{ revision: 1 }], rowCount: 1 };
    if (/SELECT solution_content AS value/.test(sql)) return { rows: [{ value: current }], rowCount: 1 };
    if (/SELECT \* FROM workshop_platform\.catalog_field_defaults/.test(sql)) return { rows: [{
      provenance_state: state,
      applied_default_hash: provenance.hashDocument(provenance.document(appliedDefault)),
    }], rowCount: 1 };
    if (/UPDATE workshop_platform\.objectives SET solution_content=/.test(sql)) {
      return { rows: [], rowCount: 1 };
    }
    if (/UPDATE workshop_platform\.catalog_field_defaults/.test(sql)) return { rows: [], rowCount: 1 };
    throw new Error(`unexpected query: ${sql}`);
  } };
}

function spec(id) {
  return { entityKind:'objective', workshopKey:'sql_injection_workshop', objectiveId:id,
    fieldName:'solution_content', sourceValue:postgres[id], sourceVersion:CATALOG_VERSION };
}

test('PostgreSQL sqli_1 and sqli_3 teaching copy names real engine outcomes', () => {
  assert.equal(CATALOG_VERSION, catalogVersion);
  assert.deepEqual(Object.keys(postgres), Object.keys(base));
  for (const id of ['sqli_1', 'sqli_3']) assert.notDeepEqual(base[id], postgres[id]);
  assert.match(postgres.sqli_1.approach, /PostgreSQL.*syntax or unterminated-quoted-string error/s);
  assert.doesNotMatch(JSON.stringify(postgres.sqli_1), /SQLITE_ERROR/i);
  assert.match(postgres.sqli_3.approach, /ORDER BY 8--.*succeeds.*ORDER BY 9--.*PostgreSQL rejects/s);
  assert.match(postgres.sqli_3.tips.join(' '), /position 9 is not in the select list/);
  assert.doesNotMatch(JSON.stringify(postgres.sqli_3), /no such column: 9/);
  for (const id of ['sqli_1', 'sqli_3']) {
    assert.deepEqual(postgres[id].hints, base[id].hints, `${id} payload guidance remains unchanged`);
    assert.deepEqual(postgres[id].examples, base[id].examples, `${id} examples remain unchanged`);
  }
});

test('managed old defaults upgrade, corrected defaults no-op, and instructor content survives', async () => {
  for (const id of ['sqli_1', 'sqli_3']) {
    const oldClient = clientFor(base[id], base[id]);
    assert.deepEqual(await provenance.reconcileField(oldClient, spec(id)),
      { changed:true, decision:'upgrade' });
    const write = oldClient.calls.find(call => /UPDATE workshop_platform\.objectives SET solution_content=/.test(call.sql));
    assert.deepEqual(JSON.parse(write.params[2]), postgres[id]);
    assert.deepEqual(JSON.parse(write.params[3]), base[id]);

    const currentClient = clientFor(postgres[id], postgres[id]);
    assert.deepEqual(await provenance.reconcileField(currentClient, spec(id)),
      { changed:false, decision:'record' });
    assert.equal(currentClient.calls.some(call => /UPDATE workshop_platform\.objectives SET solution_content=/.test(call.sql)), false);

    const edited = { ...base[id], approach: `Instructor-owned ${id} approach` };
    const editedClient = clientFor(edited, base[id]);
    assert.deepEqual(await provenance.reconcileField(editedClient, spec(id)),
      { changed:false, decision:'mark_custom' });
    assert.equal(editedClient.calls.some(call => /UPDATE workshop_platform\.objectives SET solution_content=/.test(call.sql)), false);

    const customClient = clientFor(edited, base[id], 'custom');
    assert.deepEqual(await provenance.reconcileField(customClient, spec(id)),
      { changed:false, decision:'preserve' });
    assert.equal(customClient.calls.some(call => /UPDATE workshop_platform\.objectives SET solution_content=/.test(call.sql)), false);
  }
});

test('0069 is forward-only, exact-default guarded, provenance-aware, and replay-safe', () => {
  assert.equal(fs.existsSync(path.join(__dirname,
    '../db/postgres/identity-migrations/0068_finflow_admin_enum_copy_defaults.sql')), false,
  'reserved FinFlow 0068 remains unregistered');
  const registered = fs.readdirSync(path.dirname(migrationPath)).filter(name => /^\d{4}_.*\.sql$/.test(name)).sort();
  const migrationIndex = registered.indexOf('0069_sql_injection_postgres_copy_defaults.sql');
  assert.notEqual(migrationIndex, -1, '0069 must remain registered');
  assert.ok(migrationIndex > registered.indexOf('0067_graph_observability_metadata.sql'),
    '0069 must remain forward of the preceding registered migration');
  const sql = fs.readFileSync(migrationPath, 'utf8');
  assert.match(sql, /objective\.solution_content=defaults\.old_value/);
  assert.match(sql, /objective\.updated_by IS NULL/);
  assert.match(sql, /provenance\.provenance_state='legacy_unknown'/);
  assert.match(sql, /provenance\.provenance_state='managed'/);
  assert.doesNotMatch(sql, /provenance\.provenance_state='custom'/);
  assert.match(sql, /applied_default_hash=defaults\.old_hash/);
  assert.match(sql, new RegExp(`source_version='${migrationVersion}'`));
  assert.match(sql, /WHERE id=1 AND EXISTS\(SELECT 1 FROM sql_copy_changed\)/);
  assert.doesNotMatch(sql, /\b(?:DELETE|TRUNCATE|DROP\s+TABLE\s+workshop_platform)\b/i);
  for (const id of ['sqli_1', 'sqli_3']) {
    assert.match(sql, new RegExp(`\\('${id}',\\$old_${id}\\$`));
    assert.match(sql, new RegExp(`\\$new_${id}\\$`));
    assert.match(sql, new RegExp(provenance.hashDocument(provenance.document(base[id]))));
    assert.match(sql, new RegExp(provenance.hashDocument(provenance.document(postgres[id]))));
  }
});
