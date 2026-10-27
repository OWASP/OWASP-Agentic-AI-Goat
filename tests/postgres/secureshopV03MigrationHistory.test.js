'use strict';
// Controlled original-fixture helpers only; no Pool, database or native fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { readMigrations, executionSql, migrate } = require('../../db/postgres/migrate');
const { withTransaction, verifyServer } = require('../../server/database/postgres');
const source = fs.readFileSync(path.join(__dirname, 'secureshopV03ListingOptimizeNative.integration.test.js'), 'utf8');
const directory = path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_agents');
const reviewDirectory = path.join(__dirname, '../../db/postgres/workshop-migrations/secureshop_review');
const targets = ['0105_listing_optimize_conversation_purpose.sql', '0106_listing_optimize_registry_successor.sql'];
const reviewTarget = '0054_owned_listing_image_optimize.sql';
function segment(start, end) {
  const at = source.indexOf(start), stop = source.indexOf(end, at);
  assert.ok(at >= 0 && stop > at); return source.slice(at, stop);
}
function helpers(readiness = async () => ({ ready: true })) {
  const constants = ['V31', 'V32', 'V32_GUARD', 'V39_GUARD'].map(name => {
    const line = source.match(new RegExp(`^const ${name} = '[a-f0-9]{64}';$`, 'm'));
    assert.ok(line); return line[0];
  }).join('\n');
  return new Function('assert', 'AGENTS_SUCCESSORS', 'withTransaction', 'verifyServer', 'executionSql',
    'assertBoundToolPolicyReadiness', constants + '\n' +
    segment('function exactHistory(', 'async function ledger(') +
    segment('async function runtimeRegistryProof(', "test('0105-0106") +
    '\nreturn { exactHistory, applyOptimizeSuccessors, runtimeRegistryProof, upgradeRegistry, V31, V32, V32_GUARD, V39_GUARD };')(
    assert, targets, withTransaction, verifyServer, executionSql, readiness);
}
function controlledPool(rows, failSql) {
  const calls = []; let released = 0;
  const client = { async query(sql, params) {
    calls.push({ sql, params });
    if (sql.includes("current_setting('server_version_num')")) return { rows: [{ version: 180000 }] };
    if (/SELECT name,\s*checksum FROM dvaia_migrations.ledger/.test(sql)) return { rows };
    if (failSql && sql === failSql) throw new Error('controlled SQL failure');
    return { rows: [] };
  }, release() { released += 1; } };
  return { connect: async () => client, calls, released: () => released };
}
test('original target manifests remain exact ordered current production histories', async () => {
  const h = helpers();
  for (const [dir, required] of [[directory, targets], [reviewDirectory, [reviewTarget]]]) {
    const migrations = await readMigrations(dir), result = h.exactHistory(migrations, required);
    assert.equal(result.names.length, migrations.length);
    assert.deepEqual(result.rows, migrations.map(({ name, checksum }) => ({ name, checksum })));
    const at = result.names.indexOf(required[0]);
    for (const changed of [migrations.filter((_, i) => i !== at),
      [...migrations, migrations[at]], [...migrations].reverse()]) {
      assert.throws(() => h.exactHistory(changed, required));
    }
  }
});
test('actual fresh fixture compares complete returned list and ledger checksums', async () => {
  for (const [label, dir] of [['AGENTS', directory], ['REVIEW', reviewDirectory]]) {
    const migrations = await readMigrations(dir), names = migrations.map(m => m.name);
    const rows = migrations.map(({ name, checksum }) => ({ name, checksum }));
    const start = label === 'AGENTS' ? '      const migrations = await readMigrations(AGENTS_DIRECTORY);'
      : '      const history = exactHistory(await readMigrations(REVIEW_DIRECTORY), [REVIEW_SUCCESSOR]);';
    const code = segment(start, `      assert.deepEqual(await migrate(fresh.migration, ${label}_DIRECTORY), []);`);
    const execute = new Function('assert', 'readMigrations', 'exactHistory', 'AGENTS_SUCCESSORS', 'REVIEW_SUCCESSOR',
      'AGENTS_DIRECTORY', 'REVIEW_DIRECTORY', 'fresh', 'migrate', 'ledger', `return (async()=>{${code}})();`);
    const run = (applied, ledgerRows) => execute(assert, readMigrations, helpers().exactHistory,
      targets, reviewTarget, directory, reviewDirectory, { migration: {} }, async () => applied, async () => ledgerRows);
    await run(names, rows);
    for (const applied of [names.slice(0, -1), [...names, '9999_extra.sql'], [...names].reverse()]) {
      await assert.rejects(run(applied, rows));
    }
    await assert.rejects(run(names, rows.map((row, i) => i ? row : { ...row, checksum: '0'.repeat(64) })));
    await assert.rejects(run(names, rows.slice(0, -1)));
  }
});
test('bounded historical step executes only original pair with exact checksums and transaction', async () => {
  const migrations = await readMigrations(directory), h = helpers(), history = h.exactHistory(migrations, targets);
  const at = history.names.indexOf(targets[0]), pool = controlledPool(history.rows.slice(0, at));
  assert.deepEqual(await h.applyOptimizeSuccessors(pool, migrations), targets);
  assert.equal(pool.calls[0].sql, 'BEGIN');
  assert.equal(pool.calls.at(-1).sql, 'COMMIT'); assert.equal(pool.released(), 1);
  assert.ok(pool.calls[2].sql.includes('pg_advisory_xact_lock'));
  assert.deepEqual(pool.calls.filter(c => c.sql.startsWith('INSERT INTO dvaia_migrations')).map(c => c.params),
    migrations.slice(at, at + 2).map(m => [m.name, m.checksum]));
  assert.deepEqual(pool.calls.filter(c => migrations.some(m => executionSql(m) === c.sql)).map(c => c.sql),
    migrations.slice(at, at + 2).map(executionSql));
});
test('historical prefix name/checksum/extra-row mismatch rolls back before migration SQL', async () => {
  const migrations = await readMigrations(directory), h = helpers(), history = h.exactHistory(migrations, targets);
  const at = history.names.indexOf(targets[0]), prefix = history.rows.slice(0, at);
  for (const rows of [prefix.slice(1), [...prefix, history.rows[at]],
    prefix.map((r, i) => i ? r : { ...r, checksum: 'wrong' }),
    prefix.map((r, i) => i ? r : { ...r, name: 'wrong.sql' })]) {
    const pool = controlledPool(rows); await assert.rejects(h.applyOptimizeSuccessors(pool, migrations));
    assert.equal(pool.calls.at(-1).sql, 'ROLLBACK'); assert.equal(pool.released(), 1);
    assert.equal(pool.calls.some(c => migrations.some(m => c.sql === executionSql(m))), false);
  }
});
test('actual transaction rolls back SQL fault and absent target never opens transaction', async () => {
  const migrations = await readMigrations(directory), h = helpers(), history = h.exactHistory(migrations, targets);
  const at = history.names.indexOf(targets[0]), pool = controlledPool(history.rows.slice(0, at), executionSql(migrations[at]));
  await assert.rejects(h.applyOptimizeSuccessors(pool, migrations), /controlled SQL failure/);
  assert.equal(pool.calls.at(-1).sql, 'ROLLBACK'); assert.equal(pool.released(), 1);
  const empty = controlledPool([]);
  await assert.rejects(h.applyOptimizeSuccessors(empty, migrations.filter(m => m.name !== targets[1])));
  assert.deepEqual(empty.calls, []);
});
test('ordinary production migrate remains no-op at full current exact ledger', async () => {
  for (const dir of [directory, reviewDirectory]) {
    const migrations = await readMigrations(dir), rows = migrations.map(({ name, checksum }) => ({ name, checksum }));
    const pool = controlledPool(rows); assert.deepEqual(await migrate(pool, dir), []);
    assert.equal(pool.calls.some(c => migrations.some(m => c.sql === executionSql(m))), false);
    assert.equal(pool.calls.at(-1).sql, 'COMMIT');
  }
});
test('phase guard/constraint/privilege proofs and current readiness are exact', async () => {
  for (const historical of [true, false]) {
    let ready = 0; const h = helpers(async () => { ready += 1; return { ready: true }; });
    const expected = { guard_sha: historical ? h.V32_GUARD : h.V39_GUARD, successor: true, runtime_execute: false };
    const run = (row, allowDdl = false) => h.runtimeRegistryProof({ async query(sql, params) {
      if (sql.startsWith('CREATE TABLE')) { if (allowDdl) return {}; throw Object.assign(new Error('denied'), { code: '42501' }); }
      assert.deepEqual(params, [`bound_tool_registry_successor_v${historical ? 32 : 39}`]); return { rows: [row] };
    } }, { historical });
    await run(expected); assert.equal(ready, historical ? 0 : 1);
    for (const row of [{ ...expected, guard_sha: 'wrong' }, { ...expected, successor: false }, { ...expected, runtime_execute: true }]) await assert.rejects(run(row));
    await assert.rejects(run(expected, true));
  }
  await assert.rejects(helpers(async () => { throw new Error('current not ready'); }).runtimeRegistryProof({
    async query() { throw Object.assign(new Error('denied'), { code: '42501' }); }
  }), /current not ready/);
});
test('actual historical edge request retains31to32 exact merchant denials and rollback', async () => {
  const h = helpers(), scope = { launchId: 'launch', scenarioId: 'scene', generation: 3, platformOwnerId: 4, platformSessionId: 5 };
  for (const wrong of [false, true]) {
    const calls = []; let released = 0;
    const pool = { async connect() { return { async query(sql, params) {
      calls.push({ sql, params });
      if (wrong && sql.includes('INSERT INTO secureshop_agents.bound_tool_registry_upgrades')) throw Object.assign(new Error('wrong denial'), { code: '55000' });
      return { rows: [] };
    }, release() { released += 1; } }; } };
    if (wrong) await assert.rejects(h.upgradeRegistry(pool, scope, { wrong }), e => e.code === '55000');
    else await h.upgradeRegistry(pool, scope);
    const request = calls[1]; assert.match(request.sql, /\$5,31,32,decode/);
    assert.deepEqual(request.params.slice(5, 7), [h.V31, h.V32]);
    assert.deepEqual(JSON.parse(request.params[8]), [
      { toolKey: 'listing.optimize_images', role: 'merchant' },
      { toolKey: 'merchant.listing_optimize_setup', role: wrong ? 'customer' : 'merchant' }]);
    assert.equal(calls.at(-1).sql, wrong ? 'ROLLBACK' : 'COMMIT'); assert.equal(released, 1);
  }
  const fullTail = source.indexOf('history.names.slice(afterOriginal)');
  assert.ok(fullTail < source.indexOf('await upgradeRegistry(populated.runtime, scope);'));
  assert.ok(source.includes("predecessor_version: '31', successor_version: '32', predecessor: V31"));
});
