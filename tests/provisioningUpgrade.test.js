'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { provisioningPlan, provisionApplication } = require('../db/postgres/provision-application');
async function fixture(run, failCreate = false) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-upgrade-unit-'));
  const manifestPath = path.join(directory, 'manifest.json');
  const plan = provisioningPlan(); const oldPlan = plan.slice(0, -1);
  const configuration = Object.fromEntries(oldPlan.flatMap(row => ['runtime', 'migration'].map(kind => [row[kind + 'Variable'], `postgres://${row[kind + 'Role']}:existing-secret@127.0.0.1/${row.database}`])));
  const previous = { version: 1, status: 'complete', cluster: 'fixture-cluster', plan: oldPlan, configuration, created: [] };
  await fs.writeFile(manifestPath, JSON.stringify(previous), { mode: 0o600 });
  const statements = [];
  const client = { async connect() {}, async end() {}, async query(sql, args) {
    statements.push(sql.replace(/PASSWORD '[^']*'/, 'PASSWORD [redacted]'));
    if (sql.includes('server_version_num')) return { rows: [{ server_version_num: '180000' }] };
    if (sql.includes('pg_control_system')) return { rows: [{ system_identifier: previous.cluster }] };
    if (sql.startsWith('SELECT d.datname')) return { rows: [{ datname: args[0], owner: oldPlan.find(row => row.database === args[0]).migrationRole }] };
    if (sql.startsWith('SELECT rolname,rolsuper')) return { rows: args[0].map(rolname => ({ rolname, rolcanlogin: true })) };
    if (failCreate && sql.startsWith('CREATE ROLE')) throw Object.assign(new Error('fixture'), { code: 'FIXTURE_DDL_FAILURE' });
    return { rows: [] };
  } };
  const invoke = options => provisionApplication({ adminUrl: 'postgres://fixture:unused@127.0.0.1/postgres', manifestPath, clientFactory: () => client, env: {}, ...options });
  try { await run({ directory, manifestPath, previous, plan, invoke, statements, client }); }
  finally { await fs.rm(directory, { recursive: true, force: true }); }
}
test('explicit provisioning upgrade retains old configuration and promotes only after new DDL', () => fixture(async ({ manifestPath, previous, plan, invoke, statements }) => {
  const result = await invoke({ upgrade: true });
  assert.equal(result.status, 'upgraded');
  for (const [key, value] of Object.entries(previous.configuration)) assert.equal(result.configuration[key], value);
  const stored = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  assert.equal(stored.status, 'complete'); assert.deepEqual(stored.plan, plan);
  assert.equal(statements.filter(sql => sql.startsWith('CREATE ROLE')).length, 2);
  assert.equal(statements.filter(sql => sql.startsWith('CREATE DATABASE')).length, 1);
  assert.equal((await fs.stat(manifestPath)).mode & 0o077, 0);
  await assert.rejects(fs.lstat(manifestPath + '.upgrade'), { code: 'ENOENT' });
}));
test('failed DDL keeps original manifest and private journal, refusing blind replay', () => fixture(async ({ manifestPath, previous, invoke, statements }) => {
  await assert.rejects(invoke({ upgrade: true }), { code: 'FIXTURE_DDL_FAILURE' });
  assert.deepEqual(JSON.parse(await fs.readFile(manifestPath, 'utf8')), previous);
  assert.equal((await fs.stat(manifestPath + '.upgrade')).mode & 0o077, 0);
  const count = statements.filter(sql => sql.startsWith('CREATE ROLE')).length;
  await assert.rejects(invoke({ upgrade: true }), { code: 'PROVISIONING_UPGRADE_PENDING' });
  assert.equal(statements.filter(sql => sql.startsWith('CREATE ROLE')).length, count);
}, true));

test('upgrade rejects altered credential bindings before DDL', () => fixture(async ({ manifestPath, previous, invoke, statements }) => {
  previous.configuration[previous.plan[0].runtimeVariable] = 'postgres://wrong:secret@127.0.0.1/other';
  await fs.writeFile(manifestPath, JSON.stringify(previous));
  await assert.rejects(invoke({ upgrade: true }), { code: 'MANIFEST_CONFIGURATION_MISMATCH' });
  assert.equal(statements.some(sql => sql.startsWith('CREATE ')), false);
}));
test('upgrade rejects inherited or granted role membership before DDL', () => fixture(async ({ invoke, statements, client }) => {
  const original = client.query;
  client.query = async (sql, args) => sql.includes('pg_auth_members') ? { rows: [{ member: 1 }] } : original(sql, args);
  await assert.rejects(invoke({ upgrade: true }), { code: 'ROLE_OWNERSHIP_MISMATCH' });
  assert.equal(statements.some(sql => sql.startsWith('CREATE ')), false);
}));
