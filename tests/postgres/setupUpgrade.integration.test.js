'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomBytes, createHash } = require('node:crypto');
const { Client, Pool } = require('pg');
const { provisioningPlan } = require('../../db/postgres/provision-application');
const { setup, encodeEnv } = require('../../scripts/setup-application');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' &&
  process.env.PG_SETUP_UPGRADE_FRESH_CLUSTER === 'yes' &&
  Boolean(process.env.PG_ADMIN_DATABASE_URL) && Boolean(process.env.DVAIA_ISOLATED_TEST_WORKSPACE);
const priorCount = Number(process.env.PG_SETUP_UPGRADE_PRIOR_COUNT || 15);
function quoteIdentifier(value) {
  assert.match(value, /^dvaia_[a-z_]+$/);
  return `"${value}"`;
}
test(`application upgrade preserves a ${priorCount}-store installation and initializes only its appended suffix`, {
  skip: !enabled || ![14, 15].includes(priorCount), timeout: 180_000,
}, async () => {
  const root = await fs.realpath(process.env.DVAIA_ISOLATED_TEST_WORKSPACE);
  assert.equal(path.basename(root), 'source');
  assert.match(path.basename(path.dirname(root)), /^dvaia-setup-upgrade-/);
  const home = path.join(path.dirname(root), 'home');
  await fs.mkdir(home, { mode: 0o700 });
  const workspaceId = createHash('sha256').update(root).digest('hex').slice(0, 12);
  const privateDirectory = path.join(home, '.dvaia', workspaceId);
  await fs.mkdir(privateDirectory, { recursive: true, mode: 0o700 });
  const admin = new Client({ connectionString: process.env.PG_ADMIN_DATABASE_URL });
  const oldPlan = provisioningPlan().slice(0, priorCount), passwords = new Map(), configuration = {};
  let oldRuntime, newRuntime;
  await admin.connect();
  try {
    const cluster = (await admin.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier;
    for (const row of oldPlan) {
      for (const kind of ['migration', 'runtime']) {
        const role = row[`${kind}Role`], password = randomBytes(24).toString('hex');
        passwords.set(role, password);
        await admin.query(`CREATE ROLE ${quoteIdentifier(role)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`);
      }
      await admin.query(`CREATE DATABASE ${quoteIdentifier(row.database)} OWNER ${quoteIdentifier(row.migrationRole)}`);
      await admin.query(`REVOKE CONNECT,TEMPORARY ON DATABASE ${quoteIdentifier(row.database)} FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE ${quoteIdentifier(row.database)} TO ${quoteIdentifier(row.runtimeRole)},${quoteIdentifier(row.migrationRole)}`);
      for (const kind of ['runtime', 'migration']) {
        const role = row[`${kind}Role`], url = new URL(process.env.PG_ADMIN_DATABASE_URL);
        url.username = role;url.password = passwords.get(role);url.pathname = `/${row.database}`;
        configuration[row[`${kind}Variable`]] = url.href;
      }
    }
    const manifestPath = path.join(privateDirectory, 'provisioning.json');
    await fs.writeFile(manifestPath, JSON.stringify({ version: 1, status: 'complete', cluster, plan: oldPlan,
      configuration, created: [] }, null, 2) + '\n', { mode: 0o600 });
    const envPath = path.join(root, '.env');
    const original = Buffer.from(`# native additive fixture\nJWT_SECRET="preserved-jwt"\nSESSION_SECRET="preserved-session"\n${encodeEnv(configuration)}`);
    await fs.writeFile(envPath, original, { mode: 0o600 });
    await fs.writeFile(path.join(privateDirectory, 'administrator.json'), '{"sentinel":"preserved"}\n', { mode: 0o600 });
    const markerRow = oldPlan[0];
    const oldMigration = new Client({ connectionString: configuration[markerRow.migrationVariable] });
    await oldMigration.connect();
    await oldMigration.query('CREATE TABLE public.upgrade_preservation_marker(value text NOT NULL)');
    await oldMigration.query("INSERT INTO public.upgrade_preservation_marker(value) VALUES ('retained')");
    await oldMigration.query(`GRANT SELECT ON public.upgrade_preservation_marker TO ${quoteIdentifier(markerRow.runtimeRole)}`);
    await oldMigration.end();

    const result = await setup({ root, homeDirectory: home, upgrade: true,
      adminUrl: process.env.PG_ADMIN_DATABASE_URL, processEnvironment: { ...process.env } });
    assert.deepEqual(result.upgradedSchemas, provisioningPlan().slice(priorCount).map(row => row.schema));
    const upgradedBytes = await fs.readFile(envPath);
    assert.equal(upgradedBytes.subarray(0, original.length).equals(original), true);
    const upgraded = require('dotenv').parse(upgradedBytes);
    assert.equal(upgraded.JWT_SECRET, 'preserved-jwt');
    assert.equal(upgraded.SESSION_SECRET, 'preserved-session');
    for (const [key, value] of Object.entries(configuration)) assert.equal(upgraded[key], value);
    assert.equal(await fs.readFile(path.join(privateDirectory, 'administrator.json'), 'utf8'), '{"sentinel":"preserved"}\n');
    assert.equal((await fs.stat(envPath)).mode & 0o777, 0o600);
    oldRuntime = new Pool({ connectionString: configuration[markerRow.runtimeVariable], max: 1 });
    assert.equal((await oldRuntime.query('SELECT value FROM public.upgrade_preservation_marker')).rows[0].value, 'retained');
    const appended = provisioningPlan().at(-1);
    newRuntime = new Pool({ connectionString: upgraded[appended.runtimeVariable], max: 1 });
    const identity = (await newRuntime.query('SELECT current_database() database,current_user role,EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1) initialized', [appended.schema])).rows[0];
    assert.deepEqual(identity, { database: appended.database, role: appended.runtimeRole, initialized: true });
    const replay = await setup({ root, homeDirectory: home, upgrade: true,
      adminUrl: process.env.PG_ADMIN_DATABASE_URL, processEnvironment: { ...process.env } });
    assert.deepEqual(replay.upgradedSchemas, []);
    assert.equal((await fs.readFile(envPath)).equals(upgradedBytes), true);
  } finally {
    const settled = await Promise.allSettled([oldRuntime?.end(), newRuntime?.end(), admin.end()]);
    const failures = settled.filter(row => row.status === 'rejected');
    if (failures.length) throw new AggregateError(failures.map(row => row.reason), 'Native upgrade cleanup failed');
  }
});
