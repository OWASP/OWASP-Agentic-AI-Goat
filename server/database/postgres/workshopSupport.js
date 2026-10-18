'use strict';
const path = require('node:path');
const { createPool, withTransaction, verifyServer } = require('./index');
const { migrate } = require('../../../db/postgres/migrate');

function helpers(pool) {
  const all = async (sql, params = []) => (await pool.query(sql, params)).rows;
  const get = async (sql, params = []) => (await all(sql, params))[0];
  const run = async (sql, params = []) => {
    const result = await pool.query(sql, params);
    return { lastID: result.rows[0]?.id, changes: result.rowCount };
  };
  return { all, get, run };
}
function singleton(factory, envKey) {
  let instance, pool;
  const getPool = () => pool ||= createPool(process.env, envKey);
  const method = name => async (...args) => {
    if (!instance) instance = factory(getPool());
    return instance[name](...args);
  };
  // Read adapters share the canonical runtime role and registry-owned lifetime.
  // Exposing this lazy accessor never transfers pool shutdown ownership.
  return Object.assign(method, { getPool });
}
async function initialize(pool, migrationPool, schema, seed) {
  if (!['aria', 'nova', 'xss', 'mcp', 'csrf', 'supply_chain', 'finflow', 'ctf', 'excessive_agency', 'secureshop', 'secureshop_agents', 'legacy_challenge', 'sensitive_lookup'].includes(schema)) throw new Error('Unknown workshop schema');
  await verifyServer(pool);
  const runtimeIdentity = (await pool.query('SELECT current_user AS role, current_database() AS database')).rows[0];
  const migrationIdentity = (await migrationPool.query('SELECT current_user AS role, current_database() AS database')).rows[0];
  if (runtimeIdentity.role !== `dvaia_${schema}_runtime` || migrationIdentity.role === runtimeIdentity.role || migrationIdentity.database !== runtimeIdentity.database) {
    throw new Error('Workshop requires its named runtime role and a separate migration role on the same dedicated database');
  }
  await migrate(migrationPool, path.join(__dirname, '../../../db/postgres/workshop-migrations', schema));
  await withTransaction(migrationPool, async client => {
    await client.query('SELECT pg_advisory_xact_lock(1886610804, 2)');
    await seed(client);
  });
  await verifyServer(pool);
}
module.exports = { helpers, singleton, initialize };
