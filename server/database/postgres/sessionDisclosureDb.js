'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const { createPool, withTransaction, verifyServer } = require('./index');
const { migrate } = require('../../../db/postgres/migrate');

const ENV_KEY = 'SESSION_DISCLOSURE_DATABASE_URL';

function ownerId(value) {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new TypeError('Platform owner is required');
  return id;
}

function credential(value) {
  if (typeof value !== 'string' || !/^dvaia_lab_[A-Za-z0-9_-]{43}$/.test(value)) return null;
  return value;
}

function candidate() {
  return {
    sessionId: crypto.randomUUID(),
    cookie: `dvaia_lab_${crypto.randomBytes(32).toString('base64url')}`,
    csrfToken: crypto.randomBytes(24).toString('base64url'),
    labUserId: `lab-${crypto.randomUUID()}`,
  };
}

function dto(row) {
  if (!row) return null;
  const generation = Number(row.generation);
  if (!Number.isSafeInteger(generation) || generation < 1) throw new Error('SESSION_DISCLOSURE_INVALID_STATE');
  return Object.freeze({
    platformOwnerId: Number(row.platform_owner_id),
    generation,
    sessionId: row.lab_session_id,
    cookie: row.lab_cookie,
    csrfToken: row.csrf_token,
    labUserId: row.lab_user_id,
    role: row.lab_role,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  });
}

function createSessionDisclosureDb(pool) {
  if (!pool || typeof pool.query !== 'function') throw new TypeError('PostgreSQL pool required');
  return Object.freeze({
    engine: 'postgres',
    async getOrCreate(owner) {
      const id = ownerId(owner);
      return withTransaction(pool, async client => {
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [String(id)]);
        const fresh = candidate();
        await client.query(`INSERT INTO session_disclosure.labs
          (platform_owner_id,generation,lab_session_id,lab_cookie,csrf_token,lab_user_id,lab_role)
          VALUES($1,1,$2,$3,$4,$5,'lab_admin') ON CONFLICT(platform_owner_id) DO NOTHING`,
        [id, fresh.sessionId, fresh.cookie, fresh.csrfToken, fresh.labUserId]);
        return dto((await client.query(
          'SELECT * FROM session_disclosure.labs WHERE platform_owner_id=$1', [id])).rows[0]);
      });
    },
    async resolve(owner, presentedCookie) {
      const id = ownerId(owner), token = credential(presentedCookie);
      if (!token) return null;
      return dto((await pool.query(
        'SELECT * FROM session_disclosure.labs WHERE platform_owner_id=$1 AND lab_cookie=$2',
        [id, token])).rows[0]);
    },
    async reset(owner) {
      const id = ownerId(owner);
      return withTransaction(pool, async client => {
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [String(id)]);
        const fresh = candidate();
        const row = (await client.query(`INSERT INTO session_disclosure.labs
          (platform_owner_id,generation,lab_session_id,lab_cookie,csrf_token,lab_user_id,lab_role)
          VALUES($1,1,$2,$3,$4,$5,'lab_admin')
          ON CONFLICT(platform_owner_id) DO UPDATE SET
            generation=session_disclosure.labs.generation+1,
            lab_session_id=EXCLUDED.lab_session_id,lab_cookie=EXCLUDED.lab_cookie,
            csrf_token=EXCLUDED.csrf_token,lab_user_id=EXCLUDED.lab_user_id,
            lab_role=EXCLUDED.lab_role,updated_at=clock_timestamp()
          RETURNING *`, [id, fresh.sessionId, fresh.cookie, fresh.csrfToken, fresh.labUserId])).rows[0];
        return dto(row);
      });
    },
    async destroyOwner(owner) {
      return (await pool.query('DELETE FROM session_disclosure.labs WHERE platform_owner_id=$1',
        [ownerId(owner)])).rowCount;
    },
  });
}

async function initializeSessionDisclosureDb(runtimePool, migrationPool, migrationDirectory = path.join(
  __dirname, '../../../db/postgres/workshop-migrations/session_disclosure')) {
  let ownedMigration = false;
  if (!runtimePool) runtimePool = getSessionDisclosurePool();
  if (!migrationPool) {
    migrationPool = createPool(process.env, 'SESSION_DISCLOSURE_MIGRATION_DATABASE_URL');
    ownedMigration = true;
  }
  try {
  await verifyServer(runtimePool);
  const runtime = (await runtimePool.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  const migration = (await migrationPool.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  if (runtime.role !== 'dvaia_session_disclosure_runtime' || migration.role === runtime.role ||
      migration.database !== runtime.database) {
    throw new Error('Session disclosure requires its named runtime role and a separate migration role');
  }
  await migrate(migrationPool, migrationDirectory);
  await verifyServer(runtimePool);
  } finally {
    if (ownedMigration) await migrationPool.end();
  }
}

let singleton;
let singletonPool;
function getSessionDisclosurePool() {
  if (!process.env[ENV_KEY]) throw Object.assign(new Error('Session disclosure lab is unavailable'), {
    code: 'SESSION_DISCLOSURE_UNAVAILABLE',
  });
  singletonPool ||= createPool(process.env, ENV_KEY);
  return singletonPool;
}
function getSessionDisclosureDb() {
  singleton ||= createSessionDisclosureDb(getSessionDisclosurePool());
  return singleton;
}

async function closeSessionDisclosureDb() {
  singleton = undefined;
  if (!singletonPool) return;
  const pool = singletonPool;
  singletonPool = undefined;
  await pool.end();
}

module.exports = { createSessionDisclosureDb, initializeSessionDisclosureDb, getSessionDisclosureDb,
  closeSessionDisclosureDb, ownerId, credential };
