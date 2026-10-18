'use strict';

const path = require('node:path');
const { createPool, verifyServer } = require('./index');
const { migrate } = require('../../../db/postgres/migrate');
const { createSecureShopBoundReviewRepository } = require('./secureshopBoundReviewRepository');

const ENV_KEY = 'SECURESHOP_REVIEW_DATABASE_URL';
const MIGRATION_ENV_KEY = 'SECURESHOP_REVIEW_MIGRATION_DATABASE_URL';
const RUNTIME_ROLE = 'dvaia_secureshop_review_runtime';
const MIGRATION_ROLE = 'dvaia_secureshop_review_migration';

function createSecureShopReviewRepository(pool, dependencies) {
  return createSecureShopBoundReviewRepository(pool, dependencies);
}

async function initializeSecureShopReviewDb(runtimePool, migrationPool, migrationDirectory = path.join(
  __dirname, '../../../db/postgres/workshop-migrations/secureshop_review')) {
  let ownedMigration = false;
  if (!runtimePool) runtimePool = getSecureShopReviewPool();
  if (!migrationPool) {
    migrationPool = createPool(process.env, MIGRATION_ENV_KEY);
    ownedMigration = true;
  }
  try {
    await Promise.all([verifyServer(runtimePool), verifyServer(migrationPool)]);
    const runtime = (await runtimePool.query(
      'SELECT current_user AS role,current_database() AS database')).rows[0];
    const migration = (await migrationPool.query(
      'SELECT current_user AS role,current_database() AS database')).rows[0];
    if (runtime.role !== RUNTIME_ROLE || migration.role !== MIGRATION_ROLE
      || migration.database !== runtime.database) {
      throw new Error('SecureShop review store requires its named runtime and migration roles on one dedicated database');
    }
    await migrate(migrationPool, migrationDirectory);
    await verifyServer(runtimePool);
  } finally {
    if (ownedMigration) await migrationPool.end();
  }
}

let singletonPool;
function getSecureShopReviewPool() {
  if (!process.env[ENV_KEY]) throw Object.assign(new Error('SecureShop review store is unavailable'), {
    code: 'SECURESHOP_REVIEW_UNAVAILABLE',
  });
  singletonPool ||= createPool(process.env, ENV_KEY);
  return singletonPool;
}

function getSecureShopReviewRepository(dependencies) {
  return createSecureShopReviewRepository(getSecureShopReviewPool(), dependencies);
}

async function closeSecureShopReviewDb() {
  if (!singletonPool) return;
  const pool = singletonPool;
  singletonPool = undefined;
  await pool.end();
}

module.exports = {
  createSecureShopReviewRepository,
  initializeSecureShopReviewDb,
  getSecureShopReviewPool,
  getSecureShopReviewRepository,
  closeSecureShopReviewDb,
  ENV_KEY,
  MIGRATION_ENV_KEY,
};
