'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const {
  normalizeArchiveOwnerBinding,
  recordArchiveOwnerBinding,
  verifyArchiveOwnerBinding,
} = require('../../../db/postgres/archive-owner-binding');

const TEST_DATABASE = /^dvaia_test_[a-z0-9_]+$/;
const MAX_TARGET_ID = 2147483647;

function fixtureError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

/**
 * Create a real, module-branded owner proof inside a family's disposable
 * PostgreSQL database. This is deliberately separate from the fake-query unit
 * helper in tests/fixtures/archiveOwnerBinding.js.
 *
 * The fixture installs only identity.users plus the repository's actual 0019
 * binding migration in a temporary identity schema. The full identity
 * migration chain, roles, transaction, and immutability are covered by
 * platformIdentityImport.integration.test.js. Call cleanup() in finally.
 */
async function createNativeOwnerProof(pool, rawBinding, {
  unrelatedUserIds = [7],
  disposableMarker = process.env.PG_TEST_DISPOSABLE,
} = {}) {
  if (!pool || typeof pool.query !== 'function') throw fixtureError('NATIVE_OWNER_PROOF_POOL_REQUIRED');
  if (disposableMarker !== 'yes') throw fixtureError('PG_TEST_DISPOSABLE_REQUIRED');

  const context = (await pool.query('SELECT current_database() AS database')).rows[0];
  if (!context || !TEST_DATABASE.test(context.database)) throw fixtureError('DISPOSABLE_TEST_DATABASE_REQUIRED');
  const existing = (await pool.query("SELECT to_regnamespace('identity') IS NOT NULL AS present")).rows[0];
  if (existing?.present === true) throw fixtureError('IDENTITY_FIXTURE_SCHEMA_ALREADY_EXISTS');

  const binding = normalizeArchiveOwnerBinding(rawBinding);
  const targets = new Set(binding.entries.map(([, target]) => target));
  const extras = [];
  for (const value of unrelatedUserIds) {
    if (!Number.isInteger(value) || value < 1 || value > MAX_TARGET_ID) {
      throw fixtureError('INVALID_UNRELATED_FIXTURE_USER');
    }
    if (!targets.has(value)) extras.push(value);
  }
  const userIds = [...new Set([...targets, ...extras])].sort((left, right) => left - right);
  const migrationSql = await fs.readFile(path.join(
    __dirname, '../../../db/postgres/identity-migrations/0019_archive_owner_bindings.sql',
  ), 'utf8');
  let schemaCreated = false;
  try {
    await pool.query('CREATE SCHEMA identity');
    schemaCreated = true;
    await pool.query('CREATE TABLE identity.users (id integer PRIMARY KEY)');
    await pool.query(`CREATE FUNCTION identity.reject_historical_provenance_mutation()
      RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'Historical provenance is immutable' USING ERRCODE='55000';
      END $$`);
    await pool.query(migrationSql);
    if (userIds.length) {
      await pool.query('INSERT INTO identity.users(id) SELECT unnest($1::int[])', [userIds]);
    }
    await recordArchiveOwnerBinding(pool, binding);
    const ownerProof = await verifyArchiveOwnerBinding(pool, binding);
    let cleaned = false;
    return {
      ownerProof,
      async cleanup() {
        if (cleaned) return;
        cleaned = true;
        await pool.query('DROP SCHEMA identity CASCADE');
      },
    };
  } catch (error) {
    if (schemaCreated) {
      try { await pool.query('DROP SCHEMA identity CASCADE'); } catch {}
    }
    throw error;
  }
}

module.exports = { createNativeOwnerProof };
