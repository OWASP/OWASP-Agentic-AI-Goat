'use strict';

const FIXED = Object.freeze({
  PG_TEST_DISPOSABLE: 'yes',
  PLATFORM_DATABASE_ENGINE: 'postgres',
  WORKSHOP_DATABASE_ENGINE: 'postgres',
  SS_DISABLE_OLLAMA: 'true',
  SS_ENABLE_REAL_LLM_TESTS: 'false',
  AI_PROVIDER: 'mock',
});

const STORES = Object.freeze([
  Object.freeze({
    name: 'commerce',
    runtimeKey: 'SECURESHOP_DATABASE_URL',
    migrationKey: 'SECURESHOP_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_secureshop_runtime',
    migrationRole: 'dvaia_secureshop_migration',
  }),
  Object.freeze({
    name: 'agents',
    runtimeKey: 'SECURESHOP_AGENTS_DATABASE_URL',
    migrationKey: 'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_secureshop_agents_runtime',
    migrationRole: 'dvaia_secureshop_agents_migration',
  }),
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function admittedUrl(environment, key, expectedRole) {
  const value = environment[key];
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) fail('SECURESHOP_E2E_DATABASE_URL_REQUIRED');
  let url;
  try { url = new URL(value); } catch { fail('SECURESHOP_E2E_DATABASE_URL_INVALID'); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol)) fail('SECURESHOP_E2E_DATABASE_PROTOCOL_DENIED');
  if (url.hostname !== '127.0.0.1') fail('SECURESHOP_E2E_DATABASE_HOST_DENIED');
  if (!/^\d+$/.test(url.port) || Number(url.port) < 1 || Number(url.port) > 65535) fail('SECURESHOP_E2E_DATABASE_PORT_INVALID');
  if (url.search || url.hash) fail('SECURESHOP_E2E_DATABASE_OPTIONS_DENIED');
  let username, database;
  try {
    username = decodeURIComponent(url.username);
    database = decodeURIComponent(url.pathname.slice(1));
  } catch { fail('SECURESHOP_E2E_DATABASE_URL_INVALID'); }
  if (username !== expectedRole) fail('SECURESHOP_E2E_DATABASE_ROLE_DENIED');
  if (!/^dvaia_test_[a-z0-9_]+$/.test(database)) fail('SECURESHOP_E2E_DATABASE_NAME_DENIED');
  return Object.freeze({value, hostname:url.hostname, port:url.port, database});
}

function admitSecureShopE2ePostgres(environment) {
  if (!environment || typeof environment !== 'object') fail('SECURESHOP_E2E_ENVIRONMENT_REQUIRED');
  for (const [key, expected] of Object.entries(FIXED)) if (environment[key] !== expected) fail(`SECURESHOP_E2E_${key}_DENIED`);
  const admitted = {};
  const identities = [];
  for (const store of STORES) {
    const runtime = admittedUrl(environment, store.runtimeKey, store.runtimeRole);
    const migration = admittedUrl(environment, store.migrationKey, store.migrationRole);
    if (runtime.hostname !== migration.hostname || runtime.port !== migration.port || runtime.database !== migration.database) fail('SECURESHOP_E2E_DATABASE_PAIR_MISMATCH');
    if (runtime.value === migration.value) fail('SECURESHOP_E2E_DATABASE_PAIR_NOT_DISTINCT');
    identities.push(`${runtime.hostname}:${runtime.port}/${runtime.database}`);
    admitted[store.runtimeKey] = runtime.value;
    admitted[store.migrationKey] = migration.value;
  }
  if (identities[0] === identities[1]) fail('SECURESHOP_E2E_DATABASE_STORES_NOT_DISTINCT');
  return Object.freeze({...FIXED, ...admitted});
}

module.exports = Object.freeze({admitSecureShopE2ePostgres});
