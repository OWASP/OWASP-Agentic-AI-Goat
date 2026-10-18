'use strict';

const POSTGRES_ENGINE = 'postgres';
const REQUIRED_ENGINE_ERROR_CODE = 'ERR_POSTGRES_REQUIRED';

function resolveApplicationDatabaseEngine({ env = process.env } = {}) {
  if (env.PLATFORM_DATABASE_ENGINE === POSTGRES_ENGINE
    && env.WORKSHOP_DATABASE_ENGINE === POSTGRES_ENGINE) return POSTGRES_ENGINE;

  const reason = env.PLATFORM_DATABASE_ENGINE === undefined ? 'missing' : 'unsupported';
  const error = new Error(
    `PostgreSQL is required for the application (database engine ${reason}). ` +
    'Set PLATFORM_DATABASE_ENGINE=postgres and WORKSHOP_DATABASE_ENGINE=postgres. Tests must use owned disposable PostgreSQL stores.'
  );
  error.code = REQUIRED_ENGINE_ERROR_CODE;
  throw error;
}

function assertApplicationDatabaseEngine(options) {
  return resolveApplicationDatabaseEngine(options);
}

module.exports = {
  POSTGRES_ENGINE,
  REQUIRED_ENGINE_ERROR_CODE,
  resolveApplicationDatabaseEngine,
  assertApplicationDatabaseEngine,
};
