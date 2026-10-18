/**
 * This file is retained as historical source for the isolated teaching sinks.
 * It is not an application entrypoint: loading it used to initialize the
 * SQLite platform/challenge databases before the caller could choose the
 * PostgreSQL runtime. Keep this guard before every import so an accidental
 * `node server/secureServer.js` cannot touch working data.
 */
const LEGACY_ENTRYPOINT_ERROR_CODE = 'ERR_DVAIA_LEGACY_ENTRYPOINT_RETIRED';
const LEGACY_ENTRYPOINT_MESSAGE =
  'server/secureServer.js is retired; use npm run server or npm run dev (server/index.js) with PostgreSQL.';

if (require.main === module) {
  console.error(`[DVAIA] ${LEGACY_ENTRYPOINT_MESSAGE}`);
  process.exit(1);
}

const retiredEntryPointError = new Error(LEGACY_ENTRYPOINT_MESSAGE);
retiredEntryPointError.code = LEGACY_ENTRYPOINT_ERROR_CODE;
throw retiredEntryPointError;
