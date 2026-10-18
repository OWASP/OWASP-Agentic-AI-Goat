#!/usr/bin/env node
/**
 * Retired operator wrapper for the historical SecureShop SQLite bulk seed.
 * The seed itself remains available to explicitly isolated legacy fixtures.
 */

console.error(
  '[seed-bulk-data] This SQLite repair command is retired. Supported application '
  + 'setup and data initialization use PostgreSQL: npm run setup or npm run db:initialize-all.'
);
console.error(
  '[seed-bulk-data] Historical SQLite fixtures must use the retained '
  + 'db/initialize-db/run-all.js runner with an owned disposable DB_OUTPUT_DIR.'
);
process.exitCode = 1;
