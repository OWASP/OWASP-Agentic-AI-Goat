#!/usr/bin/env node
'use strict';

// The historical command mutated obsolete SQLite files outside the active
// PostgreSQL catalog. Keep this entry point only to explain its replacement.
const message = 'Legacy PR6 visibility repair is retired. Manage current exercise and objective visibility in /admin/exercises. The PostgreSQL catalog is authoritative; a verification command must not silently enable exercises. No database was opened or changed.';
if (process.argv.length === 3 && ['--help', '-h'].includes(process.argv[2])) {
  console.log(message);
} else {
  console.error(message);
  process.exitCode = 1;
}
