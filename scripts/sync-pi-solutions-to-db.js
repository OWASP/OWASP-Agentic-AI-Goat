#!/usr/bin/env node
'use strict';

// The historical command mutated obsolete SQLite files outside the active
// PostgreSQL catalog. Keep this entry point only to explain its replacement.
const message = 'Legacy Prompt Injection solution synchronization is retired. Edit current objective hints and solutions in /admin/exercises. Ship default content changes through forward-only PostgreSQL migrations that preserve instructor edits. No database was opened or changed.';
if (process.argv.length === 3 && ['--help', '-h'].includes(process.argv[2])) {
  console.log(message);
} else {
  console.error(message);
  process.exitCode = 1;
}
