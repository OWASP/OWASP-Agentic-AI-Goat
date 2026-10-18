#!/usr/bin/env node
'use strict';

// Compatibility entry point for application initialization. Fresh provisioning
// belongs to setup-application.js; existing learner data must remain intact.
const HELP = `DVAIA application initialization
Usage: node scripts/deploy-fresh.js [init|full|help]

init / initialize / full / comprehensive
  Apply PostgreSQL migrations and idempotent seeds to configured stores.
  Existing learner data is preserved. First-time provisioning: npm run setup

reset / reset-full / reset-comprehensive
  Unsupported here. Use authenticated workshop reset or student deletion
  controls so owner isolation, external cleanup and progress stay consistent.
`;

async function main(args = process.argv.slice(2), dependencies = {}) {
  const output = dependencies.output || console.log;
  const error = dependencies.error || console.error;
  if (args.length > 1 || (args.length && typeof args[0] !== 'string')) {
    error('Expected one command. Use npm run deploy:help.');
    return 1;
  }
  const command = (args[0] || 'init').toLowerCase();
  if (['help', '-h', '--help'].includes(command)) {
    output(HELP);
    return 0;
  }
  if (['reset', 'reset-full', 'reset-comprehensive'].includes(command)) {
    error('Direct reset is unavailable. Use authenticated workshop reset or student deletion controls. No data was changed.');
    return 1;
  }
  if (!['init', 'initialize', 'full', 'comprehensive'].includes(command)) {
    error('Unknown command. Use npm run deploy:help.');
    return 1;
  }
  try {
    // Import only after argument validation: even help must have no database
    // side effects, and legacy SQLite initialization is never selected.
    const initialize = dependencies.initialize || (() => require('./application-journal-bound-maintenance').runProspectiveJournalBoundMaintenance({installationRoot:require('node:path').resolve(__dirname,'..')}));
    await initialize();
    output('PostgreSQL initialization completed. Existing learner data was preserved.');
    return 0;
  } catch (failure) {
    // Database/provider errors may contain credentials or connection strings.
    error('PostgreSQL initialization failed. Check configured store credentials and migration readiness; use npm run setup for first-time provisioning.');
    if (failure?.code === 'APPLICATION_INITIALIZATION_REQUIRES_EXIT') throw failure;
    return 1;
  }
}

if (require.main === module) main().then(code => { process.exitCode = code; }).catch(error => {
  if (error.code === 'APPLICATION_INITIALIZATION_REQUIRES_EXIT') process.exit(1);
  else process.exitCode = 1;
});
module.exports = { main, HELP };
