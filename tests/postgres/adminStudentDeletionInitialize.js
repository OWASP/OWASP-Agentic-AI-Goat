'use strict';

// Fixed, test-only entry: the exported initializer acquires its own genuine
// maintenance lease for the admitted disposable identity database. This entry
// never loads installation configuration, environment files, or CLI profiles.
const {
  initializeApplication,
  initializationFailureSummary,
} = require('../../db/postgres/initialize-application');
const { admitStores } = require('./adminStudentDeletionRenderedSupport');

try {
  admitStores(process.env);
  Promise.resolve().then(() => initializeApplication()).catch(error => {
    process.stderr.write(`Student-deletion initialization failed: ${JSON.stringify(initializationFailureSummary(error))}\n`);
    // An uncertain/retained lease must end with the owned child, exactly as the
    // canonical maintenance CLI requires. The launcher proves child absence.
    if (error?.code === 'APPLICATION_INITIALIZATION_REQUIRES_EXIT') return process.exit(1);
    process.exitCode = 1;
  });
} catch (error) {
  process.stderr.write(`Student-deletion initialization admission failed: ${JSON.stringify(initializationFailureSummary(error))}\n`);
  process.exitCode = 1;
}
