'use strict';

const FIELDS = ['schema', 'database', 'runtimeRole', 'migrationRole', 'runtimeVariable', 'migrationVariable'];
function invalid() { const error = new Error('PROVISIONING_EXTENSION_INVALID'); error.code = error.message; throw error; }

// A plan comparison is not an ownership check. The caller must separately
// verify the recorded cluster, roles and databases before any provisioning.
function provisioningExtension(previous, desired) {
  if (!Array.isArray(previous) || !Array.isArray(desired) || !previous.length || desired.length < previous.length) invalid();
  for (const plan of [previous, desired]) {
    const identities = new Set();
    for (const row of plan) {
      if (!row || Object.keys(row).length !== FIELDS.length || FIELDS.some(key => typeof row[key] !== 'string' || !row[key])) invalid();
      if (!/^[a-z][a-z_]*$/.test(row.schema) || row.database !== `owasp_ai_goat_${row.schema}`
          || row.runtimeRole !== `dvaia_${row.schema}_runtime` || row.migrationRole !== `dvaia_${row.schema}_migration`
          || !/^[A-Z][A-Z_]*_DATABASE_URL$/.test(row.runtimeVariable)
          || row.migrationVariable !== row.runtimeVariable.replace(/_DATABASE_URL$/, '_MIGRATION_DATABASE_URL')) invalid();
      for (const key of FIELDS) {
        const identity = `${key}:${row[key]}`;
        if (identities.has(identity)) invalid();
        identities.add(identity);
      }
    }
  }
  for (let index = 0; index < previous.length; index++) {
    if (FIELDS.some(key => previous[index][key] !== desired[index][key])) invalid();
  }
  return desired.slice(previous.length).map(row => ({ ...row }));
}
module.exports = { provisioningExtension };
