'use strict';

const { repositories } = require('../db/postgres/initialize-application');

async function initializeAdditions(schemas, { environment = process.env, load = require, maintenanceScope } = {}) {
  if (!Array.isArray(schemas) || !schemas.length || new Set(schemas).size !== schemas.length) {
    throw Object.assign(new Error('At least one unique appended schema is required'), { code: 'INVALID_ADDITIVE_SCHEMA' });
  }
  const selected = schemas.map(schema => {
    const row = repositories.find(item => item[0] === schema);
    if (!row || schema === 'identity') throw Object.assign(new Error('Only appended workshop schemas may be initialized'), { code: 'INVALID_ADDITIVE_SCHEMA' });
    return row;
  });
  // Preflight the complete selected closure before any initializer can write.
  const keys = ['IDENTITY_DATABASE_URL', 'IDENTITY_MIGRATION_DATABASE_URL', 'PG_TLS',
    ...selected.flatMap(([, prefix]) => [`${prefix}_DATABASE_URL`, `${prefix}_MIGRATION_DATABASE_URL`])];
  for (const key of keys) if (environment[key] !== process.env[key]) throw Object.assign(Error('Additive environment differs from process snapshot'), { code: 'ADDITIVE_ENVIRONMENT_MISMATCH' });
  const tools = require('./lib/application-maintenance-scope');
  if (!maintenanceScope) return tools.withApplicationMaintenanceScope({ environment }, scope => initializeAdditions(schemas, { environment, load, maintenanceScope: scope }));
  tools.assertApplicationMaintenanceScope(maintenanceScope, environment);
  for (const [schema, prefix, moduleName, method] of selected) {
    if (!environment[`${prefix}_DATABASE_URL`] || !environment[`${prefix}_MIGRATION_DATABASE_URL`]) {
      throw Object.assign(new Error(`Missing configuration for ${schema}`), { code: 'MISSING_ADDITIVE_CONFIGURATION' });
    }
    if (environment[`${prefix}_DATABASE_URL`] !== process.env[`${prefix}_DATABASE_URL`] || environment[`${prefix}_MIGRATION_DATABASE_URL`] !== process.env[`${prefix}_MIGRATION_DATABASE_URL`]) throw Object.assign(Error('Additive environment differs from process snapshot'), { code: 'ADDITIVE_ENVIRONMENT_MISMATCH' });
    try {
      maintenanceScope.assertHeld();
      await load(`../server/database/postgres/${moduleName}`)[method]();
      maintenanceScope.assertHeld();
    } catch (error) { tools.invalidateApplicationMaintenanceScope(maintenanceScope); throw error; }
    console.log(`Initialized additive PostgreSQL repository: ${schema}`);
  }
}

if (require.main === module) {
  require('dotenv').config({ quiet: true });
  initializeAdditions(process.argv.slice(2)).catch(error => {
    console.error('Additive PostgreSQL initialization failed:', error.code || error.message);
    if (error.code === 'APPLICATION_INITIALIZATION_REQUIRES_EXIT') process.exit(1);
    else process.exitCode = 1;
  });
}

module.exports = { initializeAdditions };
