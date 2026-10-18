"use strict";
// Test-only historical schema views. Canonical SQL stays on disk unchanged.
const fs = require('node:fs/promises');
const syncFs = require('node:fs');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
function createXssBoundedMigrationView({ identity, xss = 15, identityFailureSql }) {
  const directories = {
    identity: path.resolve(__dirname, '../../db/postgres/identity-migrations'),
    xss: path.resolve(__dirname, '../../db/postgres/workshop-migrations/xss'),
  };
  const ceilings = {};
  function setCeiling(store, value) {
    if (!Object.hasOwn(directories, store) || !Number.isInteger(value) || value < 1)
      throw new TypeError('Explicit positive historical migration ceiling required');
    if (store === 'identity' && identityFailureSql !== undefined && Object.hasOwn(ceilings, store))
      throw new TypeError('Failure-injection identity ceiling is immutable');
    if (store === 'identity' && identityFailureSql !== undefined && value >= 9999)
      throw new TypeError('Failure migration requires an available four-digit version');
    ceilings[store] = value;
  }
  setCeiling('identity', identity); setCeiling('xss', xss);
  if (identityFailureSql !== undefined && (typeof identityFailureSql !== 'string' || !identityFailureSql.includes("RAISE EXCEPTION 'owned qualification rollback'")))
    throw new TypeError('Explicit owned failure SQL required');
  const failureName = `${String(identity + 1).padStart(4, '0')}_qualification_failure.sql`;
  const virtualFs = { ...fs, async readdir(directory, ...args) {
    const names = await fs.readdir(directory, ...args);
    const store = Object.keys(directories).find(key => path.resolve(directory) === directories[key]);
    if (!store) return names;
    const selected = names.filter(name => !/^\d{4}_[a-z0-9_]+\.sql$/.test(name)
      || Number(name.slice(0, 4)) <= ceilings[store]);
    return store === 'identity' && identityFailureSql !== undefined ? [...selected, failureName] : selected;
  }, async readFile(filename, ...args) {
    if (identityFailureSql !== undefined && path.resolve(filename) === path.join(directories.identity, failureName)) return identityFailureSql;
    return fs.readFile(filename, ...args);
  } };
  function load(filename, overrides) {
    const local = createRequire(filename), loaded = new Module(filename, module);
    loaded.filename = filename;
    loaded.require = name => Object.hasOwn(overrides, name) ? overrides[name] : local(name);
    loaded._compile(syncFs.readFileSync(filename, 'utf8'), filename);
    return loaded.exports;
  }
  const migrator = load(require.resolve('../../db/postgres/migrate'), {
    'node:fs/promises': virtualFs, 'fs/promises': virtualFs,
  });
  const identityRepository = load(require.resolve('../../server/database/postgres/identityRepository'), {
    '../../../db/postgres/migrate': migrator,
  });
  const support = load(require.resolve('../../server/database/postgres/workshopSupport'), {
    '../../../db/postgres/migrate': migrator,
  });
  const xssRepository = load(require.resolve('../../server/database/postgres/xssWorkshopDb'), {
    './workshopSupport': support,
  });
  return { directories, setCeiling, ...migrator, ...identityRepository,
    createXssWorkshopDb: xssRepository.createXssWorkshopDb };
}
module.exports = { createXssBoundedMigrationView };
