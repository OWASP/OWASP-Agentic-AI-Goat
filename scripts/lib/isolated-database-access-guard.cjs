'use strict';

const Module = require('node:module');

const CODE = 'ISOLATED_DATABASE_ACCESS_DENIED';
const installed = Symbol.for('dvaia.isolatedDatabaseAccessGuard');

function denied() {
  throw Object.assign(new Error('Controlled aggregate denies database access'), { code: CODE });
}

function assertEnvironment(environment = process.env) {
  const forbidden = Object.keys(environment).filter(key =>
    key === 'DATABASE_URL' || key === 'DB_OUTPUT_DIR' || key.endsWith('_DATABASE_URL')
    || key.endsWith('_DB_PATH') || ['PGHOST','PGHOSTADDR','PGPORT','PGDATABASE','PGUSER','PGPASSWORD','PGPASSFILE','PGSERVICE','PGSERVICEFILE'].includes(key));
  if (forbidden.length) denied();
}

function patchPrototype(value) {
  const prototype = typeof value === 'function' ? value.prototype : value;
  if (!prototype || (typeof prototype !== 'object' && typeof prototype !== 'function')) return value;
  for (const method of ['connect', 'query']) {
    if (typeof prototype[method] === 'function') {
      Object.defineProperty(prototype, method, { configurable: true, writable: true, value: denied });
    }
  }
  return value;
}

function patchPostgres(value) {
  patchPrototype(value);
  if (value && (typeof value === 'object' || typeof value === 'function')) {
    for (const name of ['Client', 'Pool', 'native']) {
      let member;
      try { member = value[name]; } catch { member = null; }
      if (member && name === 'native') patchPostgres(member);
      else patchPrototype(member);
    }
  }
  return value;
}

function patchSqlite3(value) {
  if (!value || typeof value !== 'object') return value;
  const wrapped = Object.create(Object.getPrototypeOf(value), Object.getOwnPropertyDescriptors(value));
  const DeniedDatabase = class { constructor() { denied(); } };
  Object.defineProperty(wrapped, 'Database', { configurable: false, enumerable: true, writable: false, value: DeniedDatabase });
  if (value.cached && typeof value.cached === 'object') {
    const cached = Object.create(Object.getPrototypeOf(value.cached), Object.getOwnPropertyDescriptors(value.cached));
    Object.defineProperty(cached, 'Database', { configurable: false, enumerable: true, writable: false, value: denied });
    Object.defineProperty(wrapped, 'cached', { configurable: false, enumerable: true, writable: false, value: cached });
  }
  Object.defineProperty(wrapped, 'verbose', { configurable: false, enumerable: true, writable: false, value: () => wrapped });
  return wrapped;
}

function patchBetterSqlite(value) {
  if (typeof value !== 'function') return value;
  return new Proxy(value, { apply: denied, construct: denied });
}

function install({ moduleApi = Module, environment = process.env } = {}) {
  assertEnvironment(environment);
  if (moduleApi[installed]) return;
  const originalLoad = moduleApi._load;
  Object.defineProperty(moduleApi, installed, { value: true });
  moduleApi._load = function guardedLoad(request, parent, isMain) {
    const value = originalLoad.call(this, request, parent, isMain);
    if (request === 'sqlite3') return patchSqlite3(value);
    if (request === 'better-sqlite3') return patchBetterSqlite(value);
    if (request === 'pg' || request === 'pg-pool' || request.startsWith('pg/')) return patchPostgres(value);
    return value;
  };
}

install();

module.exports = { CODE, assertEnvironment, install, patchBetterSqlite, patchPostgres, patchSqlite3 };
