'use strict';

let instance;
function unavailable() {
  throw Object.assign(new Error('Email artifact storage is not ready'), {
    code: 'EMAIL_ARTIFACT_STORAGE_NOT_READY', statusCode: 503,
  });
}
function getStore() {
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres') return null;
  if (!instance) {
    const pool = require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
    instance = require('../database/postgres/emailArtifactRepository').createEmailArtifactRepository(pool);
  }
  return instance;
}
const call = name => (...args) => {
  const store = getStore();
  if (!store || typeof store[name] !== 'function') return unavailable();
  return store[name](...args);
};
module.exports = Object.freeze({
  createMany: call('createMany'), resolveCurrent: call('resolveCurrent'),
  retireOwner: call('retireOwner'), destroyOwner: call('destroyOwner'), assertReady: call('assertReady'),
});
