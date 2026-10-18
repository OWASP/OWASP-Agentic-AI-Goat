'use strict';

function unavailable() {
  return Object.assign(new Error('Isolated session disclosure lab unavailable'), {
    code: 'SESSION_DISCLOSURE_UNAVAILABLE', unavailable: true,
  });
}

function createSessionDisclosureLab({ repository } = {}) {
  if (!repository) throw new TypeError('Session disclosure repository required');
  return Object.freeze({
    getOrCreate: ownerId => repository.getOrCreate(ownerId),
    resolve: (ownerId, cookie) => repository.resolve(ownerId, cookie),
    reset: ownerId => repository.reset(ownerId),
    destroyOwner: ownerId => repository.destroyOwner(ownerId),
  });
}

let singleton;
function getSessionDisclosureLab() {
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres' ||
      !process.env.SESSION_DISCLOSURE_DATABASE_URL) throw unavailable();
  singleton ||= createSessionDisclosureLab({
    repository: require('../database/postgres/sessionDisclosureDb').getSessionDisclosureDb(),
  });
  return singleton;
}

async function closeSessionDisclosureLab() {
  singleton = undefined;
  await require('../database/postgres/sessionDisclosureDb').closeSessionDisclosureDb();
}

module.exports = { createSessionDisclosureLab, getSessionDisclosureLab, closeSessionDisclosureLab, unavailable };
