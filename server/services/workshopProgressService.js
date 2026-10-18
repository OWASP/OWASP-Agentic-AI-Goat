'use strict';
function createWorkshopProgressService(...args) {
  if (args.some(value => value !== undefined)) throw new TypeError('PostgreSQL workshop progress does not accept legacy database options');
  return require('./postgresPlatformStores').getPostgresPlatformStores().progress;
}
module.exports = { createWorkshopProgressService };
