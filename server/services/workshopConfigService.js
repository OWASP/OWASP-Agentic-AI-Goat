'use strict';
function createWorkshopConfigService(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options) || Reflect.ownKeys(options).length) {
    throw new TypeError('PostgreSQL workshop service does not accept legacy database options');
  }
  return require('./postgresPlatformStores').getPostgresPlatformStores().config;
}
module.exports = { createWorkshopConfigService };
