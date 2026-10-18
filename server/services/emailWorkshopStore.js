'use strict';

let instance;
function getStore() {
  if (!instance) instance = require('../database/postgres/emailWorkshopRepository').createEmailWorkshopRepository(require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool);
  return instance;
}
module.exports = Object.fromEntries(['saveConfiguredEmail', 'logSentEmail', 'completeObjective', 'listProgress', 'resetProgress', 'getConfiguredEmail'].map(name => [name, (...args) => getStore()[name](...args)]));
