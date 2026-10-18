const { createChangeRevisionService } = require('./changeRevisionServiceFactory');
const logger = require('../utils/logger');
const store = require('./postgresPlatformStores').getPostgresPlatformStores().revisions;
module.exports = createChangeRevisionService(store, logger);
