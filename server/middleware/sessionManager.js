'use strict';

module.exports = require('./postgresSessionManager').createPostgresSessionManager(
  require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter()
);
