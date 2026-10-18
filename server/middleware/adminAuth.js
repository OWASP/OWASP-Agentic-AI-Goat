'use strict';

module.exports = require('./postgresAdminAuth').createPostgresAdminAuth(
  require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter()
);
