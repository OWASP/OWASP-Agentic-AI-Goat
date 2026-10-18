'use strict';

module.exports = require('./postgresAuth').createPostgresAuthRouter({
  adapter: require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter(),
  limiters: require('../middleware/rateLimiter')
});
