'use strict';

// The PostgreSQL router retains the gated alg=none teaching sink.
// @intentional-vulnerability auth-bypass-jwt-none
module.exports = require('./postgres/admin');
