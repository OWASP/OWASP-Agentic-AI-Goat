'use strict';

// The PostgreSQL router retains these deliberate teaching sinks.
// @intentional-vulnerability xss-stored-review
// @intentional-vulnerability sqli-coupon
module.exports = require('./postgres/customer');
