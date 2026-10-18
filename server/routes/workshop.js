'use strict';

const adapter = require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter();
const postgresAuth = require('../middleware/postgresAdminAuth').createPostgresAdminAuth(adapter);
const router = require('./postgresWorkshop').createPostgresWorkshopRouter({
  stores: require('../services/postgresPlatformStores').getPostgresPlatformStores(),
  authenticateToken: postgresAuth.authenticateToken,
  requirePermission: postgresAuth.requirePermission,
});
router.createWorkshopProgressHandlers = require('./workshopProgressHandlers').createWorkshopProgressHandlers;
router.createWorkshopTimeHandlers = require('./workshopTimeHandlers').createWorkshopTimeHandlers;
module.exports = router;
