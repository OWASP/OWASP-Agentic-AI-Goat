'use strict';
const { createWorkshopConfigRepository } = require('../database/postgres/workshopConfigRepository');
const { createWorkshopProgressRepository } = require('../database/postgres/workshopProgressRepository');
let stores;
function getPostgresPlatformStores() {
  if (!stores) {
    const { pool } = require('./postgresIdentityAdapter').getPostgresIdentityAdapter();
    const { createWorkshopRevisionStore, createWorkshopModeRepository } = require('../database/postgres/workshopRevisionRepository');
    stores = { config: createWorkshopConfigRepository(pool), progress: createWorkshopProgressRepository(pool), revisions: createWorkshopRevisionStore(pool), modes: createWorkshopModeRepository(pool), pool };
  }
  return stores;
}
module.exports = { getPostgresPlatformStores };
