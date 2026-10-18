'use strict';
const express = require('express');

async function createSecureShopSystemConfigComposition({ agentsPool, personaAuthority, audit,
  client, authenticatePersona, modeAuthority } = {}, {
  createRepository = require('../database/postgres/secureshopSystemConfigReadRepository')
    .createSystemConfigReadRepository,
  createService = require('./secureshopBoundSystemConfigReadService')
    .createBoundSystemConfigReadService,
  createRouter = require('../routes/secureshop/boundSystemConfig').createBoundSystemConfigRouter,
  createHealthService = require('./secureshopBoundSystemHealthService').createBoundSystemHealthService,
  createHealthRouter = require('../routes/secureshop/boundSystemHealth').createBoundSystemHealthRouter,
} = {}) {
  if (typeof agentsPool?.query !== 'function' || typeof personaAuthority?.capture !== 'function'
      || typeof audit?.append !== 'function' || typeof client?.read !== 'function' || typeof client?.metrics !== 'function'
      || typeof client?.assertReady !== 'function' || typeof authenticatePersona !== 'function') {
    throw new TypeError('Bound System config composition dependencies required');
  }
  const repository = createRepository({ pool: agentsPool, personaAuthority, audit, modeAuthority });
  if (typeof repository?.checkReadiness !== 'function') {
    throw new TypeError('Bound System config repository readiness required');
  }
  await repository.checkReadiness();
  const service = createService({ repository, client, modeAuthority });
  const router = createRouter({ service, authenticatePersona });
  const healthService = createHealthService({ repository, metrics: { snapshot: healthOptions => client.metrics(healthOptions) } });
  const healthRouter = createHealthRouter({ service: healthService, authenticatePersona });
  const combinedRouter = express.Router(); combinedRouter.use(router); combinedRouter.use(healthRouter);
  if (typeof service?.read !== 'function' || typeof service?.operation !== 'function'
      || typeof service?.administration !== 'function' || typeof router !== 'function' || typeof healthRouter !== 'function') {
    throw new TypeError('Bound System config composition unavailable');
  }
  return Object.freeze({ ready: true, repository, service, healthService, router: combinedRouter });
}

module.exports = { createSecureShopSystemConfigComposition };
