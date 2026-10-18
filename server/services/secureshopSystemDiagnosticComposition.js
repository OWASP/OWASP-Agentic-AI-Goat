'use strict';

// Constructed explicitly; importing this module does not probe or mount a target.
async function createSecureShopSystemDiagnosticComposition({ agentsPool, personaAuthority,
  audit, client, authenticatePersona, modeAuthority } = {}, {
  createRepository = require('../database/postgres/secureshopSystemDiagnosticRepository').createSystemDiagnosticRepository,
  createService = require('./secureshopBoundSystemDiagnosticService').createBoundSystemDiagnosticService,
  createRouter = require('../routes/secureshop/boundSystemDiagnostic').createBoundSystemDiagnosticRouter,
} = {}) {
  if (typeof modeAuthority?.capture !== 'function' || typeof modeAuthority?.assertToken !== 'function'
      || typeof agentsPool?.query !== 'function' || typeof personaAuthority?.capture !== 'function'
      || typeof audit?.append !== 'function' || typeof client?.execute !== 'function'
      || typeof client?.assertReady !== 'function' || typeof authenticatePersona !== 'function') {
    throw new TypeError('Bound System diagnostic composition dependencies required');
  }
  const repository = createRepository({pool: agentsPool, personaAuthority, audit});
  if (typeof repository?.checkReadiness !== 'function'
      || (await repository.checkReadiness())?.ready !== true) {
    throw new Error('Bound System diagnostic database unavailable');
  }
  // Reject database drift before any remote readiness work. No command is admitted here.
  if (await client.assertReady() !== true) throw new Error('Bound System diagnostic executor unavailable');
  const service = createService({repository, client, modeAuthority});
  if (['execute', 'operation', 'administration'].some(name => typeof service?.[name] !== 'function')) {
    throw new TypeError('Bound System diagnostic service unavailable');
  }
  const router = createRouter({service, authenticatePersona});
  if (typeof router !== 'function') throw new TypeError('Bound System diagnostic router unavailable');
  return Object.freeze({ready: true, repository, service, router});
}
module.exports = {createSecureShopSystemDiagnosticComposition};
