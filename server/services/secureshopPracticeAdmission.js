'use strict';
const { assertSecureShopStandaloneAuthPrincipal } = require('./secureshopStandaloneAuth');
function createSecureShopPracticeAdmission({ repository, catalog } = {}) {
  if (['read','admit','publish'].some(key => typeof repository?.[key] !== 'function')
    || typeof catalog?.provisionPracticeTarget !== 'function') throw TypeError('Practice admission dependencies required');
  return Object.freeze({
    read(principal, operationId) {
      return repository.read(assertSecureShopStandaloneAuthPrincipal(principal), operationId);
    },
    async create(principal, operationId) {
      const base = assertSecureShopStandaloneAuthPrincipal(principal);
      const admitted = await repository.admit(base, operationId);
      if (admitted.status !== 'pending') return admitted;
      return repository.publish(base, operationId, claim => catalog.provisionPracticeTarget(claim));
    },
  });
}
module.exports = { createSecureShopPracticeAdmission };
