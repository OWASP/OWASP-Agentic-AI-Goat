'use strict';
const { assertSecureShopStandalonePrincipal } = require('./secureshopStandaloneAuth');
function createSecureShopStandaloneMode({authService,repository}) {
  if (typeof authService?.establishTenantContext !== 'function'
      || typeof repository?.getPrincipalMode !== 'function' || typeof repository?.setPrincipalMode !== 'function') {
    throw new TypeError('Canonical shop mode dependencies required');
  }
  const context = async base => assertSecureShopStandalonePrincipal(await authService.establishTenantContext(base));
  return Object.freeze({
    async get(base) { return repository.getPrincipalMode(await context(base)); },
    async set(base, input) {
      if (!input || !['vuln','fixed'].includes(input.mode) || typeof input.expectedRevision !== 'string'
          || !/^[1-9][0-9]{0,18}$/.test(input.expectedRevision)
          || BigInt(input.expectedRevision)>9223372036854775807n) {
        throw Object.assign(new Error('Invalid shop mode'),{code:'INVALID_ARGUMENT'});
      }
      return repository.setPrincipalMode(await context(base),input);
    },
  });
}
module.exports={createSecureShopStandaloneMode};
