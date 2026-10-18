'use strict';
const { assertSecureShopStandalonePrincipal } = require('./secureshopStandaloneAuth');

function createSecureShopStandaloneBootstrap({ launches, personaAuth, authService, now = Date.now } = {}) {
  if (typeof launches?.issueOrRenew !== 'function' || typeof personaAuth?.establishSession !== 'function'
      || typeof authService?.establishTenantContext !== 'function') {
    throw TypeError('Standalone shop execution dependencies required');
  }
  return async function bootstrap(rawPrincipal) {
    const principal = assertSecureShopStandalonePrincipal(await authService.establishTenantContext(rawPrincipal));
    const expiresAt = new Date(Math.min(now() + 30 * 60 * 1000, Date.parse(principal.expiresAt))).toISOString();
    const result = await launches.issueOrRenew({ platformOwnerId: principal.ownerId,
      platformSessionId: principal.sessionId, expiresAt, shopPrincipal: principal });
    const actor = await personaAuth.establishSession({ scope: result.binding, shopPrincipal: principal });
    const b = result.binding;
    const user = actor.user;
    return Object.freeze({
      launch: Object.freeze({ launchId: b.launchId, generation: b.generation,
        credentialVersion: b.credentialVersion, expiresAt: new Date(b.expiresAt).toISOString() }),
      bearer: result.bearer,
      persona: Object.freeze({ token: actor.token, expiresAt: new Date(actor.expiresAt).toISOString(),
        user: Object.freeze({ id: user.id, username: user.username, email: user.email,
          role: user.role, full_name: user.full_name ?? null, phone: user.phone ?? null }) }),
    });
  };
}
module.exports = { createSecureShopStandaloneBootstrap };
