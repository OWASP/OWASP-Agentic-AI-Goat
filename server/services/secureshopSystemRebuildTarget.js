'use strict';

const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { createPersonaProductEffect } = require('./secureshopPersonaProductEffect');
const { executionScope } = require('./secureshopSceneBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const failure = code => Object.assign(new Error('Existing rebuild target unavailable'), { code });

// Internal read-only admission preparation. It cannot allocate a reservation or
// provision catalog rows. Durable operation admission must precede any rebuild.
function createSystemRebuildTargetResolver({ launches, products, personaAuthority, scenes } = {}) {
  if (typeof launches?.assertCurrent !== 'function' || typeof launches?.readExistingProductsTarget !== 'function'
      || (scenes !== undefined && typeof scenes?.readExisting !== 'function')
      || typeof products?.open !== 'function' || typeof personaAuthority?.capture !== 'function') {
    throw new TypeError('Existing target and persona authority required');
  }
  return async function resolve(raw, { signal } = {}) {
    const input = structuredClone(raw);
    const scope = createLaunchScope(input?.scope);
    const personaBinding = createConversationBinding(scope, input?.persona);
    if (personaBinding.role !== 'admin') throw failure('ADMIN_REQUIRED');
    const session = input.personaSession;
    if (typeof session?.sessionId !== 'string' || !UUID.test(session.sessionId)
        || typeof session.authorityVersion !== 'string' || !/^[1-9]\d{0,15}$/.test(session.authorityVersion)
        || BigInt(session.authorityVersion) > BigInt(Number.MAX_SAFE_INTEGER)) throw failure('SHOP_AUTH_INVALID');
    const expected = Object.freeze({ ...scope, personaId: personaBinding.shopUserId, role: 'admin',
      sessionId: session.sessionId, authorityVersion: session.authorityVersion });
    signal?.throwIfAborted();
    await launches.assertCurrent(scope);
    const fence = await personaAuthority.capture({ scope, personaId: expected.personaId, role: 'admin',
      sessionId: expected.sessionId, authorityVersion: expected.authorityVersion });
    if (!fence?.binding || Object.keys(expected).some(key => fence.binding[key] !== expected[key])
        || typeof fence.assertRemoteAdmission !== 'function' || typeof fence.withCrossStoreEffect !== 'function') {
      throw failure('SHOP_AUTH_INVALID');
    }
    const personaEffect = createPersonaProductEffect(fence);
    const check = async () => {
      signal?.throwIfAborted();
      await launches.assertCurrent(scope);
      await personaEffect.check(scope);
      signal?.throwIfAborted();
    };
    await check();
    const reserved = scenes ? await scenes.readExisting(scope) : await launches.readExistingProductsTarget(scope);
    await check();
    if (!reserved || (!scenes && reserved.kind !== 'products') || typeof reserved.targetId !== 'string'
        || !UUID.test(reserved.targetId)
        || ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
          .some(key => executionScope(reserved)[key] !== scope[key])) {
      throw failure('PRODUCT_TARGET_UNAVAILABLE');
    }
    const binding = scenes ? reserved : Object.freeze({ ...scope, targetId: reserved.targetId });
    const opened = await products.open(binding);
    await check();
    if (!opened || Object.keys(binding).some(key => opened[key] !== binding[key])) throw failure('PRODUCT_TARGET_UNAVAILABLE');
    return Object.freeze({ binding, personaEffect, actor: Object.freeze({ id: expected.personaId,
      role: 'admin', sessionId: expected.sessionId, authorityVersion: expected.authorityVersion }) });
  };
}

module.exports = { createSystemRebuildTargetResolver };
