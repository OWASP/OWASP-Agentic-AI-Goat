'use strict';

const { createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { captureFeatureMode } = require('./secureshopFeatureModeAuthority');

const unavailable = (code = 'SHOP_AUTH_INVALID') => Object.assign(
  new Error('Ticket administration unavailable'), { code, executionBoundary: true });
const sameScope = (a, b) => Object.keys(a).every(key => a[key] === b?.[key]);

// A read never creates a shop, grants a scene, or resumes a customer effect.
// Repository reads separately check the durable producer and current consumer grants.
function createTicketAdministration({ launches, personaAuthority, modeAuthority, scenes, repository } = {}) {
  if (typeof launches?.assertCurrent !== 'function' || typeof personaAuthority?.capture !== 'function'
      || typeof modeAuthority?.capture !== 'function' || typeof modeAuthority?.assertToken !== 'function'
      || typeof scenes?.readRetained !== 'function' || typeof repository?.listForAdmin !== 'function'
      || typeof repository?.readForAdmin !== 'function') throw TypeError('Ticket administration dependencies required');

  async function read(input, options, method) {
    const scope = createLaunchScope(input?.scope);
    if (input?.persona?.role !== 'admin' || !Number.isSafeInteger(input.persona.id) || input.persona.id < 1
        || typeof input.personaSession?.sessionId !== 'string'
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.personaSession.sessionId)
        || typeof input.personaSession.authorityVersion !== 'string'
        || !/^[1-9]\d*$/.test(input.personaSession.authorityVersion)) throw unavailable();
    const persona = Object.freeze({ id: input.persona.id, role: 'admin' });
    const personaSession = Object.freeze({ sessionId: input.personaSession.sessionId.toLowerCase(),
      authorityVersion: input.personaSession.authorityVersion });
    const selected = Object.freeze({ ...options });
    await launches.assertCurrent(scope);
    const fence = await personaAuthority.capture({ scope, personaId: persona.id, role: persona.role, ...personaSession });
    if (typeof fence?.assertRemoteAdmission !== 'function' || !sameScope(scope, fence.binding)
        || fence.binding.personaId !== persona.id || fence.binding.role !== 'admin'
        || fence.binding.sessionId !== personaSession.sessionId
        || fence.binding.authorityVersion !== personaSession.authorityVersion) throw unavailable();
    await fence.assertRemoteAdmission();
    const modeToken = await captureFeatureMode(modeAuthority, scope, 'support_tickets');
    const retainedScene = await scenes.readRetained(scope);
    if (!retainedScene?.scene || !sameScope(scope, executionScope(retainedScene))) throw unavailable('SHOP_SCENE_STALE');
    await modeToken.assertCurrent();
    await fence.assertRemoteAdmission();
    const result = await repository[method]({ scope, persona, personaSession, retainedScene, modeToken }, selected);
    await modeToken.assertCurrent();
    await fence.assertRemoteAdmission();
    await launches.assertCurrent(scope);
    return result;
  }
  return Object.freeze({
    list: (input, options = {}) => read(input, options, 'listForAdmin'),
    read: (input, options = {}) => read(input, options, 'readForAdmin'),
  });
}

module.exports = { createTicketAdministration };
