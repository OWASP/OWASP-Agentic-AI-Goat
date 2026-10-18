'use strict';

const reviewScene = require('./secureshopReviewSceneBinding');
const trusted = new WeakMap();
const KEYS = ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId'];
function denied() {
  throw Object.assign(new Error('Seller review authority unavailable'),
    { code: 'SHOP_AUTH_INVALID', executionBoundary: true });
}
// Called only after server-side persona capture and target resolution. Model
// arguments, JSON copies and audit labels cannot become moderation authority.
function capture(target, persona, fence) {
  const scene = reviewScene.productScene(target);
  if (!scene) return undefined; // Explicit retained non-scene fixture path.
  const current = reviewScene.current(target);
  if (persona?.role !== 'merchant' || !Number.isSafeInteger(persona.id) || persona.id < 1
      || fence?.binding?.role !== 'merchant' || fence.binding.personaId !== persona.id
      || KEYS.some(key => current[key] !== fence.binding[key])
      || typeof fence.assertRemoteAdmission !== 'function'
      || typeof fence.withCrossStoreEffect !== 'function') denied();
  const capability = Object.freeze({});
  trusted.set(capability, { targetId: target.targetId, scene,
    actorId: persona.id, fence });
  return capability;
}
function read(capability, target, persona) {
  const value = trusted.get(capability);
  if (!value || value.targetId !== target.targetId
      || value.scene !== reviewScene.productScene(target)
      || KEYS.some(key => reviewScene.current(target)[key] !== value.fence.binding[key])
      || (persona && (persona.role !== 'merchant' || persona.id !== value.actorId))) denied();
  return value;
}
module.exports = { capture, read };
