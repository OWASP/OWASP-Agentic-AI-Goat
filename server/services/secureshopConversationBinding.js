'use strict';

// Platform launch scope and the deliberately vulnerable shop persona are
// separate identities. Construct this only from trusted server-side records.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES = new Set(['customer', 'merchant', 'admin']);
const FIELDS = Object.freeze(['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId', 'shopUserId', 'role']);
function createLaunchScope(scope) {
  if (!scope) throw new TypeError('Trusted launch required');
  const binding = {};
  for (const key of ['launchId', 'scenarioId']) {
    if (typeof scope[key] !== 'string' || !UUID.test(scope[key])) throw new TypeError(`Invalid ${key}`);
    binding[key] = scope[key].toLowerCase();
  }
  if (!Number.isSafeInteger(scope.generation) || scope.generation < 1) throw new TypeError('Invalid generation');
  binding.generation = scope.generation;
  for (const key of ['platformOwnerId', 'platformSessionId']) {
    if (!Number.isInteger(scope[key]) || scope[key] < 1 || scope[key] > 2147483647) throw new TypeError(`Invalid ${key}`);
    binding[key] = scope[key];
  }
  return Object.freeze(binding);
}
function createConversationBinding(scope, persona) {
  const binding = { ...createLaunchScope(scope) };
  if (!persona || !Number.isInteger(persona.id) || persona.id < 1 || persona.id > 2147483647 || !ROLES.has(persona.role)) {
    throw new TypeError('Invalid shop persona');
  }
  binding.shopUserId = persona.id;
  binding.role = persona.role;
  return Object.freeze(binding);
}
function conversationBindingMatches(stored, expected) {
  if (!stored || !expected) return false;
  return FIELDS.every(key => Object.hasOwn(stored, key) && Object.hasOwn(expected, key) && stored[key] === expected[key]);
}
module.exports = { createLaunchScope, createConversationBinding, conversationBindingMatches };
