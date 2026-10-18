'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createConversationBinding, conversationBindingMatches } = require('../server/services/secureshopConversationBinding');
const scope = { launchId: '50000000-0000-4000-8000-000000000001', scenarioId: '50000000-0000-4000-8000-000000000002', generation: 1, platformOwnerId: 5, platformSessionId: 6 };
const persona = { id: 1, role: 'customer' };
test('binding snapshots separate platform owner and teaching persona and excludes credentials', () => {
  const mutable = { ...scope, bearer: 'private' }, shop = { ...persona };
  const binding = createConversationBinding(mutable, shop);
  mutable.platformOwnerId = 9; shop.id = 10;
  assert.equal(binding.platformOwnerId, 5); assert.equal(binding.shopUserId, 1);
  assert.ok(Object.isFrozen(binding)); assert.ok(!JSON.stringify(binding).includes('private'));
});
test('every ownership coordinate must match even when the teaching persona is shared', () => {
  const binding = createConversationBinding(scope, persona);
  assert.ok(conversationBindingMatches(binding, { ...binding }));
  for (const key of Object.keys(binding)) {
    assert.equal(conversationBindingMatches({ ...binding, [key]: typeof binding[key] === 'number' ? binding[key] + 1 : 'other' }, binding), false, key);
    const missing = { ...binding }; delete missing[key];
    assert.equal(conversationBindingMatches(missing, binding), false, key);
  }
  assert.equal(conversationBindingMatches(null, binding), false);
});
test('invalid authority and persona values cannot create a binding', () => {
  for (const changed of [{ generation: 0 }, { generation: Number.MAX_SAFE_INTEGER + 1 }, { platformOwnerId: '5' }, { platformSessionId: -1 }, { launchId: 'bad' }]) {
    assert.throws(() => createConversationBinding({ ...scope, ...changed }, persona));
  }
  assert.throws(() => createConversationBinding(scope, { id: 1, role: 'superuser' }));
});
