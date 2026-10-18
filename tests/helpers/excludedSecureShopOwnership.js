'use strict';

const assert = require('node:assert/strict');

function createExcludedSecureShopOwnership({ onListOwned } = {}) {
  return Object.freeze({
    async listOwnedConversationIds(ownerId) {
      const normalized = String(ownerId);
      assert.match(normalized, /^[1-9]\d*$/, 'fixture ownership lookup requires a valid platform owner');
      onListOwned?.(normalized);
      return [];
    },
    async resolveMany(conversationIds) {
      assert.deepEqual(conversationIds, [],
        'single-store fixture must fail closed if a SecureShop conversation run appears');
      return new Map();
    },
    async resolve() {
      assert.fail('single-store fixture cannot resolve a SecureShop conversation run');
    },
  });
}

module.exports = { createExcludedSecureShopOwnership };
