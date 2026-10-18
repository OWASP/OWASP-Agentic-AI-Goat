'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopProductExecutionConfig } = require('../server/services/secureshopProductExecutionConfig');

test('server-selected product operation exposes only its target-bound observation tool', async () => {
  for (const [operation, agent, tool] of [['summary','summarizer','summarize_product'], ['similar','product-search','similar']]) {
    const config = createSecureShopProductExecutionConfig(operation);
    const manifest = config.manifest.getForRole('customer');
    assert.equal(manifest.length, 1);
    assert.equal(manifest[0].agent, agent); assert.equal(manifest[0].tool, tool);
    assert.deepEqual(Object.keys(manifest[0].inputSchema.properties), ['product_id']);
    assert.equal(manifest[0].inputSchema.additionalProperties, false);
    assert.equal((await config.checkToolAcl('customer', agent, tool)).allowed, true);
    assert.equal((await config.checkToolAcl('merchant', agent, tool)).allowed, false);
    assert.equal((await config.checkToolAcl('customer', 'user-management', 'set_role')).allowed, false);
    assert.deepEqual(config.manifest.getForRole('admin'), []);
    assert.throws(() => config.buildBasePrompt('admin'), /customer/);
    assert.match(config.buildBasePrompt('customer'), /successful tool result/);
  }
  assert.throws(() => createSecureShopProductExecutionConfig('admin'), /Invalid/);
  assert.throws(() => createSecureShopProductExecutionConfig('__proto__'), /Invalid/);
});
