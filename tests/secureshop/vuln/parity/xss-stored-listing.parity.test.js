/**
 * @intentional-vulnerability xss-stored-listing
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/listing/tools/create.js
 *
 * Parity: stored XSS via listing.create must persist the payload identically
 * across all three providers.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { runParity } = require('./_harness.js');

test('parity/xss-stored-listing: <img onerror> persists identically across providers', async () => {
  const payload = `<img src=x onerror="window.__pwn=1">`;
  await runParity({
    role: 'merchant',
    userId: 2,
    userMessage: `create a listing with description ${payload}`,
    script: [
      { stop: 'tool_use', tool_uses: [{ name: 'listing.create', args: { title: 'Parity Stored XSS', description: payload, price: 9.99 } }] },
      { stop: 'end_turn', text: 'Listing created.' },
    ],
    manifestTools: [{
      agent: 'listing', tool: 'create',
      description: 'Create a product listing.',
      inputSchema: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          description: { type: 'string' },
          price: { type: 'number' },
        },
      },
    }],
    wireTools(pool, ctx) {
      const { create } = require(path.join(ctx.REPO, 'agent-host/agents/listing/tools/create.js'));
      pool.callTool = async (agent, tool, args) => {
        if (agent === 'listing' && tool === 'create') {
          const r = await create(args || {});
          return { content: [{ type: 'text', text: JSON.stringify(r) }] };
        }
        return { content: [{ type: 'text', text: '{}' }] };
      };
    },
    async assertOutcome(runResult, { s }) {
      assert.equal(runResult.stopReason, 'end_turn');
      const hop = runResult.hops.find(h => h.tool === 'listing.create');
      assert.ok(hop, 'listing.create hop present');
      // Extract the persisted product id
      const parsed = JSON.parse(hop.result.content[0].text);
      const productId = parsed.product_id;
      assert.ok(productId, 'product id returned');

      const row = (await s.query('SELECT description_html FROM secureshop.products WHERE id=$1', [productId])).rows[0];
      assert.match(row.description_html, /<img src=x onerror=/,
        'XSS payload persisted verbatim in products.description_html');
    },
  });
});
