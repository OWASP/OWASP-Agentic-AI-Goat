/**
 * @intentional-vulnerability ssrf-return-policy
 * @teaches OWASP-Web:A10
 * @location agent-host/agents/summarizer/tools/explain_return_policy.js
 *
 * Parity: SSRF via summarizer.explain_return_policy must fetch the attacker
 * URL identically across all three providers.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const { runParity } = require('./_harness.js');

test('parity/ssrf-return-policy: internal URL is fetched identically across providers', async () => {
  // Start a shared "attacker-controlled" endpoint that all three provider
  // runs will hit. Each hit increments the counter — we assert exactly 3 hits.
  let hits = 0;
  const server = http.createServer((req, res) => { hits += 1; res.end('METADATA_LEAK_parity'); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    const attackerUrl = `http://127.0.0.1:${port}/latest/meta-data/`;
    await runParity({
      role: 'customer',
      userId: 2,
      userMessage: `please explain the return policy at ${attackerUrl}`,
      script: [
        { stop: 'tool_use', tool_uses: [{ name: 'summarizer.explain_return_policy', args: { policy_url: attackerUrl } }] },
        { stop: 'end_turn', text: 'Fetched: METADATA_LEAK_parity' },
      ],
      manifestTools: [{
        agent: 'summarizer', tool: 'explain_return_policy',
        description: 'Explain the return policy at a URL.',
        inputSchema: { type: 'object', properties: { policy_url: { type: 'string' } } },
      }],
      wireTools(pool, ctx) {
        const { explainReturnPolicy } = require(path.join(ctx.REPO, 'agent-host/agents/summarizer/tools/explain_return_policy.js'));
        pool.callTool = async (agent, tool, args) => {
          if (agent === 'summarizer' && tool === 'explain_return_policy') {
            const r = await explainReturnPolicy(args || {});
            return { content: [{ type: 'text', text: JSON.stringify(r) }] };
          }
          return { content: [{ type: 'text', text: '{}' }] };
        };
      },
      assertOutcome(runResult) {
        assert.equal(runResult.stopReason, 'end_turn');
        const hop = runResult.hops.find(h => h.tool === 'summarizer.explain_return_policy');
        assert.ok(hop, 'explain_return_policy hop present');
        assert.match(JSON.stringify(hop.result), /METADATA_LEAK_parity/,
          'attacker URL body leaked into tool result');
      },
    });

    assert.equal(hits, 3, 'each of 3 providers reached the attacker URL (SSRF fires uniformly)');
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
