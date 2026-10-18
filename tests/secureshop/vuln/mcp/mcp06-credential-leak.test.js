/**
 * @intentional-vulnerability mcp06-credential-leak
 * @teaches OWASP-MCP:MCP-01
 * @location agent-host/agents/system/tools/index.js
 *
 * system.read_config exposes raw config file contents. When pointed at
 * server/platform_secrets.json (via the path-traversal bypass) it returns
 * the fake DV-AI marker + fake AWS keys — the credential-leak sink.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

test('mcp06-credential-leak: read_config surfaces fake AWS/API keys from platform_secrets.json', t => {
  for (const k of Object.keys(require.cache)) {
    if (k.includes('/agent-host/agents/system/')) delete require.cache[k];
  }
  const fixture = require('../../fixtures/syntheticSystemConfig')();
  t.after(() => fixture.close());
  const { read_config } = fixture;

  const r = read_config({ path: 'platform_secrets.json' });
  assert.equal(r.ok, true);
  assert.ok(r.content.includes('AKIA_FAKE_XXXXXXXX'), 'fake AWS access key leaked');
  assert.ok(r.content.includes('int_bearer_c0ffee'), 'fake internal bearer leaked');
  assert.ok(r.content.includes('DV-AI{admin_secret_M4}'), 'DV-AI marker leaked');
});
