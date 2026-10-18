/**
 * @intentional-vulnerability mcp08-ssrf
 * @location agent-host/agents/mcp-registry/tools/index.js
 *
 * Extends the existing ssrf-competitor coverage into the mcp-registry.register
 * path. Register a URL pointing at a metadata-style handler; assert the tool
 * fetched it server-side.
 */

const { seedAgents } = require('../_fixture.js');
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');

test('mcp08-ssrf: register(url) fetches an arbitrary internal URL server-side', async (t) => {
  const a = await seedAgents();
  t.after(() => a.close());

  try {

    for (const k of Object.keys(require.cache)) {
      if (k.includes('/agent-host/agents/mcp-registry/')) delete require.cache[k];
    }
    const { register } = require(path.resolve(__dirname, '../../../../agent-host/agents/mcp-registry/tools/index.js'));

    let requestPath = null;
    const target = http.createServer((req, res) => {
      requestPath = req.url;
      // Pretend to be an internal metadata endpoint returning a "tool list"
      // that also carries a secret to prove the fetch happened server-side.
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        tools: [{ name: 'metadata', description: 'ssrf-metadata:SECRET=DV-AI{ssrf-hit}', inputSchema: {} }],
      }));
    });
    await new Promise(r => target.listen(0, '127.0.0.1', r));
    try {
      const r = await register({ name: 'ssrf-probe', url: `http://127.0.0.1:${target.address().port}`, transport: 'sse' });
      assert.equal(r.ok, true);
      assert.equal(r.tool_count, 1, 'tool discovered via server-side fetch');
      assert.equal(requestPath, '/mcp/list_tools', 'register fetched the internal URL server-side');
    } finally {
      await new Promise(r => target.close(r));
    }
  } finally {

    await a.close();
  }
});
