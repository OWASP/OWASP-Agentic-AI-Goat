'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

test('failed legacy discovery preserves the last usable PostgreSQL registration and history', async t => {
  const servers = new Map(), tools = new Map(), history = [];
  const repository = {
    async registerServer(input) {
      const old = servers.get(input.name);
      servers.set(input.name, { ...input });
      tools.set(input.name, input.tools.map((tool, index) => ({ id: index + 1,
        server_name: input.name, tool_name: tool.name, description: tool.description || '',
        input_schema_json: JSON.stringify(tool.inputSchema || {}) })));
      history.push({ id: history.length + 1, name: input.name, schema_hash: input.schemaHash,
        tools_json: JSON.stringify(input.tools) });
      return { existing: Boolean(old), changed: !old || old.schemaHash !== input.schemaHash };
    },
    async describeTools(name) { return (tools.get(name) || []).map(row => ({ ...row })); },
  };
  const repositoryPath = require.resolve('../server/database/postgres/secureshopAgentsDb');
  const modulePath = require.resolve('../agent-host/agents/mcp-registry/tools');
  const previousRepository = require.cache[repositoryPath];
  require.cache[repositoryPath] = { id: repositoryPath, filename: repositoryPath, loaded: true,
    exports: { getSecureShopAgentsDb: () => repository } };
  delete require.cache[modulePath];
  const registry = require(modulePath);
  let status = 200, body = JSON.stringify({ tools: [{ name: 'forecast', description: 'A real tool', inputSchema: {} }] });
  const server = http.createServer((_req, res) => { res.writeHead(status); res.end(body); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    delete require.cache[modulePath];
    if (previousRepository) require.cache[repositoryPath] = previousRepository;
    else delete require.cache[repositoryPath];
  });
  const request = { name: 'weather', url: `http://127.0.0.1:${server.address().port}`, transport: 'sse' };
  assert.equal((await registry.register(request)).ok, true);
  const original = structuredClone({ server: servers.get('weather'), tools: tools.get('weather'), history });
  for (const response of [
    { status: 200, body: '<html>proxy failure</html>' },
    { status: 200, body: '{}' },
    { status: 503, body: '{"tools":[]}' },
    { status: 200, body: '{"tools":[null]}' },
  ]) {
    ({ status, body } = response);
    const result = await registry.register(request);
    assert.equal(result.ok, false, `discovery failure must not register: ${status} ${body}`);
    assert.equal(typeof result.discovery_error, 'string');
    assert.deepEqual({ server: servers.get('weather'), tools: tools.get('weather'), history }, original);
    assert.equal((await registry.describe_tools({ name: 'weather' })).tools[0].tool_name, 'forecast');
    assert.equal(history.length, 1);
  }
  status = 200; body = '{"tools":[]}';
  assert.equal((await registry.register(request)).ok, true, 'a genuine empty schema remains a valid rotation');
  assert.equal((await registry.describe_tools({ name: 'weather' })).tool_count, 0);
  assert.equal(history.length, 2);
});
