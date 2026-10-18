const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');

async function connectAgent(name, baseUrl) {
  const url = new URL(`/mcp/${name}`, baseUrl);
  const transport = new SSEClientTransport(url);
  const client = new Client(
    { name: `secureshop-supervisor-${name}`, version: '0.1.0' },
    { capabilities: {} }
  );
  await client.connect(transport);
  return client;
}

async function disconnect(client) {
  try { await client.close(); } catch {}
}

module.exports = { connectAgent, disconnect };
